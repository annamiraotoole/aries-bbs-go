/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"encoding/binary"
	"errors"
	"fmt"

	ml "github.com/IBM/mathlib"
)

type VCProofVerifier interface {
	Verify(*ml.Zr, *PublicKeyWithGenerators, map[int]*SignatureMessage, []*SignatureMessage, *ProofG1, *ml.G1, *ml.G1) error
}

// PoKOfSignatureProof defines BLS signature proof.
// It is the actual proof that is sent from prover to verifier.
type PoKOfSignatureProof struct {
	aPrime *ml.G1
	aBar   *ml.G1

	ProofVC *ProofG1

	VCProofVerifier

	curve *ml.Curve
}

// GetBytesForChallenge creates bytes for proof challenge.
func (sp *PoKOfSignatureProof) GetBytesForChallenge(revealedMessages map[int]*SignatureMessage,
	pubKey *PublicKeyWithGenerators) []byte {
	hiddenCount := pubKey.MessagesCount - len(revealedMessages)

	bytesLen := (4 + hiddenCount) * sp.curve.CompressedG1ByteSize
	bytes := make([]byte, 0, bytesLen)

	bytes = append(bytes, sp.aBar.Bytes()...)
	bytes = append(bytes, sp.aPrime.Bytes()...)
	bytes = append(bytes, sp.aBar.Bytes()...)
	for i := range pubKey.H {
		if _, ok := revealedMessages[i]; !ok {
			bytes = append(bytes, pubKey.H[i].Bytes()...)
		}
	}

	bytes = append(bytes, sp.ProofVC.Commitment.Bytes()...)

	return bytes
}

// Verify verifies PoKOfSignatureProof.
func (sp *PoKOfSignatureProof) Verify(challenge *ml.Zr, pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage) error {
	aBar := sp.aBar.Copy()
	aBar.Neg()

	ok := compareTwoPairings(sp.aPrime, pubKey.w, aBar, sp.curve.GenG2, sp.curve)
	if !ok {
		return errors.New("bad signature")
	}

	return sp.VCProofVerifier.Verify(challenge, pubKey, revealedMessages, messages, sp.ProofVC, sp.aPrime, sp.aBar)
}

type defaultVCProofVerifier struct {
	curve *ml.Curve
}

func (v *defaultVCProofVerifier) Verify(challenge *ml.Zr, pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage, ProofVC *ProofG1, aPrime *ml.G1, aBar *ml.G1) error {
	revealedMessagesCount := len(revealedMessages)

	// bases should be A', aBar, then all the H[i] that are not revealed
	basesVC := make([]*ml.G1, 0, 2+pubKey.MessagesCount-revealedMessagesCount)
	basesVC = append(basesVC, aPrime, aBar)

	basesDisclosed := make([]*ml.G1, 0, 1+revealedMessagesCount)
	exponents := make([]*ml.Zr, 0, 1+revealedMessagesCount)

	basesDisclosed = append(basesDisclosed, v.curve.GenG1)
	exponents = append(exponents, v.curve.NewZrFromInt(1))

	// revealedMessagesInd := 0 // DEVIATION FROM ORIGINAL CODE: this is not used in the new code

	for i := range pubKey.H {
		if _, ok := revealedMessages[i]; ok {
			basesDisclosed = append(basesDisclosed, pubKey.H[i])
			exponents = append(exponents, revealedMessages[i].FR) // DEVIATION FROM ORIGINAL CODE
			// revealedMessagesInd++ // DEVIATION FROM ORIGINAL CODE
		} else {
			basesVC = append(basesVC, pubKey.H[i])
		}
	}

	// TODO: expose 0
	pr := v.curve.GenG1.Copy()
	pr.Sub(v.curve.GenG1)

	for i := 0; i < len(basesDisclosed); i++ {
		b := basesDisclosed[i]
		s := exponents[i]

		g := b.Mul(FrToRepr(s))
		pr.Add(g)
	}

	// pr.Neg() // DEVIATION FROM ORIGINAL CODE

	err := ProofVC.Verify(basesVC, pr, challenge)
	if err != nil {
		return errors.New("bad proof of knowledge of signature")
	}

	return nil
}

// DOUBLE CHECK CONSISTENT with ParseSignatureProof
// ToBytes converts PoKOfSignatureProof to bytes.
func (sp *PoKOfSignatureProof) ToBytes() []byte {
	bytes := make([]byte, 0)

	bytes = append(bytes, sp.aPrime.Compressed()...)
	bytes = append(bytes, sp.aBar.Compressed()...)

	proofBytes := sp.ProofVC.ToBytes()
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(proofBytes)))
	bytes = append(bytes, lenBytes...)
	bytes = append(bytes, proofBytes...)

	return bytes
}

// ProofG1 is a proof of knowledge of a signature and hidden messages.
type ProofG1 struct {
	Commitment *ml.G1
	Responses  []*ml.Zr
}

// NewProofG1 creates a new ProofG1.
func NewProofG1(commitment *ml.G1, responses []*ml.Zr) *ProofG1 {
	return &ProofG1{
		Commitment: commitment,
		Responses:  responses,
	}
}

// Verify verifies the ProofG1.
func (pg1 *ProofG1) Verify(bases []*ml.G1, commitment *ml.G1, challenge *ml.Zr) error {
	contribution := pg1.getChallengeContribution(bases, commitment, challenge)
	contribution.Sub(pg1.Commitment)

	if !contribution.IsInfinity() {
		return errors.New("contribution is not zero")
	}

	return nil
}

func (pg1 *ProofG1) getChallengeContribution(bases []*ml.G1, commitment *ml.G1,
	challenge *ml.Zr) *ml.G1 {
	points := append(bases, commitment)
	scalars := append(pg1.Responses, challenge)

	return sumOfG1Products(points, scalars)
}

// ToBytes converts ProofG1 to bytes.
func (pg1 *ProofG1) ToBytes() []byte {
	bytes := make([]byte, 0)

	commitmentBytes := pg1.Commitment.Compressed()
	bytes = append(bytes, commitmentBytes...)

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(pg1.Responses)))
	bytes = append(bytes, lenBytes...)

	for i := range pg1.Responses {
		responseBytes := FrToRepr(pg1.Responses[i]).Bytes()
		bytes = append(bytes, responseBytes...)
	}

	return bytes
}

// ParseSignatureProof parses a signature proof.
func (b *BBSLib) ParseSignatureProof(sigProofBytes []byte) (*PoKOfSignatureProof, error) {
	// TODO does this need to be changed?
	if len(sigProofBytes) < b.g1CompressedSize*3 {
		return nil, errors.New("invalid size of signature proof")
	}

	g1Points := make([]*ml.G1, 2)
	offset := 0

	for i := range g1Points {
		g1Point, err := b.curve.NewG1FromCompressed(sigProofBytes[offset : offset+b.g1CompressedSize])
		if err != nil {
			return nil, fmt.Errorf("parse G1 point: %w", err)
		}

		g1Points[i] = g1Point
		offset += b.g1CompressedSize
	}

	proofBytesLen := int(uint32FromBytes(sigProofBytes[offset : offset+4]))
	offset += 4

	proofVc, err := b.ParseProofG1(sigProofBytes[offset : offset+proofBytesLen])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	return &PoKOfSignatureProof{
		aPrime:  g1Points[0],
		aBar:    g1Points[1],
		ProofVC: proofVc,
		VCProofVerifier: &defaultVCProofVerifier{
			curve: b.curve,
		},
		curve: b.curve,
	}, nil
}

// ParseProofG1 parses ProofG1 from bytes.
func (b *BBSLib) ParseProofG1(bytes []byte) (*ProofG1, error) {
	if len(bytes) < b.g1CompressedSize+4 {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	offset := 0

	commitment, err := b.curve.NewG1FromCompressed(bytes[:b.g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("parse G1 point: %w", err)
	}

	offset += b.g1CompressedSize
	length := int(uint32FromBytes(bytes[offset : offset+4]))
	offset += 4

	if len(bytes) < b.g1CompressedSize+4+length*frCompressedSize {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	responses := make([]*ml.Zr, length)
	for i := 0; i < length; i++ {
		responses[i] = b.parseFr(bytes[offset : offset+frCompressedSize])
		offset += frCompressedSize
	}

	return NewProofG1(commitment, responses), nil
}
