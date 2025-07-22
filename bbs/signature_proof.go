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

type VC2ProofVerifier interface {
	Verify(*PublicKeyWithGenerators, map[int]*SignatureMessage, []*SignatureMessage, *ml.ProofG1, *ml.G1, ml.ChallengeProvider) error
}

// PoKOfSignatureProof defines BLS signature proof.
// It is the actual proof that is sent from prover to verifier.
type PoKOfSignatureProof struct {
	aPrime *ml.G1
	aBar   *ml.G1
	d      *ml.G1

	proofVC1 *ml.ProofG1
	ProofVC2 *ml.ProofG1

	VC2ProofVerifier

	curve *ml.Curve
}

type BBSChallProvider struct {
	curve            *ml.Curve
	aPrime           *ml.G1
	aBar             *ml.G1
	d                *ml.G1
	commitment1      *ml.G1
	commitment2      *ml.G1
	pubKey           *PublicKeyWithGenerators
	revealedMessages map[int]*SignatureMessage
	nonce            []byte
}

func NewBBSChallProvider(curve *ml.Curve, aPrime, aBar, d, commitment1, commitment2 *ml.G1, pubKey *PublicKeyWithGenerators, revealedMessages map[int]*SignatureMessage, nonce []byte) *BBSChallProvider {
	return &BBSChallProvider{
		curve:            curve,
		aPrime:           aPrime,
		aBar:             aBar,
		d:                d,
		commitment1:      commitment1,
		commitment2:      commitment2,
		pubKey:           pubKey,
		revealedMessages: revealedMessages,
		nonce:            nonce,
	}
}

func (cp *BBSChallProvider) GetChallenge() *ml.Zr {
	hiddenCount := cp.pubKey.MessagesCount - len(cp.revealedMessages)

	basesLen := (7 + hiddenCount) * cp.curve.CompressedG1ByteSize //nolint:gomnd
	bases := make([]*ml.G1, 0, basesLen)

	bases = append(bases, cp.aBar)
	bases = append(bases, cp.aPrime)
	bases = append(bases, cp.pubKey.H0)
	bases = append(bases, cp.commitment1)
	bases = append(bases, cp.d)
	bases = append(bases, cp.pubKey.H0)

	for i := range cp.pubKey.H {
		if _, ok := cp.revealedMessages[i]; !ok {
			bases = append(bases, cp.pubKey.H[i])
		}
	}

	bases = append(bases, cp.commitment2)

	challengeBytes := make([]byte, 0)

	for _, base := range bases {
		challengeBytes = append(challengeBytes, base.Bytes()...)
	}

	if cp.nonce == nil {
		panic("nonce cannot be nil in ComputeChallenge")
	}

	challengeBytes = append(challengeBytes, NonceToFrBytes(cp.curve, cp.nonce)...)
	// convert final challenge bytes to a field element
	challenge := FrFromOKM(cp.curve, challengeBytes)

	return challenge
}

// Verify verifies PoKOfSignatureProof.
func (sp *PoKOfSignatureProof) Verify(pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage, nonce []byte) error {

	ok := sp.curve.CompareTwoPairings(sp.aPrime, pubKey.w, sp.aBar, sp.curve.GenG2)
	if !ok {
		return errors.New("bad signature")
	}

	challProvider := NewBBSChallProvider(sp.curve, sp.aPrime, sp.aBar, sp.d,
		sp.proofVC1.Commitment, sp.ProofVC2.Commitment, pubKey, revealedMessages, nonce)

	err := sp.verifyVC1Proof(pubKey, challProvider)
	if err != nil {
		return err
	}

	return sp.VC2ProofVerifier.Verify(pubKey, revealedMessages, messages, sp.ProofVC2, sp.d, challProvider)
}

func (sp *PoKOfSignatureProof) verifyVC1Proof(pubKey *PublicKeyWithGenerators, challProvider ml.ChallengeProvider) error {
	basesVC1 := []*ml.G1{sp.aPrime, pubKey.H0}
	aBarD := sp.aBar.Copy()
	aBarD.Sub(sp.d)

	if !sp.curve.VerifyProofG1(sp.proofVC1, aBarD, basesVC1, challProvider) {
		return errors.New("new verifyG1 function did not work on proofVC1")
	}

	return nil
}

type defaultVC2ProofVerifier struct {
	curve *ml.Curve
}

func (v *defaultVC2ProofVerifier) Verify(pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage, ProofVC2 *ml.ProofG1,
	d *ml.G1, challProvider ml.ChallengeProvider) error {
	revealedMessagesCount := len(revealedMessages)

	basesVC2 := make([]*ml.G1, 0, 2+pubKey.MessagesCount-revealedMessagesCount)
	basesVC2 = append(basesVC2, d, pubKey.H0)

	basesDisclosed := make([]*ml.G1, 0, 1+revealedMessagesCount)
	exponents := make([]*ml.Zr, 0, 1+revealedMessagesCount)

	basesDisclosed = append(basesDisclosed, v.curve.GenG1)
	exponents = append(exponents, v.curve.NewZrFromInt(1))

	revealedMessagesInd := 0

	for i := range pubKey.H {
		if _, ok := revealedMessages[i]; ok {
			basesDisclosed = append(basesDisclosed, pubKey.H[i])
			exponents = append(exponents, messages[revealedMessagesInd].FR)
			revealedMessagesInd++
		} else {
			basesVC2 = append(basesVC2, pubKey.H[i])
		}
	}

	// TODO: expose 0
	pr := v.curve.GenG1.Copy()
	pr.Sub(v.curve.GenG1)

	for i := 0; i < len(basesDisclosed); i++ {
		b := basesDisclosed[i]
		s := exponents[i]

		g := b.Mul(s.Copy())
		pr.Add(g)
	}

	pr.Neg()

	// Verify the proof
	if !v.curve.VerifyProofG1(ProofVC2, pr, basesVC2, challProvider) {
		return errors.New("new verifyG1 function did not work on ProofVC2")
	}

	return nil
}

// ToBytes converts PoKOfSignatureProof to bytes.
func (sp *PoKOfSignatureProof) ToBytes() []byte {
	bytes := make([]byte, 0)

	bytes = append(bytes, sp.aPrime.Compressed()...)
	bytes = append(bytes, sp.aBar.Compressed()...)
	bytes = append(bytes, sp.d.Compressed()...)

	proof1Bytes := sp.proofVC1.ToBytes()
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(proof1Bytes)))
	bytes = append(bytes, lenBytes...)
	bytes = append(bytes, proof1Bytes...)

	bytes = append(bytes, sp.ProofVC2.ToBytes()...)

	return bytes
}

// ParseSignatureProof parses a signature proof.
func (b *BBSLib) ParseSignatureProof(sigProofBytes []byte) (*PoKOfSignatureProof, error) {
	if len(sigProofBytes) < b.g1CompressedSize*3 {
		return nil, errors.New("invalid size of signature proof")
	}

	g1Points := make([]*ml.G1, 3)
	offset := 0

	for i := range g1Points {
		g1Point, err := b.curve.NewG1FromCompressed(sigProofBytes[offset : offset+b.g1CompressedSize])
		if err != nil {
			return nil, fmt.Errorf("parse G1 point: %w", err)
		}

		g1Points[i] = g1Point
		offset += b.g1CompressedSize
	}

	proof1BytesLen := int(uint32FromBytes(sigProofBytes[offset : offset+4]))
	offset += 4

	proofVc1, err := b.ParseProofG1(sigProofBytes[offset : offset+proof1BytesLen])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	offset += proof1BytesLen

	proofVc2, err := b.ParseProofG1(sigProofBytes[offset:])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	return &PoKOfSignatureProof{
		aPrime:   g1Points[0],
		aBar:     g1Points[1],
		d:        g1Points[2],
		proofVC1: proofVc1,
		ProofVC2: proofVc2,
		VC2ProofVerifier: &defaultVC2ProofVerifier{
			curve: b.curve,
		},
		curve: b.curve,
	}, nil
}

// ParseProofG1 parses ProofG1 from bytes.
func (b *BBSLib) ParseProofG1(bytes []byte) (*ml.ProofG1, error) {
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

	if len(bytes) < b.g1CompressedSize+4+length*b.curve.FrCompressedSize {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	responses := make([]*ml.Zr, length)
	for i := 0; i < length; i++ {
		responses[i] = b.curve.NewZrFromBytes(bytes[offset : offset+b.curve.FrCompressedSize])
		offset += b.curve.FrCompressedSize
	}

	return ml.NewProofG1(commitment, responses), nil
}
