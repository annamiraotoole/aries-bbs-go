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
	Verify(*PublicKeyWithGenerators, map[int]*SignatureMessage, []*SignatureMessage, *ml.ProofG1, *ml.G1, *ml.G1, []byte) error
}

// PoKOfSignatureProof defines BLS signature proof.
// It is the actual proof that is sent from prover to verifier.
type PoKOfSignatureProof struct {
	APrime *ml.G1
	ABar   *ml.G1

	ProofVC *ml.ProofG1

	VCProofVerifier

	curve *ml.Curve
}

// PoKOfSignatureProof defines BLS signature proof.
// It is the actual proof that is sent from prover to verifier.
type RevPoKOfSignatureProof struct {
	APrime *ml.G1
	ABar   *ml.G1

	VCProofVerifier

	curve *ml.Curve
}

// Verify verifies PoKOfSignatureProof.
func (sp *PoKOfSignatureProof) Verify(pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage, nonce []byte) error {

	ok := sp.curve.CompareTwoPairings(sp.APrime, pubKey.w, sp.ABar, sp.curve.GenG2)
	if !ok {
		return errors.New("bad signature")
	}

	return sp.VCProofVerifier.Verify(pubKey, revealedMessages, messages, sp.ProofVC, sp.APrime, sp.ABar, nonce)
}

// Verify verifies PoKOfSignatureProof.
func RevVerify(curve *ml.Curve, aPrime *ml.G1, aBar *ml.G1, pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage) error {

	ok := curve.CompareTwoPairings(aPrime, pubKey.w, aBar, curve.GenG2)
	if !ok {
		return errors.New("bad signature")
	} else {
		return nil
	}
}

// // Verify verifies PoKOfSignatureProof.
// func (sp *RevPoKOfSignature) RevVerify(pubKey *PublicKeyWithGenerators,
// 	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage) error {

// 	ok := sp.curve.CompareTwoPairings(sp.APrime, pubKey.w, sp.ABar, sp.curve.GenG2)
// 	if !ok {
// 		return errors.New("bad revocation signature proof")
// 	} else {
// 		return nil
// 	}
// }

type defaultVCProofVerifier struct {
	curve *ml.Curve
}

func (v *defaultVCProofVerifier) Verify(pubKey *PublicKeyWithGenerators,
	revealedMessages map[int]*SignatureMessage, messages []*SignatureMessage, ProofVC *ml.ProofG1, aPrime *ml.G1, aBar *ml.G1, nonce []byte) error {
	revealedMessagesCount := len(revealedMessages)

	// bases should be A', aBar, then all the H[i] that are not revealed
	basesVC := make([]*ml.G1, 0, 2+pubKey.MessagesCount-revealedMessagesCount)
	basesVC = append(basesVC, aPrime, aBar)

	basesDisclosed := make([]*ml.G1, 0, 1+revealedMessagesCount)
	exponents := make([]*ml.Zr, 0, 1+revealedMessagesCount)

	basesDisclosed = append(basesDisclosed, v.curve.GenG1)
	exponents = append(exponents, v.curve.NewZrFromInt(1))

	for i := range pubKey.H {
		if _, ok := revealedMessages[i]; ok {
			basesDisclosed = append(basesDisclosed, pubKey.H[i])
			exponents = append(exponents, revealedMessages[i].FR)
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

		g := b.Mul(s.Copy())
		pr.Add(g)
	}

	challProvider := v.curve.NewChallengeProvider(ProofVC.Commitment, basesVC, nonce)

	// pr.Neg() // DEVIATION FROM ORIGINAL CODE

	if !v.curve.VerifyProofG1(ProofVC, pr, basesVC, challProvider) {
		return errors.New("bad proof of knowledge of signature")
	}

	return nil
}

// DOUBLE CHECK CONSISTENT with ParseSignatureProof
// ToBytes converts PoKOfSignatureProof to bytes.
func (sp *PoKOfSignatureProof) ToBytes() []byte {
	bytes := make([]byte, 0)

	bytes = append(bytes, sp.APrime.Compressed()...)
	bytes = append(bytes, sp.ABar.Compressed()...)

	proofBytes := sp.ProofVC.ToBytes()
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(proofBytes)))
	bytes = append(bytes, lenBytes...)
	bytes = append(bytes, proofBytes...)

	return bytes
}

// // Verify verifies the ProofG1.
// func (pg1 *ProofG1) Verify(bases []*ml.G1, commitment *ml.G1, challenge *ml.Zr) error {
// 	contribution := pg1.getChallengeContribution(bases, commitment, challenge)
// 	contribution.Sub(pg1.Commitment)

// 	if !contribution.IsInfinity() {
// 		return errors.New("contribution is not zero")
// 	}

// 	return nil
// }

// func (pg1 *ml.ProofG1) getChallengeContribution(bases []*ml.G1, commitment *ml.G1,
// 	challenge *ml.Zr) *ml.G1 {
// 	points := append(bases, commitment)
// 	scalars := append(pg1.Responses, challenge)

// 	return ml.SumOfG1Products(points, scalars)
// }

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

	proofVc, err := b.curve.ParseProofG1(sigProofBytes[offset : offset+proofBytesLen])
	if err != nil {
		return nil, fmt.Errorf("parse G1 proof: %w", err)
	}

	return &PoKOfSignatureProof{
		APrime:  g1Points[0],
		ABar:    g1Points[1],
		ProofVC: proofVc,
		VCProofVerifier: &defaultVCProofVerifier{
			curve: b.curve,
		},
		curve: b.curve,
	}, nil
}
