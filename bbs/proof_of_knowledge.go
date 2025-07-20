/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"fmt"

	ml "github.com/IBM/mathlib"
	zkp "github.com/annamiraotoole/mathlib-schnorr/schnorr"
)

// PoKOfSignature is Proof of Knowledge of a Signature that is used by the prover to construct PoKOfSignatureProof.
type PoKOfSignature struct {
	aPrime *ml.G1
	aBar   *ml.G1

	pokVC   *zkp.ProverCommittedG1
	secrets []*ml.Zr

	revealedMessages map[int]*SignatureMessage

	curve *ml.Curve
}

// NewPoKOfSignature creates a new PoKOfSignature.
func (bl *BBSLib) NewPoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
	pubKey *PublicKeyWithGenerators, nonce []byte, r *ml.Zr) (*PoKOfSignature, error) {

	p := &PoKOfSignatureProvider{
		VCSignatureProvider: &defaultVCSignatureProvider{
			bl: bl,
		},
		VerifySig: true,
		Curve:     bl.curve,
		Bl:        bl,
	}

	return p.PoKOfSignature(signature, messages, revealedIndexes, pubKey, nonce, r)
}

type VCSignatureProvider interface {
	New(*Signature, *ml.G1, *ml.G1, *ml.G1, *ml.Zr, *PublicKeyWithGenerators, []*SignatureMessage, map[int]*SignatureMessage, []byte) (*zkp.ProverCommittedG1, []*ml.Zr)
}

type PoKOfSignatureProvider struct {
	VCSignatureProvider

	VerifySig bool

	Curve *ml.Curve
	Bl    *BBSLib
}

func (p *PoKOfSignatureProvider) PoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
	pubKey *PublicKeyWithGenerators, nonce []byte, r *ml.Zr) (*PoKOfSignature, error) {
	b := ComputeB(messages, pubKey, p.Bl.curve)

	return p.PoKOfSignatureB(signature, messages, revealedIndexes, pubKey, b, nonce, r)
}

func (p *PoKOfSignatureProvider) PoKOfSignatureB(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
	pubKey *PublicKeyWithGenerators, b *ml.G1, nonce []byte, r *ml.Zr) (*PoKOfSignature, error) {

	if p.VerifySig {
		err := signature.Verify(messages, pubKey)
		if err != nil {
			return nil, fmt.Errorf("verify input signature: %w", err)
		}
	}

	// r := p.Bl.createRandSignatureFr()
	aPrime := signature.A.Mul(r.Copy())
	aBar := b.Mul(r.Copy())

	revealedMessages := make(map[int]*SignatureMessage, len(revealedIndexes))

	if len(messages) < len(revealedIndexes) {
		return nil, fmt.Errorf("invalid size: %d revealed indexes is larger than %d messages", len(revealedIndexes),
			len(messages))
	}

	for _, ind := range revealedIndexes {
		revealedMessages[messages[ind].Idx] = messages[ind]
	}

	pokVC, secrets := p.New(signature, aPrime, aBar, b, r, pubKey, messages, revealedMessages, nonce)

	return &PoKOfSignature{
		aPrime:           aPrime,
		aBar:             aBar,
		pokVC:            pokVC,
		secrets:          secrets,
		revealedMessages: revealedMessages,
		curve:            p.Curve,
	}, nil
}

type defaultVCSignatureProvider struct {
	bl *BBSLib
}

func (p *defaultVCSignatureProvider) New(signature *Signature, aPrime *ml.G1, aBar *ml.G1, b *ml.G1, r *ml.Zr, pubKey *PublicKeyWithGenerators, messages []*SignatureMessage, revealedMessages map[int]*SignatureMessage, nonce []byte) (*zkp.ProverCommittedG1, []*ml.Zr) {

	bases := make([]*ml.G1, 2)
	secrets := make([]*ml.Zr, 2)

	aBarDenom := aPrime.Mul(signature.E.Copy())

	aBar.Sub(aBarDenom)

	rng, err := p.bl.curve.Rand()
	if err != nil {
		panic(err)
	}

	rInv := r.Copy()
	rInv.InvModP(p.bl.curve.GroupOrder)

	eCopy := signature.E.Copy()
	eDivR := eCopy.Mul(rInv)
	bases[0] = aPrime
	secrets[0] = eDivR

	bases[1] = aBar
	secrets[1] = rInv

	// loop to add the bases for every hidden attribute
	for _, msg := range messages {

		// skip every revealed message
		if _, ok := revealedMessages[msg.Idx]; ok {
			continue
		}

		sourceFR := msg.FR
		hiddenFRCopy := sourceFR.Copy()
		hiddenFRCopy.Neg() // QUESTION: equivalent line in original code doesn't negative the exponent, but the protocol should have it negated, why? maybe this is accounted for by a division later on?

		bases = append(bases, pubKey.H[msg.Idx])
		secrets = append(secrets, hiddenFRCopy)
	}

	pokVC := zkp.StartProofG1(p.bl.curve, rng, bases, secrets)

	return pokVC, secrets
}

// GenerateProof generates PoKOfSignatureProof proof from PoKOfSignature signature.
func (pos *PoKOfSignature) GenerateProof(nonce []byte) *PoKOfSignatureProof {
	challProvider := zkp.NewChallengeProvider(pos.curve, pos.pokVC.Commitment, pos.pokVC.Bases, nonce)
	return &PoKOfSignatureProof{
		aPrime:  pos.aPrime,
		aBar:    pos.aBar,
		ProofVC: zkp.FinishProofG1(pos.curve, pos.pokVC, pos.secrets, challProvider),
		curve:   pos.curve,
		VCProofVerifier: &defaultVCProofVerifier{
			curve: pos.curve,
		},
	}
}
