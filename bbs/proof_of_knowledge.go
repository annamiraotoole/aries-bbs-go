/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"fmt"

	ml "github.com/IBM/mathlib"
)

// PoKOfSignature is Proof of Knowledge of a Signature that is used by the prover to construct PoKOfSignatureProof.
type PoKOfSignature struct {
	aPrime *ml.G1
	aBar   *ml.G1

	pokVC   *ProverCommittedG1
	secrets []*ml.Zr

	revealedMessages map[int]*SignatureMessage

	curve *ml.Curve
}

// NewPoKOfSignature creates a new PoKOfSignature.
func (bl *BBSLib) NewPoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
	pubKey *PublicKeyWithGenerators) (*PoKOfSignature, error) {

	p := &PoKOfSignatureProvider{
		VCSignatureProvider: &defaultVCSignatureProvider{
			bl: bl,
		},
		VerifySig: true,
		Curve:     bl.curve,
		Bl:        bl,
	}

	return p.PoKOfSignature(signature, messages, revealedIndexes, pubKey)
}

type VCSignatureProvider interface {
	New(*Signature, *ml.G1, *ml.G1, *ml.G1, *ml.Zr, *PublicKeyWithGenerators, []*SignatureMessage, map[int]*SignatureMessage) (*ProverCommittedG1, []*ml.Zr)
}

type PoKOfSignatureProvider struct {
	VCSignatureProvider

	VerifySig bool

	Curve *ml.Curve
	Bl    *BBSLib
}

func (p *PoKOfSignatureProvider) PoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
	pubKey *PublicKeyWithGenerators) (*PoKOfSignature, error) {
	b := ComputeB(messages, pubKey, p.Bl.curve)

	return p.PoKOfSignatureB(signature, messages, revealedIndexes, pubKey, b)
}

func (p *PoKOfSignatureProvider) PoKOfSignatureB(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
	pubKey *PublicKeyWithGenerators, b *ml.G1) (*PoKOfSignature, error) {

	if p.VerifySig {
		err := signature.Verify(messages, pubKey)
		if err != nil {
			return nil, fmt.Errorf("verify input signature: %w", err)
		}
	}

	r := p.Bl.createRandSignatureFr()
	aPrime := signature.A.Mul(FrToRepr(r))
	aBar := b.Mul(FrToRepr(r))

	revealedMessages := make(map[int]*SignatureMessage, len(revealedIndexes))

	if len(messages) < len(revealedIndexes) {
		return nil, fmt.Errorf("invalid size: %d revealed indexes is larger than %d messages", len(revealedIndexes),
			len(messages))
	}

	for _, ind := range revealedIndexes {
		revealedMessages[messages[ind].Idx] = messages[ind]
	}

	pokVC, secrets := p.New(signature, aPrime, aBar, b, r, pubKey, messages, revealedMessages)

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

func (p *defaultVCSignatureProvider) New(signature *Signature, aPrime *ml.G1, aBar *ml.G1, b *ml.G1, r *ml.Zr, pubKey *PublicKeyWithGenerators, messages []*SignatureMessage, revealedMessages map[int]*SignatureMessage) (*ProverCommittedG1, []*ml.Zr) {

	aBarDenom := aPrime.Mul(FrToRepr(signature.E))

	aBar.Sub(aBarDenom)

	committing := p.bl.NewProverCommittingG1()
	secrets := make([]*ml.Zr, 2)

	rInv := r.Copy()
	rInv.InvModP(p.bl.curve.GroupOrder)

	committing.Commit(aPrime)
	eCopy := signature.E.Copy()
	eDivR := eCopy.Mul(rInv)
	secrets[0] = eDivR

	committing.Commit(aBar)
	secrets[1] = rInv

	// loop to add the bases for every hidden attribute
	for _, msg := range messages {

		// skip every revealed message
		if _, ok := revealedMessages[msg.Idx]; ok {
			continue
		}

		committing.Commit(pubKey.H[msg.Idx])

		sourceFR := msg.FR
		hiddenFRCopy := sourceFR.Copy()
		hiddenFRCopy.Neg() // ASK ALE: equivalent line in original code doesn't negative the exponent, but the protocol should have it negated, why? maybe this is accounted for by a division later on?

		secrets = append(secrets, hiddenFRCopy)
	}

	pokVC := committing.Finish()

	return pokVC, secrets
}

// ToBytes converts PoKOfSignature to bytes.
func (pos *PoKOfSignature) ToBytes() []byte {
	challengeBytes := pos.aBar.Bytes()
	challengeBytes = append(challengeBytes, pos.pokVC.ToBytes()...)

	return challengeBytes
}

// GenerateProof generates PoKOfSignatureProof proof from PoKOfSignature signature.
func (pos *PoKOfSignature) GenerateProof(challengeHash *ml.Zr) *PoKOfSignatureProof {
	return &PoKOfSignatureProof{
		aPrime:  pos.aPrime,
		aBar:    pos.aBar,
		ProofVC: pos.pokVC.GenerateProof(challengeHash, pos.secrets),
		curve:   pos.curve,
	}
}

// ProverCommittedG1 helps to generate a ProofG1.
type ProverCommittedG1 struct {
	Bases           []*ml.G1
	BlindingFactors []*ml.Zr
	Commitment      *ml.G1
}

// ToBytes converts ProverCommittedG1 to bytes.
func (g *ProverCommittedG1) ToBytes() []byte {
	bytes := make([]byte, 0)

	for _, base := range g.Bases {
		bytes = append(bytes, base.Bytes()...)
	}

	return append(bytes, g.Commitment.Bytes()...)
}

// GenerateProof generates proof ProofG1 for all secrets.
func (g *ProverCommittedG1) GenerateProof(challenge *ml.Zr, secrets []*ml.Zr) *ProofG1 {
	responses := make([]*ml.Zr, len(g.Bases))

	for i := range g.BlindingFactors {
		c := challenge.Mul(secrets[i])

		s := g.BlindingFactors[i].Minus(c)
		responses[i] = s
	}

	return &ProofG1{
		Commitment: g.Commitment,
		Responses:  responses,
	}
}

// ProverCommittingG1 is a proof of knowledge of messages in a vector commitment.
type ProverCommittingG1 struct {
	bases           []*ml.G1
	BlindingFactors []*ml.Zr
	b               *BBSLib
}

// NewProverCommittingG1 creates a new ProverCommittingG1.
func (bl *BBSLib) NewProverCommittingG1() *ProverCommittingG1 {
	return &ProverCommittingG1{
		bases:           make([]*ml.G1, 0),
		BlindingFactors: make([]*ml.Zr, 0),
		b:               bl,
	}
}

// Commit append a base point and randomly generated blinding factor.
func (pc *ProverCommittingG1) Commit(base *ml.G1) {
	pc.bases = append(pc.bases, base)
	r := pc.b.createRandSignatureFr()
	pc.BlindingFactors = append(pc.BlindingFactors, r)
}

// Finish helps to generate ProverCommittedG1 after commitment of all base points.
func (pc *ProverCommittingG1) Finish() *ProverCommittedG1 {
	commitment := sumOfG1Products(pc.bases, pc.BlindingFactors)

	return &ProverCommittedG1{
		Bases:           pc.bases,
		BlindingFactors: pc.BlindingFactors,
		Commitment:      commitment,
	}
}
