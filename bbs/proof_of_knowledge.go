/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

// import (
// 	"fmt"

// 	ml "github.com/IBM/mathlib"
// )

// // PoKOfSignature is Proof of Knowledge of a Signature that is used by the prover to construct PoKOfSignatureProof.
// type PoKOfSignature struct {
// 	aPrime *ml.G1
// 	aBar   *ml.G1
// 	d      *ml.G1

// 	pokVC   *ProverCommittedG1
// 	secrets []*ml.Zr

// 	revealedMessages map[int]*SignatureMessage

// 	curve *ml.Curve
// }

// // NewPoKOfSignature creates a new PoKOfSignature.
// func (bl *BBSLib) NewPoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
// 	pubKey *PublicKeyWithGenerators) (*PoKOfSignature, error) {

// 	p := &PoKOfSignatureProvider{
// 		// VC2SignatureProvider: &defaultVC2SignatureProvider{
// 		// 	bl: bl,
// 		// },
// 		VerifySig: true,
// 		Curve:     bl.curve,
// 		Bl:        bl,
// 	}

// 	return p.PoKOfSignature(signature, messages, revealedIndexes, pubKey)
// }

// type VC2SignatureProvider interface {
// 	New(*ml.G1, *ml.Zr, *PublicKeyWithGenerators, *ml.Zr, []*SignatureMessage, map[int]*SignatureMessage) (*ProverCommittedG1, []*ml.Zr)
// }

// type PoKOfSignatureProvider struct {
// 	// VC2SignatureProvider

// 	VerifySig bool

// 	Curve *ml.Curve
// 	Bl    *BBSLib
// }

// func (p *PoKOfSignatureProvider) PoKOfSignature(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
// 	pubKey *PublicKeyWithGenerators) (*PoKOfSignature, error) {
// 	b := ComputeB(messages, pubKey, p.Bl.curve)

// 	return p.PoKOfSignatureB(signature, messages, revealedIndexes, pubKey, b)
// }

// func (p *PoKOfSignatureProvider) PoKOfSignatureB(signature *Signature, messages []*SignatureMessage, revealedIndexes []int,
// 	pubKey *PublicKeyWithGenerators, b *ml.G1) (*PoKOfSignature, error) {

// 	if p.VerifySig {
// 		err := signature.Verify(messages, pubKey)
// 		if err != nil {
// 			return nil, fmt.Errorf("verify input signature: %w", err)
// 		}
// 	}

// 	r := p.Bl.createRandSignatureFr()
// 	aPrime := signature.A.Mul(FrToRepr(r))

// 	aBarDenom := aPrime.Mul(FrToRepr(signature.E))

// 	aBar := b.Mul(FrToRepr(r))
// 	aBar.Sub(aBarDenom)

// 	const basesOffset = 2
// 	cb := NewCommitmentBuilder(len(revealedIndexes) + basesOffset)
// 	cb.Add(signature.curve.GenG1, signature.curve.NewZrFromInt(1))

// 	// loop to add the base and exp for each revealed attribute
// 	for _, idx := range revealedIndexes {
// 		cb.Add(pubKey.H[messages[idx].Idx], messages[idx].FR)
// 	}

// 	d := cb.Build()

// 	committing := p.Bl.NewProverCommittingG1()
// 	secrets := make([]*ml.Zr, 2)

// 	rInv := r.Copy()
// 	rInv.InvModP(p.Bl.curve.GroupOrder)

// 	committing.Commit(aPrime)
// 	eCopy := signature.E.Copy()
// 	eCopy.Mul(rInv)
// 	secrets[0] = eCopy

// 	committing.Commit(aBar)
// 	secrets[1] = rInv

// 	revealedMessages := make(map[int]*SignatureMessage, len(revealedIndexes))

// 	if len(messages) < len(revealedIndexes) {
// 		return nil, fmt.Errorf("invalid size: %d revealed indexes is larger than %d messages", len(revealedIndexes),
// 			len(messages))
// 	}

// 	for _, ind := range revealedIndexes {
// 		revealedMessages[messages[ind].Idx] = messages[ind]
// 	}

// 	// TODO loop to add the bases for every hidden attribute
// 	for _, msg := range messages {

// 		// skip every revealed message
// 		if _, ok := revealedMessages[msg.Idx]; ok {
// 			continue
// 		}

// 		committing.Commit(pubKey.H[msg.Idx])

// 		sourceFR := msg.FR
// 		hiddenFRCopy := sourceFR.Copy()
// 		hiddenFRCopy.Neg()

// 		secrets = append(secrets, hiddenFRCopy)
// 	}

// 	pokVC := committing.Finish()

// 	return &PoKOfSignature{
// 		aPrime:           aPrime,
// 		aBar:             aBar,
// 		d:                d,
// 		pokVC:            pokVC,
// 		secrets:          secrets,
// 		revealedMessages: revealedMessages,
// 		curve:            p.Curve,
// 	}, nil
// }

// // func (b *BBSLib) newVC1Signature(aPrime *ml.G1, h0 *ml.G1,
// // 	e, r2 *ml.Zr) (*ProverCommittedG1, []*ml.Zr) {
// // 	committing1 := b.NewProverCommittingG1()
// // 	secrets1 := make([]*ml.Zr, 2)

// // 	committing1.Commit(aPrime)

// // 	sigE := e.Copy()
// // 	sigE.Neg()
// // 	secrets1[0] = sigE

// // 	committing1.Commit(h0)

// // 	secrets1[1] = r2
// // 	pokVC1 := committing1.Finish()

// // 	return pokVC1, secrets1
// // }

// // type defaultVC2SignatureProvider struct {
// // 	bl *BBSLib
// // }

// // func (p *defaultVC2SignatureProvider) New(d *ml.G1, r3 *ml.Zr, pubKey *PublicKeyWithGenerators, sPrime *ml.Zr,
// // 	messages []*SignatureMessage, revealedMessages map[int]*SignatureMessage) (*ProverCommittedG1, []*ml.Zr) {
// // 	messagesCount := len(messages)
// // 	committing2 := p.bl.NewProverCommittingG1()
// // 	baseSecretsCount := 2
// // 	secrets2 := make([]*ml.Zr, 0, baseSecretsCount+messagesCount)

// // 	committing2.Commit(d)

// // 	r3D := r3.Copy()
// // 	r3D.Neg()

// // 	secrets2 = append(secrets2, r3D)

// // 	committing2.Commit(pubKey.H0)

// // 	secrets2 = append(secrets2, sPrime)

// // 	for _, msg := range messages {
// // 		if _, ok := revealedMessages[msg.Idx]; ok {
// // 			continue
// // 		}

// // 		committing2.Commit(pubKey.H[msg.Idx])

// // 		sourceFR := msg.FR
// // 		hiddenFRCopy := sourceFR.Copy()

// // 		secrets2 = append(secrets2, hiddenFRCopy)
// // 	}

// // 	pokVC2 := committing2.Finish()

// // 	return pokVC2, secrets2
// // }

// // ToBytes converts PoKOfSignature to bytes.
// func (pos *PoKOfSignature) ToBytes() []byte {
// 	challengeBytes := pos.aBar.Bytes()
// 	challengeBytes = append(challengeBytes, pos.pokVC.ToBytes()...)

// 	return challengeBytes
// }

// // GenerateProof generates PoKOfSignatureProof proof from PoKOfSignature signature.
// func (pos *PoKOfSignature) GenerateProof(challengeHash *ml.Zr) *PoKOfSignatureProof {
// 	return &PoKOfSignatureProof{
// 		aPrime:  pos.aPrime,
// 		aBar:    pos.aBar,
// 		d:       pos.d,
// 		proofVC: pos.pokVC.GenerateProof(challengeHash, pos.secrets),
// 		curve:   pos.curve,
// 	}
// }

// // ProverCommittedG1 helps to generate a ProofG1.
// type ProverCommittedG1 struct {
// 	Bases           []*ml.G1
// 	BlindingFactors []*ml.Zr
// 	Commitment      *ml.G1
// }

// // ToBytes converts ProverCommittedG1 to bytes.
// func (g *ProverCommittedG1) ToBytes() []byte {
// 	bytes := make([]byte, 0)

// 	for _, base := range g.Bases {
// 		bytes = append(bytes, base.Bytes()...)
// 	}

// 	return append(bytes, g.Commitment.Bytes()...)
// }

// // GenerateProof generates proof ProofG1 for all secrets.
// func (g *ProverCommittedG1) GenerateProof(challenge *ml.Zr, secrets []*ml.Zr) *ProofG1 {
// 	responses := make([]*ml.Zr, len(g.Bases))

// 	for i := range g.BlindingFactors {
// 		c := challenge.Mul(secrets[i])

// 		s := g.BlindingFactors[i].Minus(c)
// 		responses[i] = s
// 	}

// 	return &ProofG1{
// 		Commitment: g.Commitment,
// 		Responses:  responses,
// 	}
// }

// // ProverCommittingG1 is a proof of knowledge of messages in a vector commitment.
// type ProverCommittingG1 struct {
// 	bases           []*ml.G1
// 	BlindingFactors []*ml.Zr
// 	b               *BBSLib
// }

// // NewProverCommittingG1 creates a new ProverCommittingG1.
// func (bl *BBSLib) NewProverCommittingG1() *ProverCommittingG1 {
// 	return &ProverCommittingG1{
// 		bases:           make([]*ml.G1, 0),
// 		BlindingFactors: make([]*ml.Zr, 0),
// 		b:               bl,
// 	}
// }

// // Commit append a base point and randomly generated blinding factor.
// func (pc *ProverCommittingG1) Commit(base *ml.G1) {
// 	pc.bases = append(pc.bases, base)
// 	r := pc.b.createRandSignatureFr()
// 	pc.BlindingFactors = append(pc.BlindingFactors, r)
// }

// // Finish helps to generate ProverCommittedG1 after commitment of all base points.
// func (pc *ProverCommittingG1) Finish() *ProverCommittedG1 {
// 	commitment := sumOfG1Products(pc.bases, pc.BlindingFactors)

// 	return &ProverCommittedG1{
// 		Bases:           pc.bases,
// 		BlindingFactors: pc.BlindingFactors,
// 		Commitment:      commitment,
// 	}
// }
