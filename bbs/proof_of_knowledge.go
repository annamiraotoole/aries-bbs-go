/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"encoding/hex"
	"errors"
	"fmt"

	ml "github.com/IBM/mathlib"
)

func shortFrStr(fr *ml.Zr) string {
	res := hex.EncodeToString(fr.Bytes()[:3])
	res += "..."
	res += hex.EncodeToString(fr.Bytes()[len(fr.Bytes())-3:])
	return res
}

func shortGrStr(g *ml.G1) string {
	res := hex.EncodeToString(g.Bytes()[:3])
	res += "..."
	res += hex.EncodeToString(g.Bytes()[len(g.Bytes())-3:])
	return res
}

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
		// VC2SignatureProvider: &defaultVC2SignatureProvider{
		// 	bl: bl,
		// },
		VerifySig: true,
		Curve:     bl.curve,
		Bl:        bl,
	}

	return p.PoKOfSignature(signature, messages, revealedIndexes, pubKey)
}

// type VC2SignatureProvider interface {
// 	New(*ml.G1, *ml.Zr, *PublicKeyWithGenerators, *ml.Zr, []*SignatureMessage, map[int]*SignatureMessage) (*ProverCommittedG1, []*ml.Zr)
// }

type PoKOfSignatureProvider struct {
	// VC2SignatureProvider

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

	// print all messages
	for i, msg := range messages {
		fmt.Printf("message[%d]: idx: %d, FR: %s\n",
			i, msg.Idx, shortFrStr(msg.FR))
	}

	if p.VerifySig {
		err := signature.Verify(messages, pubKey)
		if err != nil {
			return nil, fmt.Errorf("verify input signature: %w", err)
		}
	}

	r := p.Bl.createRandSignatureFr()
	aPrime := signature.A.Mul(FrToRepr(r))

	aBarDenom := aPrime.Mul(FrToRepr(signature.E))

	aBar := b.Mul(FrToRepr(r))
	aBar.Sub(aBarDenom)

	committing := p.Bl.NewProverCommittingG1()
	secrets := make([]*ml.Zr, 2)

	rInv := r.Copy()
	rInv.InvModP(p.Bl.curve.GroupOrder)

	committing.Commit(aPrime)
	eCopy := signature.E.Copy()
	eDivR := eCopy.Mul(rInv)
	secrets[0] = eDivR
	fmt.Println("committing with aPrime: ", shortGrStr(aPrime))

	committing.Commit(aBar)
	secrets[1] = rInv
	fmt.Println("committing with aBar: ", shortGrStr(aBar))

	revealedMessages := make(map[int]*SignatureMessage, len(revealedIndexes))

	if len(messages) < len(revealedIndexes) {
		return nil, fmt.Errorf("invalid size: %d revealed indexes is larger than %d messages", len(revealedIndexes),
			len(messages))
	}

	for _, ind := range revealedIndexes {
		revealedMessages[messages[ind].Idx] = messages[ind]
	}

	// TODO loop to add the bases for every hidden attribute
	for _, msg := range messages {

		// skip every revealed message
		if _, ok := revealedMessages[msg.Idx]; ok {
			continue
		}

		committing.Commit(pubKey.H[msg.Idx])

		fmt.Println("committing with hidden base H[", msg.Idx, "] = ", shortGrStr(pubKey.H[msg.Idx]), "and message FR (to be negated): ", shortFrStr(msg.FR))

		sourceFR := msg.FR
		hiddenFRCopy := sourceFR.Copy()
		hiddenFRCopy.Neg()

		secrets = append(secrets, hiddenFRCopy)
	}

	//////////////////////////////////////////////////////////////////////
	// SANITY CHECK with body of verification code
	//////////////////////////////////////////////////////////////////////

	unknownSide := sumOfG1Products(committing.bases, secrets)

	revealedMessagesCount := len(revealedMessages)

	basesDisclosed := make([]*ml.G1, 0, 1+revealedMessagesCount)
	exponents := make([]*ml.Zr, 0, 1+revealedMessagesCount)

	fmt.Println("verifying against revealed base G1: ", shortGrStr(p.Curve.GenG1))
	basesDisclosed = append(basesDisclosed, p.Curve.GenG1)
	exponents = append(exponents, p.Curve.NewZrFromInt(1))

	revealedMessagesInd := 0 // ASK ALE: why do we need this index?

	for i := range pubKey.H {
		if _, ok := revealedMessages[i]; ok {
			basesDisclosed = append(basesDisclosed, pubKey.H[i])
			// exponents = append(exponents, messages[revealedMessagesInd].FR)
			exponents = append(exponents, revealedMessages[i].FR)
			fmt.Print("verifying against revealed base H [", i, "] ")
			fmt.Print("which should match revealedMessagesInd FR:", shortFrStr(messages[revealedMessagesInd].FR))
			fmt.Println(" and message FR:", shortFrStr(revealedMessages[i].FR))
			revealedMessagesInd++
		}
	}

	// TODO: expose 0
	pr := p.Curve.GenG1.Copy()
	pr.Sub(p.Curve.GenG1)
	// at this point pr is zero

	for i := 0; i < len(basesDisclosed); i++ {
		b := basesDisclosed[i]
		s := exponents[i]

		g := b.Mul(FrToRepr(s))
		pr.Add(g)
	}

	// pr.Neg() // ASK ALE: why are we negating?

	// check if the RHS and LHS are equal by subtracting them
	unknownSide.Sub(pr)

	if !unknownSide.IsInfinity() {
		return nil, errors.New("RHS and LHS are not equal")
	}

	//////////////////////////////////////////////////////////////////////

	pokVC := committing.Finish()

	return &PoKOfSignature{
		aPrime:           aPrime,
		aBar:             aBar,
		pokVC:            pokVC,
		secrets:          secrets,
		revealedMessages: revealedMessages,
		curve:            p.Curve,
	}, nil
}

// func (p *defaultVC2SignatureProvider) New(d *ml.G1, r3 *ml.Zr, pubKey *PublicKeyWithGenerators, sPrime *ml.Zr,
// 	messages []*SignatureMessage, revealedMessages map[int]*SignatureMessage) (*ProverCommittedG1, []*ml.Zr) {
// 	messagesCount := len(messages)
// 	committing2 := p.bl.NewProverCommittingG1()
// 	baseSecretsCount := 2
// 	secrets2 := make([]*ml.Zr, 0, baseSecretsCount+messagesCount)

// 	committing2.Commit(d)

// 	r3D := r3.Copy()
// 	r3D.Neg()

// 	secrets2 = append(secrets2, r3D)

// 	committing2.Commit(pubKey.H0)

// 	secrets2 = append(secrets2, sPrime)

// 	for _, msg := range messages {
// 		if _, ok := revealedMessages[msg.Idx]; ok {
// 			continue
// 		}

// 		committing2.Commit(pubKey.H[msg.Idx])

// 		sourceFR := msg.FR
// 		hiddenFRCopy := sourceFR.Copy()

// 		secrets2 = append(secrets2, hiddenFRCopy)
// 	}

// 	pokVC2 := committing2.Finish()

// 	return pokVC2, secrets2
// }

// CHANGED -- has to be consistent somehow with GetBytesForChallnge -- don't understand how
// ToBytes converts PoKOfSignature to bytes.
func (pos *PoKOfSignature) ToBytes() []byte {
	challengeBytes := pos.aBar.Bytes()
	fmt.Println("aBar:                ", shortGrStr(pos.aBar))
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
		fmt.Println("proofG1 base:        ", shortGrStr(base))
		bytes = append(bytes, base.Bytes()...)
	}

	fmt.Println("commitment:          ", shortGrStr(g.Commitment))

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
