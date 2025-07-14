//////////////////////////////////////////////////////////////////
/// CLEANER ZKPROOF HELPER FUNCTIONS
///
/// BASED ON aries-bbs-go's approach, but refactored and written
/// so that they could be added to mathlib directly
/// Each function is called on c *ml.Curve
/// When finished, these helpers could be exposed for each curve
///
/// (Reason: I want to avoid all this POK code breaking when
/// someone cleans up the aries-bbs-go codebase)

package bbs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	ml "github.com/IBM/mathlib"
	"golang.org/x/crypto/blake2b"
)

// DELETE once I get confirmation that this is not needed, so we can just use c.ScalarByteSize
const frCompressedSize = 32 // Size of a compressed field element in bytes

////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////

// return true if e(p1, q1) == e(p2, q2)
func compareTwoPairings(p1 *ml.G1, q1 *ml.G2,
	p2 *ml.G1, q2 *ml.G2, curve *ml.Curve) bool {

	// DEVIATION FROM aries-bbs-go, so that this function can be used black-box
	p2Copy := p2.Copy()
	p2Copy.Neg()

	p := curve.Pairing2(q1, p1, q2, p2Copy)
	p = curve.FExp(p)

	return p.IsUnity()
}

type ProofG1 struct {
	Commitment *ml.G1
	Responses  []*ml.Zr
	Nonce      []byte
}

// NewProofG1 creates a new ProofG1.
func NewProofG1(commitment *ml.G1, responses []*ml.Zr) *ProofG1 {
	return &ProofG1{
		Commitment: commitment,
		Responses:  responses,
	}
}

// The only functions exposed for curves should be:

func IsZero(c *ml.Curve, z *ml.Zr) bool {
	zero := c.NewZrFromBytes([]byte("0"))
	zero = zero.Minus(zero)
	return z.Equals(zero)
}

func ComputeChallenge(c *ml.Curve, commitment *ml.G1, bases []*ml.G1, nonce []byte) *ml.Zr {
	challengeBytes := make([]byte, 0)
	// add bytes for every base
	for _, base := range bases {
		challengeBytes = append(challengeBytes, base.Bytes()...)
	}
	// add bytes for commitment
	challengeBytes = append(challengeBytes, commitment.Bytes()...)
	// add bytes for nonce
	proofNonceBytes := FrFromOKM(c, nonce).Bytes()
	challengeBytes = append(challengeBytes, proofNonceBytes...)
	challengeBytes = append(challengeBytes, nonce...)
	// convert final challenge bytes to a field element
	challenge := FrFromOKM(c, challengeBytes)
	return challenge
}

func GenerateProof(c *ml.Curve, rng io.Reader, bases []*ml.G1, secrets []*ml.Zr, nonce []byte) *ProofG1 {
	proverCommiting := NewProverCommittingG1()
	for _, base := range bases {
		proverCommiting.Commit(c, rng, base)
	}

	committing := proverCommiting.Finish()

	challenge := ComputeChallenge(c, committing.Commitment, bases, nonce)

	proof := committing.GenerateProof(challenge, secrets)

	// include nonce information for verifier
	proof.Nonce = nonce

	return proof
}

func VerifyProofG1(c *ml.Curve, pg1 *ProofG1, bases []*ml.G1, nonce []byte) bool {

	challenge := ComputeChallenge(c, pg1.Commitment, bases, pg1.Nonce)

	points := append(bases, pg1.Commitment)
	scalars := append(pg1.Responses, challenge)

	contribution := sumOfG1Products(points, scalars)
	contribution.Sub(pg1.Commitment)

	return contribution.IsInfinity()
}

// ToBytes converts ProofG1 to bytes.
// Note that this doesn't encode bases, verifier should know them.
func (pg1 *ProofG1) ToBytes() []byte {
	bytes := make([]byte, 0)

	commitmentBytes := pg1.Commitment.Compressed()
	bytes = append(bytes, commitmentBytes...)

	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(pg1.Responses)))
	bytes = append(bytes, lenBytes...)

	for i := range pg1.Responses {
		responseBytes := pg1.Responses[i].Copy().Bytes()
		bytes = append(bytes, responseBytes...)
	}

	return bytes
}

// ParseProofG1 parses ProofG1 from bytes.
func ParseProofG1(c *ml.Curve, bytes []byte) (*ProofG1, error) {
	if len(bytes) < c.CompressedG1ByteSize+4 {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	offset := 0

	commitment, err := c.NewG1FromCompressed(bytes[:c.CompressedG1ByteSize])
	if err != nil {
		return nil, fmt.Errorf("parse G1 point: %w", err)
	}

	offset += c.CompressedG1ByteSize
	length := int(binary.BigEndian.Uint32(bytes[offset : offset+4]))
	offset += 4

	if len(bytes) < c.CompressedG1ByteSize+4+length*frCompressedSize {
		return nil, errors.New("invalid size of G1 signature proof")
	}

	responses := make([]*ml.Zr, length)
	for i := 0; i < length; i++ {
		responses[i] = c.NewZrFromBytes(bytes[offset : offset+frCompressedSize])
		offset += frCompressedSize
	}

	return NewProofG1(commitment, responses), nil
}

////////////////////////////////////////////////////////////////////////////////////
/// HIDDEN LOGIC but should be refactored anyways
/// currently is almost the same as in aries-bbs-go code
////////////////////////////////////////////////////////////////////////////////////

func FrFromOKM(c *ml.Curve, message []byte) *ml.Zr {
	const (
		eightBytes = 8
		okmMiddle  = 24
	)

	// We pass a null key so error is impossible here.
	h, _ := blake2b.New384(nil) //nolint:errcheck

	// blake2b.digest() does not return an error.
	_, _ = h.Write(message)
	okm := h.Sum(nil)
	emptyEightBytes := make([]byte, eightBytes)

	elm := c.NewZrFromBytes(append(emptyEightBytes, okm[:okmMiddle]...))

	f2192 := c.NewZrFromBytes([]byte{
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
		0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	})

	elm = elm.Mul(f2192)

	fr := c.NewZrFromBytes(append(emptyEightBytes, okm[okmMiddle:]...))
	elm = elm.Plus(fr)

	return elm
}

////////////////////////////////////////////////////////////////////////////////////

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
		Nonce:      nil,
	}
}

////////////////////////////////////////////////////////////////////////////////////

// ProverCommittingG1 is a proof of knowledge of messages in a vector commitment.
type ProverCommittingG1 struct {
	bases           []*ml.G1
	BlindingFactors []*ml.Zr
}

// NewProverCommittingG1 creates a new ProverCommittingG1.
func NewProverCommittingG1() *ProverCommittingG1 {
	return &ProverCommittingG1{
		bases:           make([]*ml.G1, 0),
		BlindingFactors: make([]*ml.Zr, 0),
	}
}

// Commit append a base point and randomly generated blinding factor.
func (pc *ProverCommittingG1) Commit(c *ml.Curve, rng io.Reader, base *ml.G1) {
	pc.bases = append(pc.bases, base)
	r := c.NewRandomZr(rng)
	pc.BlindingFactors = append(pc.BlindingFactors, r)
}

func sumOfG1Products(bases []*ml.G1, scalars []*ml.Zr) *ml.G1 {
	var res *ml.G1

	for i := 0; i < len(bases); i++ {
		b := bases[i]
		s := scalars[i]

		g := b.Mul(s.Copy())
		if res == nil {
			res = g
		} else {
			res.Add(g)
		}
	}

	return res
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
