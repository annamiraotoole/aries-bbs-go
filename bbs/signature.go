/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"errors"
	"fmt"

	ml "github.com/IBM/mathlib"
)

// Signature defines BLS signature.
type Signature struct {
	A     *ml.G1
	E     *ml.Zr
	curve *ml.Curve
}

// ParseSignature parses a Signature from bytes.
func (b *BBSLib) ParseSignature(sigBytes []byte) (*Signature, error) {
	if len(sigBytes) != b.bls12381SignatureLen {
		return nil, errors.New("invalid size of signature")
	}

	pointG1, err := b.curve.NewG1FromCompressed(sigBytes[:b.g1CompressedSize])
	if err != nil {
		return nil, fmt.Errorf("deserialize G1 compressed signature: %w", err)
	}

	// below line should now be equivalent to e := b.parseFr(sigBytes[b.g1CompressedSize:])
	e := b.parseFr(sigBytes[b.g1CompressedSize : b.g1CompressedSize+frCompressedSize])

	return &Signature{
		A:     pointG1,
		E:     e,
		curve: b.curve,
	}, nil
}

// ToBytes converts signature to bytes using compression of G1 point and E, S FR points.
func (s *Signature) ToBytes() ([]byte, error) {
	bytes := make([]byte, s.curve.CompressedG1ByteSize+frCompressedSize)

	copy(bytes, s.A.Compressed())
	copy(bytes[s.curve.CompressedG1ByteSize:s.curve.CompressedG1ByteSize+frCompressedSize], s.E.Bytes())

	return bytes, nil
}

// Verify is used for signature verification.
func (s *Signature) Verify(messages []*SignatureMessage, pubKey *PublicKeyWithGenerators) error {
	p1 := s.A

	q1 := s.curve.GenG2.Mul(FrToRepr(s.E))
	q1.Add(pubKey.w)

	p2 := ComputeB(messages, pubKey, s.curve)
	p2.Neg() // QUESTION: why are we negating this group element? doesn't match protocol afaik

	// checks if e(p1, q1) = e(p2, s.curve.GenG2)
	if compareTwoPairings(p1, q1, p2, s.curve.GenG2, s.curve) {
		return nil
	}

	return errors.New("invalid BLS12-381 signature")
}
