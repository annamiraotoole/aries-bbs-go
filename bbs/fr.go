/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"crypto/rand"

	ml "github.com/IBM/mathlib"
	"golang.org/x/crypto/blake2b"
)

const frCompressedSize = 32 // Size of a compressed field element in bytes

func NonceToFrBytes(curve *ml.Curve, nonce []byte) []byte {
	fieldElem := FrFromOKM(curve, nonce)
	return fieldElem.Bytes()
}

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

func MessagesToFr(messages [][]byte, curve *ml.Curve) []*SignatureMessage {
	messagesFr := make([]*SignatureMessage, len(messages))

	for i := range messages {
		messagesFr[i] = ParseSignatureMessage(messages[i], i, curve)
	}

	return messagesFr
}

func (b *BBSLib) createRandSignatureFr() *ml.Zr {
	return b.curve.NewRandomZr(rand.Reader)
}
