/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"crypto/rand"

	ml "github.com/IBM/mathlib"
)

func (b *BBSLib) parseFr(data []byte) *ml.Zr {
	return b.curve.NewZrFromBytes(data)
}

// nolint:gochecknoglobals
var f2192Bytes = []byte{
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
}

func f2192(curve *ml.Curve) *ml.Zr {
	return curve.NewZrFromBytes(f2192Bytes)
}

func FrToRepr(fr *ml.Zr) *ml.Zr {
	return fr.Copy()
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
