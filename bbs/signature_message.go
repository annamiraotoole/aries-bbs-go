/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	ml "github.com/IBM/mathlib"
	zkp "github.com/annamiraotoole/mathlib-schnorr/schnorr"
)

// SignatureMessage defines a message to be used for a signature check.
type SignatureMessage struct {
	FR  *ml.Zr
	Idx int
}

// ParseSignatureMessage parses SignatureMessage from bytes.
func ParseSignatureMessage(message []byte, idx int, curve *ml.Curve) *SignatureMessage {
	elm := zkp.FrFromOKM(curve, message)

	return &SignatureMessage{
		FR:  elm,
		Idx: idx,
	}
}
