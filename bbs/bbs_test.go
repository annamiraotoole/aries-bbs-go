/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs_test

import (
	"fmt"
	"log"
	"testing"

	ml "github.com/IBM/mathlib"
	"github.com/hyperledger/aries-bbs-go/bbs"
	"github.com/stretchr/testify/require"
)

func TestBBSG2Pub_SignWithKeyPair(t *testing.T) {
	for i, c := range ml.Curves {
		t.Run(fmt.Sprintf("with curve %s", ml.CurveIDToString(ml.CurveID(i))), func(t *testing.T) {
			pubKey, privKey, err := generateKeyPairRandom(c)
			require.NoError(t, err)

			bls := bbs.New(c)

			messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

			signatureBytes, err := bls.SignWithKey(messagesBytes, privKey)
			require.NoError(t, err)
			require.NotEmpty(t, signatureBytes)
			require.Len(t, signatureBytes, c.CompressedG1ByteSize+32)

			pubKeyBytes, err := pubKey.Marshal()
			require.NoError(t, err)

			require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))
		})
	}
}

func TestBBSG2Pub_Sign(t *testing.T) {
	for i, curve := range ml.Curves {
		t.Run(fmt.Sprintf("with curve %s", ml.CurveIDToString(ml.CurveID(i))), func(t *testing.T) {
			pubKey, privKey, err := generateKeyPairRandom(curve)
			require.NoError(t, err)

			bls := bbs.New(curve)

			messagesBytes := [][]byte{[]byte("message1"), []byte("message2")}

			privKeyBytes, err := privKey.Marshal()
			require.NoError(t, err)

			signatureBytes, err := bls.Sign(messagesBytes, privKeyBytes)
			require.NoError(t, err)
			require.NotEmpty(t, signatureBytes)
			require.Len(t, signatureBytes, curve.CompressedG1ByteSize+32)

			pubKeyBytes, err := pubKey.Marshal()
			require.NoError(t, err)

			require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

			// invalid private key bytes
			signatureBytes, err = bls.Sign(messagesBytes, []byte("invalid"))
			require.Error(t, err)
			require.EqualError(t, err, "unmarshal private key: invalid size of private key")
			require.Nil(t, signatureBytes)

			// at least one message must be passed
			signatureBytes, err = bls.Sign([][]byte{}, privKeyBytes)
			require.Error(t, err)
			require.EqualError(t, err, "messages are not defined")
			require.Nil(t, signatureBytes)
		})
	}
}

func TestBBSG2Pub_DeriveProof(t *testing.T) {
	for i, curve := range ml.Curves {
		t.Run(fmt.Sprintf("with curve %s", ml.CurveIDToString(ml.CurveID(i))),
			func(t *testing.T) {

				log.Printf("Testing with curve %s", ml.CurveIDToString(ml.CurveID(i)))

				pubKey, privKey, err := generateKeyPairRandom(curve)
				require.NoError(t, err)

				privKeyBytes, err := privKey.Marshal()
				require.NoError(t, err)

				messagesBytes := [][]byte{
					[]byte("message1"),
					[]byte("message2"),
					[]byte("message3"),
					[]byte("message4"),
				}
				bls := bbs.New(curve)

				signatureBytes, err := bls.Sign(messagesBytes, privKeyBytes)
				require.NoError(t, err)

				pubKeyBytes, err := pubKey.Marshal()
				require.NoError(t, err)

				require.NoError(t, bls.Verify(messagesBytes, signatureBytes, pubKeyBytes))

				nonce := []byte("nonce")
				revealedIndexes := []int{0, 2}
				proofBytes, err := bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
				require.NoError(t, err)
				require.NotEmpty(t, proofBytes)

				revealedMessages := make([][]byte, len(revealedIndexes))
				for i, ind := range revealedIndexes {
					revealedMessages[i] = messagesBytes[ind]
				}

				require.NoError(t, bls.VerifyProof(revealedMessages, proofBytes, nonce, pubKeyBytes))

				t.Run("DeriveProof with revealedIndexes larger than revealedMessages count", func(t *testing.T) {
					revealedIndexes = []int{0, 2, 4, 7, 9, 11}
					_, err = bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
					require.EqualError(t, err, "init proof of knowledge signature: invalid size: 6 revealed indexes is "+
						"larger than 4 messages")
				})

				t.Run("DeriveProof with invalid signature", func(t *testing.T) {
					signatureBytes[len(signatureBytes)-4]--
					_, err = bls.DeriveProof(messagesBytes, signatureBytes, nonce, pubKeyBytes, revealedIndexes)
					require.EqualError(t, err, "init proof of knowledge signature: verify input signature: invalid BLS12-381 signature")
				})
			})
	}
}

// TestBlindSign uses `SignWithKeyB` to show how blind signing could be implemented
// using this new primitive. Note that this implementation isn't secure since the
// signer doesn't check the well-formedness of the term received from the requester
func TestBlindSign(t *testing.T) {
	for i, curve := range ml.Curves {
		t.Run(fmt.Sprintf("with curve %s", ml.CurveIDToString(ml.CurveID(i))), func(t *testing.T) {

			pubKey, privKey, err := generateKeyPairRandom(curve)
			require.NoError(t, err)

			pubKeyBytes, err := pubKey.Marshal()
			require.NoError(t, err)

			blindMsgCount := 2

			messagesBytes := [][]byte{
				[]byte("message1"),
				[]byte("message2"),
				[]byte("message3"),
				[]byte("message4"),
			}

			pubKeyWithGenerators, err := pubKey.ToPublicKeyWithGenerators(len(messagesBytes))
			require.NoError(t, err)

			blindedMessagesBytes := [][]byte{
				[]byte("message1"),
				nil,
				nil,
				[]byte("message4"),
			}

			clearMessagesBytes := [][]byte{
				nil,
				[]byte("message2"),
				[]byte("message3"),
				nil,
			}

			// requester generates commitment to blind messages
			cb := bbs.NewCommitmentBuilder(blindMsgCount)
			for i, msg := range blindedMessagesBytes {
				if msg == nil {
					continue
				}

				cb.Add(pubKeyWithGenerators.H[i], bbs.FrFromOKM(msg, curve))
			}
			b_req := cb.Build()

			// signer adds its component
			cb = bbs.NewCommitmentBuilder(len(messagesBytes) - blindMsgCount + 2)
			for i, msg := range clearMessagesBytes {
				if msg == nil {
					continue
				}

				cb.Add(pubKeyWithGenerators.H[i], bbs.FrFromOKM(msg, curve))
			}
			cb.Add(b_req, curve.NewZrFromInt(1))
			cb.Add(curve.GenG1, curve.NewZrFromInt(1))
			comm := cb.Build()

			// signer signs
			scheme := bbs.New(curve)
			sig, err := scheme.SignWithKeyB(comm, len(messagesBytes), privKey)
			require.NoError(t, err)

			// requester verifies
			err = scheme.Verify(messagesBytes, sig, pubKeyBytes)
			require.NoError(t, err)
		})
	}
}
