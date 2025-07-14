/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package integration

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"regexp"
	"testing"

	math "github.com/IBM/mathlib"
	"github.com/annamiraotoole/aries-bbs-go/bbs"
	"github.com/stretchr/testify/require"
)

// messagesBytes needs to be kept in sync with the `messages`
// vector in ./rust_signer/src/main.go
var messagesBytes [][]byte = [][]byte{
	[]byte("message 1"),
	[]byte("message 2"),
	[]byte("message 3"),
	[]byte("message 4"),
	[]byte("message 5"),
}

func TestRustSignerGoVerifier(t *testing.T) {
	re := regexp.MustCompile(`^PK: ([0-9a-f]+)\nsig: ([0-9a-f]+)\n$`)

	output, err := exec.Command("./rust_signer/target/debug/rust_signer").Output()
	require.NoError(t, err)

	sm := re.FindStringSubmatch(string(output))
	require.Len(t, sm, 3)

	pkBytes, err := hex.DecodeString(string(sm[1]))
	require.NoError(t, err)

	sigBytes, err := hex.DecodeString(string(sm[2]))
	require.NoError(t, err)

	bbs := bbs.New(math.Curves[math.BLS12_381_BBS])

	err = bbs.Verify(messagesBytes, sigBytes, pkBytes)
	require.NoError(t, err)
}

func TestGoSignerRustVerifier(t *testing.T) {
	pubKey, privKey, err := generateKeyPairRandom(bbs.NewBBSLib(math.Curves[math.BLS12_381_BBS]))
	require.NoError(t, err)

	pubKeyBytes, err := pubKey.Marshal()
	require.NoError(t, err)
	privKeyBytes, err := privKey.Marshal()
	require.NoError(t, err)

	bbs := bbs.New(math.Curves[math.BLS12_381_BBS])

	signatureBytes, err := bbs.Sign(messagesBytes, privKeyBytes)
	require.NoError(t, err)
	require.NotEmpty(t, signatureBytes)
	require.Len(t, signatureBytes, 112)

	output, err := exec.Command(
		"./rust_signer/target/debug/rust_signer",
		hex.EncodeToString(pubKeyBytes),
		hex.EncodeToString(signatureBytes),
	).Output()
	require.NoError(t, err)
	require.Len(t, output, 0)
}

func generateKeyPairRandom(lib *bbs.BBSLib) (*bbs.PublicKey, *bbs.PrivateKey, error) {
	seed := make([]byte, 32)

	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	return lib.GenerateKeyPair(sha256.New, seed)
}
