module github.com/hyperledger/aries-bbs-go

go 1.23.0

toolchain go1.23.4

replace github.com/IBM/mathlib => ../mathlib

require (
	github.com/IBM/mathlib v0.0.3-0.20231011094432-44ee0eb539da
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/stretchr/testify v1.10.0
	golang.org/x/crypto v0.40.0
)

require (
	github.com/bits-and-blooms/bitset v1.22.0 // indirect
	github.com/btcsuite/btcd v0.20.1-beta // indirect
	github.com/consensys/bavard v0.1.31-0.20250406004941-2db259e4b582 // indirect
	github.com/consensys/gnark-crypto v0.18.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/hyperledger/fabric-amcl v0.0.0-20230602173724-9e02669dceb2 // indirect
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)
