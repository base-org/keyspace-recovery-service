package circuits

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	pbls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	pbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	pbw6761 "github.com/consensys/gnark/backend/plonk/bw6-761"
)

type Metadata struct {
	Id          string
	Field       *big.Int
	Outer       *big.Int
	Commitments int
	MultiTx     bool
	Solidity    bool
	Filenames   []string
}

func (c *Metadata) Filename(txCount int) string {
	if !c.MultiTx {
		txCount = 1
	}
	return c.Filenames[txCount-1]
}

func (c *Metadata) EmptyProof() (plonk.Proof, error) {
	if c.Field.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		return &pbls12377.Proof{}, nil
	} else if c.Field.Cmp(ecc.BN254.ScalarField()) == 0 {
		return &pbn254.Proof{}, nil
	} else if c.Field.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		return &pbw6761.Proof{}, nil
	} else {
		return nil, fmt.Errorf("unsupported field")
	}
}
