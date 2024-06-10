package proving

import (
	"bytes"
	"fmt"
	"io"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/ethereum/go-ethereum/log"

	"github.com/base-org/keyspace-recovery-service/proving/storage"
	pbls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	pbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	pbw6761 "github.com/consensys/gnark/backend/plonk/bw6-761"
	cbls12377 "github.com/consensys/gnark/constraint/bls12-377"
	cbn254 "github.com/consensys/gnark/constraint/bn254"
	cbw6761 "github.com/consensys/gnark/constraint/bw6-761"
)

func Load(store storage.Storage, filename string, field *big.Int, onlyVk bool) (constraint.ConstraintSystem, plonk.ProvingKey, plonk.VerifyingKey, error) {
	var vk plonk.VerifyingKey
	var pk plonk.ProvingKey
	var ccs constraint.ConstraintSystem

	if field.Cmp(ecc.BLS12_377.ScalarField()) == 0 {
		vk = &pbls12377.VerifyingKey{}
		pk = &pbls12377.ProvingKey{}
		ccs = &cbls12377.SparseR1CS{}
	} else if field.Cmp(ecc.BN254.ScalarField()) == 0 {
		vk = &pbn254.VerifyingKey{}
		pk = &pbn254.ProvingKey{}
		ccs = &cbn254.SparseR1CS{}
	} else if field.Cmp(ecc.BW6_761.ScalarField()) == 0 {
		vk = &pbw6761.VerifyingKey{}
		pk = &pbw6761.ProvingKey{}
		ccs = &cbw6761.SparseR1CS{}
	} else {
		return nil, nil, nil, fmt.Errorf("unsupported field")
	}

	types := []struct {
		suffix     string
		readerFrom io.ReaderFrom
		buffer     bool
	}{
		{"vk", vk, false},
		{"pk", pk, false},
		{"ccs", ccs, true},
	}
	if onlyVk {
		types = types[:1]
	}

	for _, t := range types {
		log.Info(fmt.Sprintf("Retrieving circuit %s", t.suffix), "filename", filename)
		key := fmt.Sprintf("%s.%s", filename, t.suffix)
		reader, err := store.Reader(key)
		if err != nil {
			return nil, nil, nil, err
		}
		if t.buffer {
			contents, err := io.ReadAll(reader)
			if err != nil {
				return nil, nil, nil, err
			}
			err = reader.Close()
			if err != nil {
				return nil, nil, nil, err
			}
			reader = io.NopCloser(bytes.NewBuffer(contents))
		}
		_, err = t.readerFrom.ReadFrom(reader)
		if err != nil {
			return nil, nil, nil, err
		}
		err = reader.Close()
		if err != nil {
			return nil, nil, nil, err
		}
	}

	return ccs, pk, vk, nil
}
