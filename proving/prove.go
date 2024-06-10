package proving

import (
	"bytes"
	"fmt"
	"math/big"
	"runtime/debug"

	"github.com/base-org/keyspace-recovery-service/circuits"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	rplonk "github.com/consensys/gnark/std/recursion/plonk"
	"github.com/ethereum/go-ethereum/log"
)

func Prove(c *CompiledCircuit, wit witness.Witness, field, outer *big.Int) (plonk.Proof, error) {
	var pOpts []backend.ProverOption
	var vOpts []backend.VerifierOption
	if outer.Cmp(field) != 0 {
		pOpts = append(pOpts, rplonk.GetNativeProverOptions(outer, field))
		vOpts = append(vOpts, rplonk.GetNativeVerifierOptions(outer, field))
	}
	publicWitness, err := wit.Public()
	if err != nil {
		return nil, err
	}
	proof, err := plonk.Prove(c.Ccs, c.Pk, wit, pOpts...)
	if err != nil {
		return nil, err
	}
	err = plonk.Verify(proof, c.Vk, publicWitness, vOpts...)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func ProveAsync(compiled *CompiledCircuit, field, outer *big.Int, wit []byte, result chan ProveResult) {
	go func() {
		w, err := witness.New(field)
		if err != nil {
			result <- ProveResult{Err: err}
			return
		}
		if err = w.UnmarshalBinary(wit); err != nil {
			result <- ProveResult{Err: err}
			return
		}

		pr, err := Prove(compiled, w, field, outer)
		if err != nil {
			result <- ProveResult{Err: err}
			return
		}

		var buf bytes.Buffer
		if _, err = pr.WriteTo(&buf); err != nil {
			result <- ProveResult{Err: err}
			return
		}

		result <- ProveResult{Data: buf.Bytes()}
	}()
}

func ProveAssignment(cm circuits.Metadata, compiled *CompiledCircuit, assignment frontend.Circuit) (proof plonk.Proof, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v, stack: %s", r, string(debug.Stack()))
		}
	}()
	proof, err = proveAssignment(cm, compiled, assignment)
	return
}

func proveAssignment(cm circuits.Metadata, compiled *CompiledCircuit, assignment frontend.Circuit) (plonk.Proof, error) {
	w, err := frontend.NewWitness(assignment, cm.Field)
	if err != nil {
		return nil, err
	}
	wit, err := w.MarshalBinary()
	if err != nil {
		return nil, err
	}

	result := make(chan ProveResult, 1)
	log.Info("Proving", "id", cm.Id)
	ProveAsync(compiled, cm.Field, cm.Outer, wit, result)
	log.Info("Awaiting result", "id", cm.Id)
	r := <-result
	log.Info("Proof generation complete", "id", cm.Id, "error", r.Err)
	if r.Err != nil {
		return nil, r.Err
	}

	proof, err := cm.EmptyProof()
	if err != nil {
		return nil, err
	}
	_, err = proof.ReadFrom(bytes.NewBuffer(r.Data))
	if err != nil {
		return nil, err
	}
	return proof, nil
}
