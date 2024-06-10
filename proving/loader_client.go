package proving

import (
	"bytes"
	"fmt"
	"math/big"
	"runtime/debug"

	"github.com/base-org/keyspace-recovery-service/circuits"
	"github.com/base-org/keyspace-recovery-service/proving/storage"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/log"
)

type CircuitLoader interface {
	LoadAndProve(filename string, field, outer *big.Int, wit []byte, result chan ProveResult)
	Load(filename string, field *big.Int, result chan LoadCircuitResult)
	Store() storage.Storage
}

type CircuitLoaderClient struct {
	loader CircuitLoader
}

func NewCircuitLoaderClient(loader CircuitLoader) *CircuitLoaderClient {
	return &CircuitLoaderClient{loader: loader}
}

func (clc *CircuitLoaderClient) Load(cm *circuits.Metadata, txCount int) (*CompiledCircuit, error) {
	result := make(chan LoadCircuitResult, 1)
	clc.loader.Load(cm.Filename(txCount), cm.Field, result)
	r := <-result
	if r.Err != nil {
		return nil, r.Err
	}
	return r.Circuit, nil
}

func (clc *CircuitLoaderClient) LoadAndProve(cm *circuits.Metadata, txCount int, assignment frontend.Circuit) (proof plonk.Proof, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v, stack: %s", r, string(debug.Stack()))
		}
	}()
	proof, err = clc.loadAndProve(cm, txCount, assignment)
	return
}

func (clc *CircuitLoaderClient) loadAndProve(cm *circuits.Metadata, txCount int, assignment frontend.Circuit) (plonk.Proof, error) {
	if !cm.MultiTx {
		txCount = 1
	}

	w, err := frontend.NewWitness(assignment, cm.Field)
	if err != nil {
		return nil, err
	}
	wit, err := w.MarshalBinary()
	if err != nil {
		return nil, err
	}

	result := make(chan ProveResult, 1)
	log.Info("Proving", "filename", cm.Filename(txCount-1))
	clc.loader.LoadAndProve(cm.Filename(txCount-1), cm.Field, cm.Outer, wit, result)
	log.Info("Awaiting result", "filename", cm.Filename(txCount-1))
	r := <-result
	log.Info("Proof generation complete", "filename", cm.Filename(txCount-1), "error", r.Err)
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
