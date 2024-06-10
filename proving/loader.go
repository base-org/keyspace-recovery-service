package proving

import (
	"bytes"
	"math/big"
	"sync"

	"github.com/base-org/keyspace-recovery-service/proving/storage"
	"github.com/consensys/gnark/backend/witness"
	"github.com/ethereum/go-ethereum/log"
)

type LockingCircuitLoader struct {
	store  storage.Storage
	loaded map[string]*CompiledCircuit
	lock   sync.Mutex
	locks  map[string]*sync.Mutex
}

/**
 * Creates a new CircuitStorageManager to manage loading compiled circuits asychronously.
 */
func NewLockingCircuitLoader(store storage.Storage) *LockingCircuitLoader {
	return &LockingCircuitLoader{
		store:  store,
		loaded: make(map[string]*CompiledCircuit),
		locks:  make(map[string]*sync.Mutex),
	}
}

func (p *LockingCircuitLoader) Store() storage.Storage {
	return p.store
}

func (p *LockingCircuitLoader) LoadAndProve(filename string, field, outer *big.Int, wit []byte, result chan ProveResult) {
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

		log.Info("Loading circuit", "filename", filename)
		compiled, err := p.load(filename, field)
		if err != nil {
			result <- ProveResult{Err: err}
			return
		}

		log.Info("Generating proof", "filename", filename)
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

func (p *LockingCircuitLoader) Load(filename string, field *big.Int, result chan LoadCircuitResult) {
	go func() {
		compiled, err := p.load(filename, field)
		if err != nil {
			result <- LoadCircuitResult{Err: err}
			return
		}
		result <- LoadCircuitResult{Circuit: &CompiledCircuit{
			Ccs: compiled.Ccs,
			Pk:  compiled.Pk,
			Vk:  compiled.Vk,
		}}
	}()
}

func (p *LockingCircuitLoader) load(filename string, field *big.Int) (*CompiledCircuit, error) {
	p.lock.Lock()
	if p.locks[filename] == nil {
		p.locks[filename] = new(sync.Mutex)
	}
	p.lock.Unlock()

	p.locks[filename].Lock()
	defer p.locks[filename].Unlock()

	if c, ok := p.loaded[filename]; ok {
		return c, nil
	}
	ccs, pk, vk, err := Load(p.store, filename, field, false)
	if err != nil {
		return nil, err
	}
	c := &CompiledCircuit{
		Ccs: ccs,
		Pk:  pk,
		Vk:  vk,
	}
	p.loaded[filename] = c
	return c, nil
}
