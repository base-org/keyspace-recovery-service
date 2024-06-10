package proving

import (
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
)

type ProveResult struct {
	Data []byte
	Err  error
}

type CompiledCircuit struct {
	Ccs constraint.ConstraintSystem
	Pk  plonk.ProvingKey
	Vk  plonk.VerifyingKey
}

type LoadCircuitResult struct {
	Circuit *CompiledCircuit
	Err     error
}
