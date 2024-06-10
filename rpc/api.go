package api

import (
	"errors"
	"math/big"

	"github.com/base-org/keyspace-recovery-service/proving"
	"github.com/base-org/keyspace-recovery-service/signatures"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
)

type Recover struct {
	loader proving.CircuitLoader
}

func NewRecover(loader proving.CircuitLoader) *Recover {
	return &Recover{
		loader: loader,
	}
}

type ProveSignatureHandler func(key, newKey254 *big.Int, signature []byte, signatureType string, circuitLoader proving.CircuitLoader) (*signatures.ProveSignatureResponse, error)

var ProveSignatureHandlers = map[string]ProveSignatureHandler{
	"secp256k1": signatures.ProveSignatureSecp256k1,
	"webauthn":  signatures.ProveSignatureWebAuthn,
}

func (r *Recover) ProveSignature(key, newKey *hexutil.Big, signature hexutil.Bytes, signatureType string) (*signatures.ProveSignatureResponse, error) {
	log.Info("Proving for recover_proveSignature call", "key", key, "newKey", newKey, "signatureType", signatureType)
	newKey254 := new(big.Int).Rsh(newKey.ToInt(), 2)

	handler, ok := ProveSignatureHandlers[signatureType]
	if !ok {
		return nil, errors.New("unsupported signature type")
	}

	return handler(key.ToInt(), newKey254, signature, signatureType, r.loader)
}
