package signatures

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/base-org/keyspace-recovery-service/circuits"
	"github.com/base-org/keyspace-recovery-service/proving"
	bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	"github.com/consensys/gnark/std/math/emulated"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/crypto"
)

func ProveSignatureSecp256k1(key, newKey254 *big.Int, signature []byte, signatureType string, circuitLoader proving.CircuitLoader) (*ProveSignatureResponse, error) {
	if len(signature) != 65 {
		return nil, errors.New("invalid signature length")
	}
	if signature[64] != 27 && signature[64] != 28 {
		return nil, errors.New("invalid recovery id")
	}
	// Ethereum-specific signing tools generate v values of 27 or 28, but standard
	// tools expect 0 <= v < 4.
	signature[64] -= 27

	currentPublicKey, err := crypto.SigToPub(newKey254.Bytes(), signature)
	if err != nil {
		return nil, err
	}

	currentData, currentDataInput, err := publicKeyToCircuitData(*currentPublicKey)
	if err != nil {
		return nil, err
	}
	signatureR, signatureS, err := splitSignature(signature)
	if err != nil {
		return nil, err
	}

	clc := proving.NewCircuitLoaderClient(circuitLoader)
	cc, err := clc.Load(circuits.Secp256k1AccountMetadata, 0)
	if err != nil {
		return nil, err
	}

	proof, err := proving.ProveAssignment(*circuits.Secp256k1AccountMetadata, cc, &circuits.EcdsaAccount[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		CurrentData: currentDataInput,
		NewKey:      newKey254,
		Sig: gecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](signatureR),
			S: emulated.ValueOf[emulated.Secp256k1Fr](signatureS),
		},
	})
	if err != nil {
		return nil, err
	}

	bls12377AccountProof, ok := proof.(*bls12377.Proof)
	if !ok {
		return nil, errors.New("invalid proof")
	}
	proofBytes, err := ProofToBytes(bls12377AccountProof)
	if err != nil {
		return nil, err
	}
	vkBytes, err := getVkBytes(cc.Vk)
	if err != nil {
		return nil, err
	}

	return &ProveSignatureResponse{
		Proof:       proofBytes,
		CurrentVk:   vkBytes,
		CurrentData: currentData,
	}, nil
}

func ecdsaPublicKeyToData(publicKey *ecdsa.PublicKey) []byte {
	publicKeyData := make([]byte, 256)
	publicKey.X.FillBytes(publicKeyData[:32])
	publicKey.Y.FillBytes(publicKeyData[32:64])
	return publicKeyData
}

func splitSignature(signature []byte) (r, s *big.Int, err error) {
	if len(signature) != 65 {
		return nil, nil, errors.New("invalid signature length")
	}
	r = new(big.Int).SetBytes(signature[:32])
	s = new(big.Int).SetBytes(signature[32:64])
	return
}
