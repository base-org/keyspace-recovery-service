package signatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"

	"github.com/base-org/keyspace-recovery-service/circuits"
	"github.com/base-org/keyspace-recovery-service/proving"
	bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const ClientDataJSONPrefix = `{"type":"webauthn.get","challenge":"`

const webAuthnAuthAbiJSON = `{ "components": [ { "name": "authenticatorData", "type": "bytes" }, { "name": "clientDataJSON", "type": "bytes" }, { "name": "challengeIndex", "type": "uint256" }, { "name": "typeIndex", "type": "uint256" }, { "name": "r", "type": "uint256" }, { "name": "s", "type": "uint256" } ], "name": "WebAuthnAuth", "type": "tuple"}`

func ProveSignatureWebAuthn(key, newKey254 *big.Int, signature []byte, signatureType string, circuitLoader proving.CircuitLoader) (*ProveSignatureResponse, error) {
	// Decode signature data into public key and bytes containing WebAuthnAuth.
	var sigDataAbi [3]abi.Argument
	sigDataAbi[0].UnmarshalJSON([]byte(`{"type":"bytes32"}`))
	sigDataAbi[1].UnmarshalJSON([]byte(`{"type":"bytes32"}`))
	sigDataAbi[2].UnmarshalJSON([]byte(`{"type":"bytes"}`))
	sigData, err := abi.Arguments(sigDataAbi[:]).Unpack(signature)
	if err != nil {
		return nil, err
	}
	xb := sigData[0].([32]byte)
	yb := sigData[1].([32]byte)
	currentPublicKeyX := new(big.Int).SetBytes(xb[:])
	currentPublicKeyY := new(big.Int).SetBytes(yb[:])

	// Decode WebAuthnAuth from the final bytes argument.
	webAuthnAuthBytes := sigData[2].([]byte)
	var webAuthnAuthAbi [1]abi.Argument
	webAuthnAuthAbi[0].UnmarshalJSON([]byte(webAuthnAuthAbiJSON))
	waaDecoded, err := abi.Arguments(webAuthnAuthAbi[:]).Unpack(webAuthnAuthBytes)
	if err != nil {
		return nil, err
	}
	webAuthnAuth := waaDecoded[0].(struct {
		AuthenticatorData []uint8  "json:\"authenticatorData\""
		ClientDataJSON    []uint8  "json:\"clientDataJSON\""
		ChallengeIndex    *big.Int "json:\"challengeIndex\""
		TypeIndex         *big.Int "json:\"typeIndex\""
		R                 *big.Int "json:\"r\""
		S                 *big.Int "json:\"s\""
	})
	clientHash := sha256.Sum256(webAuthnAuth.ClientDataJSON)
	hash := sha256.Sum256(append(webAuthnAuth.AuthenticatorData, clientHash[:]...))

	currentPublicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     currentPublicKeyX,
		Y:     currentPublicKeyY,
	}
	if !ecdsa.Verify(currentPublicKey, hash[:], webAuthnAuth.R, webAuthnAuth.S) {
		return nil, errors.New("invalid signature")
	}

	currentData, currentDataInput, err := publicKeyToCircuitData(*currentPublicKey)
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(common.BytesToHash(newKey254.Bytes()).Bytes())
	// TODO: Update the WebAuthn circuit to take the challengeIndex and typeIndex
	// into account.
	if !strings.HasPrefix(string(webAuthnAuth.ClientDataJSON), ClientDataJSONPrefix+encoded) {
		return nil, errors.New("invalid client data JSON")
	}
	clientDataJSONSuffix := webAuthnAuth.ClientDataJSON[len(ClientDataJSONPrefix+encoded):]
	paddedSuffix, blockCount := PaddedClientDataSuffix(clientDataJSONSuffix)
	clc := &proving.CircuitLoaderClient{Loader: circuitLoader}
	cc, err := clc.Load(circuits.WebauthnAccountMetadata, 0)
	if err != nil {
		return nil, err
	}

	proof, err := proving.ProveAssignment(*circuits.WebauthnAccountMetadata, cc, &circuits.WebauthnAccount{
		CurrentData: currentDataInput,
		NewKey:      newKey254,
		Sig: gecdsa.Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](webAuthnAuth.R),
			S: emulated.ValueOf[emulated.P256Fr](webAuthnAuth.S),
		},
		ClientDataSuffixBlockCount: blockCount,
		PaddedClientDataSuffix:     paddedSuffix,
		AuthenticatorData:          AuthenticatorData(webAuthnAuth.AuthenticatorData),
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

func PaddedClientDataSuffix(buf []byte) (res [241]uints.U8, count byte) {
	bytesLen := len(buf)
	zeroPadLen := 241 - bytesLen
	lenPosition := zeroPadLen
	count = 5 // 1x 64-bit block for prefix + challenge, and 4x 64-bit blocks for suffix + padding
	for lenPosition > 64 {
		lenPosition -= 64
		count--
	}
	for i, b := range buf {
		res[i] = uints.NewU8(b)
	}
	padding := make([]byte, zeroPadLen)
	padding[0] = 0x80
	binary.BigEndian.PutUint64(padding[lenPosition-8:], uint64(8*(36+43+bytesLen)))
	for i, b := range padding {
		res[i+bytesLen] = uints.NewU8(b)
	}
	return
}

func AuthenticatorData(buf []byte) (res [37]uints.U8) {
	for i, b := range buf {
		res[i] = uints.NewU8(b)
	}
	return
}
