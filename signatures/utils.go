package signatures

import (
	"crypto/ecdsa"
	"errors"

	"github.com/consensys/gnark/backend/plonk"
	bls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	"github.com/consensys/gnark/frontend"
)

func publicKeyToCircuitData(publicKey ecdsa.PublicKey) (currentData []byte, currentDataInput [9]frontend.Variable, err error) {
	currentData = ecdsaPublicKeyToData(&publicKey)
	_, _, currentDataInput, _, err = DataToBytes31Chunks(currentData)
	if err != nil {
		return
	}
	return
}

func getVkBytes(vk plonk.VerifyingKey) ([]byte, error) {
	bls12377vk, ok := vk.(*bls12377.VerifyingKey)
	if !ok {
		return nil, errors.New("invalid vk")
	}
	return VkToBytes(bls12377vk)
}
