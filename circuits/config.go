package circuits

import (
	"errors"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

type EcdsaAccount[T, S emulated.FieldParams] struct {
	CurrentData [9]frontend.Variable `gnark:",public"`
	NewKey      frontend.Variable    `gnark:",public"`
	Sig         gecdsa.Signature[S]
}

func (c *EcdsaAccount[T, S]) Define(api frontend.API) error {
	return errors.New("not implemented")
}

var Secp256k1AccountMetadata = &Metadata{
	Id:          "Secp256k1Account",
	Field:       ecc.BLS12_377.ScalarField(),
	Outer:       ecc.BW6_761.ScalarField(),
	Commitments: 3,
}

type WebauthnAccount struct {
	CurrentData [9]frontend.Variable `gnark:",public"`
	NewKey      frontend.Variable    `gnark:",public"`

	Sig                        gecdsa.Signature[emulated.P256Fr]
	ClientDataSuffixBlockCount frontend.Variable
	PaddedClientDataSuffix     [241]uints.U8
	AuthenticatorData          [37]uints.U8
}

func (c *WebauthnAccount) Define(api frontend.API) error {
	return errors.New("not implemented")
}

var WebauthnAccountMetadata = &Metadata{
	Id:          "WebauthnAccount",
	Field:       ecc.BLS12_377.ScalarField(),
	Outer:       ecc.BW6_761.ScalarField(),
	Commitments: 3,
}
