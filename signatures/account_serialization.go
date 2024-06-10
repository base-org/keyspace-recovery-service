package signatures

import (
	"encoding/binary"
	"errors"
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	pbls12377 "github.com/consensys/gnark/backend/plonk/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bw6761"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	rplonk "github.com/consensys/gnark/std/recursion/plonk"
)

const RawDataSize = 256
const DataSize = 288

// ErrInvalidVk is returned when the verification key is not valid
var ErrInvalidVk = errors.New("invalid verification key")

// ErrInvalidProof is returned when the proof is not valid
var ErrInvalidProof = errors.New("invalid proof")

// ErrInvalidData is returned when the data is not valid
var ErrInvalidData = errors.New("invalid data")

// VkToBytes converts a BLS12-377 circuit plonk.VerifyingKey to a byte array.
// Used to serialize the verification key for submission onchain.
func VkToBytes(vk *pbls12377.VerifyingKey) ([]byte, error) {
	if vk.NbPublicVariables != 10 || len(vk.CommitmentConstraintIndexes) != 3 || len(vk.Qcp) != 3 {
		return nil, ErrInvalidVk
	}
	var b []byte
	b = binary.BigEndian.AppendUint64(b, vk.Size)
	b = appendBytes32(b, vk.SizeInv.Bytes())
	b = appendBytes32(b, vk.Generator.Bytes())
	b = appendBytes32(b, vk.CosetShift.Bytes())
	for _, c := range vk.CommitmentConstraintIndexes {
		b = binary.BigEndian.AppendUint64(b, c)
	}
	b = appendG2Bytes(b, vk.Kzg.G2[0])
	b = appendG2Bytes(b, vk.Kzg.G2[1])
	b = appendG1Bytes(b, vk.Kzg.G1)
	for _, s := range vk.S {
		b = appendG1Bytes(b, s)
	}
	b = appendG1Bytes(b, vk.Ql)
	b = appendG1Bytes(b, vk.Qr)
	b = appendG1Bytes(b, vk.Qm)
	b = appendG1Bytes(b, vk.Qo)
	b = appendG1Bytes(b, vk.Qk)
	for _, q := range vk.Qcp {
		b = appendG1Bytes(b, q)
	}
	return b, nil
}

// BytesToVk converts a byte array to a BLS12-377 circuit plonk.VerifyingKey.
// Used to deserialize the verification key from an onchain submission.
func BytesToVk(b []byte) (*pbls12377.VerifyingKey, error) {
	if len(b) != 1664 {
		return nil, ErrInvalidVk
	}
	vk := new(pbls12377.VerifyingKey)
	vk.NbPublicVariables = 10
	vk.Size = binary.BigEndian.Uint64(b)
	vk.SizeInv.SetBytes(b[8:40])
	vk.Generator.SetBytes(b[40:72])
	vk.CosetShift.SetBytes(b[72:104])
	vk.CommitmentConstraintIndexes = append(vk.CommitmentConstraintIndexes, binary.BigEndian.Uint64(b[104:112]))
	vk.CommitmentConstraintIndexes = append(vk.CommitmentConstraintIndexes, binary.BigEndian.Uint64(b[112:120]))
	vk.CommitmentConstraintIndexes = append(vk.CommitmentConstraintIndexes, binary.BigEndian.Uint64(b[120:128]))
	vk.Kzg.G2[0].X.A0.SetBytes(b[128:176])
	vk.Kzg.G2[0].X.A1.SetBytes(b[176:224])
	vk.Kzg.G2[0].Y.A0.SetBytes(b[224:272])
	vk.Kzg.G2[0].Y.A1.SetBytes(b[272:320])
	vk.Kzg.G2[1].X.A0.SetBytes(b[320:368])
	vk.Kzg.G2[1].X.A1.SetBytes(b[368:416])
	vk.Kzg.G2[1].Y.A0.SetBytes(b[416:464])
	vk.Kzg.G2[1].Y.A1.SetBytes(b[464:512])
	vk.Kzg.G1.X.SetBytes(b[512:560])
	vk.Kzg.G1.Y.SetBytes(b[560:608])
	vk.Kzg.Lines[0] = bls12377.PrecomputeLines(vk.Kzg.G2[0])
	vk.Kzg.Lines[1] = bls12377.PrecomputeLines(vk.Kzg.G2[1])
	vk.S[0].X.SetBytes(b[608:656])
	vk.S[0].Y.SetBytes(b[656:704])
	vk.S[1].X.SetBytes(b[704:752])
	vk.S[1].Y.SetBytes(b[752:800])
	vk.S[2].X.SetBytes(b[800:848])
	vk.S[2].Y.SetBytes(b[848:896])
	vk.Ql.X.SetBytes(b[896:944])
	vk.Ql.Y.SetBytes(b[944:992])
	vk.Qr.X.SetBytes(b[992:1040])
	vk.Qr.Y.SetBytes(b[1040:1088])
	vk.Qm.X.SetBytes(b[1088:1136])
	vk.Qm.Y.SetBytes(b[1136:1184])
	vk.Qo.X.SetBytes(b[1184:1232])
	vk.Qo.Y.SetBytes(b[1232:1280])
	vk.Qk.X.SetBytes(b[1280:1328])
	vk.Qk.Y.SetBytes(b[1328:1376])
	vk.Qcp = make([]bls12377.G1Affine, 3)
	vk.Qcp[0].X.SetBytes(b[1376:1424])
	vk.Qcp[0].Y.SetBytes(b[1424:1472])
	vk.Qcp[1].X.SetBytes(b[1472:1520])
	vk.Qcp[1].Y.SetBytes(b[1520:1568])
	vk.Qcp[2].X.SetBytes(b[1568:1616])
	vk.Qcp[2].Y.SetBytes(b[1616:1664])
	return vk, nil
}

// CircuitVkToVariables converts a BLS12-377 circuit plonk.VerifyingKey to a slice of frontend.Variable.
// Used in-circuit to serialize the verification key ready for Poseidon hashing it in BW6-761.
func CircuitVkToVariables(api frontend.API, field *emulated.Field[sw_bls12377.ScalarField], vk rplonk.VerifyingKey[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]) ([]frontend.Variable, error) {
	if vk.NbPublicVariables != 10 || len(vk.CommitmentConstraintIndexes) != 3 || len(vk.Qcp) != 3 {
		return nil, ErrInvalidVk
	}
	var v []frontend.Variable
	v = append(v, vk.Size)
	v = append(v, api.FromBinary(field.ToBits(&vk.SizeInv)...))
	v = append(v, api.FromBinary(field.ToBits(&vk.Generator)...))
	v = append(v, api.FromBinary(field.ToBits(&vk.CosetShift)...))
	for i := 0; i < len(vk.CommitmentConstraintIndexes); i++ {
		v = append(v, vk.CommitmentConstraintIndexes[i])
	}
	v = appendG2Variables(v, vk.Kzg.G2[0])
	v = appendG2Variables(v, vk.Kzg.G2[1])
	v = appendG1Variables(v, vk.Kzg.G1)
	for i := 0; i < len(vk.S); i++ {
		v = appendG1Variables(v, vk.S[i].G1El)
	}
	v = appendG1Variables(v, vk.Ql.G1El)
	v = appendG1Variables(v, vk.Qr.G1El)
	v = appendG1Variables(v, vk.Qm.G1El)
	v = appendG1Variables(v, vk.Qo.G1El)
	v = appendG1Variables(v, vk.Qk.G1El)
	for i := 0; i < len(vk.Qcp); i++ {
		v = appendG1Variables(v, vk.Qcp[i].G1El)
	}
	return v, nil
}

// EmulatedVkToUints8 converts a slice of BW6-761 emulated.Element to a slice of uints.U8.
// Used in-circuit to serialize the verification key ready for Keccak256 hashing it in BLS12-377.
func EmulatedVkToUints8(api frontend.API, bwField *emulated.Field[sw_bw6761.ScalarField], binaryField *uints.BinaryField[uints.U64], e [39]emulated.Element[sw_bw6761.ScalarField]) []uints.U8 {
	var b []uints.U8
	b = appendElementAsUints8(api, bwField, binaryField, b, &e[0], 8)  // size = 8 bytes
	b = appendElementAsUints8(api, bwField, binaryField, b, &e[1], 32) // size-inv = 32 bytes
	b = appendElementAsUints8(api, bwField, binaryField, b, &e[2], 32) // generator = 32 bytes
	b = appendElementAsUints8(api, bwField, binaryField, b, &e[3], 32) // coset-shift = 32 bytes
	for i := 4; i < 7; i++ {
		b = appendElementAsUints8(api, bwField, binaryField, b, &e[i], 8) // commitment constraint indexes = 8 bytes
	}
	for i := 7; i < len(e); i++ {
		b = appendElementAsUints8(api, bwField, binaryField, b, &e[i], 48) // remainder = 48 bytes
	}
	return b
}

// VkToBigInts converts a BLS12-377 circuit plonk.VerifyingKey to a slice of *big.Int and [39]emulated.Element.
// Used to serialize the verification key ready for Poseidon hashing outside the circuit, and for passing it as elements
// to the Recurse circuit.
func VkToBigInts(vk *pbls12377.VerifyingKey) ([]*big.Int, [39]emulated.Element[sw_bw6761.ScalarField], error) {
	var e [39]emulated.Element[sw_bw6761.ScalarField]
	if vk.NbPublicVariables != 10 || len(vk.CommitmentConstraintIndexes) != 3 || len(vk.Qcp) != 3 {
		return nil, e, ErrInvalidVk
	}
	var i []*big.Int
	i = append(i, new(big.Int).SetUint64(vk.Size))
	i = append(i, vk.SizeInv.BigInt(new(big.Int)))
	i = append(i, vk.Generator.BigInt(new(big.Int)))
	i = append(i, vk.CosetShift.BigInt(new(big.Int)))
	for _, c := range vk.CommitmentConstraintIndexes {
		i = append(i, new(big.Int).SetUint64(c))
	}
	i = appendG2BigInts(i, vk.Kzg.G2[0])
	i = appendG2BigInts(i, vk.Kzg.G2[1])
	i = appendG1BigInts(i, vk.Kzg.G1)
	for _, s := range vk.S {
		i = appendG1BigInts(i, s)
	}
	i = appendG1BigInts(i, vk.Ql)
	i = appendG1BigInts(i, vk.Qr)
	i = appendG1BigInts(i, vk.Qm)
	i = appendG1BigInts(i, vk.Qo)
	i = appendG1BigInts(i, vk.Qk)
	for _, q := range vk.Qcp {
		i = appendG1BigInts(i, q)
	}
	if len(i) != len(e) {
		return nil, e, ErrInvalidVk
	}
	for j := 0; j < len(e); j++ {
		e[j] = emulated.ValueOf[sw_bw6761.ScalarField](i[j])
	}
	return i, e, nil
}

// ProofToBytes converts a BLS12-377 circuit plonk.Proof to a byte array.
// Used to serialize the proof for submission onchain.
func ProofToBytes(proof *pbls12377.Proof) ([]byte, error) {
	if len(proof.Bsb22Commitments) != 3 || len(proof.BatchedProof.ClaimedValues) != 10 {
		return nil, ErrInvalidProof
	}
	var b []byte
	for _, l := range proof.LRO {
		b = appendG1Bytes(b, l)
	}
	b = appendG1Bytes(b, proof.Z)
	for _, h := range proof.H {
		b = appendG1Bytes(b, h)
	}
	for _, c := range proof.Bsb22Commitments {
		b = appendG1Bytes(b, c)
	}
	b = appendG1Bytes(b, proof.BatchedProof.H)
	b = appendG1Bytes(b, proof.ZShiftedOpening.H)
	for _, v := range proof.BatchedProof.ClaimedValues {
		b = appendBytes32(b, v.Bytes())
	}
	b = appendBytes32(b, proof.ZShiftedOpening.ClaimedValue.Bytes())
	return b, nil
}

// BytesToProof converts a byte array to a BLS12-377 circuit plonk.Proof.
// Used to deserialize the proof from an onchain submission.
func BytesToProof(b []byte) (*pbls12377.Proof, error) {
	if len(b) != 1504 {
		return nil, ErrInvalidProof
	}
	proof := new(pbls12377.Proof)
	proof.LRO[0].X.SetBytes(b[0:48])
	proof.LRO[0].Y.SetBytes(b[48:96])
	proof.LRO[1].X.SetBytes(b[96:144])
	proof.LRO[1].Y.SetBytes(b[144:192])
	proof.LRO[2].X.SetBytes(b[192:240])
	proof.LRO[2].Y.SetBytes(b[240:288])
	proof.Z.X.SetBytes(b[288:336])
	proof.Z.Y.SetBytes(b[336:384])
	proof.H[0].X.SetBytes(b[384:432])
	proof.H[0].Y.SetBytes(b[432:480])
	proof.H[1].X.SetBytes(b[480:528])
	proof.H[1].Y.SetBytes(b[528:576])
	proof.H[2].X.SetBytes(b[576:624])
	proof.H[2].Y.SetBytes(b[624:672])
	proof.Bsb22Commitments = make([]bls12377.G1Affine, 3)
	proof.Bsb22Commitments[0].X.SetBytes(b[672:720])
	proof.Bsb22Commitments[0].Y.SetBytes(b[720:768])
	proof.Bsb22Commitments[1].X.SetBytes(b[768:816])
	proof.Bsb22Commitments[1].Y.SetBytes(b[816:864])
	proof.Bsb22Commitments[2].X.SetBytes(b[864:912])
	proof.Bsb22Commitments[2].Y.SetBytes(b[912:960])
	proof.BatchedProof.H.X.SetBytes(b[960:1008])
	proof.BatchedProof.H.Y.SetBytes(b[1008:1056])
	proof.ZShiftedOpening.H.X.SetBytes(b[1056:1104])
	proof.ZShiftedOpening.H.Y.SetBytes(b[1104:1152])
	proof.BatchedProof.ClaimedValues = make([]fr.Element, 10)
	proof.BatchedProof.ClaimedValues[0].SetBytes(b[1152:1184])
	proof.BatchedProof.ClaimedValues[1].SetBytes(b[1184:1216])
	proof.BatchedProof.ClaimedValues[2].SetBytes(b[1216:1248])
	proof.BatchedProof.ClaimedValues[3].SetBytes(b[1248:1280])
	proof.BatchedProof.ClaimedValues[4].SetBytes(b[1280:1312])
	proof.BatchedProof.ClaimedValues[5].SetBytes(b[1312:1344])
	proof.BatchedProof.ClaimedValues[6].SetBytes(b[1344:1376])
	proof.BatchedProof.ClaimedValues[7].SetBytes(b[1376:1408])
	proof.BatchedProof.ClaimedValues[8].SetBytes(b[1408:1440])
	proof.BatchedProof.ClaimedValues[9].SetBytes(b[1440:1472])
	proof.ZShiftedOpening.ClaimedValue.SetBytes(b[1472:1504])
	return proof, nil
}

// CircuitProofToVariables converts a BLS12-377 circuit plonk.Proof to a slice of frontend.Variable.
// Used in-circuit to serialize the verification key ready for Poseidon hashing it in BW6-761.
func CircuitProofToVariables(api frontend.API, field *emulated.Field[sw_bls12377.ScalarField], proof rplonk.Proof[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine]) ([]frontend.Variable, error) {
	if len(proof.Bsb22Commitments) != 3 || len(proof.BatchedProof.ClaimedValues) != 10 {
		return nil, ErrInvalidProof
	}
	var v []frontend.Variable
	for i := 0; i < len(proof.LRO); i++ {
		v = appendG1Variables(v, proof.LRO[i].G1El)
	}
	v = appendG1Variables(v, proof.Z.G1El)
	for i := 0; i < len(proof.H); i++ {
		v = appendG1Variables(v, proof.H[i].G1El)
	}
	for i := 0; i < len(proof.Bsb22Commitments); i++ {
		v = appendG1Variables(v, proof.Bsb22Commitments[i].G1El)
	}
	v = appendG1Variables(v, proof.BatchedProof.Quotient)
	v = appendG1Variables(v, proof.ZShiftedOpening.Quotient)
	for i := 0; i < len(proof.BatchedProof.ClaimedValues); i++ {
		v = append(v, api.FromBinary(field.ToBits(&proof.BatchedProof.ClaimedValues[i])...))
	}
	v = append(v, api.FromBinary(field.ToBits(&proof.ZShiftedOpening.ClaimedValue)...))
	return v, nil
}

// EmulatedProofToUints8 converts a slice of BW6-761 emulated.Element to a slice of uints.U8.
// Used in-circuit to serialize the proof ready for Keccak256 hashing it in BLS12-377.
func EmulatedProofToUints8(api frontend.API, bwField *emulated.Field[sw_bw6761.ScalarField], binaryField *uints.BinaryField[uints.U64], e [35]emulated.Element[sw_bw6761.ScalarField]) []uints.U8 {
	var b []uints.U8
	for i := 0; i < 24; i++ {
		b = appendElementAsUints8(api, bwField, binaryField, b, &e[i], 48)
	}
	for i := 24; i < 35; i++ {
		b = appendElementAsUints8(api, bwField, binaryField, b, &e[i], 32)
	}
	return b
}

// ProofToBigInts converts a BLS12-377 circuit plonk.Proof to a slice of *big.Int and [28]emulated.Element.
// Used to serialize the proof ready for Poseidon hashing outside the circuit, and for passing it as elements
// to the Recurse circuit.
func ProofToBigInts(proof *pbls12377.Proof) ([]*big.Int, [35]emulated.Element[sw_bw6761.ScalarField], error) {
	var e [35]emulated.Element[sw_bw6761.ScalarField]
	if len(proof.Bsb22Commitments) != 3 || len(proof.BatchedProof.ClaimedValues) != 10 {
		return nil, e, ErrInvalidProof
	}
	var i []*big.Int
	for _, l := range proof.LRO {
		i = appendG1BigInts(i, l)
	}
	i = appendG1BigInts(i, proof.Z)
	for _, h := range proof.H {
		i = appendG1BigInts(i, h)
	}
	for _, c := range proof.Bsb22Commitments {
		i = appendG1BigInts(i, c)
	}
	i = appendG1BigInts(i, proof.BatchedProof.H)
	i = appendG1BigInts(i, proof.ZShiftedOpening.H)
	for _, v := range proof.BatchedProof.ClaimedValues {
		i = append(i, v.BigInt(new(big.Int)))
	}
	i = append(i, proof.ZShiftedOpening.ClaimedValue.BigInt(new(big.Int)))
	if len(i) != len(e) {
		return nil, e, ErrInvalidVk
	}
	for j := 0; j < len(e); j++ {
		e[j] = emulated.ValueOf[sw_bw6761.ScalarField](i[j])
	}
	return i, e, nil
}

func DataToUints8[T emulated.FieldParams](api frontend.API, field *emulated.Field[T], binaryField *uints.BinaryField[uints.U64], array [DataSize / 32]emulated.Element[T]) []uints.U8 {
	size := RawDataSize
	elementSize := 31
	last := ((size-1)%elementSize + 1) * 8
	bits := field.ToBits(&array[len(array)-1])[:last]
	for i := len(array) - 2; i >= 0; i-- {
		bits = append(bits, field.ToBits(&array[i])[:elementSize*8]...)
	}
	b := make([]uints.U8, size)
	for i := size - 1; i >= 0; i-- {
		b[size-i-1] = binaryField.ByteValueOf(api.FromBinary(bits[i*8 : (i+1)*8]...))
	}
	return b
}

func DataToBytes31Chunks(a []byte) ([]byte, []*big.Int, [DataSize / 32]frontend.Variable, [DataSize / 32]emulated.Element[sw_bw6761.ScalarField], error) {
	var v [DataSize / 32]frontend.Variable
	var e [DataSize / 32]emulated.Element[sw_bw6761.ScalarField]
	if len(a) != RawDataSize {
		return nil, nil, v, e, ErrInvalidData
	}
	l := len(e)
	i := make([]*big.Int, l)
	b := make([]byte, DataSize)
	for j := 0; j < l-1; j++ {
		copy(b[j*32+1:], a[j*31:(j+1)*31])
		i[j] = new(big.Int).SetBytes(a[j*31 : (j+1)*31])
		e[j] = emulated.ValueOf[sw_bw6761.ScalarField](i[j])
		v[j] = i[j]
	}
	copy(b[(l-1)*32+1:], a[(l-1)*31:])
	i[l-1] = new(big.Int).SetBytes(a[(l-1)*31:])
	e[l-1] = emulated.ValueOf[sw_bw6761.ScalarField](i[l-1])
	v[l-1] = i[l-1]
	return b, i, v, e, nil
}

func appendBytes32(b []byte, v [32]byte) []byte {
	return append(b, v[:]...)
}

func appendBytes48(b []byte, v [48]byte) []byte {
	return append(b, v[:]...)
}

func appendG1Bytes(b []byte, v bls12377.G1Affine) []byte {
	b = appendBytes48(b, v.X.Bytes())
	return appendBytes48(b, v.Y.Bytes())
}

func appendG1BigInts(i []*big.Int, g bls12377.G1Affine) []*big.Int {
	i = append(i, g.X.BigInt(new(big.Int)))
	return append(i, g.Y.BigInt(new(big.Int)))
}

func appendG1Variables(v []frontend.Variable, g sw_bls12377.G1Affine) []frontend.Variable {
	v = append(v, g.X)
	return append(v, g.Y)
}

func appendG2Bytes(b []byte, v bls12377.G2Affine) []byte {
	b = appendBytes48(b, v.X.A0.Bytes())
	b = appendBytes48(b, v.X.A1.Bytes())
	b = appendBytes48(b, v.Y.A0.Bytes())
	return appendBytes48(b, v.Y.A1.Bytes())
}

func appendG2BigInts(i []*big.Int, g bls12377.G2Affine) []*big.Int {
	i = append(i, g.X.A0.BigInt(new(big.Int)))
	i = append(i, g.X.A1.BigInt(new(big.Int)))
	i = append(i, g.Y.A0.BigInt(new(big.Int)))
	return append(i, g.Y.A1.BigInt(new(big.Int)))
}

func appendG2Variables(v []frontend.Variable, g sw_bls12377.G2Affine) []frontend.Variable {
	v = append(v, g.P.X.A0)
	v = append(v, g.P.X.A1)
	v = append(v, g.P.Y.A0)
	return append(v, g.P.Y.A1)
}

func appendElementAsUints8(api frontend.API, bwField *emulated.Field[sw_bw6761.ScalarField], binaryField *uints.BinaryField[uints.U64], i []uints.U8, e *emulated.Element[sw_bw6761.ScalarField], length int) []uints.U8 {
	bits := bwField.ToBits(e)
	for j := length - 1; j >= 0; j-- {
		i = append(i, binaryField.ByteValueOf(api.FromBinary(bits[j*8:j*8+8]...)))
	}
	return i
}
