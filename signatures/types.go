package signatures

import "github.com/ethereum/go-ethereum/common/hexutil"

type ProveSignatureResponse struct {
	Proof       hexutil.Bytes `json:"proof"`
	CurrentVk   hexutil.Bytes `json:"currentVk"`
	CurrentData hexutil.Bytes `json:"currentData"`
}
