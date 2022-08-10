package rvtests

type RVTestID string

const (
	FIDO_RVT_20_BAD_ENCODING RVTestID = "FIDO_RVT_20_BAD_ENCODING"
)

type RVTestState struct {
	_      struct{} `cbor:",toarray"`
	Passed bool
	Error  string
}

type RVTestMap map[RVTestID]RVTestState
