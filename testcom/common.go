package testcom

type FDOTestState struct {
	_      struct{} `cbor:",toarray"`
	Passed bool     `json:"passed"`
	Error  string   `json:"error"`
}
