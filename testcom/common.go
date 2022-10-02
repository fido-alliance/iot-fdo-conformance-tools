package testcom

type FDOTestState struct {
	_      struct{}  `cbor:",toarray"`
	Passed bool      `json:"passed"`
	Error  string    `json:"error"`
	TestID FDOTestID `json:"testId"`
}

func NewSuccessTestState(testId FDOTestID) FDOTestState {
	return FDOTestState{
		Passed: true,
		TestID: testId,
	}
}

func NewFailTestState(testId FDOTestID, errorMsg string) FDOTestState {
	return FDOTestState{
		Passed: false,
		Error:  errorMsg,
		TestID: testId,
	}
}
