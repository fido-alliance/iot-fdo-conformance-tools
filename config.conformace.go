package fdoshared

type CONFIG_ENTRY string

const (
	CFG_RESULTS_API_KEY CONFIG_ENTRY = "results_api_key"
	CFG_MODE            CONFIG_ENTRY = "mode"
)

type CONFIG_MODE_TYPE string

const (
	CFG_MODE_ONPREM CONFIG_MODE_TYPE = "onprem"
	CFG_MODE_ONLINE CONFIG_MODE_TYPE = "online"
)
