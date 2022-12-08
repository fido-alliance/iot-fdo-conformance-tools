package fdoshared

type CONFIG_ENTRY string

const (
	CFG_API_KEY_RESULTS CONFIG_ENTRY = "results_api_key"
	CFG_API_BUILDS_URL  CONFIG_ENTRY = "builds_api_url"
	CFG_MODE            CONFIG_ENTRY = "mode"
)

type CONFIG_MODE_TYPE string

const (
	CFG_MODE_ONPREM CONFIG_MODE_TYPE = "onprem"
	CFG_MODE_ONLINE CONFIG_MODE_TYPE = "online"
)
