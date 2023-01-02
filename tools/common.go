package tools

import fdoshared "github.com/WebauthnWorks/fdo-shared"

const (
	CFG_DEV_ENV fdoshared.CONFIG_ENTRY = "DEV"

	CFG_GITHUB_CLIENTID     fdoshared.CONFIG_ENTRY = "OAUTH2_GITHUB_CLIENTID"
	CFG_GITHUB_CLIENTSECRET fdoshared.CONFIG_ENTRY = "OAUTH2_GITHUB_CLIENTSECRET"
	CFG_GITHUB_REDIRECTURL  fdoshared.CONFIG_ENTRY = "OAUTH2_GITHUB_REDIRECTURL"
)

const (
	ENV_DEV string = "dev"
)
