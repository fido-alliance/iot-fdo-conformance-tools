package main

import (
	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/tools"
)

// Domain to access FDO endpoints. Will be returned in RVInfo etc.
const FDO_SERVICE_URL = "http://fdo.tools"

// CFG_MODE_ONLINE (FIDO Alliance hosted fido.tools) or CFG_MODE_ONPREM for on premises hosting
const TOOLS_MODE = fdoshared.CFG_MODE_ONPREM

// ENV_PROD for fully built version, ENV_DEV for development with frontend running in a dev mode
const FDO_DEV_ENV_DEFAULT = tools.ENV_PROD

/* ----- FIDO Alliance Only ----- */
// API key to submit test results (FIDO Alliance Only)
const APIKEY_RESULT_SUBMISSION = "010203040506"

// API endpoint to access builds (FIDO Alliance Only)
const APIKEY_BUILDS_URL = "https://builds.fidoalliance.org"

// Notify email service for fido.tools (FIDO Alliance Only)
const NOTIFY_SERVICE_HOST = "http://localhost:3031"
const NOTIFY_SERVICE_SECRET = "abcdefg"

// OAuth2 config for github (FIDO Alliance Only)
const GITHUB_OAUTH2_CLIENTID = "abcdefg"
const GITHUB_OAUTH2_CLIENTISECRET = "abcdefg"
const GITHUB_OAUTH2_REDIRECTURL = "http://localhost:3033/api/oauth2/github/callback"

// OAuth2 config for github (FIDO Alliance Only)
const GOOGLE_OAUTH2_CLIENTID = "abcdefg"
const GOOGLE_OAUTH2_CLIENTISECRET = "abcdefg"
const GOOGLE_OAUTH2_REDIRECTURL = "http://localhost:3033/api/oauth2/google/callback"
