package services

type Oauth2ServiceConfig struct {
	RedirectUrl  string
	ClientSecret string
	ClientId     string
}

type Oauth2ServiceInst interface {
	GetRedirectUrl() (string, string, string)
	GetUserInfo() string
}

type Oauth2Services struct {
	Services map[string]Oauth2ServiceInst
}

// func (h *Oidc) ServiceExists(string) bool {

// }
