package services

type Oauth2ProviderConfig struct {
	RedirectUrl  string
	ClientSecret string
	ClientId     string
}

type Oauth2Provider interface {
	GetRedirectUrl() (string, string, string)
	GetUserInfo() string
}

type Oauth2Services struct {
	Services map[string]Oauth2Provider
}

// func (h *Oidc) ServiceExists(string) bool {

// }
