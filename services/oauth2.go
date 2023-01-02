package services

import (
	"fmt"
)

type OAuth2ProviderConfig struct {
	// RedirectUrl  string
	ClientSecret string
	ClientId     string
}

type OAuth2ProviderID string

const (
	OATH2_GITHUB = "github"
	OATH2_GOOGLE = "google"
)

type OAuth2Provider interface {
	// Redirect URL, State, Nonce
	GetRedirectUrl() (string, string, string)
	GetUserInfo(resultCode string) (string, bool, error)
}

type OAuth2Service struct {
	Providers map[OAuth2ProviderID]OAuth2Provider
}

func (h *OAuth2Service) ProviderExists(providerId OAuth2ProviderID) bool {
	for k, _ := range h.Providers {
		if k == providerId {
			return true
		}
	}

	return false
}

func (h *OAuth2Service) GetProvider(providerId OAuth2ProviderID) (OAuth2Provider, error) {
	val, ok := h.Providers[providerId]
	if ok {
		return val, nil
	} else {
		return nil, fmt.Errorf("%s provider does not exist", providerId)
	}
}
