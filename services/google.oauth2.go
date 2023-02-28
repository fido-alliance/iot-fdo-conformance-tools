package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	fdoshared "github.com/fido-alliance/fdo-shared"
	"golang.org/x/oauth2"
)

var Google_EndpointConfig = oauth2.Endpoint{
	AuthURL:  "https://accounts.google.com/o/oauth2/auth",
	TokenURL: "https://oauth2.googleapis.com/token",
}

var Google_OAuth2Scopes = []string{
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

const Google_UserUrl = "https://openidconnect.googleapis.com/v1/userinfo"

// https://developers.google.com/identity/openid-connect/openid-connect
type GoogleUser struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

type GoogleOrg struct {
	OrgName string `json:"login"`
}

type GoogleOAuth2Provider struct {
	Config   OAuth2ProviderConfig
	Endpoint oauth2.Endpoint
	LogTag   string
}

func NewGoogleOAuth2Connector(config OAuth2ProviderConfig) GoogleOAuth2Provider {
	return GoogleOAuth2Provider{
		Config:   config,
		Endpoint: Google_EndpointConfig,
		LogTag:   "GoogleOAuth2",
	}
}

func (h GoogleOAuth2Provider) getUserInfo(authToken string) (string, error) {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("GET", Google_UserUrl, nil)
	if err != nil {
		return "", fmt.Errorf("%s: Error generating new request instance. %s", h.LogTag, err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: Error sending request. %s", h.LogTag, err.Error())
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%s: Error reading response body. %s", h.LogTag, err.Error())
	}

	var userInst GoogleUser
	err = json.Unmarshal(bodyBytes, &userInst)
	if err != nil {
		return "", fmt.Errorf("%s: Error decoding userinfo. %s", h.LogTag, err.Error())
	}

	return userInst.Email, nil
}

func (h GoogleOAuth2Provider) getGithubOauthConfig() *oauth2.Config {
	return &oauth2.Config{
		// RedirectURL:  h.Config.RedirectUrl,
		ClientID:     h.Config.ClientId,
		ClientSecret: h.Config.ClientSecret,
		RedirectURL:  h.Config.RedirectUrl,
		Scopes:       Google_OAuth2Scopes,
		Endpoint:     h.Endpoint,
	}
}

func (h GoogleOAuth2Provider) GetRedirectUrl() (string, string, string) {

	state := fdoshared.NewRandomString(16)
	nonce := fdoshared.NewRandomString(16)

	return h.getGithubOauthConfig().AuthCodeURL(state), state, nonce
}

func (h GoogleOAuth2Provider) GetUserInfo(resultCode string) (string, bool, error) {
	oauth2Token, err := h.getGithubOauthConfig().Exchange(context.Background(), resultCode)
	if err != nil {
		return "", false, err
	}

	email, err := h.getUserInfo(oauth2Token.AccessToken)
	if err != nil {
		return "", false, err
	}

	return email, false, nil
}
