package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"golang.org/x/oauth2"
)

var Github_EndpointConfig = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_token",
}

var Github_OAuth2Scopes = []string{
	"read:user",
	"user:email",
	"read:org",
}

const Github_UserUrl = "https://api.github.com/user"
const Github_OrgsUrl = "https://api.github.com/user"
const Github_FIDOAllianceID = "fido-alliance"

type GithubUser struct {
	Username string `json:"login"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Company  string `json:"company"`
	Location string `json:"location"`
	Bio      string `json:"bio"`
}

type GithubOrg struct {
	OrgName string `json:"login"`
}

type GithubOAuth2Provider struct {
	Config   OAuth2ProviderConfig
	Endpoint oauth2.Endpoint
	LogTag   string
}

func NewGithubOAuth2Connector(config OAuth2ProviderConfig) GithubOAuth2Provider {
	return GithubOAuth2Provider{
		Config:   config,
		Endpoint: Github_EndpointConfig,
		LogTag:   "GithubOAuth2",
	}
}

func (h GithubOAuth2Provider) getGithubUser(authToken string) (string, error) {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("GET", Github_UserUrl, nil)
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

	var userInst GithubUser
	err = json.Unmarshal(bodyBytes, &userInst)
	if err != nil {
		return "", fmt.Errorf("%s: Error decoding userinfo. %s", h.LogTag, err.Error())
	}

	return userInst.Email, nil
}

func (h GithubOAuth2Provider) getGithubUser_Orgs(authToken string) ([]string, error) {
	var result = []string{}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("GET", Github_UserUrl, nil)
	if err != nil {
		return result, fmt.Errorf("%s: Error generating new request instance. %s", h.LogTag, err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+authToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return result, fmt.Errorf("%s: Error sending request. %s", h.LogTag, err.Error())
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("%s: Error reading response body. %s", h.LogTag, err.Error())
	}

	var userOrgs []GithubOrg
	err = json.Unmarshal(bodyBytes, &userOrgs)
	if err != nil {
		return result, fmt.Errorf("%s: Error decoding userinfo. %s", h.LogTag, err.Error())
	}

	for _, org := range userOrgs {
		result = append(result, org.OrgName)
	}

	return result, nil
}

func (h GithubOAuth2Provider) getGithubOauthConfig() *oauth2.Config {
	return &oauth2.Config{
		// RedirectURL:  h.Config.RedirectUrl,
		ClientID:     h.Config.ClientId,
		ClientSecret: h.Config.ClientSecret,
		Scopes:       Github_OAuth2Scopes,
		Endpoint:     h.Endpoint,
	}
}

func (h GithubOAuth2Provider) GetRedirectUrl() (string, string, string) {

	state := fdoshared.NewRandomString(16)
	nonce := fdoshared.NewRandomString(16)

	return h.getGithubOauthConfig().AuthCodeURL(state), state, nonce
}

func (h GithubOAuth2Provider) GetUserInfo(resultCode string) (string, bool, error) {
	oauth2Token, err := h.getGithubOauthConfig().Exchange(context.Background(), resultCode)
	if err != nil {
		return "", false, err
	}

	email, err := h.getGithubUser(oauth2Token.AccessToken)
	if err != nil {
		return "", false, err
	}

	orgs, err := h.getGithubUser_Orgs(oauth2Token.AccessToken)
	if err != nil {
		return email, false, err
	}

	return email, fdoshared.StringsContain(orgs, Github_FIDOAllianceID), nil
}
