package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
)

const FIDO_NOTIFY_EMAIL = "certification@fidoalliance.org"

type NotifyPayload struct {
	VendorEmail   string `json:"vendor_email"`
	VendorName    string `json:"vendor_name"`
	VendorPhone   string `json:"vendor_phone"`
	VendorCompany string `json:"vendor_company"`

	ApproveLink       string `json:"approve_link,omitempty"`
	RejectLink        string `json:"reject_link,omitempty"`
	PasswordResetLink string `json:"reset_link,omitempty"`
	EmailVerifyLink   string `json:"verify_link,omitempty"`

	Type              dbs.VerifyType `json:"type"`
	SubmissionCountry string         `json:"submission_country"`
	RandomKss         string         `json:"randomkss,omitempty"`
}


type NotifyService struct {
	ResultsApiKey string
	ResultsHost   string
	VerifyDB      *dbs.VerifyDB
	LogTag        string
}

func NewNotifyService(resultsApiKey string, resultsHost string, verifyDb *dbs.VerifyDB) NotifyService {
	return NotifyService{
		ResultsApiKey: resultsApiKey,
		ResultsHost:   resultsHost,
		VerifyDB:      verifyDb,
		LogTag:        "NotifyService",
	}
}

func (h *NotifyService) getResultsUrl(vttype dbs.VerifyType) string {
	return fmt.Sprintf("%s/api/fdotools/notify/%s", h.ResultsHost, vttype)
}

func (h *NotifyService) createNotifyUserSession(email string, vttype dbs.VerifyType) ([]byte, error) {
	var entry = dbs.VerifyEntry{
		Email: email,
		Type:  vttype,
	}

	entryId, err := h.VerifyDB.SaveEntry(entry)
	if err != nil {
		return nil, err
	}

	return entryId, nil
}

func (h *NotifyService) sendEmailNotification(requestPayload NotifyPayload) error {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("POST", h.getResultsUrl(requestPayload.Type), nil)
	if err != nil {
		return fmt.Errorf("%s: Error generating new request instance. %s", h.LogTag, err.Error())
	}

	req.Header.Set("Authorization", "Bearer "+h.ResultsApiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: Error sending request. %s", h.LogTag, err.Error())
	}

	defer resp.Body.Close()
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s: Error reading response body. %s", h.LogTag, err.Error())
	}

	var userInst GithubUser
	err = json.Unmarshal(bodyBytes, &userInst)
	if err != nil {
		return fmt.Errorf("%s: Error decoding userinfo. %s", h.LogTag, err.Error())
	}

	return nil
}

// Send user email validation link
func (h *NotifyService) NotifyUserRegistration_EmailVerification(email string, submissionCountry string, ctx context.Context) error {
	entryId, err := h.createNotifyUserSession(email, dbs.VT_Email)
	if err != nil {
		return nil
	}

	emailVerificationLink := fmt.Sprintf("%s/api/user/email/check/%s/%s", ctx.Value(fdoshared.CFG_FDO_SERVICE_URL).(string), email, string(entryId))

	return h.sendEmailNotification(NotifyPayload{
		VendorEmail: email,
		ApproveLink: emailVerificationLink,
		Type:        dbs.VT_Email,
	})
}

// Send FIDO email about new user
func (h *NotifyService) NotifyUserRegistration_AccountValidation(email string, userInfo NotifyPayload, submissionCountry string, ctx context.Context) error {
	entryId, err := h.createNotifyUserSession(email, dbs.VT_User)
	if err != nil {
		return nil
	}

	userApprovalLink := fmt.Sprintf("%s/api/user/approve/%s/%s", ctx.Value(fdoshared.CFG_FDO_SERVICE_URL).(string), email, string(entryId))
	userRejectLink := fmt.Sprintf("%s/api/user/approve/%s/%s", ctx.Value(fdoshared.CFG_FDO_SERVICE_URL).(string), email, string(entryId))

	reqPayload := userInfo
	reqPayload.ApproveLink = userApprovalLink
	reqPayload.RejectLink = userRejectLink
	reqPayload.VendorEmail = email
	reqPayload.SubmissionCountry = submissionCountry
	reqPayload.Type = dbs.VT_User

	return h.sendEmailNotification(NotifyPayload{
		VendorEmail:       email,
		ApproveLink:       userApprovalLink,
		RejectLink:        userRejectLink,
		SubmissionCountry: submissionCountry,
		Type:              dbs.VT_Email,
	})
}

// Send FIDO email about new user
func (h *NotifyService) NotifyUserRegistration_Approved(email string, ctx context.Context) error {
	return h.sendEmailNotification(NotifyPayload{
		VendorEmail: email,
		Type:        dbs.VT_RegistrationApproved,
	})
}

// Send FIDO email about new user
func (h *NotifyService) NotifyUserRegistration_Rejected(email string, ctx context.Context) error {
	return h.sendEmailNotification(NotifyPayload{
		VendorEmail: email,
		Type:        dbs.VT_RegistrationRejected,
	})
}

func (h *NotifyService) NotifyUserRegistration_PasswordReset(email string, ctx context.Context) error {
	entryId, err := h.createNotifyUserSession(email, dbs.VT_PasswordReset)
	if err != nil {
		return nil
	}

	resetLink := fmt.Sprintf("%s/api/user/password/reset/%s/%s", ctx.Value(fdoshared.CFG_FDO_SERVICE_URL).(string), email, string(entryId))

	return h.sendEmailNotification(NotifyPayload{
		VendorEmail:       email,
		PasswordResetLink: resetLink,
		Type:              dbs.VT_PasswordReset,
	})
}
