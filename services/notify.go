package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	fdoshared "github.com/fido-alliance/fdo-fido-conformance-server/core/shared"
	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
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

func NewNotifyService(resultsHost string, resultsApiKey string, verifyDb *dbs.VerifyDB) NotifyService {
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

	return h.VerifyDB.SaveEntry(entry)
}

func (h *NotifyService) sendEmailNotification(requestPayload NotifyPayload) error {
	reqBytes, _ := json.Marshal(requestPayload)

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	req, err := http.NewRequest("POST", h.getResultsUrl(requestPayload.Type), bytes.NewBuffer(reqBytes))
	if err != nil {
		return fmt.Errorf("%s: Error generating new request instance. %s", h.LogTag, err.Error())
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.ResultsApiKey)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s: Error sending request. %s", h.LogTag, err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		log.Println(resp.Status)
	}
	return nil
}

// Send user email validation link
func (h *NotifyService) NotifyUserRegistration_EmailVerification(email string, submissionCountry string, ctx context.Context) error {
	entryId, err := h.createNotifyUserSession(email, dbs.VT_Email)
	if err != nil {
		log.Println("Error notifying user... " + err.Error())
		return nil
	}

	emailVerificationLink := fmt.Sprintf("%s/api/user/email/check/%s/%s", ctx.Value(fdoshared.CFG_ENV_FDO_SERVICE_URL).(string), string(entryId), email)

	return h.sendEmailNotification(NotifyPayload{
		VendorEmail: email,
		ApproveLink: emailVerificationLink,
		Type:        dbs.VT_Email,
	})
}

// Send FIDO email about new user
func (h *NotifyService) NotifyUserRegistration_AccountValidation(email string, userInfo NotifyPayload, submissionCountry string, ctx context.Context) error {
	entryId, err := h.createNotifyUserSession(email, dbs.VT_AccountValidation)
	if err != nil {
		return nil
	}

	userApprovalLink := fmt.Sprintf("%s/api/user/approve/%s/%s", ctx.Value(fdoshared.CFG_ENV_FDO_SERVICE_URL).(string), string(entryId), email)
	userRejectLink := fmt.Sprintf("%s/api/user/approve/%s/%s", ctx.Value(fdoshared.CFG_ENV_FDO_SERVICE_URL).(string), string(entryId), email)

	reqPayload := userInfo
	reqPayload.ApproveLink = userApprovalLink
	reqPayload.RejectLink = userRejectLink
	reqPayload.VendorEmail = email
	reqPayload.SubmissionCountry = submissionCountry
	reqPayload.Type = dbs.VT_AccountValidation

	return h.sendEmailNotification(reqPayload)
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
		return err
	}

	resetLink := fmt.Sprintf("%s/api/user/password/reset/%s/%s", ctx.Value(fdoshared.CFG_ENV_FDO_SERVICE_URL).(string), string(entryId), email)

	return h.sendEmailNotification(NotifyPayload{
		VendorEmail:       email,
		PasswordResetLink: resetLink,
		Type:              dbs.VT_PasswordReset,
	})
}
