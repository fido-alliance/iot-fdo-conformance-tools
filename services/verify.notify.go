package services

import "github.com/WebauthnWorks/fdo-fido-conformance-server/dbs"

type NotifyService struct {
	ApiKey   string
	VerifyDB *dbs.VerifyDB
}

func (h *NotifyService) sendgridSend_VerificationEmail(email string, verifylink string) error {
	// TODO
	return nil
}

func (h *NotifyService) notifyUserRegistration(email string, verifyType dbs.VerifyType) error {
	var entry = dbs.VerifyEntry{
		Email: email,
		Type:  verifyType,
	}

	entryId, err := h.VerifyDB.SaveEntry(entry)
	if err != nil {
		return err
	}

	return h.sendgridSend_VerificationEmail(email, string(entryId))
}

// Send user email validation link
func (h *NotifyService) NotifyUserRegistration_EmailVerification(email string) error {
	return h.notifyUserRegistration(email, dbs.VT_Email)
}

// Send FIDO email about new user
func (h *NotifyService) NotifyUserRegistration_AccountValidation(email string) error {
	return h.notifyUserRegistration(email, dbs.VT_User)

}

func (h *NotifyService) NotifyFDOResults_Caspio() error {
	return nil
}

func (h *NotifyService) NotifyFDOResults_FIDO() error {
	return nil
}

func (h *NotifyService) NotifyFDOResults_User() error {
	return nil
}
