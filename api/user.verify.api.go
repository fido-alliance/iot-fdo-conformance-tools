package api

import (
	"net/http"
	"time"

	"github.com/fido-alliance/fdo-fido-conformance-server/dbs"
)

const MAX_PASSWORD_RESET time.Duration = time.Hour

type UserVerify struct {
	UserDB    *dbs.UserTestDB
	VerifyDB  *dbs.VerifyDB
	SessionDB *dbs.SessionDB
}

func (h *UserVerify) getSession(r *http.Request) (*dbs.SessionEntry, error) {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return nil, err
	}

	if sessionCookie == nil {
		return nil, err
	}

	sessionInst, err := h.SessionDB.GetSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		return nil, err
	}

	return sessionInst, nil
}

func (h *UserVerify) deleteSession(r *http.Request) error {
	sessionCookie, err := r.Cookie("session")
	if err != nil {
		return err
	}

	if sessionCookie == nil {
		return err
	}

	err = h.SessionDB.DeleteSessionEntry([]byte(sessionCookie.Value))
	if err != nil {
		return err
	}

	return nil
}
