package api

import (
	"bytes"
	"errors"
	"net/http"
	"regexp"

	"github.com/fido-alliance/iot-fdo-conformance-tools/api/commonapi"
	fdoshared "github.com/fido-alliance/iot-fdo-conformance-tools/core/shared"
	"github.com/fido-alliance/iot-fdo-conformance-tools/dbs"
	"golang.org/x/crypto/scrypt"
)

const ONPREM_CONFIG string = "tester@fido.local"

type UserAPI struct {
	UserDB    *dbs.UserTestDB
	SessionDB *dbs.SessionDB
}

func isEmailValid(e string) bool {
	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(e)
}

func (h *UserAPI) generatePasswordHash(password string) ([]byte, error) {
	salt := fdoshared.NewRandomBuffer(8)

	dk, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return []byte{}, errors.New("Error hashing password")
	}

	return append(salt, dk...), nil
}

func (h *UserAPI) verifyPasswordHash(password string, passwordHash []byte) (bool, error) {
	salt := passwordHash[0:8]

	dk, err := scrypt.Key([]byte(password), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return false, errors.New("Error hashing password")
	}

	return bytes.Equal(append(salt, dk...), passwordHash), nil
}

func (h *UserAPI) setUserSession(w http.ResponseWriter, sessionInst dbs.SessionEntry) error {
	sessionDbId, err := h.SessionDB.NewSessionEntry(sessionInst)
	if err != nil {
		return errors.New("Error creating session. " + err.Error())
	}

	http.SetCookie(w, commonapi.GenerateCookie(sessionDbId))
	return nil
}
