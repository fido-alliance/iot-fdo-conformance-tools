package dbs

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"time"

	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/dgraph-io/badger/v3"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/uuid"
)

type VoucherDB struct {
	db *badger.DB
}

func NewVoucherDB(db *badger.DB) VoucherDB {
	return VoucherDB{
		db: db,
	}
}

type VoucherDBEntry struct {
	_              struct{} `cbor:",toarray"`
	Voucher        fdoshared.OwnershipVoucher
	PrivateKeyX509 []byte
}

type UserInfo struct {
	Counter  int
	UUID     string
	GuidList []GuidToFileName
}

type GuidToFileName struct {
	Guid     []byte
	FileName string
}

func (h *SessionDB) RegisterAuthToken() (string, error) {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	newUuid, _ := uuid.NewRandom()
	uuidBytes, _ := newUuid.MarshalBinary()
	var userApiToken [16]byte
	copy(userApiToken[:], uuidBytes)
	userTokenBaseEncoded := base64.StdEncoding.EncodeToString(userApiToken[:])

	// counter = 0. Generate UUID
	userUUIDRandom, _ := uuid.NewRandom()
	userUUIDBytes, _ := userUUIDRandom.MarshalBinary()
	var userUUID [16]byte
	copy(userUUID[:], userUUIDBytes)
	UserInfo := UserInfo{
		Counter:  0,
		UUID:     hex.EncodeToString(userUUID[:]),
		GuidList: nil,
	}
	UserInfoBytes, err := cbor.Marshal(UserInfo)
	if err != nil {
		return "", errors.New("Internal Server Error creating user profile " + err.Error())
	}

	entry := badger.NewEntry([]byte(userTokenBaseEncoded), UserInfoBytes).WithTTL(time.Minute * 10) // Session entry will only exist for 10 minutes
	err = dbtxn.SetEntry(entry)
	if err != nil {
		return "", errors.New("Failed creating session db entry instance. The error is: " + err.Error())
	}

	dbtxn.Commit()
	if err != nil {
		return "", errors.New("Failed saving session entry. The error is: " + err.Error())
	}

	authToken := "Bearer " + userTokenBaseEncoded
	return authToken, nil
}

func (h *SessionDB) GetAuthTokenInfo(authToken []byte) (*UserInfo, error) {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	item, err := dbtxn.Get(authToken)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return nil, errors.New("Authorisation Token was not found. Check it is valid or create new one: " + err.Error())
	} else if err != nil {
		return nil, errors.New("Failed locating entry. The error is: " + err.Error())
	}

	itemBytes, err := item.ValueCopy(nil)
	if err != nil {
		return nil, errors.New("Failed reading entry value. The error is: " + err.Error())
	}

	var userInfoInst UserInfo
	err = cbor.Unmarshal(itemBytes, &userInfoInst)
	if err != nil {
		log.Println(err)
		return nil, errors.New("Failed cbor decoding entry value. The error is: " + err.Error())
	}

	return &userInfoInst, nil

}

func (h *SessionDB) AuthTokenExists(authToken []byte) (bool, error) {
	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()
	_, err := dbtxn.Get(authToken)
	if err != nil && errors.Is(err, badger.ErrKeyNotFound) {
		return false, errors.New("Authorisation Token was not found. Check it is valid or create new one: " + err.Error())
	} else if err != nil {
		return false, errors.New("Failed locating entry. The error is: " + err.Error())
	}
	return true, nil
}

func (h *SessionDB) UpdateTokenEntry(entryId []byte, userInst UserInfo) error {

	dbtxn := h.db.NewTransaction(true)
	defer dbtxn.Discard()

	sessionInstBytes, err := cbor.Marshal(userInst)
	if err != nil {
		return errors.New("Failed to marshal session. The error is: " + err.Error())
	}

	err = dbtxn.Set(entryId, sessionInstBytes)
	if err != nil {
		return errors.New("Failed to create saving inst. The error is: " + err.Error())
	}

	err = dbtxn.Commit()
	if err != nil {
		return errors.New("Failed to save session. The error is: " + err.Error())
	}

	return nil
}
