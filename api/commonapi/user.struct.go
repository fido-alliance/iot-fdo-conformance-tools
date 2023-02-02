package commonapi

import fdoshared "github.com/WebauthnWorks/fdo-shared"

type User_UserReq struct {
	Name     string `json:"name"`
	Phone    string `json:"phone"`
	Company  string `json:"company"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type User_ResetPassword struct {
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

type User_ResetPasswordReq struct {
	Email string `json:"email"`
}

type User_Config struct {
	Mode fdoshared.CONFIG_MODE_TYPE `json:"mode"`
}
