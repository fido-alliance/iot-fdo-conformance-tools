package commonapi

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
