package externalapi

type User_UserReq struct {
	Name     string `json:"name"`
	Phone    string `json:"phone"`
	Company  string `json:"company"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
