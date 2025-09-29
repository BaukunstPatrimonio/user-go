package dto

import (
	"github.com/baukunstpatrimonio/user-go/server/models"
	"github.com/golang-jwt/jwt/v5"
)

type ClaimsResponse struct {
	jwt.RegisteredClaims
	models.DeviceInfo
	Email      string `json:"email"`
	Admin      bool   `json:"admin"`
	SuperAdmin bool   `json:"superAdmin"`
}

type ClaimsRefreshResponse struct {
	jwt.RegisteredClaims
	models.DeviceInfo
	CodeRefresh string `json:"codeRefresh"`
}

type UserLogin struct {
	models.DeviceInfo
	Email string `json:"email" validate:"email,required"`
}

type UserUpdate struct {
	Name       string `validate:"required"`
	ProfilePic string
	Bucket     string
}
