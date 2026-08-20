package dto

import (
	"github.com/BaukunstPatrimonio/user-go/server/models"
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

type UserLoginWithPassword struct {
	models.DeviceInfo
	Email     string `json:"email" validate:"omitempty,email"`
	PhoneE164 string `json:"phone_e164,omitempty"`
	Password  string `json:"-" validate:"required"`
}

type UserRegisterWithPassword struct {
	models.DeviceInfo
	Email     string `json:"email" validate:"email,required"`
	Name      string `json:"name" validate:"required"`
	Password  string `json:"-" validate:"required,min=8,max=128"`
	PhoneE164 string `json:"phone_e164,omitempty"`
}

type UserSetPhone struct {
	models.DeviceInfo
	Token     string `json:"-" validate:"required"`
	PhoneE164 string `json:"phone_e164" validate:"required"`
}

type UserRequestPasswordReset struct {
	Email string `json:"email" validate:"email,required"`
}

type UserResetPassword struct {
	ResetToken  string `json:"-" validate:"required"`
	NewPassword string `json:"-" validate:"required,min=8,max=128"`
}

type UserUpdate struct {
	Name       string `validate:"required"`
	ProfilePic string
	Bucket     string
}
