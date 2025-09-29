package controllers

import (
	"context"
	"errors"

	"github.com/baukunstpatrimonio/user-go/server/dto"
	"github.com/baukunstpatrimonio/user-go/server/models"
	"github.com/golang-jwt/jwt/v5"
)

func (u *controllerUser) TokenToUser(
	c context.Context,
	token string,
	browser string,
	browserVersion string,
	operatingSystem string,
	operatingSystemVersion string,
	cpu string,
	language string,
	timezone string,
	cookiesEnabled bool,
) (*models.User, error) {
	claims := &dto.ClaimsResponse{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		return u.conf.JWTKey, nil
	})

	if err := u.validateToken(tkn, err); err != nil {
		return &models.User{}, err
	}

	user, err := u.GetByEmail(c, claims.Email)
	if err != nil {
		return &models.User{}, err
	}
	if user.Code == "OUT" {
		u.log.Error(models.ErrUserNotLogged.Error())
		return &models.User{}, models.ErrUserNotLogged
	}
	if len(user.Code) != u.conf.SizeRandomStringValidation {
		u.log.Error(models.ErrInvalidUser.Error())
		return &models.User{}, models.ErrInvalidUser
	}

	secs := models.DeviceInfo{
		Browser:                browser,
		BrowserVersion:         browserVersion,
		OperatingSystem:        operatingSystem,
		OperatingSystemVersion: operatingSystemVersion,
		Cpu:                    cpu,
		Language:               language,
		Timezone:               timezone,
		CookiesEnabled:         cookiesEnabled,
	}

	if claims.DeviceInfo != secs {
		u.log.Error(models.ErrSecurityMismatch.Error())
		return &models.User{}, models.ErrSecurityMismatch
	}

	return user, nil
}

func (u *controllerUser) validateToken(tkn *jwt.Token, err error) error {
	if errors.Is(err, jwt.ErrSignatureInvalid) {
		return u.logAndReturnError(models.ErrInvalidSignature.Error())
	}
	if errors.Is(err, jwt.ErrTokenExpired) {
		return u.logAndReturnError(models.ErrTokenExpired.Error())
	}
	if err != nil {
		return u.logAndReturnError(models.ErrParsingToken.Error())
	}
	if !tkn.Valid {
		return u.logAndReturnError(models.ErrInvalidToken.Error())
	}
	return nil
}

func (u *controllerUser) logAndReturnError(errMsg string) error {
	u.log.Error(errMsg)
	return errors.New(errMsg)
}
