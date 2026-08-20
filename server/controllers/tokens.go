package controllers

import (
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/golang-jwt/jwt/v5"
)

func (u *controllerUser) issueTokenPair(user *models.User, device models.DeviceInfo, codeRefresh string) (models.Token, error) {
	expirationTime := getExpirationTime(uint(u.conf.TokenExpirationTime))
	claims := &dto.ClaimsResponse{
		Email:      user.Email,
		Admin:      user.Admin,
		SuperAdmin: user.SuperAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    u.conf.Issuer,
		},
		DeviceInfo: device,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(u.conf.JWTKey)
	if err != nil {
		return models.Token{}, err
	}

	expirationTimeRefresh := getExpirationTime(uint(u.conf.TokenExpirationTimeRefresh))
	claimsRefresh := &dto.ClaimsRefreshResponse{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTimeRefresh),
			Issuer:    u.conf.Issuer,
		},
		CodeRefresh: codeRefresh,
		DeviceInfo:  device,
	}
	tokenRefresh := jwt.NewWithClaims(jwt.SigningMethodHS256, claimsRefresh)
	tokenRefreshString, err := tokenRefresh.SignedString(u.conf.JWTKey)
	if err != nil {
		return models.Token{}, err
	}

	return models.Token{
		Email:               user.Email,
		Token:               tokenString,
		TokenExpires:        expirationTime,
		TokenRefresh:        tokenRefreshString,
		TokenRefreshExpires: expirationTimeRefresh,
	}, nil
}

func getExpirationTime(seconds uint) time.Time {
	var expirationTime time.Time
	now := time.Now().UTC()
	expirationTime = now.Add(time.Duration(seconds) * time.Second)
	return expirationTime
}

func createDeviceInfo(user *models.User) models.DeviceInfo {
	return models.DeviceInfo{
		Browser:                user.Browser,
		BrowserVersion:         user.BrowserVersion,
		OperatingSystem:        user.OperatingSystem,
		OperatingSystemVersion: user.OperatingSystemVersion,
		Cpu:                    user.Cpu,
		Language:               user.Language,
		Timezone:               user.Timezone,
		CookiesEnabled:         user.CookiesEnabled,
	}
}
