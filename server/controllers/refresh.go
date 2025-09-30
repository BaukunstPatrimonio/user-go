package controllers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/baukunstpatrimonio/user-go/server/dto"
	"github.com/baukunstpatrimonio/user-go/server/models"
	pb "github.com/baukunstpatrimonio/user-go/server/user-pb"
	"github.com/golang-jwt/jwt/v5"
)

func (u *controllerUser) Refresh(ctx context.Context, refreshToken string, req *pb.UserTokenRequest) (int, *models.Token, error) {
	claims := &dto.ClaimsRefreshResponse{}

	tkn, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (any, error) {
		return u.conf.JWTKey, nil
	})

	if err := u.validateToken(tkn, err); err != nil {
		return http.StatusBadRequest, &models.Token{}, err
	}

	user, err := u.GetByCodeRefresh(ctx, claims.CodeRefresh)
	if errors.Is(err, models.ErrUserNotFound) {
		return http.StatusNotFound, &models.Token{}, models.ErrInvalidCode
	}
	if err != nil {
		return http.StatusInternalServerError, &models.Token{}, err
	}

	if user == nil {
		errMsg := "code refresh is invalid"
		u.log.Error(errMsg)
		return http.StatusBadRequest, &models.Token{}, errors.New(errMsg)
	}

	if user.Code == "OUT" || strings.TrimSpace(user.Code) == "" {
		errMsg := "code refresh is invalid"
		u.log.Error(errMsg)
		return http.StatusBadRequest, &models.Token{}, errors.New(errMsg)
	}

	if u.conf.SizeRandomStringValidationRefresh != len(user.CodeRefresh) {
		errMsg := "code refresh is invalid"
		u.log.Error(errMsg)
		return http.StatusBadRequest, &models.Token{}, errors.New(errMsg)
	}

	user.CodeRefresh = u.GenerateRandomString(u.conf.SizeRandomStringValidationRefresh)
	
	// Update device info if provided
	if req != nil {
		user.Browser = req.GetBrowser()
		user.BrowserVersion = req.GetBrowserVersion()
		user.OperatingSystem = req.GetOperatingSystem()
		user.OperatingSystemVersion = req.GetOperatingSystemVersion()
		user.Cpu = req.GetCpu()
		user.Language = req.GetLanguage()
		user.Timezone = req.GetTimezone()
		user.CookiesEnabled = req.GetCookiesEnabled()
		
		// Update the user with new device info and refresh code
		err = u.Update(ctx, user.ID, *user)
		if err != nil {
			u.log.Error(err.Error())
			return http.StatusInternalServerError, &models.Token{}, err
		}
	} else {
		// Only update the refresh code if no device info provided
		err = u.UpdateField(ctx, user.ID, "code_refresh", user.CodeRefresh)
		if err != nil {
			u.log.Error(err.Error())
			return http.StatusInternalServerError, &models.Token{}, err
		}
	}

	// Generate new access token and refresh token directly
	expirationTime := getExpirationTime(uint(u.conf.TokenExpirationTime))

	claims := &dto.ClaimsResponse{
		Email:      user.Email,
		Admin:      user.Admin,
		SuperAdmin: user.SuperAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    u.conf.Issuer,
		},
		DeviceInfo: createDeviceInfo(user),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(u.conf.JWTKey)
	if err != nil {
		u.log.Error(err.Error())
		return http.StatusInternalServerError, &models.Token{}, err
	}

	expirationTimeRefresh := getExpirationTime(uint(u.conf.TokenExpirationTimeRefresh))

	refreshClaims := &dto.ClaimsRefreshResponse{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTimeRefresh),
			Issuer:    u.conf.Issuer,
		},
		CodeRefresh: user.CodeRefresh,
		DeviceInfo: createDeviceInfo(user),
	}
	tokenRefresh := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	tokenRefreshString, err := tokenRefresh.SignedString(u.conf.JWTKey)
	if err != nil {
		u.log.Error(err.Error())
		return http.StatusInternalServerError, &models.Token{}, err
	}

	modelToken := &models.Token{
		Email:               user.Email,
		Token:               tokenString,
		TokenExpires:        expirationTime,
		TokenRefresh:        tokenRefreshString,
		TokenRefreshExpires: expirationTimeRefresh,
	}

	return http.StatusOK, modelToken, nil
}
