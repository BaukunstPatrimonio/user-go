package controllers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"github.com/golang-jwt/jwt/v5"
)

func signRefreshToken(token *jwt.Token, key []byte) (string, error) {
	return token.SignedString(key)
}

func (u *controllerUser) Refresh(ctx context.Context, refreshToken string, req *pb.UserTokenRequest) (int, *models.Token, error) {
	return u.refresh(ctx, refreshToken, req, signRefreshToken)
}

func (u *controllerUser) refresh(ctx context.Context, refreshToken string, req *pb.UserTokenRequest, signToken func(*jwt.Token, []byte) (string, error)) (int, *models.Token, error) {
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

	if claims.CodeRefresh != user.CodeRefresh || u.conf.SizeRandomStringValidationRefresh != len(user.CodeRefresh) {
		errMsg := "code refresh is invalid"
		u.log.Error(errMsg)
		return http.StatusBadRequest, &models.Token{}, errors.New(errMsg)
	}

	storedDevice := createDeviceInfo(user)
	acceptedDevice := storedDevice
	var browserPresent, browserVersionPresent, operatingSystemPresent, operatingSystemVersionPresent bool
	var cpuPresent, languagePresent, timezonePresent bool
	acceptedDevice.Browser, browserPresent = u.acceptRefreshDeviceField("browser", req.GetBrowser(), storedDevice.Browser)
	acceptedDevice.BrowserVersion, browserVersionPresent = u.acceptRefreshDeviceField("browser_version", req.GetBrowserVersion(), storedDevice.BrowserVersion)
	acceptedDevice.OperatingSystem, operatingSystemPresent = u.acceptRefreshDeviceField("operating_system", req.GetOperatingSystem(), storedDevice.OperatingSystem)
	acceptedDevice.OperatingSystemVersion, operatingSystemVersionPresent = u.acceptRefreshDeviceField("operating_system_version", req.GetOperatingSystemVersion(), storedDevice.OperatingSystemVersion)
	acceptedDevice.Cpu, cpuPresent = u.acceptRefreshDeviceField("cpu", req.GetCpu(), storedDevice.Cpu)
	acceptedDevice.Language, languagePresent = u.acceptRefreshDeviceField("language", req.GetLanguage(), storedDevice.Language)
	acceptedDevice.Timezone, timezonePresent = u.acceptRefreshDeviceField("timezone", req.GetTimezone(), storedDevice.Timezone)

	browserBaselinePresent := strings.TrimSpace(storedDevice.Browser) != ""
	operatingSystemBaselinePresent := strings.TrimSpace(storedDevice.OperatingSystem) != ""
	browserMismatch := browserPresent && browserBaselinePresent && !deviceFamilyMatches(storedDevice.Browser, acceptedDevice.Browser)
	operatingSystemMismatch := operatingSystemPresent && operatingSystemBaselinePresent && !deviceFamilyMatches(storedDevice.OperatingSystem, acceptedDevice.OperatingSystem)

	if browserMismatch && operatingSystemMismatch {
		u.log.Warn("refresh device hard mismatch")
		if err := u.UpdateRefreshSession(ctx, user.ID, storedDevice, claims.CodeRefresh, ""); err != nil {
			u.log.Error(err.Error())
			if errors.Is(err, models.ErrInvalidCode) {
				return http.StatusBadRequest, &models.Token{}, models.ErrInvalidCode
			}
			return http.StatusInternalServerError, &models.Token{}, err
		}
		return http.StatusUnauthorized, &models.Token{}, models.ErrSessionDeviceMismatch
	}
	if browserMismatch || operatingSystemMismatch {
		u.log.Warn(
			"refresh device medium risk",
			"browser_family_mismatch", browserMismatch,
			"operating_system_family_mismatch", operatingSystemMismatch,
		)
	}

	persistedDevice := storedDevice
	if browserPresent && !browserBaselinePresent {
		persistedDevice.Browser = acceptedDevice.Browser
	}
	if operatingSystemPresent && !operatingSystemBaselinePresent {
		persistedDevice.OperatingSystem = acceptedDevice.OperatingSystem
	}
	if browserVersionPresent && !browserMismatch {
		persistedDevice.BrowserVersion = acceptedDevice.BrowserVersion
	}
	if operatingSystemVersionPresent && !operatingSystemMismatch {
		persistedDevice.OperatingSystemVersion = acceptedDevice.OperatingSystemVersion
	}
	if cpuPresent {
		persistedDevice.Cpu = acceptedDevice.Cpu
	}
	if languagePresent {
		persistedDevice.Language = acceptedDevice.Language
	}
	if timezonePresent {
		persistedDevice.Timezone = acceptedDevice.Timezone
	}

	newCodeRefresh := u.GenerateRandomString(u.conf.SizeRandomStringValidationRefresh)

	expirationTime := getExpirationTime(uint(u.conf.TokenExpirationTime))

	accessClaims := &dto.ClaimsResponse{
		Email:      user.Email,
		Admin:      user.Admin,
		SuperAdmin: user.SuperAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    u.conf.Issuer,
		},
		DeviceInfo: acceptedDevice,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	tokenString, err := signToken(token, u.conf.JWTKey)
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
		CodeRefresh: newCodeRefresh,
		DeviceInfo:  acceptedDevice,
	}
	tokenRefresh := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	tokenRefreshString, err := signToken(tokenRefresh, u.conf.JWTKey)
	if err != nil {
		u.log.Error(err.Error())
		return http.StatusInternalServerError, &models.Token{}, err
	}

	err = u.UpdateRefreshSession(ctx, user.ID, persistedDevice, claims.CodeRefresh, newCodeRefresh)
	if err != nil {
		u.log.Error(err.Error())
		if errors.Is(err, models.ErrInvalidCode) {
			return http.StatusBadRequest, &models.Token{}, models.ErrInvalidCode
		}
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

func deviceFamilyMatches(stored, incoming string) bool {
	return strings.EqualFold(strings.TrimSpace(stored), strings.TrimSpace(incoming))
}

func (u *controllerUser) acceptRefreshDeviceField(field, incoming, stored string) (string, bool) {
	trimmed := strings.TrimSpace(incoming)
	if trimmed == "" {
		u.log.Warn("refresh device field missing", "field", field)
		return stored, false
	}
	return trimmed, true
}
