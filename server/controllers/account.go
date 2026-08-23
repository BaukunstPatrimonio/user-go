package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	passwordService "github.com/BaukunstPatrimonio/user-go/server/password"
	entModels "github.com/alvarotor/entitier-go/models"
	"gorm.io/gorm"
)

func (u *controllerUser) ChangePassword(ctx context.Context, request dto.UserChangePassword) (int, error) {
	user, err := u.authenticatedUser(ctx, request.Token, request.DeviceInfo)
	if err != nil {
		return http.StatusUnauthorized, err
	}
	if err := passwordService.ValidateResetPassword(request.NewPassword); err != nil {
		return http.StatusBadRequest, models.ErrInvalidPassword
	}
	credential, err := u.GetPasswordCredential(ctx, user.ID)
	if errors.Is(err, models.ErrCredentialNotFound) || errors.Is(err, entModels.ErrNotFound) || errors.Is(err, gorm.ErrRecordNotFound) || credential == nil {
		return http.StatusBadRequest, models.ErrCurrentPasswordInvalid
	}
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("look up authenticated password credential: %w", err)
	}
	valid, err := u.passwords.VerifyPassword(request.CurrentPassword, credential.PasswordHash)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("verify authenticated current password: %w", err)
	}
	if !valid {
		return http.StatusBadRequest, models.ErrCurrentPasswordInvalid
	}
	passwordHash, err := u.passwords.HashPassword(request.NewPassword)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("hash authenticated new password: %w", err)
	}
	storage, ok := u.IUserService.(accountStorage)
	if !ok {
		return http.StatusInternalServerError, errors.New("authenticated account storage is unavailable")
	}
	if err := storage.ChangePasswordAndRevokeSessions(ctx, user.ID, passwordHash); err != nil {
		return http.StatusInternalServerError, fmt.Errorf("change authenticated password: %w", err)
	}
	return http.StatusNoContent, nil
}

func (u *controllerUser) ChangeEmail(ctx context.Context, request dto.UserChangeEmail) (int, *models.EmailChange, error) {
	user, err := u.authenticatedUser(ctx, request.Token, request.DeviceInfo)
	if err != nil {
		return http.StatusUnauthorized, &models.EmailChange{}, err
	}
	email := strings.ToLower(strings.TrimSpace(request.Email))
	if email == user.Email {
		return http.StatusBadRequest, &models.EmailChange{}, models.ErrUserAlreadyExists
	}
	exists, err := u.PasswordRegistrationEmailExists(ctx, email)
	if err != nil {
		return http.StatusInternalServerError, &models.EmailChange{}, fmt.Errorf("check email change ownership: %w", err)
	}
	if exists {
		return http.StatusConflict, &models.EmailChange{}, models.ErrUserAlreadyExists
	}
	verificationCode, err := secureRandomString(u.conf.RandomStringValidation, u.conf.SizeRandomStringValidation)
	if err != nil {
		return http.StatusInternalServerError, &models.EmailChange{}, fmt.Errorf("generate email change verification code: %w", err)
	}
	expiresAt := time.Now().UTC().Add(passwordRegistrationCodeLifetime)
	storage, ok := u.IUserService.(accountStorage)
	if !ok {
		return http.StatusInternalServerError, &models.EmailChange{}, errors.New("authenticated account storage is unavailable")
	}
	if err := storage.ChangeEmailAndRequireValidation(ctx, user.ID, email, verificationCode, expiresAt); err != nil {
		if errors.Is(err, models.ErrUserAlreadyExists) {
			return http.StatusConflict, &models.EmailChange{}, models.ErrUserAlreadyExists
		}
		return http.StatusInternalServerError, &models.EmailChange{}, fmt.Errorf("change authenticated email: %w", err)
	}
	return http.StatusAccepted, &models.EmailChange{VerificationCode: verificationCode, CodeExpires: expiresAt}, nil
}

func (u *controllerUser) authenticatedUser(ctx context.Context, token string, device models.DeviceInfo) (*models.User, error) {
	return u.TokenToUser(ctx, token, device.Browser, device.BrowserVersion, device.OperatingSystem, device.OperatingSystemVersion, device.Cpu, device.Language, device.Timezone, device.CookiesEnabled)
}

type accountStorage interface {
	ChangePasswordAndRevokeSessions(context.Context, uint, string) error
	ChangeEmailAndRequireValidation(context.Context, uint, string, string, time.Time) error
}
