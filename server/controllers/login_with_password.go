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
	"github.com/BaukunstPatrimonio/user-go/server/phone"
	entModels "github.com/alvarotor/entitier-go/models"
	"gorm.io/gorm"
)

func (u *controllerUser) LoginWithPassword(ctx context.Context, login dto.UserLoginWithPassword) (int, *models.Token, error) {
	emailPresent := strings.TrimSpace(login.Email) != ""
	phonePresent := strings.TrimSpace(login.PhoneE164) != ""
	if emailPresent == phonePresent {
		return http.StatusBadRequest, &models.Token{}, models.ErrInvalidLoginIdentity
	}

	var user *models.User
	var err error
	if emailPresent {
		user, err = u.GetByEmail(ctx, login.Email)
	} else {
		login.PhoneE164, err = phone.NormalizeE164(login.PhoneE164)
		if err != nil {
			return http.StatusBadRequest, &models.Token{}, models.ErrInvalidPhone
		}
		user, err = u.GetByPhone(ctx, login.PhoneE164)
	}
	if errors.Is(err, entModels.ErrNotFound) || errors.Is(err, gorm.ErrRecordNotFound) || errors.Is(err, models.ErrUserNotFound) {
		return http.StatusUnauthorized, &models.Token{}, models.ErrInvalidCredentials
	}
	if err != nil {
		return http.StatusInternalServerError, &models.Token{}, fmt.Errorf("look up password user: %w", err)
	}
	if user == nil {
		return http.StatusUnauthorized, &models.Token{}, models.ErrInvalidCredentials
	}

	credential, err := u.GetPasswordCredential(ctx, user.ID)
	if errors.Is(err, models.ErrCredentialNotFound) || errors.Is(err, entModels.ErrNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
		return http.StatusUnauthorized, &models.Token{}, models.ErrInvalidCredentials
	}
	if err != nil {
		return http.StatusInternalServerError, &models.Token{}, fmt.Errorf("look up password credential: %w", err)
	}
	if credential == nil {
		return http.StatusUnauthorized, &models.Token{}, models.ErrInvalidCredentials
	}

	valid, err := u.passwords.VerifyPassword(login.Password, credential.PasswordHash)
	if err != nil {
		return http.StatusInternalServerError, &models.Token{}, fmt.Errorf("verify password credential: %w", err)
	}
	if !valid {
		return http.StatusUnauthorized, &models.Token{}, models.ErrInvalidCredentials
	}
	if !user.Validated {
		return http.StatusPreconditionFailed, &models.Token{}, models.ErrAccountNotValidated
	}

	if u.passwords.IsBcryptHash(credential.PasswordHash) {
		upgradedHash, err := u.passwords.HashPassword(login.Password)
		if err != nil {
			return http.StatusInternalServerError, &models.Token{}, fmt.Errorf("upgrade password credential: %w", err)
		}
		if err := u.UpdatePasswordCredentialHash(ctx, user.ID, upgradedHash); err != nil {
			return http.StatusInternalServerError, &models.Token{}, fmt.Errorf("persist upgraded password credential: %w", err)
		}
		credential.PasswordHash = upgradedHash
	}

	code := user.Code
	codeExpire := user.CodeExpire
	if code == "OUT" || len(code) != u.conf.SizeRandomStringValidation {
		code = u.GenerateRandomString(u.conf.SizeRandomStringValidation)
		codeExpire = time.Now().UTC()
	}
	codeRefresh := u.GenerateRandomString(u.conf.SizeRandomStringValidationRefresh)
	tokens, err := u.issueTokenPair(user, login.DeviceInfo, codeRefresh)
	if err != nil {
		return http.StatusInternalServerError, &models.Token{}, fmt.Errorf("issue password session tokens: %w", err)
	}
	if err := u.StartPasswordSession(ctx, user.ID, login.DeviceInfo, code, codeExpire, codeRefresh); err != nil {
		return http.StatusInternalServerError, &models.Token{}, fmt.Errorf("persist password session: %w", err)
	}

	user.DeviceInfo = login.DeviceInfo
	user.Code = code
	user.CodeExpire = codeExpire
	user.CodeRefresh = codeRefresh
	return http.StatusOK, &tokens, nil
}
