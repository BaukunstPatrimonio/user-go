package controllers

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	passwordService "github.com/BaukunstPatrimonio/user-go/server/password"
	"github.com/BaukunstPatrimonio/user-go/server/phone"
	entModels "github.com/alvarotor/entitier-go/models"
	"gorm.io/gorm"
)

const passwordRegistrationCodeLifetime = 10 * time.Minute

func (u *controllerUser) RegisterWithPassword(ctx context.Context, registration dto.UserRegisterWithPassword) (int, *models.PasswordRegistration, error) {
	if err := passwordService.ValidateRegistrationPassword(registration.Password); err != nil {
		return http.StatusBadRequest, &models.PasswordRegistration{}, models.ErrInvalidPassword
	}

	registration.Email = strings.ToLower(strings.TrimSpace(registration.Email))
	exists, err := u.PasswordRegistrationEmailExists(ctx, registration.Email)
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordRegistration{}, fmt.Errorf("check password registration email: %w", err)
	}
	if exists {
		return http.StatusConflict, &models.PasswordRegistration{}, models.ErrUserAlreadyExists
	}

	var phoneE164 *string
	if strings.TrimSpace(registration.PhoneE164) != "" {
		canonicalPhone, err := phone.NormalizeE164(registration.PhoneE164)
		if err != nil {
			return http.StatusBadRequest, &models.PasswordRegistration{}, models.ErrInvalidPhone
		}
		phoneUser, err := u.GetByPhone(ctx, canonicalPhone)
		if err == nil && phoneUser != nil {
			return http.StatusConflict, &models.PasswordRegistration{}, models.ErrPhoneAlreadyExists
		}
		if err != nil && !errors.Is(err, models.ErrUserNotFound) && !errors.Is(err, entModels.ErrNotFound) && !errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusInternalServerError, &models.PasswordRegistration{}, fmt.Errorf("check password registration phone: %w", err)
		}
		phoneE164 = &canonicalPhone
	}

	passwordHash, err := u.passwords.HashPassword(registration.Password)
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordRegistration{}, fmt.Errorf("hash registration password: %w", err)
	}
	verificationCode, err := secureRandomString(u.conf.RandomStringValidation, u.conf.SizeRandomStringValidation)
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordRegistration{}, fmt.Errorf("generate registration verification code: %w", err)
	}
	codeRefresh, err := secureRandomString(u.conf.RandomStringValidationRefresh, u.conf.SizeRandomStringValidationRefresh)
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordRegistration{}, fmt.Errorf("generate registration refresh code: %w", err)
	}

	codeExpires := time.Now().UTC().Add(passwordRegistrationCodeLifetime)
	user := models.User{
		Email:       registration.Email,
		PhoneE164:   phoneE164,
		Name:        strings.TrimSpace(registration.Name),
		Validated:   false,
		Admin:       false,
		SuperAdmin:  false,
		Code:        verificationCode,
		CodeExpire:  codeExpires,
		CodeRefresh: codeRefresh,
		DeviceInfo:  registration.DeviceInfo,
	}
	created, err := u.CreatePasswordUser(ctx, user, passwordHash)
	if errors.Is(err, models.ErrUserAlreadyExists) {
		return http.StatusConflict, &models.PasswordRegistration{}, models.ErrUserAlreadyExists
	}
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordRegistration{}, fmt.Errorf("create password registration: %w", err)
	}
	if created == nil || created.ID == 0 {
		return http.StatusInternalServerError, &models.PasswordRegistration{}, errors.New("password registration did not create a user")
	}

	return http.StatusCreated, &models.PasswordRegistration{
		UserID:           created.ID,
		VerificationCode: created.Code,
		CodeExpires:      created.CodeExpire,
	}, nil
}

func secureRandomString(alphabet string, length int) (string, error) {
	letters := []rune(alphabet)
	if len(letters) == 0 || length <= 0 {
		return "", errors.New("random string configuration is invalid")
	}

	result := make([]rune, length)
	maximum := big.NewInt(int64(len(letters)))
	for index := range result {
		position, err := cryptorand.Int(cryptorand.Reader, maximum)
		if err != nil {
			return "", err
		}
		result[index] = letters[position.Int64()]
	}
	return string(result), nil
}
