package controllers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
)

func (u *controllerUser) Validate(c context.Context, code string) (int, models.Token, error) {
	user, err := u.GetByCode(c, code)
	if err != nil {
		u.log.Error(err.Error())
		return http.StatusNotFound, models.Token{}, err
	}

	if user == nil {
		u.log.Error(models.ErrInvalidCode.Error())
		return http.StatusBadRequest, models.Token{}, models.ErrInvalidCode
	}

	if user.Code == "OUT" || strings.TrimSpace(user.Code) == "" {
		u.log.Error(models.ErrInvalidCode.Error())
		return http.StatusBadRequest, models.Token{}, models.ErrInvalidCode
	}

	if user.CodeExpire.Before(time.Now().UTC()) {
		u.log.Error(models.ErrExpiredCode.Error())
		return http.StatusBadRequest, models.Token{}, models.ErrExpiredCode
	}

	if user.PendingEmail != "" {
		sessionCode, err := secureRandomString(u.conf.RandomStringValidation, u.conf.SizeRandomStringValidation)
		if err != nil {
			return http.StatusInternalServerError, models.Token{}, err
		}
		sessionRefresh, err := secureRandomString(u.conf.RandomStringValidationRefresh, u.conf.SizeRandomStringValidationRefresh)
		if err != nil {
			return http.StatusInternalServerError, models.Token{}, err
		}
		device := createDeviceInfo(user)
		updatedUser := *user
		updatedUser.Email = user.PendingEmail
		updatedUser.PendingEmail = ""
		updatedUser.Validated = true
		storage, ok := u.IUserService.(emailChangeValidationStorage)
		if !ok {
			return http.StatusInternalServerError, models.Token{}, errors.New("email change validation storage is unavailable")
		}
		if err := storage.CompletePendingEmailChange(c, user.ID, code, device, sessionCode, time.Now().UTC(), sessionRefresh); err != nil {
			if errors.Is(err, models.ErrUserAlreadyExists) {
				return http.StatusConflict, models.Token{}, err
			}
			if errors.Is(err, models.ErrInvalidCode) {
				return http.StatusBadRequest, models.Token{}, err
			}
			return http.StatusInternalServerError, models.Token{}, err
		}
		model, err := u.issueTokenPair(&updatedUser, device, sessionRefresh)
		if err != nil {
			return http.StatusInternalServerError, models.Token{}, err
		}
		return http.StatusOK, model, nil
	}

	if !user.Validated {
		err = u.ValidateSvc(c, user.Email)
		if err != nil {
			u.log.Error(err.Error())
			return http.StatusInternalServerError, models.Token{}, err
		}
	}

	model, err := u.issueTokenPair(user, createDeviceInfo(user), user.CodeRefresh)
	if err != nil {
		u.log.Error(err.Error())
		return http.StatusInternalServerError, models.Token{}, err
	}

	return http.StatusOK, model, nil
}

type emailChangeValidationStorage interface {
	CompletePendingEmailChange(context.Context, uint, string, models.DeviceInfo, string, time.Time, string) error
}
