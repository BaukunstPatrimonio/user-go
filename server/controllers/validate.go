package controllers

import (
	"context"
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
