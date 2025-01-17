package controllers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/alvarotor/user-go/server/dto"
	"github.com/alvarotor/user-go/server/models"
	"github.com/golang-jwt/jwt/v5"
)

func (u *controllerUser) Refresh(ctx context.Context, refreshToken string) (int, *models.Token, error) {
	claims := &dto.ClaimsRefreshResponse{}

	tkn, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (any, error) {
		return u.conf.JWTKey, nil
	})

	if err := u.validateToken(tkn, err); err != nil {
		return http.StatusBadRequest, &models.Token{}, err
	}

	user, err := u.GetByCodeRefresh(ctx, claims.CodeRefresh)
	if err != nil {
		return http.StatusNotFound, &models.Token{}, err
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
	err = u.UpdateField(ctx, user.ID, "code_refresh", user.CodeRefresh)
	if err != nil {
		u.log.Error(err.Error())
		return http.StatusInternalServerError, &models.Token{}, err
	}

	status, modelToken, err := u.Validate(ctx, user.Code)
	if err != nil {
		return http.StatusBadRequest, &models.Token{}, err
	}

	return status, &modelToken, nil
}
