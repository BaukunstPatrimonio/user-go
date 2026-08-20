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
	"github.com/BaukunstPatrimonio/user-go/server/passwordreset"
)

const passwordResetLifetime = 30 * time.Minute

func (u *controllerUser) RequestPasswordReset(ctx context.Context, request dto.UserRequestPasswordReset) (int, *models.PasswordResetRequest, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(request.Email))
	user, err := u.FindPasswordResetUser(ctx, normalizedEmail)
	if errors.Is(err, models.ErrPasswordResetUnavailable) || (err == nil && user == nil) {
		return http.StatusAccepted, &models.PasswordResetRequest{}, nil
	}
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordResetRequest{}, fmt.Errorf("find password reset account: %w", err)
	}

	rawToken, tokenDigest, err := passwordreset.GenerateToken()
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordResetRequest{}, fmt.Errorf("generate password reset token: %w", err)
	}
	expiresAt := time.Now().UTC().Add(passwordResetLifetime)
	err = u.StorePasswordResetToken(ctx, models.PasswordResetToken{
		UserID:      user.ID,
		TokenDigest: tokenDigest,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordResetRequest{}, fmt.Errorf("store password reset token: %w", err)
	}

	return http.StatusAccepted, &models.PasswordResetRequest{ResetToken: rawToken, ExpiresAt: expiresAt}, nil
}

func (u *controllerUser) ResetPassword(ctx context.Context, reset dto.UserResetPassword) (int, error) {
	if err := passwordService.ValidateRegistrationPassword(reset.NewPassword); err != nil {
		return http.StatusBadRequest, models.ErrInvalidPassword
	}
	tokenDigest, err := passwordreset.DigestToken(reset.ResetToken)
	if err != nil {
		return http.StatusUnauthorized, models.ErrInvalidPasswordResetToken
	}
	passwordHash, err := u.passwords.HashPassword(reset.NewPassword)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("hash reset password: %w", err)
	}
	if err := u.ResetPasswordWithToken(ctx, tokenDigest, passwordHash, time.Now().UTC()); err != nil {
		if errors.Is(err, models.ErrInvalidPasswordResetToken) {
			return http.StatusUnauthorized, models.ErrInvalidPasswordResetToken
		}
		return http.StatusInternalServerError, fmt.Errorf("complete password reset: %w", err)
	}
	return http.StatusOK, nil
}
