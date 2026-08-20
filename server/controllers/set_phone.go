package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/BaukunstPatrimonio/user-go/server/phone"
)

func (u *controllerUser) SetPhone(ctx context.Context, request dto.UserSetPhone) (int, *models.User, error) {
	user, err := u.TokenToUser(
		ctx,
		request.Token,
		request.Browser,
		request.BrowserVersion,
		request.OperatingSystem,
		request.OperatingSystemVersion,
		request.Cpu,
		request.Language,
		request.Timezone,
		request.CookiesEnabled,
	)
	if err != nil {
		return http.StatusUnauthorized, &models.User{}, err
	}
	canonicalPhone, err := phone.NormalizeE164(request.PhoneE164)
	if err != nil {
		return http.StatusBadRequest, &models.User{}, models.ErrInvalidPhone
	}
	if err := u.UpdatePhoneIdentity(ctx, user.ID, canonicalPhone); err != nil {
		if errors.Is(err, models.ErrPhoneAlreadyExists) {
			return http.StatusConflict, &models.User{}, models.ErrPhoneAlreadyExists
		}
		return http.StatusInternalServerError, &models.User{}, fmt.Errorf("set authenticated phone identity: %w", err)
	}
	user.PhoneE164 = &canonicalPhone
	return http.StatusOK, user, nil
}
