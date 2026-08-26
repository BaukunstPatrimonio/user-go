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
	"github.com/BaukunstPatrimonio/user-go/server/passwordreset"
	"github.com/BaukunstPatrimonio/user-go/server/phone"
	entModels "github.com/alvarotor/entitier-go/models"
	"gorm.io/gorm"
)

const passwordInvitationLifetime = 24 * time.Hour

type passwordInvitationStorage interface {
	InvitePasswordUser(context.Context, models.User, models.PasswordResetToken) (*models.User, bool, bool, error)
}

func (u *controllerUser) InviteWithPasswordSetup(ctx context.Context, invitation dto.UserInvitation) (int, *models.PasswordInvitation, error) {
	storage, ok := u.IUserService.(passwordInvitationStorage)
	if !ok {
		return http.StatusInternalServerError, &models.PasswordInvitation{}, errors.New("password invitation storage is unavailable")
	}

	invitation.Email = strings.ToLower(strings.TrimSpace(invitation.Email))
	invitation.Name = strings.TrimSpace(invitation.Name)
	var phoneE164 *string
	if strings.TrimSpace(invitation.PhoneE164) != "" {
		canonicalPhone, err := phone.NormalizeE164(invitation.PhoneE164)
		if err != nil {
			return http.StatusBadRequest, &models.PasswordInvitation{}, models.ErrInvalidPhone
		}
		phoneUser, err := u.GetByPhone(ctx, canonicalPhone)
		if err == nil && phoneUser != nil && !strings.EqualFold(phoneUser.Email, invitation.Email) {
			return http.StatusConflict, &models.PasswordInvitation{}, models.ErrPhoneAlreadyExists
		}
		if err != nil && !errors.Is(err, models.ErrUserNotFound) && !errors.Is(err, entModels.ErrNotFound) && !errors.Is(err, gorm.ErrRecordNotFound) {
			return http.StatusInternalServerError, &models.PasswordInvitation{}, fmt.Errorf("check invitation phone: %w", err)
		}
		phoneE164 = &canonicalPhone
	}

	rawToken, tokenDigest, err := passwordreset.GenerateToken()
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordInvitation{}, fmt.Errorf("generate invitation token: %w", err)
	}
	codeRefresh, err := secureRandomString(u.conf.RandomStringValidationRefresh, u.conf.SizeRandomStringValidationRefresh)
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordInvitation{}, fmt.Errorf("generate invitation session state: %w", err)
	}
	expiresAt := time.Now().UTC().Add(passwordInvitationLifetime)
	user, existing, configured, err := storage.InvitePasswordUser(ctx, models.User{
		Email: invitation.Email, PhoneE164: phoneE164, Name: invitation.Name,
		Validated: false, Admin: false, SuperAdmin: false, CodeRefresh: codeRefresh,
	}, models.PasswordResetToken{TokenDigest: tokenDigest, ExpiresAt: expiresAt})
	if err != nil {
		return http.StatusInternalServerError, &models.PasswordInvitation{}, fmt.Errorf("create invited identity: %w", err)
	}
	if configured {
		if !user.Validated {
			return http.StatusPreconditionFailed, &models.PasswordInvitation{}, models.ErrExistingAccountNotReady
		}
		return http.StatusOK, &models.PasswordInvitation{UserID: user.ID, ExistingIdentity: true, PasswordConfigured: true}, nil
	}

	statusCode := http.StatusCreated
	if existing {
		statusCode = http.StatusAccepted
	}
	return statusCode, &models.PasswordInvitation{
		UserID: user.ID, InvitationToken: rawToken, ExpiresAt: expiresAt,
		ExistingIdentity: existing, PasswordConfigured: false,
	}, nil
}
