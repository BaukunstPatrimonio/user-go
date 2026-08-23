package services

import (
	"context"
	"errors"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
)

func (s *userService) ChangeEmailAndRequireValidation(ctx context.Context, userID uint, email, verificationCode string, expiresAt time.Time) error {
	if email == "" || verificationCode == "" || expiresAt.IsZero() {
		return errors.New("email change fields are required")
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		updated := tx.Model(&models.User{}).
			Where("id = ?", userID).
			Updates(map[string]any{
				"pending_email": email,
				"code":          verificationCode,
				"code_expire":   expiresAt,
			})
		if updated.Error != nil {
			if isDuplicateKeyError(updated.Error) {
				return models.ErrUserAlreadyExists
			}
			return updated.Error
		}
		if updated.RowsAffected != 1 {
			return models.ErrUserNotFound
		}
		return nil
	})
}

// CompletePendingEmailChange atomically promotes a verified pending email and
// replaces the account session material so old-email sessions cannot persist.
func (s *userService) CompletePendingEmailChange(
	ctx context.Context,
	userID uint,
	verificationCode string,
	device models.DeviceInfo,
	sessionCode string,
	sessionCodeExpires time.Time,
	sessionRefresh string,
) error {
	if verificationCode == "" || sessionCode == "" || sessionRefresh == "" || sessionCodeExpires.IsZero() {
		return errors.New("email change completion fields are required")
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user models.User
		if err := tx.Select("pending_email").First(&user, userID).Error; err != nil {
			return err
		}
		if user.PendingEmail == "" {
			return models.ErrInvalidCode
		}

		updated := tx.Model(&models.User{}).
			Where("id = ? AND code = ? AND pending_email <> ''", userID, verificationCode).
			Updates(map[string]any{
				"email":                    user.PendingEmail,
				"pending_email":            "",
				"validated":                true,
				"browser":                  device.Browser,
				"browser_version":          device.BrowserVersion,
				"operating_system":         device.OperatingSystem,
				"operating_system_version": device.OperatingSystemVersion,
				"language":                 device.Language,
				"timezone":                 device.Timezone,
				"cpu":                      device.Cpu,
				"cookies_enabled":          device.CookiesEnabled,
				"code":                     sessionCode,
				"code_expire":              sessionCodeExpires,
				"code_refresh":             sessionRefresh,
			})
		if updated.Error != nil {
			if isDuplicateKeyError(updated.Error) {
				return models.ErrUserAlreadyExists
			}
			return updated.Error
		}
		if updated.RowsAffected != 1 {
			return models.ErrInvalidCode
		}
		return nil
	})
}
