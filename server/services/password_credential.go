package services

import (
	"context"
	"errors"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	entModels "github.com/alvarotor/entitier-go/models"
	"gorm.io/gorm"
)

func (s *userService) GetPasswordCredential(ctx context.Context, userID uint) (*models.PasswordCredential, error) {
	credential, err := s.passwordCredentials.Get(ctx, userID, "")
	if errors.Is(err, entModels.ErrNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, models.ErrCredentialNotFound
	}
	if err != nil {
		return nil, err
	}
	return credential, nil
}

func (s *userService) CreatePasswordCredential(ctx context.Context, credential models.PasswordCredential) (*models.PasswordCredential, error) {
	created, err := s.passwordCredentials.Create(ctx, credential)
	if err != nil {
		return nil, err
	}
	return &created, nil
}

func (s *userService) UpdatePasswordCredentialHash(ctx context.Context, userID uint, passwordHash string) error {
	if passwordHash == "" {
		return errors.New("password hash is required")
	}
	result := s.db.WithContext(ctx).
		Model(&models.PasswordCredential{}).
		Where("user_id = ?", userID).
		Update("password_hash", passwordHash)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrCredentialNotFound
	}
	return nil
}

func (s *userService) ChangePasswordAndRevokeSessions(ctx context.Context, userID uint, passwordHash string) error {
	if passwordHash == "" {
		return errors.New("password hash is required")
	}
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		credential := tx.Model(&models.PasswordCredential{}).
			Where("user_id = ?", userID).
			Update("password_hash", passwordHash)
		if credential.Error != nil {
			return credential.Error
		}
		if credential.RowsAffected != 1 {
			return models.ErrCredentialNotFound
		}
		revoked := tx.Model(&models.User{}).
			Where("id = ?", userID).
			Updates(map[string]any{"code": "OUT", "code_refresh": "OUT"})
		if revoked.Error != nil {
			return revoked.Error
		}
		if revoked.RowsAffected != 1 {
			return models.ErrUserNotFound
		}
		return nil
	})
}

func (s *userService) StartPasswordSession(
	ctx context.Context,
	userID uint,
	device models.DeviceInfo,
	code string,
	codeExpire time.Time,
	codeRefresh string,
) error {
	result := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Updates(map[string]any{
			"browser":                  device.Browser,
			"browser_version":          device.BrowserVersion,
			"operating_system":         device.OperatingSystem,
			"operating_system_version": device.OperatingSystemVersion,
			"language":                 device.Language,
			"timezone":                 device.Timezone,
			"cpu":                      device.Cpu,
			"cookies_enabled":          device.CookiesEnabled,
			"code":                     code,
			"code_expire":              codeExpire,
			"code_refresh":             codeRefresh,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return models.ErrUserNotFound
	}
	return nil
}
