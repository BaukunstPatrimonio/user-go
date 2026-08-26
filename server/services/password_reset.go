package services

import (
	"context"
	"errors"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

func (s *userService) FindPasswordResetUser(ctx context.Context, normalizedEmail string) (*models.User, error) {
	user := &models.User{}
	err := s.passwordResetDB(ctx).
		Model(&models.User{}).
		Joins("INNER JOIN password_credentials ON password_credentials.user_id = users.id").
		Where("LOWER(users.email) = ?", normalizedEmail).
		First(user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, models.ErrPasswordResetUnavailable
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *userService) StorePasswordResetToken(ctx context.Context, resetToken models.PasswordResetToken) error {
	if resetToken.UserID == 0 || resetToken.TokenDigest == "" || resetToken.ExpiresAt.IsZero() {
		return errors.New("password reset token persistence fields are required")
	}
	return s.passwordResetDB(ctx).Transaction(func(tx *gorm.DB) error {
		return tx.Omit("User").Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"token_digest",
				"expires_at",
				"used_at",
				"created_at",
			}),
		}).Create(&resetToken).Error
	})
}

func (s *userService) ResetPasswordWithToken(ctx context.Context, tokenDigest, passwordHash string, now time.Time) error {
	if tokenDigest == "" || passwordHash == "" {
		return errors.New("password reset digest and hash are required")
	}

	err := s.passwordResetDB(ctx).Transaction(func(tx *gorm.DB) error {
		resetToken := &models.PasswordResetToken{}
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("token_digest = ? AND used_at IS NULL AND expires_at > ?", tokenDigest, now).
			First(resetToken).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return models.ErrInvalidPasswordResetToken
		}
		if err != nil {
			return err
		}

		credential := models.PasswordCredential{UserID: resetToken.UserID, PasswordHash: passwordHash}
		if err := tx.Omit("User").Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"password_hash", "updated_at"}),
		}).Create(&credential).Error; err != nil {
			return err
		}

		used := tx.Model(&models.PasswordResetToken{}).
			Where("id = ? AND used_at IS NULL AND expires_at > ?", resetToken.ID, now).
			Update("used_at", now)
		if used.Error != nil {
			return used.Error
		}
		if used.RowsAffected != 1 {
			return models.ErrInvalidPasswordResetToken
		}

		revoked := tx.Model(&models.User{}).
			Where("id = ?", resetToken.UserID).
			Updates(map[string]any{"code_refresh": "OUT", "validated": true})
		if revoked.Error != nil {
			return revoked.Error
		}
		if revoked.RowsAffected != 1 {
			return models.ErrInvalidPasswordResetToken
		}
		return nil
	})
	if errors.Is(err, models.ErrInvalidPasswordResetToken) {
		return models.ErrInvalidPasswordResetToken
	}
	return err
}

func (s *userService) passwordResetDB(ctx context.Context) *gorm.DB {
	return s.db.Session(&gorm.Session{Logger: logger.Discard}).WithContext(ctx)
}
