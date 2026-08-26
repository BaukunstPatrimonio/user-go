package services

import (
	"context"
	"errors"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// InvitePasswordUser creates a passwordless identity and its setup token in
// one transaction, or safely replaces the setup token for an existing
// passwordless identity. A validated identity with a credential is reused
// without changing its identity fields or password.
func (s *userService) InvitePasswordUser(ctx context.Context, candidate models.User, token models.PasswordResetToken) (*models.User, bool, bool, error) {
	var (
		user               models.User
		existingIdentity   bool
		passwordConfigured bool
	)
	err := s.passwordResetDB(ctx).Transaction(func(tx *gorm.DB) error {
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("LOWER(email) = ?", candidate.Email).
			First(&user).Error
		switch {
		case err == nil:
			existingIdentity = true
		case errors.Is(err, gorm.ErrRecordNotFound):
			user = candidate
			if err := tx.Create(&user).Error; err != nil {
				return err
			}
		default:
			return err
		}

		var credentialCount int64
		if err := tx.Model(&models.PasswordCredential{}).Where("user_id = ?", user.ID).Count(&credentialCount).Error; err != nil {
			return err
		}
		passwordConfigured = credentialCount > 0
		if passwordConfigured {
			return nil
		}

		token.UserID = user.ID
		return tx.Omit("User").Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"token_digest", "expires_at", "used_at", "created_at"}),
		}).Create(&token).Error
	})
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, false, false, models.ErrUserAlreadyExists
		}
		return nil, false, false, err
	}
	return &user, existingIdentity, passwordConfigured, nil
}
