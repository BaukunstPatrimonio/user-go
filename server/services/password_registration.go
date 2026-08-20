package services

import (
	"context"
	"errors"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
)

type sqlStateError interface {
	SQLState() string
}

func (s *userService) PasswordRegistrationEmailExists(ctx context.Context, normalizedEmail string) (bool, error) {
	var count int64
	err := s.db.WithContext(ctx).
		Unscoped().
		Model(&models.User{}).
		Where("LOWER(email) = ?", normalizedEmail).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *userService) CreatePasswordUser(ctx context.Context, user models.User, passwordHash string) (*models.User, error) {
	if passwordHash == "" {
		return nil, errors.New("password hash is required")
	}

	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&user).Error; err != nil {
			return err
		}
		credential := models.PasswordCredential{UserID: user.ID, PasswordHash: passwordHash}
		return tx.Omit("User").Create(&credential).Error
	})
	if err != nil {
		if isDuplicateKeyError(err) {
			return nil, models.ErrUserAlreadyExists
		}
		return nil, err
	}
	return &user, nil
}

func isDuplicateKeyError(err error) bool {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	var sqlState sqlStateError
	return errors.As(err, &sqlState) && sqlState.SQLState() == "23505"
}
