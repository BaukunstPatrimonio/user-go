package services

import (
	"context"
	"errors"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
)

func (s *userService) GetByPhone(ctx context.Context, phoneE164 string) (*models.User, error) {
	user := &models.User{}
	err := s.db.WithContext(ctx).Where("phone_e164 = ?", phoneE164).First(user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, models.ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *userService) UpdatePhoneIdentity(ctx context.Context, userID uint, phoneE164 string) error {
	result := s.db.WithContext(ctx).
		Model(&models.User{}).
		Where("id = ?", userID).
		Update("phone_e164", phoneE164)
	if result.Error != nil {
		if isDuplicateKeyError(result.Error) {
			return models.ErrPhoneAlreadyExists
		}
		return result.Error
	}
	if result.RowsAffected != 1 {
		return models.ErrUserNotFound
	}
	return nil
}
