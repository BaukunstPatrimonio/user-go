package services

import (
	"context"

	"github.com/BaukunstPatrimonio/user-go/server/models"
)

func (s userService) GetByCodeRefresh(ctx context.Context, code string) (*models.User, error) {
	users, err := s.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		if user.CodeRefresh == code {
			return user, nil
		}
	}

	return nil, models.ErrUserNotFound
}
