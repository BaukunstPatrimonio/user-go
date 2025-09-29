package services

import (
	"context"

	entModels "github.com/alvarotor/entitier-go/models"
	"github.com/baukunstpatrimonio/user-go/server/models"
)

func (s userService) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	users, err := s.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, user := range users {
		if user.Email == email {
			return user, nil
		}
	}

	return nil, entModels.ErrNotFound
}
