package services

import (
	"context"

	"github.com/BaukunstPatrimonio/user-go/server/models"
)

func (s *userService) ValidateSvc(ctx context.Context, email string) error {
	user, err := s.GetByEmail(ctx, email)
	if err != nil {
		return err
	}

	user.Validated = true

	return s.Update(ctx, user.ID, *user)
}

// VerifyUserSvc manually validates an existing identity. It deliberately uses
// the same persisted state as the ordinary validation flow and leaves all
// identity and credential fields untouched.
func (s *userService) VerifyUserSvc(ctx context.Context, userID uint) error {
	if userID == 0 {
		return models.ErrUserNotFound
	}
	user, err := s.Get(ctx, userID, "")
	if err != nil {
		return err
	}
	if user.Validated {
		return nil
	}
	user.Validated = true
	return s.Update(ctx, user.ID, *user)
}
