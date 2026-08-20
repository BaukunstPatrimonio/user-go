package services

import (
	"context"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
)

type logoutRepository struct {
	users       []*models.User
	updatedID   uint
	updatedUser models.User
	updateCalls int
}

func (r *logoutRepository) Create(_ context.Context, user models.User) (models.User, error) {
	return user, nil
}

func (r *logoutRepository) GetAll(context.Context) ([]*models.User, error) {
	return r.users, nil
}

func (r *logoutRepository) Get(_ context.Context, _ uint, _ string) (*models.User, error) {
	return nil, models.ErrUserNotFound
}

func (r *logoutRepository) Update(_ context.Context, id uint, user models.User) error {
	r.updatedID = id
	r.updatedUser = user
	r.updateCalls++
	return nil
}

func (r *logoutRepository) Delete(_ context.Context, _ uint, _ bool) error {
	return nil
}

func (r *logoutRepository) UpdateField(_ context.Context, _ uint, _ string, _ interface{}) error {
	return nil
}

func TestLogOutSvcInvalidatesCurrentCodesAndExpiry(t *testing.T) {
	user := &models.User{
		Model:       gorm.Model{ID: 583},
		Email:       "person@example.com",
		Code:        "validation-code",
		CodeRefresh: "refresh-code",
		CodeExpire:  time.Now().UTC().Add(time.Hour),
	}
	repository := &logoutRepository{users: []*models.User{user}}
	service := &userService{IGenericRepo: repository}
	before := time.Now().UTC()

	if err := service.LogOutSvc(context.Background(), user.Email); err != nil {
		t.Fatalf("LogOutSvc() error = %v", err)
	}
	if repository.updateCalls != 1 || repository.updatedID != user.ID {
		t.Fatalf("LogOutSvc() update = calls:%d ID:%d, want 1/%d", repository.updateCalls, repository.updatedID, user.ID)
	}
	if repository.updatedUser.Code != "OUT" || repository.updatedUser.CodeRefresh != "OUT" {
		t.Fatalf("LogOutSvc() codes = %q/%q, want OUT/OUT", repository.updatedUser.Code, repository.updatedUser.CodeRefresh)
	}
	if repository.updatedUser.CodeExpire.Before(before) || repository.updatedUser.CodeExpire.After(time.Now().UTC()) {
		t.Fatalf("LogOutSvc() expiry = %v, want current UTC time", repository.updatedUser.CodeExpire)
	}
}
