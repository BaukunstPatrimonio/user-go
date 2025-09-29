package controllers

import (
	"context"

	"github.com/baukunstpatrimonio/user-go/server/dto"
	"github.com/baukunstpatrimonio/user-go/server/models"
	"github.com/baukunstpatrimonio/user-go/server/services"
)

type IControllerUser interface {
	services.IUserService
	Login(context.Context, dto.UserLogin) (int, string, error)
	LogOut(context.Context, string) (int, error)
	Validate(context.Context, string) (int, models.Token, error)
	TokenToUser(context.Context, string, string, string, string, string, string, string, string, bool) (*models.User, error)
	Health(context.Context, uint32) int
	UpdateUserAdminStatus(context.Context, string, bool) error
	Refresh(context.Context, string) (int, *models.Token, error)
}
