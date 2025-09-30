package controllers

import (
	"context"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/BaukunstPatrimonio/user-go/server/services"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
)

type IControllerUser interface {
	services.IUserService
	Login(context.Context, dto.UserLogin) (int, string, error)
	LogOut(context.Context, string) (int, error)
	Validate(context.Context, string) (int, models.Token, error)
	TokenToUser(context.Context, string, string, string, string, string, string, string, string, bool) (*models.User, error)
	Health(context.Context, uint32) int
	UpdateUserAdminStatus(context.Context, string, bool) error
	Refresh(context.Context, string, *pb.UserTokenRequest) (int, *models.Token, error)
}
