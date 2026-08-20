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
	LoginWithPassword(context.Context, dto.UserLoginWithPassword) (int, *models.Token, error)
	RegisterWithPassword(context.Context, dto.UserRegisterWithPassword) (int, *models.PasswordRegistration, error)
	RequestPasswordReset(context.Context, dto.UserRequestPasswordReset) (int, *models.PasswordResetRequest, error)
	ResetPassword(context.Context, dto.UserResetPassword) (int, error)
	SetPhone(context.Context, dto.UserSetPhone) (int, *models.User, error)
	LogOut(context.Context, string) (int, error)
	Validate(context.Context, string) (int, models.Token, error)
	TokenToUser(context.Context, string, string, string, string, string, string, string, string, bool) (*models.User, error)
	Health(context.Context, uint32) int
	UpdateUserAdminStatus(context.Context, string, bool) error
	Refresh(context.Context, string, *pb.UserTokenRequest) (int, *models.Token, error)
}
