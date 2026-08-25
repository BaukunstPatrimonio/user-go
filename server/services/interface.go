package services

import (
	"context"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/alvarotor/entitier-go/repository"
)

type IUserService interface {
	repository.IGenericRepo[models.User, uint]
	GetByEmail(context.Context, string) (*models.User, error)
	GetByPhone(context.Context, string) (*models.User, error)
	GetByCode(context.Context, string) (*models.User, error)
	GetByCodeRefresh(context.Context, string) (*models.User, error)
	GetPasswordCredential(context.Context, uint) (*models.PasswordCredential, error)
	CreatePasswordCredential(context.Context, models.PasswordCredential) (*models.PasswordCredential, error)
	PasswordRegistrationEmailExists(context.Context, string) (bool, error)
	CreatePasswordUser(context.Context, models.User, string) (*models.User, error)
	FindPasswordResetUser(context.Context, string) (*models.User, error)
	StorePasswordResetToken(context.Context, models.PasswordResetToken) error
	ResetPasswordWithToken(context.Context, string, string, time.Time) error
	UpdatePhoneIdentity(context.Context, uint, string) error
	StartPasswordSession(context.Context, uint, models.DeviceInfo, string, time.Time, string) error
	UpdateRefreshSession(context.Context, uint, models.DeviceInfo, string, string) error
	ValidateSvc(context.Context, string) error
	VerifyUserSvc(context.Context, uint) error
	LogOutSvc(context.Context, string) error
}
