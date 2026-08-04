package services

import (
	"context"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/alvarotor/entitier-go/repository"
)

type IUserService interface {
	repository.IGenericRepo[models.User, uint]
	GetByEmail(context.Context, string) (*models.User, error)
	GetByCode(context.Context, string) (*models.User, error)
	GetByCodeRefresh(context.Context, string) (*models.User, error)
	UpdateRefreshSession(context.Context, uint, models.DeviceInfo, string, string) error
	ValidateSvc(context.Context, string) error
	LogOutSvc(context.Context, string) error
}
