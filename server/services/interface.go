package services

import (
	"context"

	"github.com/alvarotor/entitier-go/repository"
	"github.com/baukunstpatrimonio/user-go/server/models"
)

type IUserService interface {
	repository.IGenericRepo[models.User, uint]
	GetByEmail(context.Context, string) (*models.User, error)
	GetByCode(context.Context, string) (*models.User, error)
	GetByCodeRefresh(context.Context, string) (*models.User, error)
	ValidateSvc(context.Context, string) error
	LogOutSvc(context.Context, string) error
}
