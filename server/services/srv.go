package services

import (
	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/alvarotor/entitier-go/repository"
	"gorm.io/gorm"
)

type userService struct {
	repository.IGenericRepo[models.User, uint]
	passwordCredentials repository.IGenericRepo[models.PasswordCredential, uint]
	db                  *gorm.DB
}

func NewUserService(
	db *gorm.DB,
) IUserService {
	repo := repository.NewGenericRepository[models.User, uint](db)
	passwordCredentials := repository.NewGenericRepository[models.PasswordCredential, uint](db)
	return &userService{
		IGenericRepo:        repo,
		passwordCredentials: passwordCredentials,
		db:                  db,
	}
}
