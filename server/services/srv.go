package services

import (
	"github.com/alvarotor/entitier-go/repository"
	"github.com/baukunstpatrimonio/user-go/server/models"
	"gorm.io/gorm"
)

type userService struct {
	repository.IGenericRepo[models.User, uint]
}

func NewUserService(
	db *gorm.DB,
) IUserService {
	repo := repository.NewGenericRepository[models.User, uint](db)
	return &userService{
		IGenericRepo: repo,
	}
}
