package server

import (
	"context"
	"fmt"
	"time"

	"github.com/baukunstpatrimonio/user-go/server/models"
	pb "github.com/baukunstpatrimonio/user-go/server/user-pb"
	"github.com/go-playground/validator/v10"
)

func (s *UserServer) Create(ctx context.Context, req *pb.UserRequest) (*pb.UserIDResponse, error) {
	user := models.User{
		Email:           req.Email,
		Name:            req.Name,
		ProfilePic:      req.ProfilePic,
		Validated:       false,
		Admin:           false,
		SuperAdmin:      false,
		Code:            "",
		CodeExpire:      time.Time{},
	}

	s.Log.Info(fmt.Sprintf("%v\n", user))

	validate := validator.New(validator.WithRequiredStructEnabled())
	err := validate.Struct(user)
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserIDResponse{}, err
	}

	userCreated, err := s.UserController.Create(ctx, user)
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserIDResponse{}, err
	}

	return &pb.UserIDResponse{
		Id:     uint32(userCreated.ID),
		Status: 1,
	}, nil
}
