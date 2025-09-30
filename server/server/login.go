package server

import (
	"context"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"github.com/go-playground/validator/v10"
)

func (s *UserServer) Login(ctx context.Context, req *pb.UserLoginRequest) (*pb.UserLoginResponse, error) {
	userLogin := dto.UserLogin{
		Email: req.GetEmail(),
		DeviceInfo: models.DeviceInfo{
			Browser:                req.GetBrowser(),
			BrowserVersion:         req.GetBrowserVersion(),
			OperatingSystem:        req.GetOperatingSystem(),
			OperatingSystemVersion: req.GetOperatingSystemVersion(),
			Cpu:                    req.GetCpu(),
			Language:               req.GetLanguage(),
			Timezone:               req.GetTimezone(),
			CookiesEnabled:         req.GetCookiesEnabled(),
		},
	}

	validator := validator.New(validator.WithRequiredStructEnabled())
	err := validator.Struct(userLogin)
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserLoginResponse{}, err
	}

	status, code, err := s.UserController.Login(ctx, userLogin)
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserLoginResponse{}, err
	}

	return &pb.UserLoginResponse{
		Code:   code,
		Status: uint32(status),
	}, nil
}
