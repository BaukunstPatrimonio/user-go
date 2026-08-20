package server

import (
	"context"
	"errors"
	"strings"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/BaukunstPatrimonio/user-go/server/phone"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *UserServer) RegisterWithPassword(ctx context.Context, req *pb.UserRegisterWithPasswordRequest) (*pb.UserRegisterWithPasswordResponse, error) {
	phoneE164 := strings.TrimSpace(req.GetPhoneE164())
	if phoneE164 != "" {
		var err error
		phoneE164, err = phone.NormalizeE164(phoneE164)
		if err != nil {
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.InvalidArgument, models.ErrInvalidPhone.Error())
		}
	}
	registration := dto.UserRegisterWithPassword{
		Email:     strings.ToLower(strings.TrimSpace(req.GetEmail())),
		Name:      strings.TrimSpace(req.GetName()),
		Password:  req.GetPassword(),
		PhoneE164: phoneE164,
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

	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(registration); err != nil {
		return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.InvalidArgument, "invalid password registration request")
	}

	statusCode, result, err := s.UserController.RegisterWithPassword(ctx, registration)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidPassword):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.InvalidArgument, models.ErrInvalidPassword.Error())
		case errors.Is(err, models.ErrInvalidPhone):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.InvalidArgument, models.ErrInvalidPhone.Error())
		case errors.Is(err, models.ErrUserAlreadyExists):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.AlreadyExists, models.ErrUserAlreadyExists.Error())
		case errors.Is(err, models.ErrPhoneAlreadyExists):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.AlreadyExists, models.ErrPhoneAlreadyExists.Error())
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		default:
			s.Log.Error("password registration failed")
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
		}
	}

	return &pb.UserRegisterWithPasswordResponse{
		UserId:           uint64(result.UserID),
		VerificationCode: result.VerificationCode,
		CodeExpires:      timestamppb.New(result.CodeExpires),
		Status:           uint32(statusCode),
	}, nil
}
