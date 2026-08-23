package server

import (
	"context"
	"errors"
	"strings"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"github.com/go-playground/validator/v10"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *UserServer) ChangePassword(ctx context.Context, req *pb.UserChangePasswordRequest) (*pb.UserStatusResponse, error) {
	request := dto.UserChangePassword{CurrentPassword: req.GetCurrentPassword(), NewPassword: req.GetNewPassword(), Token: req.GetAuth().GetToken(), DeviceInfo: deviceInfo(req.GetAuth())}
	if err := validator.New(validator.WithRequiredStructEnabled()).Struct(request); err != nil {
		return &pb.UserStatusResponse{}, grpcstatus.Error(codes.InvalidArgument, "invalid password change request")
	}
	controller, ok := s.UserController.(accountController)
	if !ok {
		s.Log.Error("authenticated account controller is unavailable")
		return &pb.UserStatusResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
	}
	statusCode, err := controller.ChangePassword(ctx, request)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrCurrentPasswordInvalid):
			return &pb.UserStatusResponse{}, grpcstatus.Error(codes.FailedPrecondition, "current password is incorrect")
		case errors.Is(err, models.ErrInvalidPassword):
			return &pb.UserStatusResponse{}, grpcstatus.Error(codes.InvalidArgument, models.ErrInvalidPassword.Error())
		case isAuthenticationError(err):
			return &pb.UserStatusResponse{}, grpcstatus.Error(codes.Unauthenticated, "invalid authentication")
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserStatusResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		default:
			s.Log.Error("authenticated password change failed")
			return &pb.UserStatusResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
		}
	}
	return &pb.UserStatusResponse{Status: uint32(statusCode)}, nil
}

func (s *UserServer) ChangeEmail(ctx context.Context, req *pb.UserChangeEmailRequest) (*pb.UserChangeEmailResponse, error) {
	request := dto.UserChangeEmail{Email: strings.ToLower(strings.TrimSpace(req.GetEmail())), Token: req.GetAuth().GetToken(), DeviceInfo: deviceInfo(req.GetAuth())}
	if err := validator.New(validator.WithRequiredStructEnabled()).Struct(request); err != nil {
		return &pb.UserChangeEmailResponse{}, grpcstatus.Error(codes.InvalidArgument, "invalid email change request")
	}
	controller, ok := s.UserController.(accountController)
	if !ok {
		s.Log.Error("authenticated account controller is unavailable")
		return &pb.UserChangeEmailResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
	}
	statusCode, result, err := controller.ChangeEmail(ctx, request)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrUserAlreadyExists):
			return &pb.UserChangeEmailResponse{}, grpcstatus.Error(codes.AlreadyExists, "email already exists")
		case isAuthenticationError(err):
			return &pb.UserChangeEmailResponse{}, grpcstatus.Error(codes.Unauthenticated, "invalid authentication")
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserChangeEmailResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		default:
			s.Log.Error("authenticated email change failed")
			return &pb.UserChangeEmailResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
		}
	}
	return &pb.UserChangeEmailResponse{VerificationCode: result.VerificationCode, CodeExpires: timestamppb.New(result.CodeExpires), Status: uint32(statusCode)}, nil
}

func deviceInfo(auth *pb.UserTokenRequest) models.DeviceInfo {
	return models.DeviceInfo{Browser: auth.GetBrowser(), BrowserVersion: auth.GetBrowserVersion(), OperatingSystem: auth.GetOperatingSystem(), OperatingSystemVersion: auth.GetOperatingSystemVersion(), Cpu: auth.GetCpu(), Language: auth.GetLanguage(), Timezone: auth.GetTimezone(), CookiesEnabled: auth.GetCookiesEnabled()}
}

func isAuthenticationError(err error) bool {
	return errors.Is(err, models.ErrSecurityMismatch) || errors.Is(err, models.ErrInvalidSignature) || errors.Is(err, models.ErrTokenExpired) || errors.Is(err, models.ErrParsingToken) || errors.Is(err, models.ErrInvalidToken) || errors.Is(err, models.ErrUserNotLogged) || errors.Is(err, models.ErrInvalidUser) || errors.Is(err, models.ErrUserNotFound)
}

type accountController interface {
	ChangePassword(context.Context, dto.UserChangePassword) (int, error)
	ChangeEmail(context.Context, dto.UserChangeEmail) (int, *models.EmailChange, error)
}
