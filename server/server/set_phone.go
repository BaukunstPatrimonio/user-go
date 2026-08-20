package server

import (
	"context"
	"errors"
	"strings"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *UserServer) SetPhone(ctx context.Context, req *pb.UserSetPhoneRequest) (*pb.UserResponse, error) {
	auth := req.GetAuth()
	if auth.GetToken() == "" || strings.TrimSpace(req.GetPhoneE164()) == "" {
		return &pb.UserResponse{}, grpcstatus.Error(codes.InvalidArgument, "invalid set phone request")
	}
	request := dto.UserSetPhone{
		Token:     auth.GetToken(),
		PhoneE164: req.GetPhoneE164(),
		DeviceInfo: models.DeviceInfo{
			Browser:                auth.GetBrowser(),
			BrowserVersion:         auth.GetBrowserVersion(),
			OperatingSystem:        auth.GetOperatingSystem(),
			OperatingSystemVersion: auth.GetOperatingSystemVersion(),
			Cpu:                    auth.GetCpu(),
			Language:               auth.GetLanguage(),
			Timezone:               auth.GetTimezone(),
			CookiesEnabled:         auth.GetCookiesEnabled(),
		},
	}
	_, user, err := s.UserController.SetPhone(ctx, request)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidPhone):
			return &pb.UserResponse{}, grpcstatus.Error(codes.InvalidArgument, models.ErrInvalidPhone.Error())
		case errors.Is(err, models.ErrPhoneAlreadyExists):
			return &pb.UserResponse{}, grpcstatus.Error(codes.AlreadyExists, models.ErrPhoneAlreadyExists.Error())
		case errors.Is(err, models.ErrSecurityMismatch):
			return &pb.UserResponse{}, grpcstatus.Error(codes.PermissionDenied, models.ErrSecurityMismatch.Error())
		case errors.Is(err, models.ErrInvalidSignature), errors.Is(err, models.ErrTokenExpired), errors.Is(err, models.ErrParsingToken), errors.Is(err, models.ErrInvalidToken), errors.Is(err, models.ErrUserNotLogged), errors.Is(err, models.ErrInvalidUser), errors.Is(err, models.ErrUserNotFound):
			return &pb.UserResponse{}, grpcstatus.Error(codes.Unauthenticated, "invalid authentication")
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		default:
			s.Log.Error("set phone failed")
			return &pb.UserResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
		}
	}
	return &pb.UserResponse{
		Id:         uint64(user.ID),
		Email:      user.Email,
		PhoneE164:  phoneE164Value(user.PhoneE164),
		Name:       user.Name,
		ProfilePic: user.ProfilePic,
		Validated:  user.Validated,
		Admin:      user.Admin,
		SuperAdmin: user.SuperAdmin,
		Code:       user.Code,
		CodeExpire: timestamppb.New(user.CodeExpire),
		Bucket:     user.Bucket,
	}, nil
}
