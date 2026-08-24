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

func (s *UserServer) LoginWithPassword(ctx context.Context, req *pb.UserLoginWithPasswordRequest) (response *pb.UserTokenResponse, err error) {
	defer func() { s.logApplicationOutcome(ctx, "login", err) }()
	email := req.GetEmail()
	phoneE164 := strings.TrimSpace(req.GetPhoneE164())
	if (email == "") == (phoneE164 == "") {
		return &pb.UserTokenResponse{}, grpcstatus.Error(codes.InvalidArgument, "provide exactly one password login identity")
	}
	if phoneE164 != "" {
		var err error
		phoneE164, err = phone.NormalizeE164(phoneE164)
		if err != nil {
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.InvalidArgument, models.ErrInvalidPhone.Error())
		}
	}
	login := dto.UserLoginWithPassword{
		Email:     email,
		PhoneE164: phoneE164,
		Password:  req.GetPassword(),
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
	if err := validate.Struct(login); err != nil {
		return &pb.UserTokenResponse{}, grpcstatus.Error(codes.InvalidArgument, "invalid password login request")
	}

	statusCode, token, err := s.UserController.LoginWithPassword(ctx, login)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidPhone), errors.Is(err, models.ErrInvalidLoginIdentity):
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.InvalidArgument, err.Error())
		case errors.Is(err, models.ErrInvalidCredentials):
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.Unauthenticated, models.ErrInvalidCredentials.Error())
		case errors.Is(err, models.ErrAccountNotValidated):
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.FailedPrecondition, "account_not_validated")
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		default:
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
		}
	}

	return &pb.UserTokenResponse{
		Token:               token.Token,
		TokenRefresh:        token.TokenRefresh,
		TokenRefreshExpires: timestamppb.New(token.TokenRefreshExpires),
		TokenExpires:        timestamppb.New(token.TokenExpires),
		Email:               token.Email,
		Status:              uint32(statusCode),
	}, nil
}
