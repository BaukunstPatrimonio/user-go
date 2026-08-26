package server

import (
	"context"
	"errors"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"

	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *UserServer) TokenToUser(ctx context.Context, req *pb.UserTokenRequest) (response *pb.UserResponse, err error) {
	defer func() { s.logApplicationOutcome(ctx, "authenticate_token", err) }()
	user, err := s.UserController.TokenToUser(
		ctx,
		req.GetToken(),
		req.GetBrowser(),
		req.GetBrowserVersion(),
		req.GetOperatingSystem(),
		req.GetOperatingSystemVersion(),
		req.GetCpu(),
		req.GetLanguage(),
		req.GetTimezone(),
		req.GetCookiesEnabled(),
	)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidSignature),
			errors.Is(err, models.ErrTokenExpired),
			errors.Is(err, models.ErrParsingToken),
			errors.Is(err, models.ErrInvalidToken),
			errors.Is(err, models.ErrUserNotLogged),
			errors.Is(err, models.ErrInvalidUser),
			errors.Is(err, models.ErrSecurityMismatch),
			errors.Is(err, models.ErrUserNotFound):
			return &pb.UserResponse{}, grpcstatus.Error(codes.Unauthenticated, "invalid authentication")
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		default:
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
