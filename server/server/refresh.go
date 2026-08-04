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

func (s *UserServer) Refresh(ctx context.Context, req *pb.UserTokenRequest) (*pb.UserTokenResponse, error) {
	status, token, err := s.UserController.Refresh(ctx, req.GetToken(), req)
	if err != nil {
		s.Log.Error(err.Error())
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		case matchesRefreshError(err, models.ErrInvalidSignature),
			matchesRefreshError(err, models.ErrParsingToken),
			matchesRefreshError(err, models.ErrInvalidToken),
			matchesRefreshError(err, models.ErrTokenExpired),
			matchesRefreshError(err, models.ErrInvalidCode):
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.Unauthenticated, err.Error())
		case matchesRefreshError(err, models.ErrSessionDeviceMismatch):
			return &pb.UserTokenResponse{}, grpcstatus.Error(codes.Unauthenticated, "session_device_mismatch")
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
		Status:              uint32(status),
	}, nil
}

func matchesRefreshError(err, target error) bool {
	return errors.Is(err, target) || err.Error() == target.Error()
}
