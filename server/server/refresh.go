package server

import (
	"context"

	pb "github.com/baukunstpatrimonio/user-go/server/user-pb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *UserServer) Refresh(ctx context.Context, req *pb.UserTokenRequest) (*pb.UserTokenResponse, error) {
	status, token, err := s.UserController.Refresh(ctx, req.GetToken())
	if err != nil {
		s.Log.Error(err.Error())
		return &pb.UserTokenResponse{}, err
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
