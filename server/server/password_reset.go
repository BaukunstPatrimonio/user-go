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

func (s *UserServer) RequestPasswordReset(ctx context.Context, req *pb.UserRequestPasswordResetRequest) (*pb.UserRequestPasswordResetResponse, error) {
	request := dto.UserRequestPasswordReset{Email: strings.ToLower(strings.TrimSpace(req.GetEmail()))}
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(request); err != nil {
		return &pb.UserRequestPasswordResetResponse{}, grpcstatus.Error(codes.InvalidArgument, "invalid password reset request")
	}

	statusCode, result, err := s.UserController.RequestPasswordReset(ctx, request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return &pb.UserRequestPasswordResetResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		}
		s.Log.Error("password reset request failed")
		return &pb.UserRequestPasswordResetResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
	}

	response := &pb.UserRequestPasswordResetResponse{
		ResetToken: result.ResetToken,
		Status:     uint32(statusCode),
	}
	if !result.ExpiresAt.IsZero() {
		response.ExpiresAt = timestamppb.New(result.ExpiresAt)
	}
	return response, nil
}

func (s *UserServer) ResetPassword(ctx context.Context, req *pb.UserResetPasswordRequest) (*pb.UserResetPasswordResponse, error) {
	reset := dto.UserResetPassword{ResetToken: req.GetResetToken(), NewPassword: req.GetNewPassword()}
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(reset); err != nil {
		return &pb.UserResetPasswordResponse{}, grpcstatus.Error(codes.InvalidArgument, "invalid password reset request")
	}

	statusCode, err := s.UserController.ResetPassword(ctx, reset)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidPassword):
			return &pb.UserResetPasswordResponse{}, grpcstatus.Error(codes.InvalidArgument, models.ErrInvalidPassword.Error())
		case errors.Is(err, models.ErrInvalidPasswordResetToken):
			return &pb.UserResetPasswordResponse{}, grpcstatus.Error(codes.Unauthenticated, models.ErrInvalidPasswordResetToken.Error())
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserResetPasswordResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		default:
			s.Log.Error("password reset failed")
			return &pb.UserResetPasswordResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
		}
	}
	return &pb.UserResetPasswordResponse{Status: uint32(statusCode)}, nil
}
