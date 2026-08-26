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

func (s *UserServer) InviteWithPasswordSetup(ctx context.Context, req *pb.UserRegisterWithPasswordRequest) (response *pb.UserRegisterWithPasswordResponse, err error) {
	defer func() { s.logApplicationOutcome(ctx, "invite_with_password_setup", err) }()
	invitation := dto.UserInvitation{
		Email:     strings.ToLower(strings.TrimSpace(req.GetEmail())),
		Name:      strings.TrimSpace(req.GetName()),
		PhoneE164: strings.TrimSpace(req.GetPhoneE164()),
	}
	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.Struct(invitation); err != nil {
		return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.InvalidArgument, "invalid password invitation request")
	}

	statusCode, result, err := s.UserController.InviteWithPasswordSetup(ctx, invitation)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrInvalidPhone):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.InvalidArgument, models.ErrInvalidPhone.Error())
		case errors.Is(err, models.ErrPhoneAlreadyExists), errors.Is(err, models.ErrUserAlreadyExists):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.AlreadyExists, err.Error())
		case errors.Is(err, models.ErrExistingAccountNotReady):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.FailedPrecondition, err.Error())
		case errors.Is(err, context.DeadlineExceeded):
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
		default:
			return &pb.UserRegisterWithPasswordResponse{}, grpcstatus.Error(codes.Internal, "internal server error")
		}
	}

	response = &pb.UserRegisterWithPasswordResponse{
		UserId: uint64(result.UserID), VerificationCode: result.InvitationToken, Status: uint32(statusCode),
	}
	if !result.ExpiresAt.IsZero() {
		response.CodeExpires = timestamppb.New(result.ExpiresAt)
	}
	return response, nil
}
