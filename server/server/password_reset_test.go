package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/controllers"
	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type passwordResetControllerStub struct {
	controllers.IControllerUser
	requestStatus int
	requestResult *models.PasswordResetRequest
	requestErr    error
	request       dto.UserRequestPasswordReset
	resetStatus   int
	resetErr      error
	reset         dto.UserResetPassword
}

func (s *passwordResetControllerStub) RequestPasswordReset(_ context.Context, request dto.UserRequestPasswordReset) (int, *models.PasswordResetRequest, error) {
	s.request = request
	return s.requestStatus, s.requestResult, s.requestErr
}

func (s *passwordResetControllerStub) ResetPassword(_ context.Context, reset dto.UserResetPassword) (int, error) {
	s.reset = reset
	return s.resetStatus, s.resetErr
}

func TestRequestPasswordResetValidatesAndNormalizesEmail(t *testing.T) {
	for _, email := range []string{"", "not-an-email"} {
		controller := &passwordResetControllerStub{}
		server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
		response, err := server.RequestPasswordReset(context.Background(), &pb.UserRequestPasswordResetRequest{Email: email})
		if status.Code(err) != codes.InvalidArgument || response == nil || controller.request.Email != "" {
			t.Fatalf("RequestPasswordReset(%q) = %#v, %v request:%#v", email, response, err, controller.request)
		}
	}

	expires := time.Date(2026, time.August, 20, 12, 30, 0, 0, time.UTC)
	controller := &passwordResetControllerStub{
		requestStatus: http.StatusAccepted,
		requestResult: &models.PasswordResetRequest{ResetToken: "internal-token", ExpiresAt: expires},
	}
	server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
	response, err := server.RequestPasswordReset(context.Background(), &pb.UserRequestPasswordResetRequest{Email: "  Person@Example.COM "})
	if err != nil || response.GetResetToken() != "internal-token" || response.GetStatus() != http.StatusAccepted || !response.GetExpiresAt().AsTime().Equal(expires) || controller.request.Email != "person@example.com" {
		t.Fatalf("RequestPasswordReset() = %#v, %v request:%#v", response, err, controller.request)
	}
}

func TestRequestPasswordResetReturnsGenericAcceptedResponseForIneligibleEmail(t *testing.T) {
	controller := &passwordResetControllerStub{requestStatus: http.StatusAccepted, requestResult: &models.PasswordResetRequest{}}
	server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
	response, err := server.RequestPasswordReset(context.Background(), &pb.UserRequestPasswordResetRequest{Email: "unknown@example.com"})
	if err != nil || response.GetStatus() != http.StatusAccepted || response.GetResetToken() != "" || response.GetExpiresAt() != nil {
		t.Fatalf("RequestPasswordReset(ineligible) = %#v, %v, want generic accepted", response, err)
	}
}

func TestRequestPasswordResetMapsInternalErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
	}{
		{name: "deadline", err: context.DeadlineExceeded, code: codes.DeadlineExceeded},
		{name: "internal", err: errors.New("database unavailable"), code: codes.Internal},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := &passwordResetControllerStub{requestErr: test.err}
			server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
			response, err := server.RequestPasswordReset(context.Background(), &pb.UserRequestPasswordResetRequest{Email: "person@example.com"})
			if status.Code(err) != test.code || response == nil {
				t.Fatalf("RequestPasswordReset() = %#v, %v, want %v", response, err, test.code)
			}
		})
	}
}

func TestResetPasswordValidatesRequestAndMapsErrors(t *testing.T) {
	invalidRequests := []*pb.UserResetPasswordRequest{
		{NewPassword: "valid-fake-password!"},
		{ResetToken: "token"},
		{ResetToken: "token", NewPassword: "short"},
	}
	for _, request := range invalidRequests {
		controller := &passwordResetControllerStub{}
		server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
		response, err := server.ResetPassword(context.Background(), request)
		if status.Code(err) != codes.InvalidArgument || response == nil || controller.reset.ResetToken != "" {
			t.Fatalf("ResetPassword(%#v) = %#v, %v reset:%#v", request, response, err, controller.reset)
		}
	}

	tests := []struct {
		name string
		err  error
		code codes.Code
		msg  string
	}{
		{name: "invalid password", err: models.ErrInvalidPassword, code: codes.InvalidArgument, msg: models.ErrInvalidPassword.Error()},
		{name: "invalid token", err: models.ErrInvalidPasswordResetToken, code: codes.Unauthenticated, msg: models.ErrInvalidPasswordResetToken.Error()},
		{name: "wrapped token", err: errors.Join(errors.New("reset"), models.ErrInvalidPasswordResetToken), code: codes.Unauthenticated, msg: models.ErrInvalidPasswordResetToken.Error()},
		{name: "deadline", err: context.DeadlineExceeded, code: codes.DeadlineExceeded, msg: context.DeadlineExceeded.Error()},
		{name: "internal", err: errors.New("database unavailable"), code: codes.Internal, msg: "internal server error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := &passwordResetControllerStub{resetErr: test.err}
			server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
			response, err := server.ResetPassword(context.Background(), validResetPasswordRequest())
			if status.Code(err) != test.code || status.Convert(err).Message() != test.msg || response == nil {
				t.Fatalf("ResetPassword() = %#v, %v, want %v/%q", response, err, test.code, test.msg)
			}
		})
	}
}

func TestResetPasswordReturnsStatusOnly(t *testing.T) {
	controller := &passwordResetControllerStub{resetStatus: http.StatusOK}
	server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := validResetPasswordRequest()
	response, err := server.ResetPassword(context.Background(), request)
	if err != nil || response.GetStatus() != http.StatusOK || controller.reset.ResetToken != request.ResetToken || controller.reset.NewPassword != request.NewPassword {
		t.Fatalf("ResetPassword() = %#v, %v reset:%#v", response, err, controller.reset)
	}
	fields := response.ProtoReflect().Descriptor().Fields()
	if fields.Len() != 1 || fields.ByName("token") != nil || fields.ByName("token_refresh") != nil || fields.ByName("password_hash") != nil {
		t.Fatal("reset response unexpectedly exposes authentication or credential data")
	}
}

func validResetPasswordRequest() *pb.UserResetPasswordRequest {
	return &pb.UserResetPasswordRequest{ResetToken: "valid-structured-token", NewPassword: "phase-four-new-password!"}
}
