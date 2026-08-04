package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/controllers"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type refreshControllerStub struct {
	controllers.IControllerUser
	status int
	token  *models.Token
	err    error
}

func (s refreshControllerStub) Refresh(context.Context, string, *pb.UserTokenRequest) (int, *models.Token, error) {
	return s.status, s.token, s.err
}

func TestRefreshMapsAuthenticationFailuresToUnauthenticated(t *testing.T) {
	tests := []struct {
		name    string
		target  error
		message string
	}{
		{name: "invalid signature", target: models.ErrInvalidSignature, message: models.ErrInvalidSignature.Error()},
		{name: "malformed token", target: models.ErrParsingToken, message: models.ErrParsingToken.Error()},
		{name: "invalid token", target: models.ErrInvalidToken, message: models.ErrInvalidToken.Error()},
		{name: "expired token", target: models.ErrTokenExpired, message: models.ErrTokenExpired.Error()},
		{name: "stale token", target: models.ErrInvalidCode, message: models.ErrInvalidCode.Error()},
		{name: "device mismatch", target: models.ErrSessionDeviceMismatch, message: "session_device_mismatch"},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			variants := []struct {
				name    string
				err     error
				message string
			}{
				{name: "direct", err: test.target, message: test.message},
				{name: "wrapped", err: fmt.Errorf("controller: %w", test.target), message: "controller: " + test.target.Error()},
			}
			if errors.Is(test.target, models.ErrSessionDeviceMismatch) {
				variants[1].message = "session_device_mismatch"
			}

			for _, variant := range variants {
				t.Run(variant.name, func(t *testing.T) {
					server := NewServer(refreshControllerStub{err: variant.err}, logger)

					response, err := server.Refresh(context.Background(), &pb.UserTokenRequest{})
					if got, want := status.Code(err), codes.Unauthenticated; got != want {
						t.Fatalf("Refresh() error code = %v, want %v", got, want)
					}
					if got := status.Convert(err).Message(); got != variant.message {
						t.Fatalf("Refresh() error message = %q, want %q", got, variant.message)
					}
					if response == nil {
						t.Fatal("Refresh() response = nil, want empty response")
					}
				})
			}
		})
	}
}

func TestRefreshMapsContextTimeoutToDeadlineExceeded(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(refreshControllerStub{err: errors.Join(errors.New("query failed"), context.DeadlineExceeded)}, logger)

	response, err := server.Refresh(context.Background(), &pb.UserTokenRequest{})
	if got, want := status.Code(err), codes.DeadlineExceeded; got != want {
		t.Fatalf("Refresh() error code = %v, want %v", got, want)
	}
	if response == nil {
		t.Fatal("Refresh() response = nil, want empty response")
	}
}

func TestRefreshMapsInternalFailuresToInternal(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "database failure", err: errors.New("database unavailable")},
		{name: "unexpected failure", err: errors.New("unexpected signing failure")},
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := NewServer(refreshControllerStub{err: test.err}, logger)

			response, err := server.Refresh(context.Background(), &pb.UserTokenRequest{})
			if got, want := status.Code(err), codes.Internal; got != want {
				t.Fatalf("Refresh() error code = %v, want %v", got, want)
			}
			if got, want := status.Convert(err).Message(), "internal server error"; got != want {
				t.Fatalf("Refresh() error message = %q, want %q", got, want)
			}
			if response == nil {
				t.Fatal("Refresh() response = nil, want empty response")
			}
		})
	}
}

func TestRefreshPreservesSuccessfulResponse(t *testing.T) {
	accessExpires := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	refreshExpires := accessExpires.Add(24 * time.Hour)
	token := &models.Token{
		Email:               "user@example.com",
		Token:               "access-token",
		TokenExpires:        accessExpires,
		TokenRefresh:        "refresh-token",
		TokenRefreshExpires: refreshExpires,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewServer(refreshControllerStub{status: http.StatusOK, token: token}, logger)

	response, err := server.Refresh(context.Background(), &pb.UserTokenRequest{})
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if response.GetToken() != token.Token || response.GetTokenRefresh() != token.TokenRefresh || response.GetEmail() != token.Email {
		t.Fatalf("Refresh() response tokens/email = %#v, want values from controller", response)
	}
	if got, want := response.GetStatus(), uint32(http.StatusOK); got != want {
		t.Fatalf("Refresh() status = %v, want %v", got, want)
	}
	if !response.GetTokenExpires().AsTime().Equal(accessExpires) {
		t.Fatalf("Refresh() token expiry = %v, want %v", response.GetTokenExpires().AsTime(), accessExpires)
	}
	if !response.GetTokenRefreshExpires().AsTime().Equal(refreshExpires) {
		t.Fatalf("Refresh() refresh expiry = %v, want %v", response.GetTokenRefreshExpires().AsTime(), refreshExpires)
	}
}
