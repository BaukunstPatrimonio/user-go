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

type passwordLoginControllerStub struct {
	controllers.IControllerUser
	statusCode int
	token      *models.Token
	err        error
	login      dto.UserLoginWithPassword
}

func (s *passwordLoginControllerStub) LoginWithPassword(_ context.Context, login dto.UserLoginWithPassword) (int, *models.Token, error) {
	s.login = login
	return s.statusCode, s.token, s.err
}

func TestLoginWithPasswordRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name string
		req  *pb.UserLoginWithPasswordRequest
	}{
		{name: "missing email", req: &pb.UserLoginWithPasswordRequest{Password: "fake-password"}},
		{name: "malformed email", req: &pb.UserLoginWithPasswordRequest{Email: "not-an-email", Password: "fake-password"}},
		{name: "both identities", req: &pb.UserLoginWithPasswordRequest{Email: "person@example.com", PhoneE164: "+34600111222", Password: "fake-password"}},
		{name: "invalid phone", req: &pb.UserLoginWithPasswordRequest{PhoneE164: "600111222", Password: "fake-password"}},
		{name: "missing password", req: &pb.UserLoginWithPasswordRequest{Email: "person@example.com"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := &passwordLoginControllerStub{}
			server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))

			response, err := server.LoginWithPassword(context.Background(), test.req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("LoginWithPassword() error = %v, want InvalidArgument", err)
			}
			if response == nil || controller.login.Email != "" || controller.login.Password != "" {
				t.Fatalf("invalid request reached controller or returned nil response: login %#v response %#v", controller.login, response)
			}
		})
	}
}

func TestLoginWithPasswordMapsAuthenticationErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code codes.Code
		msg  string
	}{
		{name: "invalid credentials", err: models.ErrInvalidCredentials, code: codes.Unauthenticated, msg: models.ErrInvalidCredentials.Error()},
		{name: "wrapped invalid credentials", err: errors.Join(errors.New("authentication"), models.ErrInvalidCredentials), code: codes.Unauthenticated, msg: models.ErrInvalidCredentials.Error()},
		{name: "unvalidated", err: models.ErrAccountNotValidated, code: codes.FailedPrecondition, msg: "account_not_validated"},
		{name: "deadline", err: context.DeadlineExceeded, code: codes.DeadlineExceeded, msg: context.DeadlineExceeded.Error()},
		{name: "internal", err: errors.New("database unavailable"), code: codes.Internal, msg: "internal server error"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller := &passwordLoginControllerStub{err: test.err}
			server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))

			response, err := server.LoginWithPassword(context.Background(), validPasswordLoginRequest())
			if got := status.Code(err); got != test.code {
				t.Fatalf("LoginWithPassword() code = %v, want %v", got, test.code)
			}
			if got := status.Convert(err).Message(); got != test.msg {
				t.Fatalf("LoginWithPassword() message = %q, want %q", got, test.msg)
			}
			if response == nil {
				t.Fatal("LoginWithPassword() response = nil, want empty response")
			}
		})
	}
}

func TestLoginWithPasswordReturnsExistingTokenResponse(t *testing.T) {
	accessExpires := time.Date(2026, time.August, 20, 12, 0, 0, 0, time.UTC)
	refreshExpires := accessExpires.Add(24 * time.Hour)
	token := &models.Token{
		Email:               "person@example.com",
		Token:               "access-token",
		TokenExpires:        accessExpires,
		TokenRefresh:        "refresh-token",
		TokenRefreshExpires: refreshExpires,
	}
	controller := &passwordLoginControllerStub{statusCode: http.StatusOK, token: token}
	server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := validPasswordLoginRequest()
	req.Email = "Person@Example.COM"

	response, err := server.LoginWithPassword(context.Background(), req)
	if err != nil {
		t.Fatalf("LoginWithPassword() error = %v", err)
	}
	if response.GetEmail() != token.Email || response.GetToken() != token.Token || response.GetTokenRefresh() != token.TokenRefresh || response.GetStatus() != http.StatusOK {
		t.Fatalf("LoginWithPassword() response = %#v, want existing UserTokenResponse values", response)
	}
	if !response.GetTokenExpires().AsTime().Equal(accessExpires) || !response.GetTokenRefreshExpires().AsTime().Equal(refreshExpires) {
		t.Fatalf("LoginWithPassword() expiries = %v/%v, want %v/%v", response.GetTokenExpires(), response.GetTokenRefreshExpires(), accessExpires, refreshExpires)
	}
	if controller.login.Email != req.Email || controller.login.Password != req.Password || controller.login.DeviceInfo.Browser != req.Browser || controller.login.DeviceInfo.CookiesEnabled != req.CookiesEnabled {
		t.Fatalf("controller login = %#v, want request email/password/device mapping", controller.login)
	}
}

func TestLoginWithPasswordMapsCanonicalPhoneIdentity(t *testing.T) {
	controller := &passwordLoginControllerStub{statusCode: http.StatusOK, token: &models.Token{}}
	server := NewServer(controller, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := validPasswordLoginRequest()
	req.Email = ""
	req.PhoneE164 = "  +34600111222  "

	if _, err := server.LoginWithPassword(context.Background(), req); err != nil {
		t.Fatalf("LoginWithPassword(phone) error = %v", err)
	}
	if controller.login.Email != "" || controller.login.PhoneE164 != "+34600111222" || controller.login.Password != req.Password || controller.login.DeviceInfo != (models.DeviceInfo{
		Browser: req.Browser, BrowserVersion: req.BrowserVersion, OperatingSystem: req.OperatingSystem,
		OperatingSystemVersion: req.OperatingSystemVersion, Cpu: req.Cpu, Language: req.Language,
		Timezone: req.Timezone, CookiesEnabled: req.CookiesEnabled,
	}) {
		t.Fatalf("controller phone login = %#v, want canonical identity and existing device mapping", controller.login)
	}
}

func validPasswordLoginRequest() *pb.UserLoginWithPasswordRequest {
	return &pb.UserLoginWithPasswordRequest{
		Email:                  "person@example.com",
		Password:               "phase-two-fake-password!",
		Browser:                "Firefox",
		BrowserVersion:         "128",
		OperatingSystem:        "Linux",
		OperatingSystemVersion: "6.10",
		Cpu:                    "x86_64",
		Language:               "en-US",
		Timezone:               "Europe/Madrid",
		CookiesEnabled:         true,
	}
}
