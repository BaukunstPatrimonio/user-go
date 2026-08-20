package controllers

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	"github.com/golang-jwt/jwt/v5"
)

type setPhoneService struct {
	*authRegressionService
	updateErr    error
	updateCalls  int
	updatedID    uint
	updatedPhone string
}

func (s *setPhoneService) UpdatePhoneIdentity(_ context.Context, userID uint, phoneE164 string) error {
	s.updateCalls++
	s.updatedID = userID
	s.updatedPhone = phoneE164
	return s.updateErr
}

func TestSetPhoneUsesAuthenticatedUserAndSupportsSetAndChange(t *testing.T) {
	user := authRegressionUser()
	baseController, _, conf := newAuthRegressionController(user)
	service := &setPhoneService{authRegressionService: &authRegressionService{user: user}}
	baseController.IUserService = service
	token := setPhoneAccessToken(t, user, conf)

	for index, supplied := range []string{"  +34600111222  ", "+447700900123"} {
		statusCode, updated, err := baseController.SetPhone(context.Background(), dto.UserSetPhone{
			Token: token, PhoneE164: supplied, DeviceInfo: user.DeviceInfo,
		})
		if err != nil || statusCode != http.StatusOK || updated != user {
			t.Fatalf("SetPhone(%q) = %d, %#v, %v", supplied, statusCode, updated, err)
		}
		want := []string{"+34600111222", "+447700900123"}[index]
		if service.updatedID != user.ID || service.updatedPhone != want || user.PhoneE164 == nil || *user.PhoneE164 != want {
			t.Fatalf("phone update = id %d phone %q model %#v, want authenticated ID %d/%q", service.updatedID, service.updatedPhone, user.PhoneE164, user.ID, want)
		}
	}
	if service.updateCalls != 2 {
		t.Fatalf("update calls = %d, want 2", service.updateCalls)
	}
}

func TestSetPhoneRejectsInvalidAuthenticationDevicePhoneAndDuplicate(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*dto.UserSetPhone, *setPhoneService)
		wantStatus int
		wantErr    error
	}{
		{name: "invalid token", mutate: func(r *dto.UserSetPhone, _ *setPhoneService) { r.Token = "not-a-jwt" }, wantStatus: http.StatusUnauthorized},
		{name: "device mismatch", mutate: func(r *dto.UserSetPhone, _ *setPhoneService) { r.Browser = "Different" }, wantStatus: http.StatusUnauthorized, wantErr: models.ErrSecurityMismatch},
		{name: "invalid phone", mutate: func(r *dto.UserSetPhone, _ *setPhoneService) { r.PhoneE164 = "600111222" }, wantStatus: http.StatusBadRequest, wantErr: models.ErrInvalidPhone},
		{name: "duplicate phone", mutate: func(_ *dto.UserSetPhone, s *setPhoneService) { s.updateErr = models.ErrPhoneAlreadyExists }, wantStatus: http.StatusConflict, wantErr: models.ErrPhoneAlreadyExists},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			user := authRegressionUser()
			controller, _, conf := newAuthRegressionController(user)
			service := &setPhoneService{authRegressionService: &authRegressionService{user: user}}
			controller.IUserService = service
			request := dto.UserSetPhone{Token: setPhoneAccessToken(t, user, conf), PhoneE164: "+34600111222", DeviceInfo: user.DeviceInfo}
			test.mutate(&request, service)
			statusCode, _, err := controller.SetPhone(context.Background(), request)
			if statusCode != test.wantStatus || (test.wantErr != nil && !errors.Is(err, test.wantErr)) || err == nil {
				t.Fatalf("SetPhone() = %d, %v, want %d/%v", statusCode, err, test.wantStatus, test.wantErr)
			}
			if test.name != "duplicate phone" && service.updateCalls != 0 {
				t.Fatalf("failed request performed %d updates", service.updateCalls)
			}
		})
	}
}

func TestSetPhoneDoesNotCreatePasswordCredentials(t *testing.T) {
	user := authRegressionUser()
	controller, _, conf := newAuthRegressionController(user)
	// The stub intentionally implements no credential creation or lookup methods.
	// A successful call therefore proves SetPhone only updates the identity column.
	service := &setPhoneService{authRegressionService: &authRegressionService{user: user}}
	controller.IUserService = service
	statusCode, _, err := controller.SetPhone(context.Background(), dto.UserSetPhone{
		Token: setPhoneAccessToken(t, user, conf), PhoneE164: "+34600111222", DeviceInfo: user.DeviceInfo,
	})
	if err != nil || statusCode != http.StatusOK || service.updateCalls != 1 {
		t.Fatalf("SetPhone(passwordless) = %d, %v updates %d, want success without credential calls", statusCode, err, service.updateCalls)
	}
}

func setPhoneAccessToken(t *testing.T, user *models.User, conf *models.Config) string {
	t.Helper()
	claims := &dto.ClaimsResponse{
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)), Issuer: conf.Issuer},
		DeviceInfo:       user.DeviceInfo, Email: user.Email, Admin: user.Admin, SuperAdmin: user.SuperAdmin,
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(conf.JWTKey)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	return token
}
