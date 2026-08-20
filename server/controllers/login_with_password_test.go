package controllers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/dto"
	"github.com/BaukunstPatrimonio/user-go/server/models"
	passwordService "github.com/BaukunstPatrimonio/user-go/server/password"
	"github.com/BaukunstPatrimonio/user-go/server/services"
	entModels "github.com/alvarotor/entitier-go/models"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const passwordLoginFakePassword = "phase-two-fake-password!"

type passwordLoginService struct {
	services.IUserService
	user                *models.User
	credential          *models.PasswordCredential
	userLookupErr       error
	credentialLookupErr error
	credentialUpdateErr error
	sessionErr          error
	credentialUpdates   int
	sessionUpdates      int
	lastDevice          models.DeviceInfo
	lastCode            string
	lastCodeExpire      time.Time
	lastCodeRefresh     string
	lastReplacementHash string
}

func (s *passwordLoginService) UpdatePhoneIdentity(_ context.Context, userID uint, phoneE164 string) error {
	if s.user == nil || s.user.ID != userID {
		return models.ErrUserNotFound
	}
	s.user.PhoneE164 = &phoneE164
	return nil
}

func (s *passwordLoginService) GetByEmail(_ context.Context, email string) (*models.User, error) {
	if s.userLookupErr != nil {
		return nil, s.userLookupErr
	}
	if s.user == nil || s.user.Email != email {
		return nil, entModels.ErrNotFound
	}
	return s.user, nil
}

func (s *passwordLoginService) GetByPhone(_ context.Context, phoneE164 string) (*models.User, error) {
	if s.userLookupErr != nil {
		return nil, s.userLookupErr
	}
	if s.user == nil || s.user.PhoneE164 == nil || *s.user.PhoneE164 != phoneE164 {
		return nil, models.ErrUserNotFound
	}
	return s.user, nil
}

func (s *passwordLoginService) GetPasswordCredential(_ context.Context, userID uint) (*models.PasswordCredential, error) {
	if s.credentialLookupErr != nil {
		return nil, s.credentialLookupErr
	}
	if s.credential == nil || s.credential.UserID != userID {
		return nil, models.ErrCredentialNotFound
	}
	return s.credential, nil
}

func (s *passwordLoginService) UpdatePasswordCredentialHash(_ context.Context, userID uint, passwordHash string) error {
	s.credentialUpdates++
	s.lastReplacementHash = passwordHash
	if s.credentialUpdateErr != nil {
		return s.credentialUpdateErr
	}
	if s.credential == nil || s.credential.UserID != userID {
		return models.ErrCredentialNotFound
	}
	s.credential.PasswordHash = passwordHash
	return nil
}

func (s *passwordLoginService) StartPasswordSession(_ context.Context, userID uint, device models.DeviceInfo, code string, codeExpire time.Time, codeRefresh string) error {
	s.sessionUpdates++
	s.lastDevice = device
	s.lastCode = code
	s.lastCodeExpire = codeExpire
	s.lastCodeRefresh = codeRefresh
	if s.sessionErr != nil {
		return s.sessionErr
	}
	if s.user == nil || s.user.ID != userID {
		return models.ErrUserNotFound
	}
	s.user.DeviceInfo = device
	s.user.Code = code
	s.user.CodeExpire = codeExpire
	s.user.CodeRefresh = codeRefresh
	return nil
}

func TestLoginWithPasswordReturnsExistingTokenFormatAndPersistsFreshSession(t *testing.T) {
	controller, service, conf := newPasswordLoginController(t)
	service.user.Code = "OUT"
	service.user.CodeRefresh = "old-refresh-code"
	device := authRegressionDevice()
	device.Language = "es-ES"
	before := time.Now().UTC()

	statusCode, tokens, err := controller.LoginWithPassword(context.Background(), passwordLoginRequest(device, passwordLoginFakePassword))
	if err != nil {
		t.Fatalf("LoginWithPassword() error = %v", err)
	}
	if statusCode != http.StatusOK || tokens.Token == "" || tokens.TokenRefresh == "" {
		t.Fatalf("LoginWithPassword() = status %d tokens %#v, want status 200 and both tokens", statusCode, tokens)
	}
	if service.sessionUpdates != 1 || service.lastDevice != device {
		t.Fatalf("session persistence = calls:%d device:%#v, want one update with %#v", service.sessionUpdates, service.lastDevice, device)
	}
	if len(service.lastCodeRefresh) != conf.SizeRandomStringValidationRefresh || service.lastCodeRefresh == "old-refresh-code" {
		t.Fatalf("stored refresh code = %q, want fresh length %d", service.lastCodeRefresh, conf.SizeRandomStringValidationRefresh)
	}
	if len(service.lastCode) != conf.SizeRandomStringValidation || service.lastCodeExpire.Before(before) || service.lastCodeExpire.After(time.Now().UTC()) {
		t.Fatalf("reactivated access marker = %q/%v, want fresh marker expired at current time", service.lastCode, service.lastCodeExpire)
	}

	accessClaims := &dto.ClaimsResponse{}
	accessToken := parseAuthRegressionToken(t, tokens.Token, conf.JWTKey, accessClaims)
	if accessToken.Method.Alg() != jwt.SigningMethodHS256.Alg() || accessClaims.Email != service.user.Email || accessClaims.DeviceInfo != device || accessClaims.Admin != service.user.Admin || accessClaims.SuperAdmin != service.user.SuperAdmin {
		t.Fatalf("access claims = %#v, want existing HS256 claims with supplied device", accessClaims)
	}
	refreshClaims := &dto.ClaimsRefreshResponse{}
	parseAuthRegressionToken(t, tokens.TokenRefresh, conf.JWTKey, refreshClaims)
	if refreshClaims.CodeRefresh != service.lastCodeRefresh || refreshClaims.DeviceInfo != device {
		t.Fatalf("refresh claims = %#v, want persisted refresh code and supplied device", refreshClaims)
	}
	if tokens.TokenExpires.IsZero() || tokens.TokenRefreshExpires.IsZero() {
		t.Fatalf("token expirations = %v/%v, want both set", tokens.TokenExpires, tokens.TokenRefreshExpires)
	}

	resolved, err := controller.TokenToUser(
		context.Background(), tokens.Token,
		device.Browser, device.BrowserVersion,
		device.OperatingSystem, device.OperatingSystemVersion,
		device.Cpu, device.Language, device.Timezone, device.CookiesEnabled,
	)
	if err != nil || resolved.ID != service.user.ID {
		t.Fatalf("TokenToUser(password token) = %#v, %v, want user ID %d", resolved, err, service.user.ID)
	}
}

func TestLoginWithPasswordByPhoneUsesTheExistingTokenAndSessionFlow(t *testing.T) {
	controller, service, conf := newPasswordLoginController(t)
	phone := "+34600111222"
	service.user.PhoneE164 = &phone
	device := authRegressionDevice()
	device.Timezone = "Europe/London"

	statusCode, tokens, err := controller.LoginWithPassword(context.Background(), dto.UserLoginWithPassword{
		PhoneE164: "  +34600111222  ", Password: passwordLoginFakePassword, DeviceInfo: device,
	})
	if err != nil || statusCode != http.StatusOK || tokens.Token == "" || tokens.TokenRefresh == "" {
		t.Fatalf("LoginWithPassword(phone) = %d, %#v, %v, want success", statusCode, tokens, err)
	}
	if service.sessionUpdates != 1 || service.lastDevice != device {
		t.Fatalf("phone session = calls %d device %#v, want existing session flow", service.sessionUpdates, service.lastDevice)
	}
	claims := &dto.ClaimsResponse{}
	parseAuthRegressionToken(t, tokens.Token, conf.JWTKey, claims)
	if claims.Email != service.user.Email || claims.DeviceInfo != device {
		t.Fatalf("phone-login claims = %#v, want email-bound existing claims", claims)
	}
}

func TestLoginWithPasswordRequiresExactlyOneIdentity(t *testing.T) {
	controller, service, _ := newPasswordLoginController(t)
	for _, request := range []dto.UserLoginWithPassword{
		{Password: passwordLoginFakePassword},
		{Email: service.user.Email, PhoneE164: "+34600111222", Password: passwordLoginFakePassword},
		{PhoneE164: "600111222", Password: passwordLoginFakePassword},
	} {
		statusCode, tokens, err := controller.LoginWithPassword(context.Background(), request)
		if statusCode != http.StatusBadRequest || (!errors.Is(err, models.ErrInvalidLoginIdentity) && !errors.Is(err, models.ErrInvalidPhone)) {
			t.Fatalf("LoginWithPassword(%#v) = %d, %#v, %v, want invalid identity", request, statusCode, tokens, err)
		}
		if tokens.Token != "" || service.sessionUpdates != 0 {
			t.Fatal("invalid identity created a session")
		}
	}
}

func TestLoginWithPasswordPhoneFailuresRemainGeneric(t *testing.T) {
	for _, test := range []struct {
		name    string
		prepare func(*passwordLoginService)
		pass    string
	}{
		{name: "unknown phone", prepare: func(s *passwordLoginService) { s.user.PhoneE164 = nil }, pass: passwordLoginFakePassword},
		{name: "wrong password", pass: "obviously-wrong-password"},
		{name: "missing credential", prepare: func(s *passwordLoginService) { s.credential = nil }, pass: passwordLoginFakePassword},
	} {
		t.Run(test.name, func(t *testing.T) {
			controller, service, _ := newPasswordLoginController(t)
			phone := "+34600111222"
			service.user.PhoneE164 = &phone
			if test.prepare != nil {
				test.prepare(service)
			}
			statusCode, tokens, err := controller.LoginWithPassword(context.Background(), dto.UserLoginWithPassword{PhoneE164: phone, Password: test.pass, DeviceInfo: authRegressionDevice()})
			if statusCode != http.StatusUnauthorized || !errors.Is(err, models.ErrInvalidCredentials) || tokens.Token != "" || service.sessionUpdates != 0 {
				t.Fatalf("phone failure = %d, %#v, %v, want generic unauthorized", statusCode, tokens, err)
			}
		})
	}
}

func TestLoginWithPasswordByPhoneStillRequiresValidatedAccount(t *testing.T) {
	controller, service, _ := newPasswordLoginController(t)
	phone := "+34600111222"
	service.user.PhoneE164 = &phone
	service.user.Validated = false
	statusCode, tokens, err := controller.LoginWithPassword(context.Background(), dto.UserLoginWithPassword{
		PhoneE164: phone, Password: passwordLoginFakePassword, DeviceInfo: authRegressionDevice(),
	})
	if statusCode != http.StatusPreconditionFailed || !errors.Is(err, models.ErrAccountNotValidated) || tokens.Token != "" || service.sessionUpdates != 0 {
		t.Fatalf("unvalidated phone login = %d, %#v, %v, want existing validation gate", statusCode, tokens, err)
	}
}

func TestSetPhoneDoesNotGivePasswordlessAccountPasswordCapability(t *testing.T) {
	controller, service, conf := newPasswordLoginController(t)
	service.credential = nil
	statusCode, _, err := controller.SetPhone(context.Background(), dto.UserSetPhone{
		Token: setPhoneAccessToken(t, service.user, conf), PhoneE164: "+34600111222", DeviceInfo: service.user.DeviceInfo,
	})
	if err != nil || statusCode != http.StatusOK || service.user.PhoneE164 == nil {
		t.Fatalf("SetPhone(passwordless) = %d, %v phone %#v", statusCode, err, service.user.PhoneE164)
	}
	statusCode, tokens, err := controller.LoginWithPassword(context.Background(), dto.UserLoginWithPassword{
		PhoneE164: *service.user.PhoneE164, Password: passwordLoginFakePassword, DeviceInfo: service.user.DeviceInfo,
	})
	if statusCode != http.StatusUnauthorized || !errors.Is(err, models.ErrInvalidCredentials) || tokens.Token != "" || service.sessionUpdates != 0 {
		t.Fatalf("passwordless phone login = %d, %#v, %v, want generic unauthorized", statusCode, tokens, err)
	}
}

func TestLoginWithPasswordAuthenticationFailuresAreGeneric(t *testing.T) {
	tests := []struct {
		name     string
		prepare  func(*passwordLoginService)
		password string
	}{
		{name: "wrong password", password: "obviously-wrong-password"},
		{name: "unknown email", password: passwordLoginFakePassword, prepare: func(s *passwordLoginService) { s.user = nil }},
		{name: "missing credential", password: passwordLoginFakePassword, prepare: func(s *passwordLoginService) { s.credential = nil }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller, service, _ := newPasswordLoginController(t)
			if test.prepare != nil {
				test.prepare(service)
			}
			statusCode, tokens, err := controller.LoginWithPassword(context.Background(), passwordLoginRequest(authRegressionDevice(), test.password))
			if statusCode != http.StatusUnauthorized || !errors.Is(err, models.ErrInvalidCredentials) {
				t.Fatalf("LoginWithPassword() = status %d error %v, want 401/%v", statusCode, err, models.ErrInvalidCredentials)
			}
			if tokens.Token != "" || tokens.TokenRefresh != "" || service.sessionUpdates != 0 {
				t.Fatalf("failed login issued/persisted session: tokens %#v updates %d", tokens, service.sessionUpdates)
			}
		})
	}
}

func TestLoginWithPasswordRejectsUnvalidatedAccountAfterCorrectPassword(t *testing.T) {
	controller, service, _ := newPasswordLoginController(t)
	service.user.Validated = false

	statusCode, tokens, err := controller.LoginWithPassword(context.Background(), passwordLoginRequest(authRegressionDevice(), passwordLoginFakePassword))
	if statusCode != http.StatusPreconditionFailed || !errors.Is(err, models.ErrAccountNotValidated) {
		t.Fatalf("LoginWithPassword() = status %d error %v, want 412/%v", statusCode, err, models.ErrAccountNotValidated)
	}
	if tokens.Token != "" || tokens.TokenRefresh != "" || service.sessionUpdates != 0 {
		t.Fatalf("unvalidated login issued/persisted session: tokens %#v updates %d", tokens, service.sessionUpdates)
	}
}

func TestLoginWithPasswordUpgradesValidBcryptCredential(t *testing.T) {
	controller, service, _ := newPasswordLoginController(t)
	legacyHash, err := bcrypt.GenerateFromPassword([]byte(passwordLoginFakePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	service.credential.PasswordHash = string(legacyHash)

	statusCode, tokens, err := controller.LoginWithPassword(context.Background(), passwordLoginRequest(authRegressionDevice(), passwordLoginFakePassword))
	if err != nil || statusCode != http.StatusOK || tokens.Token == "" {
		t.Fatalf("LoginWithPassword(bcrypt) = status %d tokens %#v error %v, want success", statusCode, tokens, err)
	}
	if service.credentialUpdates != 1 || !strings.HasPrefix(service.lastReplacementHash, "$argon2id$") || service.credential.PasswordHash != service.lastReplacementHash {
		t.Fatalf("bcrypt upgrade = calls:%d hash prefix:%q, want one persisted Argon2id hash", service.credentialUpdates, service.lastReplacementHash)
	}
}

func TestLoginWithPasswordDoesNotAuthenticateWhenBcryptUpgradePersistenceFails(t *testing.T) {
	controller, service, _ := newPasswordLoginController(t)
	legacyHash, err := bcrypt.GenerateFromPassword([]byte(passwordLoginFakePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	service.credential.PasswordHash = string(legacyHash)
	service.credentialUpdateErr = errors.New("credential update failed")

	statusCode, tokens, err := controller.LoginWithPassword(context.Background(), passwordLoginRequest(authRegressionDevice(), passwordLoginFakePassword))
	if statusCode != http.StatusInternalServerError || err == nil {
		t.Fatalf("LoginWithPassword() = status %d error %v, want internal failure", statusCode, err)
	}
	if tokens.Token != "" || tokens.TokenRefresh != "" || service.sessionUpdates != 0 {
		t.Fatalf("failed bcrypt upgrade issued/persisted session: tokens %#v updates %d", tokens, service.sessionUpdates)
	}
}

func newPasswordLoginController(t *testing.T) (*controllerUser, *passwordLoginService, *models.Config) {
	t.Helper()
	passwords := passwordService.NewManager(passwordService.Parameters{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	hash, err := passwords.HashPassword(passwordLoginFakePassword)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	user := authRegressionUser()
	service := &passwordLoginService{
		user:       user,
		credential: &models.PasswordCredential{UserID: user.ID, PasswordHash: hash},
	}
	conf := &models.Config{
		RandomStringValidation:            "abcdef0123456789",
		RandomStringValidationRefresh:     "abcdef0123456789",
		SizeRandomStringValidation:        16,
		SizeRandomStringValidationRefresh: 8,
		Issuer:                            "password-login-test",
		JWTKey:                            []byte("password-login-test-secret"),
		TokenExpirationTime:               300,
		TokenExpirationTimeRefresh:        600,
	}
	controller := &controllerUser{
		IUserService: service,
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		conf:         conf,
		passwords:    passwords,
	}
	return controller, service, conf
}

func passwordLoginRequest(device models.DeviceInfo, password string) dto.UserLoginWithPassword {
	return dto.UserLoginWithPassword{
		Email:      "person@example.com",
		Password:   password,
		DeviceInfo: device,
	}
}
