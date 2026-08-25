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
)

const registrationFakePassword = "phase-three-fake-password!"

type passwordRegistrationService struct {
	services.IUserService
	user              *models.User
	credential        *models.PasswordCredential
	createErr         error
	createCalls       int
	credentialCreates int
	sessionUpdates    int
}

func (s *passwordRegistrationService) PasswordRegistrationEmailExists(_ context.Context, email string) (bool, error) {
	return s.user != nil && strings.EqualFold(s.user.Email, email), nil
}

func (s *passwordRegistrationService) CreatePasswordUser(_ context.Context, user models.User, passwordHash string) (*models.User, error) {
	s.createCalls++
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.user != nil {
		return nil, models.ErrUserAlreadyExists
	}
	user.ID = 583
	s.user = &user
	s.credential = &models.PasswordCredential{UserID: user.ID, PasswordHash: passwordHash}
	s.credentialCreates++
	return s.user, nil
}

func (s *passwordRegistrationService) GetByCode(_ context.Context, code string) (*models.User, error) {
	if s.user == nil || s.user.Code != code {
		return nil, models.ErrUserNotFound
	}
	return s.user, nil
}

func (s *passwordRegistrationService) ValidateSvc(_ context.Context, email string) error {
	if s.user == nil || s.user.Email != email {
		return models.ErrUserNotFound
	}
	s.user.Validated = true
	return nil
}

func (s *passwordRegistrationService) GetByEmail(_ context.Context, email string) (*models.User, error) {
	if s.user == nil || s.user.Email != email {
		return nil, entModels.ErrNotFound
	}
	return s.user, nil
}

func (s *passwordRegistrationService) GetByPhone(_ context.Context, phoneE164 string) (*models.User, error) {
	if s.user == nil || s.user.PhoneE164 == nil || *s.user.PhoneE164 != phoneE164 {
		return nil, models.ErrUserNotFound
	}
	return s.user, nil
}

func (s *passwordRegistrationService) GetPasswordCredential(_ context.Context, userID uint) (*models.PasswordCredential, error) {
	if s.credential == nil || s.credential.UserID != userID {
		return nil, models.ErrCredentialNotFound
	}
	return s.credential, nil
}

func (s *passwordRegistrationService) StartPasswordSession(_ context.Context, userID uint, device models.DeviceInfo, code string, codeExpire time.Time, codeRefresh string) error {
	if s.user == nil || s.user.ID != userID {
		return models.ErrUserNotFound
	}
	s.sessionUpdates++
	s.user.DeviceInfo = device
	s.user.Code = code
	s.user.CodeExpire = codeExpire
	s.user.CodeRefresh = codeRefresh
	return nil
}

func TestRegisterWithPasswordCreatesUnvalidatedUserAndArgonCredential(t *testing.T) {
	controller, service, conf := newPasswordRegistrationController()
	device := authRegressionDevice()
	before := time.Now().UTC()

	statusCode, result, err := controller.RegisterWithPassword(context.Background(), dto.UserRegisterWithPassword{
		Email: "  New.Person@Example.COM ", Name: "New Person", Password: registrationFakePassword, DeviceInfo: device,
	})
	if err != nil || statusCode != http.StatusCreated {
		t.Fatalf("RegisterWithPassword() = status %d result %#v error %v, want created", statusCode, result, err)
	}
	if service.createCalls != 1 || service.credentialCreates != 1 || service.user == nil || service.credential == nil {
		t.Fatalf("registration persistence = calls %d/%d user %#v credential %#v", service.createCalls, service.credentialCreates, service.user, service.credential)
	}
	if service.user.Email != "new.person@example.com" || service.user.Name != "New Person" || service.user.ID != 583 || result.UserID != 583 {
		t.Fatalf("created identity/result = %#v/%#v", service.user, result)
	}
	if service.user.PhoneE164 != nil {
		t.Fatalf("registration without phone stored %#v, want NULL", service.user.PhoneE164)
	}
	if service.user.Validated || service.user.Admin || service.user.SuperAdmin {
		t.Fatalf("created account flags = validated:%v admin:%v super:%v, want all false", service.user.Validated, service.user.Admin, service.user.SuperAdmin)
	}
	if service.user.DeviceInfo != device {
		t.Fatalf("stored device = %#v, want %#v", service.user.DeviceInfo, device)
	}
	if len(service.user.Code) != conf.SizeRandomStringValidation || result.VerificationCode != service.user.Code {
		t.Fatalf("verification code = %q/%q, want stored configured-length code", service.user.Code, result.VerificationCode)
	}
	for _, character := range service.user.Code {
		if !strings.ContainsRune(conf.RandomStringValidation, character) {
			t.Fatalf("verification code %q contains character outside configured alphabet", service.user.Code)
		}
	}
	if len(service.user.CodeRefresh) != conf.SizeRandomStringValidationRefresh {
		t.Fatalf("refresh code length = %d, want %d", len(service.user.CodeRefresh), conf.SizeRandomStringValidationRefresh)
	}
	for _, character := range service.user.CodeRefresh {
		if !strings.ContainsRune(conf.RandomStringValidationRefresh, character) {
			t.Fatalf("refresh code %q contains character outside configured alphabet", service.user.CodeRefresh)
		}
	}
	if service.user.CodeExpire.Before(before.Add(9*time.Minute+59*time.Second)) || service.user.CodeExpire.After(time.Now().UTC().Add(10*time.Minute+time.Second)) || !result.CodeExpires.Equal(service.user.CodeExpire) {
		t.Fatalf("verification expiry = %v/%v, want approximately ten minutes", service.user.CodeExpire, result.CodeExpires)
	}
	if service.credential.UserID != service.user.ID || !strings.HasPrefix(service.credential.PasswordHash, "$argon2id$") || service.credential.PasswordHash == registrationFakePassword {
		t.Fatalf("stored credential = user:%d hash-prefix:%q", service.credential.UserID, service.credential.PasswordHash)
	}
	valid, verifyErr := controller.passwords.VerifyPassword(registrationFakePassword, service.credential.PasswordHash)
	if verifyErr != nil || !valid {
		t.Fatalf("stored credential verification = %v, %v, want true, nil", valid, verifyErr)
	}
}

func TestRegisterWithPasswordProtectsExistingAccount(t *testing.T) {
	controller, service, _ := newPasswordRegistrationController()
	existing := authRegressionUser()
	existing.Email = "Existing@Example.com"
	existingCredential := &models.PasswordCredential{UserID: existing.ID, PasswordHash: "$argon2id$existing-hash"}
	service.user = existing
	service.credential = existingCredential
	beforeUser := *existing
	beforeCredential := *existingCredential

	statusCode, result, err := controller.RegisterWithPassword(context.Background(), dto.UserRegisterWithPassword{
		Email: "existing@example.com", Name: "Attacker", Password: registrationFakePassword, DeviceInfo: authRegressionDevice(),
	})
	if statusCode != http.StatusConflict || !errors.Is(err, models.ErrUserAlreadyExists) {
		t.Fatalf("RegisterWithPassword(existing) = status %d result %#v error %v, want conflict", statusCode, result, err)
	}
	if service.createCalls != 0 || *service.user != beforeUser || *service.credential != beforeCredential {
		t.Fatalf("existing account changed: calls %d user %#v credential %#v", service.createCalls, service.user, service.credential)
	}
}

func TestPasswordAccountRegisterValidateAndLoginLifecycle(t *testing.T) {
	controller, service, _ := newPasswordRegistrationController()
	device := authRegressionDevice()
	registrationStatus, registration, err := controller.RegisterWithPassword(context.Background(), dto.UserRegisterWithPassword{
		Email: "lifecycle@example.com", Name: "Lifecycle User", Password: registrationFakePassword, PhoneE164: "  +34600111222  ", DeviceInfo: device,
	})
	if err != nil || registrationStatus != http.StatusCreated {
		t.Fatalf("RegisterWithPassword() = %d, %#v, %v", registrationStatus, registration, err)
	}
	if service.user.Validated {
		t.Fatal("registration authenticated user before Validate")
	}
	if service.user.PhoneE164 == nil || *service.user.PhoneE164 != "+34600111222" {
		t.Fatalf("stored phone = %#v, want canonical E.164", service.user.PhoneE164)
	}

	validateStatus, initialTokens, err := controller.Validate(context.Background(), registration.VerificationCode)
	if err != nil || validateStatus != http.StatusOK || initialTokens.Token == "" || initialTokens.TokenRefresh == "" || !service.user.Validated {
		t.Fatalf("Validate() = %d, %#v, %v validated:%v", validateStatus, initialTokens, err, service.user.Validated)
	}

	loginStatus, laterTokens, err := controller.LoginWithPassword(context.Background(), dto.UserLoginWithPassword{
		Email: service.user.Email, Password: registrationFakePassword, DeviceInfo: device,
	})
	if err != nil || loginStatus != http.StatusOK || laterTokens.Token == "" || laterTokens.TokenRefresh == "" || service.sessionUpdates != 1 {
		t.Fatalf("LoginWithPassword() = %d, %#v, %v sessions:%d", loginStatus, laterTokens, err, service.sessionUpdates)
	}
	phoneStatus, phoneTokens, err := controller.LoginWithPassword(context.Background(), dto.UserLoginWithPassword{
		PhoneE164: *service.user.PhoneE164, Password: registrationFakePassword, DeviceInfo: device,
	})
	if err != nil || phoneStatus != http.StatusOK || phoneTokens.Token == "" || phoneTokens.TokenRefresh == "" || service.sessionUpdates != 2 {
		t.Fatalf("LoginWithPassword(phone) = %d, %#v, %v sessions:%d", phoneStatus, phoneTokens, err, service.sessionUpdates)
	}
}

func TestRegisterWithPasswordRejectsDuplicatePhoneWithoutChangingAccount(t *testing.T) {
	controller, service, _ := newPasswordRegistrationController()
	phone := "+34600111222"
	existing := authRegressionUser()
	existing.PhoneE164 = &phone
	service.user = existing
	before := *existing

	statusCode, _, err := controller.RegisterWithPassword(context.Background(), dto.UserRegisterWithPassword{
		Email: "different@example.com", Name: "Different", Password: registrationFakePassword, PhoneE164: phone,
	})
	if statusCode != http.StatusConflict || !errors.Is(err, models.ErrPhoneAlreadyExists) || service.createCalls != 0 || *service.user != before {
		t.Fatalf("duplicate phone = status %d error %v calls %d user %#v", statusCode, err, service.createCalls, service.user)
	}
}

func TestRegisterWithPasswordRejectsInvalidPasswordWithoutPersistence(t *testing.T) {
	controller, service, _ := newPasswordRegistrationController()
	statusCode, _, err := controller.RegisterWithPassword(context.Background(), dto.UserRegisterWithPassword{
		Email: "new@example.com", Name: "New User", Password: "", DeviceInfo: authRegressionDevice(),
	})
	if statusCode != http.StatusBadRequest || !errors.Is(err, models.ErrInvalidPassword) || service.createCalls != 0 {
		t.Fatalf("RegisterWithPassword(empty) = status %d error %v creates %d", statusCode, err, service.createCalls)
	}
}

func TestRegisterWithPasswordAcceptsExistingHortaTechPassword(t *testing.T) {
	controller, service, _ := newPasswordRegistrationController()
	statusCode, _, err := controller.RegisterWithPassword(context.Background(), dto.UserRegisterWithPassword{
		Email: "existing-frontend@example.com", Name: "Existing Frontend", Password: "hola", DeviceInfo: authRegressionDevice(),
	})
	if err != nil || statusCode != http.StatusCreated || service.createCalls != 1 {
		t.Fatalf("RegisterWithPassword(hola) = status %d error %v creates %d", statusCode, err, service.createCalls)
	}
}

func newPasswordRegistrationController() (*controllerUser, *passwordRegistrationService, *models.Config) {
	passwords := passwordService.NewManager(passwordService.Parameters{
		Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
	})
	service := &passwordRegistrationService{}
	conf := &models.Config{
		RandomStringValidation:            "ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
		RandomStringValidationRefresh:     "abcdef0123456789",
		SizeRandomStringValidation:        16,
		SizeRandomStringValidationRefresh: 8,
		Issuer:                            "password-registration-test",
		JWTKey:                            []byte("password-registration-test-secret"),
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
