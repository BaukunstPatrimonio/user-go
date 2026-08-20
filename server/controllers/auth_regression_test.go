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
	"github.com/BaukunstPatrimonio/user-go/server/services"
	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	entModels "github.com/alvarotor/entitier-go/models"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/reflect/protoreflect"
	"gorm.io/gorm"
)

type authRegressionService struct {
	services.IUserService
	user        *models.User
	createCalls int
	updateCalls int
}

func (s *authRegressionService) GetByEmail(_ context.Context, email string) (*models.User, error) {
	if s.user == nil || s.user.Email != email {
		return nil, entModels.ErrNotFound
	}
	return s.user, nil
}

func (s *authRegressionService) GetByCode(_ context.Context, code string) (*models.User, error) {
	if s.user == nil || s.user.Code != code {
		return nil, models.ErrUserNotFound
	}
	return s.user, nil
}

func (s *authRegressionService) Create(_ context.Context, user models.User) (models.User, error) {
	s.createCalls++
	if user.ID == 0 {
		user.ID = 42
	}
	s.user = &user
	return user, nil
}

func (s *authRegressionService) Update(_ context.Context, id uint, user models.User) error {
	if user.ID != id {
		return errors.New("updated user ID does not match")
	}
	s.updateCalls++
	s.user = &user
	return nil
}

func (s *authRegressionService) ValidateSvc(_ context.Context, email string) error {
	if s.user == nil || s.user.Email != email {
		return models.ErrUserNotFound
	}
	s.user.Validated = true
	return nil
}

func (s *authRegressionService) LogOutSvc(_ context.Context, email string) error {
	if s.user == nil || s.user.Email != email {
		return models.ErrUserNotFound
	}
	s.user.Code = "OUT"
	s.user.CodeRefresh = "OUT"
	s.user.CodeExpire = time.Now().UTC()
	return nil
}

func TestLoginContractRemainsPasswordlessAndReturnsNoTokens(t *testing.T) {
	requestFields := (&pb.UserLoginRequest{}).ProtoReflect().Descriptor().Fields()
	if requestFields.ByName(protoreflect.Name("password")) != nil {
		t.Fatal("UserLoginRequest unexpectedly contains a password field")
	}

	responseFields := (&pb.UserLoginResponse{}).ProtoReflect().Descriptor().Fields()
	if responseFields.ByName(protoreflect.Name("token")) != nil || responseFields.ByName(protoreflect.Name("token_refresh")) != nil {
		t.Fatal("UserLoginResponse unexpectedly contains authentication tokens")
	}
	if got, want := string((&pb.UserLoginResponse{}).ProtoReflect().Descriptor().FullName()), "user_pb.UserLoginResponse"; got != want {
		t.Fatalf("Login response type = %q, want %q", got, want)
	}

	service := pb.File_server_user_pb_user_proto.Services().ByName("User")
	loginMethod := service.Methods().ByName("Login")
	if loginMethod == nil || loginMethod.Input().FullName() != "user_pb.UserLoginRequest" || loginMethod.Output().FullName() != "user_pb.UserLoginResponse" {
		t.Fatalf("Login method = %#v, want original request and response types", loginMethod)
	}
}

func TestLoginWithPasswordContractIsAdditiveAndReusesTokenResponse(t *testing.T) {
	service := pb.File_server_user_pb_user_proto.Services().ByName("User")
	method := service.Methods().ByName("LoginWithPassword")
	if method == nil || method.Input().FullName() != "user_pb.UserLoginWithPasswordRequest" || method.Output().FullName() != "user_pb.UserTokenResponse" {
		t.Fatalf("LoginWithPassword method = %#v, want new request and existing token response", method)
	}

	fields := (&pb.UserLoginWithPasswordRequest{}).ProtoReflect().Descriptor().Fields()
	want := []struct {
		name   protoreflect.Name
		number protoreflect.FieldNumber
	}{
		{name: "email", number: 1},
		{name: "password", number: 2},
		{name: "browser", number: 3},
		{name: "browser_version", number: 4},
		{name: "operating_system", number: 5},
		{name: "operating_system_version", number: 6},
		{name: "cpu", number: 7},
		{name: "language", number: 8},
		{name: "timezone", number: 9},
		{name: "cookies_enabled", number: 10},
		{name: "phone_e164", number: 11},
	}
	if fields.Len() != len(want) {
		t.Fatalf("UserLoginWithPasswordRequest fields = %d, want %d", fields.Len(), len(want))
	}
	for _, expected := range want {
		field := fields.ByName(expected.name)
		if field == nil || field.Number() != expected.number {
			t.Fatalf("UserLoginWithPasswordRequest.%s = %#v, want field number %d", expected.name, field, expected.number)
		}
	}
}

func TestRegisterWithPasswordContractIsAdditiveAndReturnsRegistrationOnly(t *testing.T) {
	service := pb.File_server_user_pb_user_proto.Services().ByName("User")
	method := service.Methods().ByName("RegisterWithPassword")
	if method == nil || method.Input().FullName() != "user_pb.UserRegisterWithPasswordRequest" || method.Output().FullName() != "user_pb.UserRegisterWithPasswordResponse" {
		t.Fatalf("RegisterWithPassword method = %#v, want additive registration request/response", method)
	}

	requestFields := (&pb.UserRegisterWithPasswordRequest{}).ProtoReflect().Descriptor().Fields()
	requestWant := []struct {
		name   protoreflect.Name
		number protoreflect.FieldNumber
	}{
		{name: "email", number: 1},
		{name: "name", number: 2},
		{name: "password", number: 3},
		{name: "browser", number: 4},
		{name: "browser_version", number: 5},
		{name: "operating_system", number: 6},
		{name: "operating_system_version", number: 7},
		{name: "cpu", number: 8},
		{name: "language", number: 9},
		{name: "timezone", number: 10},
		{name: "cookies_enabled", number: 11},
		{name: "phone_e164", number: 12},
	}
	if requestFields.Len() != len(requestWant) {
		t.Fatalf("UserRegisterWithPasswordRequest fields = %d, want %d", requestFields.Len(), len(requestWant))
	}
	for _, expected := range requestWant {
		field := requestFields.ByName(expected.name)
		if field == nil || field.Number() != expected.number {
			t.Fatalf("UserRegisterWithPasswordRequest.%s = %#v, want field number %d", expected.name, field, expected.number)
		}
	}

	responseFields := (&pb.UserRegisterWithPasswordResponse{}).ProtoReflect().Descriptor().Fields()
	responseWant := []struct {
		name   protoreflect.Name
		number protoreflect.FieldNumber
	}{
		{name: "user_id", number: 1},
		{name: "verification_code", number: 2},
		{name: "code_expires", number: 3},
		{name: "status", number: 4},
	}
	if responseFields.Len() != len(responseWant) {
		t.Fatalf("UserRegisterWithPasswordResponse fields = %d, want %d", responseFields.Len(), len(responseWant))
	}
	for _, expected := range responseWant {
		field := responseFields.ByName(expected.name)
		if field == nil || field.Number() != expected.number {
			t.Fatalf("UserRegisterWithPasswordResponse.%s = %#v, want field number %d", expected.name, field, expected.number)
		}
	}
	if responseFields.ByName("token") != nil || responseFields.ByName("token_refresh") != nil || responseFields.ByName("password_hash") != nil {
		t.Fatal("registration response unexpectedly exposes tokens or password credentials")
	}
}

func TestSetPhoneContractIsAdditiveAndUsesAuthenticatedIdentity(t *testing.T) {
	service := pb.File_server_user_pb_user_proto.Services().ByName("User")
	method := service.Methods().ByName("SetPhone")
	if method == nil || method.Input().FullName() != "user_pb.UserSetPhoneRequest" || method.Output().FullName() != "user_pb.UserResponse" {
		t.Fatalf("SetPhone method = %#v, want authenticated request and existing user response", method)
	}

	fields := (&pb.UserSetPhoneRequest{}).ProtoReflect().Descriptor().Fields()
	if fields.Len() != 2 {
		t.Fatalf("UserSetPhoneRequest fields = %d, want 2", fields.Len())
	}
	auth := fields.ByName("auth")
	if auth == nil || auth.Number() != 1 || auth.Message().FullName() != "user_pb.UserTokenRequest" {
		t.Fatalf("UserSetPhoneRequest.auth = %#v, want UserTokenRequest field 1", auth)
	}
	phone := fields.ByName("phone_e164")
	if phone == nil || phone.Number() != 2 {
		t.Fatalf("UserSetPhoneRequest.phone_e164 = %#v, want field 2", phone)
	}
	for _, forbidden := range []protoreflect.Name{"user_id", "email", "password", "phone_verified"} {
		if fields.ByName(forbidden) != nil {
			t.Fatalf("UserSetPhoneRequest unexpectedly contains %q", forbidden)
		}
	}
}

func TestPasswordResetContractsAreAdditiveAndReturnNoTokens(t *testing.T) {
	service := pb.File_server_user_pb_user_proto.Services().ByName("User")
	requestMethod := service.Methods().ByName("RequestPasswordReset")
	if requestMethod == nil || requestMethod.Input().FullName() != "user_pb.UserRequestPasswordResetRequest" || requestMethod.Output().FullName() != "user_pb.UserRequestPasswordResetResponse" {
		t.Fatalf("RequestPasswordReset method = %#v, want additive reset request contract", requestMethod)
	}
	resetMethod := service.Methods().ByName("ResetPassword")
	if resetMethod == nil || resetMethod.Input().FullName() != "user_pb.UserResetPasswordRequest" || resetMethod.Output().FullName() != "user_pb.UserResetPasswordResponse" {
		t.Fatalf("ResetPassword method = %#v, want additive reset completion contract", resetMethod)
	}

	requestFields := (&pb.UserRequestPasswordResetRequest{}).ProtoReflect().Descriptor().Fields()
	if requestFields.Len() != 1 || requestFields.ByName("email").Number() != 1 {
		t.Fatalf("UserRequestPasswordResetRequest fields = %#v, want email=1", requestFields)
	}
	requestResponseFields := (&pb.UserRequestPasswordResetResponse{}).ProtoReflect().Descriptor().Fields()
	requestResponseWant := []struct {
		name   protoreflect.Name
		number protoreflect.FieldNumber
	}{{"reset_token", 1}, {"expires_at", 2}, {"status", 3}}
	if requestResponseFields.Len() != len(requestResponseWant) {
		t.Fatalf("UserRequestPasswordResetResponse fields = %d, want %d", requestResponseFields.Len(), len(requestResponseWant))
	}
	for _, expected := range requestResponseWant {
		field := requestResponseFields.ByName(expected.name)
		if field == nil || field.Number() != expected.number {
			t.Fatalf("UserRequestPasswordResetResponse.%s = %#v, want %d", expected.name, field, expected.number)
		}
	}

	resetFields := (&pb.UserResetPasswordRequest{}).ProtoReflect().Descriptor().Fields()
	if resetFields.Len() != 2 || resetFields.ByName("reset_token").Number() != 1 || resetFields.ByName("new_password").Number() != 2 {
		t.Fatalf("UserResetPasswordRequest fields = %#v, want reset_token=1/new_password=2", resetFields)
	}
	resetResponseFields := (&pb.UserResetPasswordResponse{}).ProtoReflect().Descriptor().Fields()
	if resetResponseFields.Len() != 1 || resetResponseFields.ByName("status").Number() != 1 {
		t.Fatalf("UserResetPasswordResponse fields = %#v, want status=1", resetResponseFields)
	}
	if resetResponseFields.ByName("token") != nil || resetResponseFields.ByName("token_refresh") != nil || resetResponseFields.ByName("password_hash") != nil {
		t.Fatal("password reset response unexpectedly exposes tokens or credentials")
	}
}

func TestLoginCreatesAbsentUserWithValidationCodeAndDevice(t *testing.T) {
	controller, service, conf := newAuthRegressionController(nil)
	device := authRegressionDevice()
	login := dto.UserLogin{Email: "new@example.com", DeviceInfo: device}
	before := time.Now().UTC()

	statusCode, code, err := controller.Login(context.Background(), login)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("Login() status = %d, want %d", statusCode, http.StatusOK)
	}
	if service.createCalls != 1 || service.updateCalls != 0 {
		t.Fatalf("Login() persistence calls = create:%d update:%d, want 1/0", service.createCalls, service.updateCalls)
	}
	if service.user == nil || service.user.ID != 42 || service.user.Email != login.Email {
		t.Fatalf("created user = %#v, want ID 42 and email %q", service.user, login.Email)
	}
	if code != service.user.Code || len(code) != conf.SizeRandomStringValidation {
		t.Fatalf("validation code = %q, want stored code with length %d", code, conf.SizeRandomStringValidation)
	}
	if len(service.user.CodeRefresh) != conf.SizeRandomStringValidationRefresh {
		t.Fatalf("refresh code length = %d, want %d", len(service.user.CodeRefresh), conf.SizeRandomStringValidationRefresh)
	}
	if service.user.DeviceInfo != device {
		t.Fatalf("stored device = %#v, want %#v", service.user.DeviceInfo, device)
	}
	if service.user.Validated {
		t.Fatal("created user is validated, want current unvalidated behavior")
	}
	if service.user.CodeExpire.Before(before.Add(9*time.Minute+59*time.Second)) || service.user.CodeExpire.After(time.Now().UTC().Add(10*time.Minute+time.Second)) {
		t.Fatalf("code expiry = %v, want approximately ten minutes from now", service.user.CodeExpire)
	}
}

func TestLoginExistingUserRotatesCodesAndPreservesValidationState(t *testing.T) {
	user := authRegressionUser()
	user.Validated = true
	user.Code = strings.Repeat("z", 16)
	user.CodeRefresh = strings.Repeat("z", 8)
	controller, service, conf := newAuthRegressionController(user)
	device := authRegressionDevice()
	device.Language = "es-ES"

	statusCode, code, err := controller.Login(context.Background(), dto.UserLogin{Email: user.Email, DeviceInfo: device})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if statusCode != http.StatusOK || len(code) != conf.SizeRandomStringValidation {
		t.Fatalf("Login() = status %d code %q, want status 200 and length %d", statusCode, code, conf.SizeRandomStringValidation)
	}
	if service.createCalls != 0 || service.updateCalls != 1 {
		t.Fatalf("Login() persistence calls = create:%d update:%d, want 0/1", service.createCalls, service.updateCalls)
	}
	if !service.user.Validated {
		t.Fatal("Login() changed an existing validated account to unvalidated")
	}
	if service.user.DeviceInfo != device || service.user.Code != code || len(service.user.CodeRefresh) != conf.SizeRandomStringValidationRefresh {
		t.Fatalf("updated user = %#v, want new codes and supplied device", service.user)
	}
}

func TestValidateValidCodeValidatesAndReturnsCompatibleTokenPair(t *testing.T) {
	user := authRegressionUser()
	user.Validated = false
	controller, service, conf := newAuthRegressionController(user)

	statusCode, tokens, err := controller.Validate(context.Background(), user.Code)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("Validate() status = %d, want %d", statusCode, http.StatusOK)
	}
	if !service.user.Validated {
		t.Fatal("Validate() left account unvalidated")
	}
	if tokens.Email != user.Email || tokens.Token == "" || tokens.TokenRefresh == "" {
		t.Fatalf("Validate() tokens = %#v, want email and both tokens", tokens)
	}

	accessClaims := &dto.ClaimsResponse{}
	accessToken := parseAuthRegressionToken(t, tokens.Token, conf.JWTKey, accessClaims)
	if accessToken.Method.Alg() != jwt.SigningMethodHS256.Alg() {
		t.Fatalf("access token algorithm = %q, want %q", accessToken.Method.Alg(), jwt.SigningMethodHS256.Alg())
	}
	if accessClaims.Email != user.Email || accessClaims.Admin != user.Admin || accessClaims.SuperAdmin != user.SuperAdmin || accessClaims.DeviceInfo != user.DeviceInfo {
		t.Fatalf("access claims = %#v, want existing identity and device claims", accessClaims)
	}
	if accessClaims.Issuer != conf.Issuer || accessClaims.ExpiresAt == nil {
		t.Fatalf("access registered claims = %#v, want issuer and expiry", accessClaims.RegisteredClaims)
	}

	refreshClaims := &dto.ClaimsRefreshResponse{}
	refreshToken := parseAuthRegressionToken(t, tokens.TokenRefresh, conf.JWTKey, refreshClaims)
	if refreshToken.Method.Alg() != jwt.SigningMethodHS256.Alg() || refreshClaims.CodeRefresh != user.CodeRefresh || refreshClaims.DeviceInfo != user.DeviceInfo {
		t.Fatalf("refresh claims = %#v, want HS256, stored refresh code, and device", refreshClaims)
	}
	if refreshClaims.Issuer != conf.Issuer || refreshClaims.ExpiresAt == nil {
		t.Fatalf("refresh registered claims = %#v, want issuer and expiry", refreshClaims.RegisteredClaims)
	}
}

func TestTokenToUserResolvesValidAccessTokenAndPreservesDeviceCheck(t *testing.T) {
	user := authRegressionUser()
	controller, _, conf := newAuthRegressionController(user)
	claims := &dto.ClaimsResponse{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
			Issuer:    conf.Issuer,
		},
		DeviceInfo: user.DeviceInfo,
		Email:      user.Email,
		Admin:      user.Admin,
		SuperAdmin: user.SuperAdmin,
	}
	tokenString, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(conf.JWTKey)
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}

	resolved, err := controller.TokenToUser(
		context.Background(), tokenString,
		user.Browser, user.BrowserVersion,
		user.OperatingSystem, user.OperatingSystemVersion,
		user.Cpu, user.Language, user.Timezone, user.CookiesEnabled,
	)
	if err != nil {
		t.Fatalf("TokenToUser() error = %v", err)
	}
	if resolved != user || resolved.Email != user.Email || resolved.Name != user.Name || resolved.Admin != user.Admin || resolved.SuperAdmin != user.SuperAdmin {
		t.Fatalf("TokenToUser() user = %#v, want original user %#v", resolved, user)
	}

	_, err = controller.TokenToUser(
		context.Background(), tokenString,
		"DifferentBrowser", user.BrowserVersion,
		user.OperatingSystem, user.OperatingSystemVersion,
		user.Cpu, user.Language, user.Timezone, user.CookiesEnabled,
	)
	if !errors.Is(err, models.ErrSecurityMismatch) {
		t.Fatalf("TokenToUser() device mismatch error = %v, want %v", err, models.ErrSecurityMismatch)
	}
}

func TestLogOutPreservesCurrentSessionInvalidation(t *testing.T) {
	user := authRegressionUser()
	controller, service, _ := newAuthRegressionController(user)
	before := time.Now().UTC()

	statusCode, err := controller.LogOut(context.Background(), user.Email)
	if err != nil {
		t.Fatalf("LogOut() error = %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("LogOut() status = %d, want %d", statusCode, http.StatusOK)
	}
	if service.user.Code != "OUT" || service.user.CodeRefresh != "OUT" {
		t.Fatalf("logout codes = %q/%q, want OUT/OUT", service.user.Code, service.user.CodeRefresh)
	}
	if service.user.CodeExpire.Before(before) || service.user.CodeExpire.After(time.Now().UTC()) {
		t.Fatalf("logout expiry = %v, want current UTC time", service.user.CodeExpire)
	}
}

func newAuthRegressionController(user *models.User) (*controllerUser, *authRegressionService, *models.Config) {
	service := &authRegressionService{user: user}
	conf := &models.Config{
		RandomStringValidation:            "abcdef0123456789",
		RandomStringValidationRefresh:     "abcdef0123456789",
		SizeRandomStringValidation:        16,
		SizeRandomStringValidationRefresh: 8,
		Issuer:                            "auth-regression-test",
		JWTKey:                            []byte("auth-regression-test-secret"),
		TokenExpirationTime:               300,
		TokenExpirationTimeRefresh:        600,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &controllerUser{IUserService: service, log: logger, conf: conf}, service, conf
}

func authRegressionUser() *models.User {
	return &models.User{
		Model:       gorm.Model{ID: 583},
		DeviceInfo:  authRegressionDevice(),
		Email:       "person@example.com",
		Name:        "Existing Person",
		ProfilePic:  "profile.png",
		Admin:       true,
		SuperAdmin:  false,
		Validated:   true,
		Code:        strings.Repeat("c", 16),
		CodeRefresh: strings.Repeat("r", 8),
		CodeExpire:  time.Now().UTC().Add(10 * time.Minute),
		Bucket:      "profile-bucket",
	}
}

func authRegressionDevice() models.DeviceInfo {
	return models.DeviceInfo{
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

func parseAuthRegressionToken(t *testing.T, tokenString string, key []byte, claims jwt.Claims) *jwt.Token {
	t.Helper()
	token, err := jwt.ParseWithClaims(tokenString, claims, func(_ *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !token.Valid {
		t.Fatal("token is invalid")
	}
	return token
}
