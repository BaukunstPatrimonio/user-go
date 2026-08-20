package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	entModels "github.com/alvarotor/entitier-go/models"
	"gorm.io/gorm"
)

type passwordCredentialRepositoryStub struct {
	credentials map[uint]models.PasswordCredential
}

func (r *passwordCredentialRepositoryStub) Create(_ context.Context, credential models.PasswordCredential) (models.PasswordCredential, error) {
	if _, exists := r.credentials[credential.UserID]; exists {
		return models.PasswordCredential{}, gorm.ErrDuplicatedKey
	}
	r.credentials[credential.UserID] = credential
	return credential, nil
}

func (r *passwordCredentialRepositoryStub) GetAll(context.Context) ([]*models.PasswordCredential, error) {
	credentials := make([]*models.PasswordCredential, 0, len(r.credentials))
	for _, credential := range r.credentials {
		copy := credential
		credentials = append(credentials, &copy)
	}
	return credentials, nil
}

func (r *passwordCredentialRepositoryStub) Get(_ context.Context, userID uint, _ string) (*models.PasswordCredential, error) {
	credential, exists := r.credentials[userID]
	if !exists {
		return nil, entModels.ErrNotFound
	}
	copy := credential
	return &copy, nil
}

func (r *passwordCredentialRepositoryStub) Update(_ context.Context, userID uint, credential models.PasswordCredential) error {
	if _, exists := r.credentials[userID]; !exists {
		return entModels.ErrNotFound
	}
	r.credentials[userID] = credential
	return nil
}

func (r *passwordCredentialRepositoryStub) Delete(_ context.Context, userID uint, _ bool) error {
	delete(r.credentials, userID)
	return nil
}

func (r *passwordCredentialRepositoryStub) UpdateField(_ context.Context, userID uint, field string, value interface{}) error {
	credential, exists := r.credentials[userID]
	if !exists {
		return entModels.ErrNotFound
	}
	if field != "password_hash" {
		return errors.New("unexpected credential field")
	}
	credential.PasswordHash = value.(string)
	r.credentials[userID] = credential
	return nil
}

func TestPasswordCredentialServiceCreateRetrieveAndReplace(t *testing.T) {
	repository := &passwordCredentialRepositoryStub{credentials: map[uint]models.PasswordCredential{}}
	service := &userService{passwordCredentials: repository}
	credential := models.PasswordCredential{UserID: 583, PasswordHash: "$argon2id$fake-initial-hash"}

	created, err := service.CreatePasswordCredential(context.Background(), credential)
	if err != nil {
		t.Fatalf("CreatePasswordCredential() error = %v", err)
	}
	if *created != credential {
		t.Fatalf("created credential = %#v, want %#v", created, credential)
	}

	got, err := service.GetPasswordCredential(context.Background(), credential.UserID)
	if err != nil || *got != credential {
		t.Fatalf("GetPasswordCredential() = %#v, %v, want %#v, nil", got, err, credential)
	}

	replacement := "$argon2id$fake-replacement-hash"
	if err := service.UpdatePasswordCredentialHash(context.Background(), credential.UserID, replacement); err != nil {
		t.Fatalf("UpdatePasswordCredentialHash() error = %v", err)
	}
	got, err = service.GetPasswordCredential(context.Background(), credential.UserID)
	if err != nil || got.PasswordHash != replacement {
		t.Fatalf("updated credential = %#v, %v, want replacement hash", got, err)
	}
}

func TestPasswordCredentialServiceEnforcesOneCredentialPerUser(t *testing.T) {
	repository := &passwordCredentialRepositoryStub{credentials: map[uint]models.PasswordCredential{}}
	service := &userService{passwordCredentials: repository}
	credential := models.PasswordCredential{UserID: 583, PasswordHash: "$argon2id$fake-hash"}

	if _, err := service.CreatePasswordCredential(context.Background(), credential); err != nil {
		t.Fatalf("first CreatePasswordCredential() error = %v", err)
	}
	if _, err := service.CreatePasswordCredential(context.Background(), credential); !errors.Is(err, gorm.ErrDuplicatedKey) {
		t.Fatalf("duplicate CreatePasswordCredential() error = %v, want %v", err, gorm.ErrDuplicatedKey)
	}
}

func TestPasswordCredentialServiceNormalizesMissingCredential(t *testing.T) {
	service := &userService{passwordCredentials: &passwordCredentialRepositoryStub{credentials: map[uint]models.PasswordCredential{}}}

	credential, err := service.GetPasswordCredential(context.Background(), 583)
	if credential != nil || !errors.Is(err, models.ErrCredentialNotFound) {
		t.Fatalf("GetPasswordCredential(missing) = %#v, %v, want nil, %v", credential, err, models.ErrCredentialNotFound)
	}
}

func TestPasswordCredentialServiceRejectsEmptyReplacementHash(t *testing.T) {
	repository := &passwordCredentialRepositoryStub{credentials: map[uint]models.PasswordCredential{
		583: {UserID: 583, PasswordHash: "$argon2id$fake-hash"},
	}}
	service := &userService{passwordCredentials: repository}

	if err := service.UpdatePasswordCredentialHash(context.Background(), 583, ""); err == nil {
		t.Fatal("UpdatePasswordCredentialHash(empty) error = nil, want error")
	}
}

func TestStartPasswordSessionPersistsDeviceAndFreshCodesTogether(t *testing.T) {
	state := &refreshDatabaseState{user: refreshServiceUser()}
	service := newRefreshServiceTest(t, state)
	device := state.user.DeviceInfo
	device.BrowserVersion = "129"
	device.Language = "es-ES"
	device.CookiesEnabled = false
	codeExpire := time.Now().UTC()
	var updates map[string]any
	if err := service.db.Callback().Update().Replace("gorm:update", func(tx *gorm.DB) {
		updates = tx.Statement.Dest.(map[string]any)
		tx.RowsAffected = 1
	}); err != nil {
		t.Fatalf("replace update callback: %v", err)
	}

	err := service.StartPasswordSession(context.Background(), state.user.ID, device, "access-marker", codeExpire, "fresh-refresh-code")
	if err != nil {
		t.Fatalf("StartPasswordSession() error = %v", err)
	}
	want := map[string]any{
		"browser":                  device.Browser,
		"browser_version":          device.BrowserVersion,
		"operating_system":         device.OperatingSystem,
		"operating_system_version": device.OperatingSystemVersion,
		"language":                 device.Language,
		"timezone":                 device.Timezone,
		"cpu":                      device.Cpu,
		"cookies_enabled":          device.CookiesEnabled,
		"code":                     "access-marker",
		"code_expire":              codeExpire,
		"code_refresh":             "fresh-refresh-code",
	}
	if len(updates) != len(want) {
		t.Fatalf("StartPasswordSession() updates = %#v, want %#v", updates, want)
	}
	for field, wantValue := range want {
		if got := updates[field]; got != wantValue {
			t.Fatalf("StartPasswordSession() %s = %#v, want %#v", field, got, wantValue)
		}
	}
}

func TestStartPasswordSessionRejectsMissingUser(t *testing.T) {
	state := &refreshDatabaseState{user: refreshServiceUser()}
	service := newRefreshServiceTest(t, state)
	if err := service.db.Callback().Update().Replace("gorm:update", func(tx *gorm.DB) {
		tx.RowsAffected = 0
	}); err != nil {
		t.Fatalf("replace update callback: %v", err)
	}

	err := service.StartPasswordSession(context.Background(), state.user.ID+1, state.user.DeviceInfo, "access-marker", time.Now().UTC(), "fresh-refresh-code")
	if !errors.Is(err, models.ErrUserNotFound) {
		t.Fatalf("StartPasswordSession() error = %v, want %v", err, models.ErrUserNotFound)
	}
}
