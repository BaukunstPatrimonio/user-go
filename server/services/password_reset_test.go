package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
)

type passwordResetServiceBehavior struct {
	lockingSeen    bool
	updateOrder    []string
	tokenUpdateErr error
}

func TestFindPasswordResetUserRequiresPasswordCredential(t *testing.T) {
	state := &registrationDatabaseState{
		user:       &models.User{Email: "Mixed@Example.com"},
		credential: &models.PasswordCredential{UserID: 583, PasswordHash: "$argon2id$hash"},
	}
	state.user.ID = 583
	service := newPasswordRegistrationServiceTest(t, state)
	var joinSeen, normalizedLookupSeen bool
	if err := service.db.Callback().Query().Replace("gorm:query", func(tx *gorm.DB) {
		user, ok := tx.Statement.Dest.(*models.User)
		if !ok {
			tx.AddError(fmt.Errorf("unexpected query destination %T", tx.Statement.Dest))
			return
		}
		joinSeen = strings.Contains(fmt.Sprint(tx.Statement.Joins), "password_credentials")
		normalizedLookupSeen = strings.Contains(fmt.Sprint(tx.Statement.Clauses["WHERE"]), "mixed@example.com")
		if state.credential == nil {
			tx.AddError(gorm.ErrRecordNotFound)
			return
		}
		*user = *state.user
		tx.RowsAffected = 1
	}); err != nil {
		t.Fatalf("replace query callback: %v", err)
	}

	user, err := service.FindPasswordResetUser(context.Background(), "mixed@example.com")
	if err != nil || user.ID != state.user.ID || !joinSeen || !normalizedLookupSeen {
		t.Fatalf("FindPasswordResetUser() = %#v, %v join:%v normalized:%v", user, err, joinSeen, normalizedLookupSeen)
	}
	state.credential = nil
	user, err = service.FindPasswordResetUser(context.Background(), "mixed@example.com")
	if user != nil || !errors.Is(err, models.ErrPasswordResetUnavailable) {
		t.Fatalf("FindPasswordResetUser(passwordless) = %#v, %v", user, err)
	}
}

func TestStorePasswordResetTokenAtomicallyReplacesPreviousToken(t *testing.T) {
	state := &registrationDatabaseState{}
	service := newPasswordRegistrationServiceTest(t, state)
	var conflictSeen bool
	if err := service.db.Callback().Create().Replace("gorm:create", func(tx *gorm.DB) {
		resetToken, ok := tx.Statement.Dest.(*models.PasswordResetToken)
		if !ok {
			tx.AddError(fmt.Errorf("unexpected create destination %T", tx.Statement.Dest))
			return
		}
		_, conflictSeen = tx.Statement.Clauses["ON CONFLICT"]
		copy := *resetToken
		copy.ID = 901
		state.pendingResetToken = &copy
		tx.RowsAffected = 1
	}); err != nil {
		t.Fatalf("replace create callback: %v", err)
	}

	first := models.PasswordResetToken{UserID: 583, TokenDigest: "first-digest", ExpiresAt: time.Now().UTC().Add(30 * time.Minute)}
	if err := service.StorePasswordResetToken(context.Background(), first); err != nil {
		t.Fatalf("first StorePasswordResetToken() error = %v", err)
	}
	second := models.PasswordResetToken{UserID: 583, TokenDigest: "second-digest", ExpiresAt: first.ExpiresAt.Add(time.Minute)}
	if err := service.StorePasswordResetToken(context.Background(), second); err != nil {
		t.Fatalf("second StorePasswordResetToken() error = %v", err)
	}
	if !conflictSeen || state.beginCount != 2 || state.commitCount != 2 || state.rollbackCount != 0 {
		t.Fatalf("upsert transaction = conflict:%v counts:%d/%d/%d", conflictSeen, state.beginCount, state.commitCount, state.rollbackCount)
	}
	if state.resetToken == nil || state.resetToken.TokenDigest != second.TokenDigest || !state.resetToken.ExpiresAt.Equal(second.ExpiresAt) || state.resetToken.UsedAt != nil {
		t.Fatalf("stored reset token = %#v, want second unused token", state.resetToken)
	}
}

func TestResetPasswordWithTokenCommitsHashUseAndRevocationTogether(t *testing.T) {
	now := time.Now().UTC()
	state := passwordResetDatabaseState(now)
	service, behavior := newPasswordResetServiceTest(t, state)

	err := service.ResetPasswordWithToken(context.Background(), state.resetToken.TokenDigest, "$argon2id$new-hash", now)
	if err != nil {
		t.Fatalf("ResetPasswordWithToken() error = %v", err)
	}
	if state.beginCount != 1 || state.commitCount != 1 || state.rollbackCount != 0 || !behavior.lockingSeen {
		t.Fatalf("transaction = counts:%d/%d/%d locking:%v", state.beginCount, state.commitCount, state.rollbackCount, behavior.lockingSeen)
	}
	if fmt.Sprint(behavior.updateOrder) != "[credential token user]" {
		t.Fatalf("update order = %v, want credential/token/user", behavior.updateOrder)
	}
	if state.credential.PasswordHash != "$argon2id$new-hash" || state.resetToken.UsedAt == nil || !state.resetToken.UsedAt.Equal(now) || state.user.CodeRefresh != "OUT" {
		t.Fatalf("committed reset state = credential:%#v token:%#v user:%#v", state.credential, state.resetToken, state.user)
	}

	err = service.ResetPasswordWithToken(context.Background(), state.resetToken.TokenDigest, "$argon2id$second-hash", now.Add(time.Second))
	if !errors.Is(err, models.ErrInvalidPasswordResetToken) || state.commitCount != 1 || state.rollbackCount != 1 || state.credential.PasswordHash != "$argon2id$new-hash" {
		t.Fatalf("reuse = %v counts:%d/%d hash:%q", err, state.commitCount, state.rollbackCount, state.credential.PasswordHash)
	}
}

func TestResetPasswordWithTokenRejectsExpiredTokenWithoutChanges(t *testing.T) {
	now := time.Now().UTC()
	state := passwordResetDatabaseState(now)
	state.resetToken.ExpiresAt = now.Add(-time.Second)
	service, _ := newPasswordResetServiceTest(t, state)
	oldHash, oldRefresh := state.credential.PasswordHash, state.user.CodeRefresh

	err := service.ResetPasswordWithToken(context.Background(), state.resetToken.TokenDigest, "$argon2id$new-hash", now)
	if !errors.Is(err, models.ErrInvalidPasswordResetToken) || state.commitCount != 0 || state.rollbackCount != 1 {
		t.Fatalf("expired reset = %v counts:%d/%d", err, state.commitCount, state.rollbackCount)
	}
	if state.credential.PasswordHash != oldHash || state.user.CodeRefresh != oldRefresh || state.resetToken.UsedAt != nil {
		t.Fatal("expired reset changed persisted state")
	}
}

func TestResetPasswordWithTokenCannotCreateCredentialForPasswordlessUser(t *testing.T) {
	now := time.Now().UTC()
	state := passwordResetDatabaseState(now)
	state.credential = nil
	service, _ := newPasswordResetServiceTest(t, state)
	oldRefresh := state.user.CodeRefresh

	err := service.ResetPasswordWithToken(context.Background(), state.resetToken.TokenDigest, "$argon2id$new-hash", now)
	if !errors.Is(err, models.ErrInvalidPasswordResetToken) || state.commitCount != 0 || state.rollbackCount != 1 {
		t.Fatalf("passwordless reset = %v counts:%d/%d", err, state.commitCount, state.rollbackCount)
	}
	if state.credential != nil || state.user.CodeRefresh != oldRefresh || state.resetToken.UsedAt != nil {
		t.Fatal("passwordless reset created credential or changed reset/session state")
	}
}

func TestResetPasswordWithTokenRollsBackWhenMarkUsedFails(t *testing.T) {
	now := time.Now().UTC()
	state := passwordResetDatabaseState(now)
	service, behavior := newPasswordResetServiceTest(t, state)
	behavior.tokenUpdateErr = errors.New("mark used failed")
	oldHash, oldRefresh := state.credential.PasswordHash, state.user.CodeRefresh

	err := service.ResetPasswordWithToken(context.Background(), state.resetToken.TokenDigest, "$argon2id$new-hash", now)
	if !errors.Is(err, behavior.tokenUpdateErr) || state.commitCount != 0 || state.rollbackCount != 1 {
		t.Fatalf("failed reset = %v counts:%d/%d", err, state.commitCount, state.rollbackCount)
	}
	if state.credential.PasswordHash != oldHash || state.user.CodeRefresh != oldRefresh || state.resetToken.UsedAt != nil {
		t.Fatalf("rollback left partial state: credential:%#v token:%#v user:%#v", state.credential, state.resetToken, state.user)
	}
}

func passwordResetDatabaseState(now time.Time) *registrationDatabaseState {
	return &registrationDatabaseState{
		user:       &models.User{CodeRefresh: "current-refresh"},
		credential: &models.PasswordCredential{UserID: 583, PasswordHash: "$argon2id$old-hash"},
		resetToken: &models.PasswordResetToken{ID: 901, UserID: 583, TokenDigest: "valid-digest", ExpiresAt: now.Add(30 * time.Minute)},
	}
}

func newPasswordResetServiceTest(t *testing.T, state *registrationDatabaseState) (*userService, *passwordResetServiceBehavior) {
	t.Helper()
	state.user.ID = 583
	service := newPasswordRegistrationServiceTest(t, state)
	behavior := &passwordResetServiceBehavior{}

	if err := service.db.Callback().Query().Replace("gorm:query", func(tx *gorm.DB) {
		resetToken, ok := tx.Statement.Dest.(*models.PasswordResetToken)
		if !ok {
			tx.AddError(fmt.Errorf("unexpected query destination %T", tx.Statement.Dest))
			return
		}
		_, behavior.lockingSeen = tx.Statement.Clauses["FOR"]
		if state.pendingResetToken == nil || state.pendingResetToken.UsedAt != nil {
			tx.AddError(gorm.ErrRecordNotFound)
			return
		}
		if !state.pendingResetToken.ExpiresAt.After(time.Now().UTC()) {
			tx.AddError(gorm.ErrRecordNotFound)
			return
		}
		*resetToken = *state.pendingResetToken
		tx.RowsAffected = 1
	}); err != nil {
		t.Fatalf("replace query callback: %v", err)
	}

	if err := service.db.Callback().Update().Replace("gorm:update", func(tx *gorm.DB) {
		values, ok := tx.Statement.Dest.(map[string]interface{})
		if !ok {
			tx.AddError(fmt.Errorf("unexpected update destination %T", tx.Statement.Dest))
			return
		}
		switch tx.Statement.Model.(type) {
		case *models.PasswordCredential:
			behavior.updateOrder = append(behavior.updateOrder, "credential")
			if state.pendingCredential == nil {
				tx.RowsAffected = 0
				return
			}
			state.pendingCredential.PasswordHash = values["password_hash"].(string)
		case *models.PasswordResetToken:
			behavior.updateOrder = append(behavior.updateOrder, "token")
			if behavior.tokenUpdateErr != nil {
				tx.AddError(behavior.tokenUpdateErr)
				return
			}
			usedAt := values["used_at"].(time.Time)
			state.pendingResetToken.UsedAt = &usedAt
		case *models.User:
			behavior.updateOrder = append(behavior.updateOrder, "user")
			state.pendingUser.CodeRefresh = values["code_refresh"].(string)
		default:
			tx.AddError(fmt.Errorf("unexpected update model %T", tx.Statement.Model))
			return
		}
		tx.RowsAffected = 1
	}); err != nil {
		t.Fatalf("replace update callback: %v", err)
	}
	return service, behavior
}
