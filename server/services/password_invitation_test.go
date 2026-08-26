package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
)

func TestInvitePasswordUserAtomicallyCreatesIdentityWithoutCredentialAndStoresDigest(t *testing.T) {
	state := &registrationDatabaseState{}
	service := newPasswordInvitationServiceTest(t, state)
	candidate := models.User{Email: "invite@example.com", Name: "Invite"}
	token := models.PasswordResetToken{TokenDigest: "digest-only", ExpiresAt: time.Now().UTC().Add(time.Hour)}

	user, existing, configured, err := service.InvitePasswordUser(context.Background(), candidate, token)
	if err != nil || existing || configured || user.ID != 583 {
		t.Fatalf("InvitePasswordUser() = %#v, %v/%v, %v", user, existing, configured, err)
	}
	if state.credential != nil || state.user == nil || state.resetToken == nil || state.resetToken.UserID != 583 || state.resetToken.TokenDigest != "digest-only" {
		t.Fatalf("stored state = user:%#v credential:%#v token:%#v", state.user, state.credential, state.resetToken)
	}
	if state.beginCount != 1 || state.commitCount != 1 || state.rollbackCount != 0 {
		t.Fatalf("transaction counts = %d/%d/%d", state.beginCount, state.commitCount, state.rollbackCount)
	}
}

func TestInvitePasswordUserReusesConfiguredIdentityWithoutReplacingPassword(t *testing.T) {
	state := &registrationDatabaseState{
		user:       &models.User{Email: "existing@example.com", Name: "Existing", Validated: true},
		credential: &models.PasswordCredential{UserID: 583, PasswordHash: "$argon2id$existing"},
	}
	state.user.ID = 583
	service := newPasswordInvitationServiceTest(t, state)
	user, existing, configured, err := service.InvitePasswordUser(context.Background(), models.User{Email: state.user.Email, Name: "Ignored"}, models.PasswordResetToken{TokenDigest: "unused", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil || !existing || !configured || user.Name != "Existing" || state.resetToken != nil || state.credential.PasswordHash != "$argon2id$existing" {
		t.Fatalf("configured identity = %#v existing:%v configured:%v err:%v state:%#v", user, existing, configured, err, state)
	}
}

func newPasswordInvitationServiceTest(t *testing.T, state *registrationDatabaseState) *userService {
	t.Helper()
	service := newPasswordRegistrationServiceTest(t, state)
	if err := service.db.Callback().Query().Replace("gorm:query", func(tx *gorm.DB) {
		switch destination := tx.Statement.Dest.(type) {
		case *models.User:
			if state.pendingUser == nil {
				tx.AddError(gorm.ErrRecordNotFound)
				return
			}
			*destination = *state.pendingUser
			tx.RowsAffected = 1
		case *int64:
			if state.pendingCredential != nil {
				*destination = 1
			}
			tx.RowsAffected = 1
		default:
			tx.AddError(fmt.Errorf("unexpected query destination %T", destination))
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.db.Callback().Create().Replace("gorm:create", func(tx *gorm.DB) {
		switch value := tx.Statement.Dest.(type) {
		case *models.User:
			value.ID = 583
			copy := *value
			state.pendingUser = &copy
		case *models.PasswordResetToken:
			value.ID = 901
			copy := *value
			state.pendingResetToken = &copy
		default:
			tx.AddError(fmt.Errorf("unexpected create destination %T", value))
			return
		}
		tx.RowsAffected = 1
	}); err != nil {
		t.Fatal(err)
	}
	return service
}
