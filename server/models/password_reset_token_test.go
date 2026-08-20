package models

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/protobuf/reflect/protoreflect"
	"gorm.io/gorm/schema"
)

func TestPasswordResetTokenSchemaIsSeparateAndDigestOnly(t *testing.T) {
	parsed, err := schema.Parse(&PasswordResetToken{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse PasswordResetToken schema: %v", err)
	}
	if parsed.Table != "password_reset_tokens" {
		t.Fatalf("table name = %q, want password_reset_tokens", parsed.Table)
	}
	userID := parsed.LookUpField("UserID")
	digest := parsed.LookUpField("TokenDigest")
	expires := parsed.LookUpField("ExpiresAt")
	used := parsed.LookUpField("UsedAt")
	if userID == nil || !userID.NotNull || !strings.Contains(userID.StructField.Tag.Get("gorm"), "uniqueIndex") {
		t.Fatalf("UserID schema = %#v, want non-null unique owner", userID)
	}
	if digest == nil || digest.DBName != "token_digest" || !digest.NotNull || digest.Size != 64 || digest.StructField.Tag.Get("json") != "-" || !strings.Contains(digest.StructField.Tag.Get("gorm"), "uniqueIndex") {
		t.Fatalf("TokenDigest schema = %#v, want hidden unique 64-character digest", digest)
	}
	if expires == nil || !strings.Contains(expires.StructField.Tag.Get("gorm"), "index") || used == nil || used.FieldType != reflect.TypeOf((*time.Time)(nil)) {
		t.Fatalf("expiry/used schema = %#v/%#v, want indexed expiry and nullable used_at", expires, used)
	}
	if _, found := reflect.TypeOf(PasswordResetToken{}).FieldByName("ResetToken"); found {
		t.Fatal("PasswordResetToken contains a raw reset token field")
	}
	relationship := parsed.Relationships.Relations["User"]
	if relationship == nil || relationship.Type != schema.BelongsTo || relationship.ParseConstraint() == nil {
		t.Fatalf("User relationship = %#v, want local belongs-to foreign key", relationship)
	}
}

func TestPasswordResetProtobufResponsesExposeNoDigestOrCredentials(t *testing.T) {
	responses := []protoreflect.MessageDescriptor{
		(&pb.UserRequestPasswordResetResponse{}).ProtoReflect().Descriptor(),
		(&pb.UserResetPasswordResponse{}).ProtoReflect().Descriptor(),
	}
	for _, response := range responses {
		fields := response.Fields()
		for _, name := range []protoreflect.Name{"token_digest", "password", "password_hash", "token", "token_refresh"} {
			if fields.ByName(name) != nil {
				t.Fatalf("%s unexpectedly exposes %q", response.FullName(), name)
			}
		}
	}
}
