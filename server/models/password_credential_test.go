package models

import (
	"reflect"
	"sync"
	"testing"
	"time"

	pb "github.com/BaukunstPatrimonio/user-go/server/user-pb"
	"google.golang.org/protobuf/reflect/protoreflect"
	"gorm.io/gorm/schema"
)

func TestPasswordCredentialSchemaIsOneToOneWithUser(t *testing.T) {
	parsed, err := schema.Parse(&PasswordCredential{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse PasswordCredential schema: %v", err)
	}
	if parsed.Table != "password_credentials" {
		t.Fatalf("table name = %q, want %q", parsed.Table, "password_credentials")
	}

	userID := parsed.LookUpField("UserID")
	if userID == nil {
		t.Fatal("UserID field is missing")
	}
	if !userID.PrimaryKey || userID.AutoIncrement {
		t.Fatalf("UserID primary/auto-increment = %v/%v, want true/false", userID.PrimaryKey, userID.AutoIncrement)
	}
	if userID.DBName != "user_id" {
		t.Fatalf("UserID column = %q, want %q", userID.DBName, "user_id")
	}

	relationship := parsed.Relationships.Relations["User"]
	if relationship == nil {
		t.Fatal("User relationship is missing")
	}
	if relationship.Type != schema.BelongsTo {
		t.Fatalf("User relationship type = %v, want belongs-to", relationship.Type)
	}
	if len(relationship.References) != 1 || relationship.References[0].ForeignKey.Name != "UserID" || relationship.References[0].PrimaryKey.Name != "ID" {
		t.Fatalf("User relationship references = %#v, want PasswordCredential.UserID -> User.ID", relationship.References)
	}
	constraint := relationship.ParseConstraint()
	if constraint == nil {
		t.Fatal("User foreign-key constraint is missing")
	}
	if constraint.OnDelete != "CASCADE" || constraint.OnUpdate != "CASCADE" {
		t.Fatalf("User constraint actions = update:%q delete:%q, want CASCADE/CASCADE", constraint.OnUpdate, constraint.OnDelete)
	}
}

func TestPasswordCredentialStoresOnlyAHashAndTimestamps(t *testing.T) {
	parsed, err := schema.Parse(&PasswordCredential{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse PasswordCredential schema: %v", err)
	}
	hash := parsed.LookUpField("PasswordHash")
	if hash == nil || hash.DBName != "password_hash" || !hash.NotNull || hash.TagSettings["TYPE"] != "text" {
		t.Fatalf("PasswordHash schema = %#v, want non-null text password_hash", hash)
	}
	if hash.StructField.Tag.Get("json") != "-" {
		t.Fatalf("PasswordHash json tag = %q, want hidden", hash.StructField.Tag.Get("json"))
	}

	credentialType := reflect.TypeOf(PasswordCredential{})
	if _, found := credentialType.FieldByName("Password"); found {
		t.Fatal("PasswordCredential contains a plaintext Password field")
	}
	for _, name := range []string{"CreatedAt", "UpdatedAt"} {
		field, found := credentialType.FieldByName(name)
		if !found || field.Type != reflect.TypeOf(time.Time{}) {
			t.Fatalf("%s field = %#v, want time.Time", name, field)
		}
	}
}

func TestUserResponseNeverExposesPasswordCredentialFields(t *testing.T) {
	fields := (&pb.UserResponse{}).ProtoReflect().Descriptor().Fields()
	for _, name := range []protoreflect.Name{"password", "password_hash", "credential"} {
		if fields.ByName(name) != nil {
			t.Fatalf("UserResponse unexpectedly exposes %q", name)
		}
	}
	if got := fields.ByName("id"); got == nil || got.Number() != 10 || got.Kind() != protoreflect.Uint64Kind {
		t.Fatalf("UserResponse.id descriptor = %#v, want uint64 field number 10", got)
	}
	if got := fields.ByName("phone_e164"); got == nil || got.Number() != 11 || got.Kind() != protoreflect.StringKind {
		t.Fatalf("UserResponse.phone_e164 descriptor = %#v, want string field number 11", got)
	}
}
