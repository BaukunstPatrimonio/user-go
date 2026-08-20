package models

import (
	"reflect"
	"sync"
	"testing"

	"gorm.io/gorm/schema"
)

func TestUserPhoneIdentityIsNullableAndUniquelyIndexed(t *testing.T) {
	parsed, err := schema.Parse(&User{}, &sync.Map{}, schema.NamingStrategy{})
	if err != nil {
		t.Fatalf("parse User schema: %v", err)
	}
	field := parsed.LookUpField("PhoneE164")
	if field == nil || field.DBName != "phone_e164" || field.FieldType.Kind() != reflect.Pointer || field.NotNull {
		t.Fatalf("PhoneE164 schema = %#v, want nullable pointer column phone_e164", field)
	}
	index, ok := parsed.ParseIndexes()["idx_phone_e164"]
	if !ok || index.Class != "UNIQUE" || len(index.Fields) != 1 || index.Fields[0].Field != field {
		t.Fatalf("phone index = %#v, want one-column unique index", index)
	}
	if parsed.LookUpField("PhoneValidated") != nil || parsed.LookUpField("PhoneVerified") != nil {
		t.Fatal("User unexpectedly contains phone verification state")
	}
	if (&User{}).PhoneE164 != nil {
		t.Fatal("legacy user zero value phone is not NULL")
	}
}
