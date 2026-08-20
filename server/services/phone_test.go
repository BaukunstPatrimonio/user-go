package services

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

func TestGetByPhoneUsesDirectIndexedPredicate(t *testing.T) {
	service := newPasswordRegistrationServiceTest(t, &registrationDatabaseState{})
	var queries bytes.Buffer
	service.db = service.db.Session(&gorm.Session{
		DryRun: true,
		Logger: logger.New(log.New(&queries, "", 0), logger.Config{LogLevel: logger.Info}),
	})

	if _, err := service.GetByPhone(context.Background(), "+34600111222"); err != nil {
		t.Fatalf("GetByPhone() dry-run error = %v", err)
	}
	sql := strings.ToLower(queries.String())
	if !strings.Contains(sql, "where phone_e164 = '+34600111222'") || !strings.Contains(sql, "limit 1") {
		t.Fatalf("GetByPhone() SQL = %q, want direct phone_e164 predicate with LIMIT 1", queries.String())
	}
	if strings.Contains(sql, "select * from \"users\";") {
		t.Fatalf("GetByPhone() performed an unfiltered scan: %q", queries.String())
	}
}

func TestUpdatePhoneIdentityIsSingleAtomicUpdate(t *testing.T) {
	for _, test := range []struct {
		name         string
		rowsAffected int64
		updateErr    error
		wantErr      error
	}{
		{name: "success", rowsAffected: 1},
		{name: "missing user", rowsAffected: 0, wantErr: models.ErrUserNotFound},
		{name: "duplicate phone", updateErr: registrationUniqueViolation{}, wantErr: models.ErrPhoneAlreadyExists},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := newPasswordRegistrationServiceTest(t, &registrationDatabaseState{})
			calls := 0
			statement := ""
			destination := ""
			var updatedID uint
			if err := service.db.Callback().Update().Replace("gorm:update", func(tx *gorm.DB) {
				calls++
				statement = fmt.Sprintf("%#v", tx.Statement.Clauses)
				destination = fmt.Sprintf("%#v", tx.Statement.Dest)
				where := tx.Statement.Clauses["WHERE"].Expression.(clause.Where)
				expression := where.Exprs[0].(clause.Expr)
				updatedID = expression.Vars[0].(uint)
				tx.RowsAffected = test.rowsAffected
				if test.updateErr != nil {
					tx.AddError(test.updateErr)
				}
			}); err != nil {
				t.Fatalf("replace update callback: %v", err)
			}

			err := service.UpdatePhoneIdentity(context.Background(), 583, "+34600111222")
			if !errors.Is(err, test.wantErr) || (test.wantErr == nil && err != nil) {
				t.Fatalf("UpdatePhoneIdentity() error = %v, want %v", err, test.wantErr)
			}
			if calls != 1 || updatedID != 583 || !strings.Contains(statement, "id") || !strings.Contains(destination, "phone_e164") || !strings.Contains(destination, "+34600111222") {
				t.Fatalf("atomic update = calls %d id %d clauses %s dest %s", calls, updatedID, statement, destination)
			}
		})
	}
}
