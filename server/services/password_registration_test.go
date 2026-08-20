package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var registrationDriverNumber uint64

type registrationUniqueViolation struct{}

func (registrationUniqueViolation) Error() string    { return "unique violation" }
func (registrationUniqueViolation) SQLState() string { return "23505" }

type registrationDatabaseState struct {
	user              *models.User
	credential        *models.PasswordCredential
	resetToken        *models.PasswordResetToken
	pendingUser       *models.User
	pendingCredential *models.PasswordCredential
	pendingResetToken *models.PasswordResetToken
	userErr           error
	credentialErr     error
	beginCount        int
	commitCount       int
	rollbackCount     int
	emailCount        int64
	lastQuery         string
	lastArguments     []driver.NamedValue
}

type registrationTestDriver struct {
	state *registrationDatabaseState
}

func (d *registrationTestDriver) Open(string) (driver.Conn, error) {
	return &registrationTestConn{state: d.state}, nil
}

type registrationTestConn struct {
	state *registrationDatabaseState
}

func (*registrationTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not supported")
}

func (*registrationTestConn) Close() error { return nil }

func (c *registrationTestConn) QueryContext(_ context.Context, query string, arguments []driver.NamedValue) (driver.Rows, error) {
	c.state.lastQuery = query
	c.state.lastArguments = append([]driver.NamedValue(nil), arguments...)
	return &registrationTestRows{count: c.state.emailCount}, nil
}

func (c *registrationTestConn) Begin() (driver.Tx, error) {
	return c.begin(), nil
}

func (c *registrationTestConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.begin(), nil
}

func (c *registrationTestConn) begin() driver.Tx {
	c.state.beginCount++
	c.state.pendingUser = cloneTestValue(c.state.user)
	c.state.pendingCredential = cloneTestValue(c.state.credential)
	c.state.pendingResetToken = cloneTestValue(c.state.resetToken)
	return &registrationTestTx{state: c.state}
}

type registrationTestTx struct {
	state *registrationDatabaseState
}

type registrationTestRows struct {
	count int64
	read  bool
}

func (*registrationTestRows) Columns() []string { return []string{"count"} }
func (*registrationTestRows) Close() error      { return nil }

func (rows *registrationTestRows) Next(values []driver.Value) error {
	if rows.read {
		return io.EOF
	}
	values[0] = rows.count
	rows.read = true
	return nil
}

func TestPasswordRegistrationEmailExistsUsesCaseInsensitiveUnscopedLookup(t *testing.T) {
	state := &registrationDatabaseState{emailCount: 1}
	service := newPasswordRegistrationServiceTest(t, state)

	exists, err := service.PasswordRegistrationEmailExists(context.Background(), "mixed@example.com")
	if err != nil || !exists {
		t.Fatalf("PasswordRegistrationEmailExists() = %v, %v, want true, nil", exists, err)
	}
	if !strings.Contains(state.lastQuery, "LOWER(email)") || strings.Contains(state.lastQuery, "deleted_at") {
		t.Fatalf("email lookup query = %q, want case-insensitive unscoped query", state.lastQuery)
	}
	if len(state.lastArguments) != 1 || state.lastArguments[0].Value != "mixed@example.com" {
		t.Fatalf("email lookup arguments = %#v, want normalized email", state.lastArguments)
	}
}

func (tx *registrationTestTx) Commit() error {
	tx.state.user = tx.state.pendingUser
	tx.state.credential = tx.state.pendingCredential
	tx.state.resetToken = tx.state.pendingResetToken
	tx.state.pendingUser = nil
	tx.state.pendingCredential = nil
	tx.state.pendingResetToken = nil
	tx.state.commitCount++
	return nil
}

func (tx *registrationTestTx) Rollback() error {
	tx.state.pendingUser = nil
	tx.state.pendingCredential = nil
	tx.state.pendingResetToken = nil
	tx.state.rollbackCount++
	return nil
}

func cloneTestValue[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func TestCreatePasswordUserCommitsUserAndCredentialTogether(t *testing.T) {
	state := &registrationDatabaseState{}
	service := newPasswordRegistrationServiceTest(t, state)
	phone := "+34600111222"
	user := models.User{Email: "new@example.com", PhoneE164: &phone, Name: "New User", Code: "verification", CodeRefresh: "refresh"}

	created, err := service.CreatePasswordUser(context.Background(), user, "$argon2id$test-hash")
	if err != nil {
		t.Fatalf("CreatePasswordUser() error = %v", err)
	}
	if state.beginCount != 1 || state.commitCount != 1 || state.rollbackCount != 0 {
		t.Fatalf("transaction counts = %d/%d/%d, want 1/1/0", state.beginCount, state.commitCount, state.rollbackCount)
	}
	if created.ID != 583 || state.user == nil || state.user.ID != created.ID || state.credential == nil || state.credential.UserID != created.ID {
		t.Fatalf("committed registration = created %#v user %#v credential %#v", created, state.user, state.credential)
	}
	if state.credential.PasswordHash != "$argon2id$test-hash" {
		t.Fatalf("credential hash = %q, want supplied hash", state.credential.PasswordHash)
	}
	if state.user.PhoneE164 == nil || *state.user.PhoneE164 != phone {
		t.Fatalf("transactional user phone = %#v, want %q", state.user.PhoneE164, phone)
	}
}

func TestCreatePasswordUserRollsBackWhenCredentialCreationFails(t *testing.T) {
	databaseErr := errors.New("credential insert failed")
	state := &registrationDatabaseState{credentialErr: databaseErr}
	service := newPasswordRegistrationServiceTest(t, state)

	created, err := service.CreatePasswordUser(context.Background(), models.User{Email: "new@example.com", Name: "New User"}, "$argon2id$test-hash")
	if created != nil || !errors.Is(err, databaseErr) {
		t.Fatalf("CreatePasswordUser() = %#v, %v, want nil/%v", created, err, databaseErr)
	}
	if state.beginCount != 1 || state.commitCount != 0 || state.rollbackCount != 1 {
		t.Fatalf("transaction counts = %d/%d/%d, want 1/0/1", state.beginCount, state.commitCount, state.rollbackCount)
	}
	if state.user != nil || state.credential != nil || state.pendingUser != nil || state.pendingCredential != nil {
		t.Fatalf("rollback left partial registration: %#v", state)
	}
}

func TestCreatePasswordUserMapsUniqueViolationAndRollsBack(t *testing.T) {
	state := &registrationDatabaseState{userErr: registrationUniqueViolation{}}
	service := newPasswordRegistrationServiceTest(t, state)

	phone := "+34600111222"
	created, err := service.CreatePasswordUser(context.Background(), models.User{Email: "new@example.com", PhoneE164: &phone, Name: "New User"}, "$argon2id$test-hash")
	if created != nil || !errors.Is(err, models.ErrUserAlreadyExists) {
		t.Fatalf("CreatePasswordUser() = %#v, %v, want nil/%v", created, err, models.ErrUserAlreadyExists)
	}
	if state.commitCount != 0 || state.rollbackCount != 1 || state.user != nil || state.credential != nil {
		t.Fatalf("unique violation did not roll back cleanly: %#v", state)
	}
}

func newPasswordRegistrationServiceTest(t *testing.T, state *registrationDatabaseState) *userService {
	t.Helper()
	driverName := fmt.Sprintf("password_registration_test_%d", atomic.AddUint64(&registrationDriverNumber, 1))
	sql.Register(driverName, &registrationTestDriver{state: state})
	sqlDB, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	database, err := gorm.Open(postgres.New(postgres.Config{Conn: sqlDB}), &gorm.Config{
		DisableAutomaticPing: true,
		Logger:               logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("gorm.Open() error = %v", err)
	}
	if err := database.Callback().Create().Replace("gorm:create", func(tx *gorm.DB) {
		switch value := tx.Statement.Dest.(type) {
		case *models.User:
			if state.userErr != nil {
				tx.AddError(state.userErr)
				return
			}
			value.ID = 583
			copy := *value
			state.pendingUser = &copy
			tx.RowsAffected = 1
		case *models.PasswordCredential:
			if state.credentialErr != nil {
				tx.AddError(state.credentialErr)
				return
			}
			copy := *value
			state.pendingCredential = &copy
			tx.RowsAffected = 1
		default:
			tx.AddError(fmt.Errorf("unexpected create destination %T", value))
		}
	}); err != nil {
		t.Fatalf("replace create callback: %v", err)
	}
	return &userService{db: database}
}
