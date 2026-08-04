package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BaukunstPatrimonio/user-go/server/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var refreshDriverNumber uint64

type refreshDatabaseState struct {
	user          models.User
	updateErr     error
	beginCount    int
	commitCount   int
	rollbackCount int
}

type refreshTestDriver struct {
	state *refreshDatabaseState
}

func (d *refreshTestDriver) Open(string) (driver.Conn, error) {
	return &refreshTestConn{state: d.state}, nil
}

type refreshTestConn struct {
	state *refreshDatabaseState
	tx    *refreshTestTx
}

func (*refreshTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("prepared statements are not supported")
}

func (*refreshTestConn) Close() error {
	return nil
}

func (c *refreshTestConn) Begin() (driver.Tx, error) {
	return c.begin(), nil
}

func (c *refreshTestConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return c.begin(), nil
}

func (c *refreshTestConn) begin() *refreshTestTx {
	c.state.beginCount++
	c.tx = &refreshTestTx{conn: c, pending: c.state.user}
	return c.tx
}

func (*refreshTestConn) CheckNamedValue(value *driver.NamedValue) error {
	switch typed := value.Value.(type) {
	case uint:
		value.Value = int64(typed)
	case uint32:
		value.Value = int64(typed)
	case uint64:
		value.Value = int64(typed)
	}
	return nil
}

func (c *refreshTestConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.tx == nil {
		return nil, errors.New("update executed outside transaction")
	}
	columns, err := refreshUpdateColumns(query)
	if err != nil {
		return nil, err
	}
	if len(args) != len(columns)+2 {
		return nil, fmt.Errorf("unexpected update arguments: got %d, want %d", len(args), len(columns)+2)
	}
	id, ok := args[len(args)-2].Value.(int64)
	if !ok {
		return nil, fmt.Errorf("unexpected id type %T", args[len(args)-2].Value)
	}
	oldCodeRefresh, ok := args[len(args)-1].Value.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected old refresh code type %T", args[len(args)-1].Value)
	}
	if uint(id) != c.tx.pending.ID || oldCodeRefresh != c.tx.pending.CodeRefresh {
		return driver.RowsAffected(0), nil
	}

	for index, column := range columns {
		value := args[index].Value
		switch column {
		case "browser":
			c.tx.pending.Browser = value.(string)
		case "browser_version":
			c.tx.pending.BrowserVersion = value.(string)
		case "operating_system":
			c.tx.pending.OperatingSystem = value.(string)
		case "operating_system_version":
			c.tx.pending.OperatingSystemVersion = value.(string)
		case "language":
			c.tx.pending.Language = value.(string)
		case "timezone":
			c.tx.pending.Timezone = value.(string)
		case "cpu":
			c.tx.pending.Cpu = value.(string)
		case "code_refresh":
			c.tx.pending.CodeRefresh = value.(string)
		case "updated_at":
			c.tx.pending.UpdatedAt = value.(time.Time)
		default:
			return nil, fmt.Errorf("unexpected update column %q", column)
		}
	}
	if c.state.updateErr != nil {
		return nil, c.state.updateErr
	}
	return driver.RowsAffected(1), nil
}

type refreshTestTx struct {
	conn    *refreshTestConn
	pending models.User
}

func (tx *refreshTestTx) Commit() error {
	tx.conn.state.user = tx.pending
	tx.conn.state.commitCount++
	tx.conn.tx = nil
	return nil
}

func (tx *refreshTestTx) Rollback() error {
	tx.conn.state.rollbackCount++
	tx.conn.tx = nil
	return nil
}

func refreshUpdateColumns(query string) ([]string, error) {
	setIndex := strings.Index(query, " SET ")
	whereIndex := strings.LastIndex(query, " WHERE ")
	if setIndex < 0 || whereIndex < 0 || whereIndex <= setIndex {
		return nil, fmt.Errorf("unexpected update query %q", query)
	}
	assignments := strings.Split(query[setIndex+5:whereIndex], ",")
	columns := make([]string, 0, len(assignments))
	for _, assignment := range assignments {
		parts := strings.SplitN(assignment, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unexpected assignment %q", assignment)
		}
		columns = append(columns, strings.Trim(strings.TrimSpace(parts[0]), `"`))
	}
	return columns, nil
}

func TestUpdateRefreshSessionSuccess(t *testing.T) {
	state := &refreshDatabaseState{user: refreshServiceUser()}
	service := newRefreshServiceTest(t, state)
	device := state.user.DeviceInfo
	device.BrowserVersion = "129"
	device.OperatingSystemVersion = "6.11"
	device.Language = "es-ES"
	device.Timezone = "UTC"
	device.Cpu = "arm64"
	device.CookiesEnabled = false

	err := service.UpdateRefreshSession(context.Background(), state.user.ID, device, "old-code", "new-code")
	if err != nil {
		t.Fatalf("UpdateRefreshSession() error = %v", err)
	}
	if state.beginCount != 1 || state.commitCount != 1 || state.rollbackCount != 0 {
		t.Fatalf("transaction counts = begin:%d commit:%d rollback:%d, want 1/1/0", state.beginCount, state.commitCount, state.rollbackCount)
	}
	device.CookiesEnabled = true
	if state.user.DeviceInfo != device || state.user.CodeRefresh != "new-code" {
		t.Fatalf("stored session = %#v/%q, want %#v/%q", state.user.DeviceInfo, state.user.CodeRefresh, device, "new-code")
	}
}

func TestUpdateRefreshSessionReturnsInvalidCodeWhenConditionDoesNotMatch(t *testing.T) {
	state := &refreshDatabaseState{user: refreshServiceUser()}
	service := newRefreshServiceTest(t, state)
	before := state.user

	err := service.UpdateRefreshSession(context.Background(), state.user.ID+1, state.user.DeviceInfo, "old-code", "new-code")
	if !errors.Is(err, models.ErrInvalidCode) {
		t.Fatalf("UpdateRefreshSession() error = %v, want %v", err, models.ErrInvalidCode)
	}
	if state.commitCount != 0 || state.rollbackCount != 1 || state.user != before {
		t.Fatalf("not-found transaction changed state: %#v", state)
	}
}

func TestUpdateRefreshSessionStaleWriteCannotOverwriteRotatedSession(t *testing.T) {
	state := &refreshDatabaseState{user: refreshServiceUser()}
	service := newRefreshServiceTest(t, state)
	firstDevice := state.user.DeviceInfo
	firstDevice.Language = "es-ES"
	if err := service.UpdateRefreshSession(context.Background(), state.user.ID, firstDevice, "old-code", "first-new-code"); err != nil {
		t.Fatalf("first UpdateRefreshSession() error = %v", err)
	}

	staleDevice := state.user.DeviceInfo
	staleDevice.Language = "de-DE"
	err := service.UpdateRefreshSession(context.Background(), state.user.ID, staleDevice, "old-code", "stale-new-code")
	if !errors.Is(err, models.ErrInvalidCode) {
		t.Fatalf("stale UpdateRefreshSession() error = %v, want %v", err, models.ErrInvalidCode)
	}
	if state.user.CodeRefresh != "first-new-code" {
		t.Fatalf("stored code_refresh = %q, want %q", state.user.CodeRefresh, "first-new-code")
	}
	if state.user.Language != "es-ES" {
		t.Fatalf("stored language = %q, want first update value %q", state.user.Language, "es-ES")
	}
}

func TestUpdateRefreshSessionRollsBackWithoutPartialChanges(t *testing.T) {
	databaseErr := errors.New("database update failed")
	state := &refreshDatabaseState{user: refreshServiceUser(), updateErr: databaseErr}
	service := newRefreshServiceTest(t, state)
	before := state.user
	device := before.DeviceInfo
	device.Browser = "Chrome"
	device.BrowserVersion = "130"
	device.Language = "es-ES"

	err := service.UpdateRefreshSession(context.Background(), state.user.ID, device, "old-code", "new-code")
	if !errors.Is(err, databaseErr) {
		t.Fatalf("UpdateRefreshSession() error = %v, want %v", err, databaseErr)
	}
	if state.commitCount != 0 || state.rollbackCount != 1 {
		t.Fatalf("transaction counts = commit:%d rollback:%d, want 0/1", state.commitCount, state.rollbackCount)
	}
	if state.user != before {
		t.Fatalf("stored session changed after rollback: %#v, want %#v", state.user, before)
	}
}

func TestUpdateRefreshSessionAdoptsEmptyBaselines(t *testing.T) {
	user := refreshServiceUser()
	user.Browser = ""
	user.OperatingSystem = ""
	state := &refreshDatabaseState{user: user}
	service := newRefreshServiceTest(t, state)
	device := user.DeviceInfo
	device.Browser = "Chrome"
	device.OperatingSystem = "Windows"

	if err := service.UpdateRefreshSession(context.Background(), user.ID, device, "old-code", "new-code"); err != nil {
		t.Fatalf("UpdateRefreshSession() error = %v", err)
	}
	if state.user.Browser != "Chrome" || state.user.OperatingSystem != "Windows" {
		t.Fatalf("stored baselines = %q/%q, want Chrome/Windows", state.user.Browser, state.user.OperatingSystem)
	}
}

func TestUpdateRefreshSessionRevokesCode(t *testing.T) {
	state := &refreshDatabaseState{user: refreshServiceUser()}
	service := newRefreshServiceTest(t, state)

	if err := service.UpdateRefreshSession(context.Background(), state.user.ID, state.user.DeviceInfo, "old-code", ""); err != nil {
		t.Fatalf("UpdateRefreshSession() error = %v", err)
	}
	if state.user.CodeRefresh != "" {
		t.Fatalf("stored code_refresh = %q, want revoked", state.user.CodeRefresh)
	}
}

func newRefreshServiceTest(t *testing.T, state *refreshDatabaseState) *userService {
	t.Helper()
	driverName := fmt.Sprintf("refresh-service-test-%d", atomic.AddUint64(&refreshDriverNumber, 1))
	sql.Register(driverName, &refreshTestDriver{state: state})
	sqlDB, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	db, err := gorm.Open(
		postgres.New(postgres.Config{Conn: sqlDB, WithoutReturning: true}),
		&gorm.Config{DisableAutomaticPing: true, Logger: logger.Default.LogMode(logger.Silent)},
	)
	if err != nil {
		t.Fatalf("open gorm test database: %v", err)
	}
	return &userService{db: db}
}

func refreshServiceUser() models.User {
	return models.User{
		Model: gorm.Model{ID: 42},
		DeviceInfo: models.DeviceInfo{
			Browser:                "Firefox",
			BrowserVersion:         "128",
			OperatingSystem:        "Linux",
			OperatingSystemVersion: "6.10",
			Cpu:                    "x86_64",
			Language:               "en-US",
			Timezone:               "Europe/Madrid",
			CookiesEnabled:         true,
		},
		Email:       "person@example.com",
		CodeRefresh: "old-code",
	}
}
