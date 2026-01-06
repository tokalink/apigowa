package store

import (
	"database/sql"
	"fmt"
	"sync"

	"go.mau.fi/whatsmeow/types"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// SQLiteDriver implements DBDriver for SQLite
type SQLiteDriver struct {
	db   *sql.DB
	mu   sync.RWMutex
	path string
}

// NewSQLiteDriver creates a new SQLite driver
func NewSQLiteDriver(dbPath string) (*SQLiteDriver, error) {
	// Open with WAL mode and busy timeout for better concurrency
	dsn := fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout=5000&_pragma=journal_mode=WAL", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	// Set connection pool settings for SQLite
	db.SetMaxOpenConns(1) // SQLite only supports one writer at a time
	db.SetMaxIdleConns(1)

	driver := &SQLiteDriver{
		db:   db,
		path: dbPath,
	}

	// Run migrations
	if err := driver.Migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate: %w", err)
	}

	return driver, nil
}

// GetDB returns the underlying database connection
func (d *SQLiteDriver) GetDB() *sql.DB {
	return d.db
}

// Close closes the database connection
func (d *SQLiteDriver) Close() error {
	return d.db.Close()
}

// DriverName returns the driver name
func (d *SQLiteDriver) DriverName() string {
	return "sqlite"
}

// Migrate creates all necessary tables
func (d *SQLiteDriver) Migrate() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Create tables
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS account_tokens (
			token TEXT PRIMARY KEY,
			jid TEXT,
			push_name TEXT,
			webhook_url TEXT,
			workspace TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE TABLE IF NOT EXISTS admin (
			username TEXT PRIMARY KEY,
			password_hash TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_account_tokens_jid ON account_tokens(jid);
		CREATE INDEX IF NOT EXISTS idx_account_tokens_workspace ON account_tokens(workspace);
	`)
	if err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Run migrations for existing databases (ignore errors if columns already exist)
	migrations := []string{
		"ALTER TABLE account_tokens ADD COLUMN push_name TEXT;",
		"ALTER TABLE account_tokens ADD COLUMN webhook_url TEXT;",
		"ALTER TABLE account_tokens ADD COLUMN workspace TEXT;",
		"ALTER TABLE account_tokens ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP;",
		"ALTER TABLE account_tokens ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;",
	}

	for _, migration := range migrations {
		_, _ = d.db.Exec(migration) // Ignore errors for already existing columns
	}

	return nil
}

// GetJID retrieves the JID for a token
func (d *SQLiteDriver) GetJID(token string) (types.JID, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var jidStr sql.NullString
	err := d.db.QueryRow("SELECT jid FROM account_tokens WHERE token = ? AND jid IS NOT NULL", token).Scan(&jidStr)
	if err != nil {
		return types.EmptyJID, err
	}
	if !jidStr.Valid || jidStr.String == "" {
		return types.EmptyJID, sql.ErrNoRows
	}
	return types.ParseJID(jidStr.String)
}

// InsertToken inserts a new token
func (d *SQLiteDriver) InsertToken(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("INSERT OR IGNORE INTO account_tokens (token, jid) VALUES (?, NULL)", token)
	return err
}

// UpdateTokenJID updates the JID and push name for a token
func (d *SQLiteDriver) UpdateTokenJID(token string, jid types.JID, pushName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET jid = ?, push_name = ?, updated_at = CURRENT_TIMESTAMP WHERE token = ?",
		jid.String(), pushName, token,
	)
	return err
}

// ClearTokenJID clears the JID and push name for a token
func (d *SQLiteDriver) ClearTokenJID(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET jid = NULL, push_name = NULL, updated_at = CURRENT_TIMESTAMP WHERE token = ?",
		token,
	)
	return err
}

// DeleteToken deletes a token
func (d *SQLiteDriver) DeleteToken(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM account_tokens WHERE token = ?", token)
	return err
}

// TokenExists checks if token exists and returns JID if present
func (d *SQLiteDriver) TokenExists(token string) (bool, string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var jidStr sql.NullString
	err := d.db.QueryRow("SELECT jid FROM account_tokens WHERE token = ?", token).Scan(&jidStr)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, jidStr.String, nil
}

// GetDeviceInfo retrieves device info for a token
func (d *SQLiteDriver) GetDeviceInfo(token string) (*DeviceSummary, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var ds DeviceSummary
	var jid, name, webhook, workspace sql.NullString

	err := d.db.QueryRow(
		"SELECT token, jid, push_name, webhook_url, workspace FROM account_tokens WHERE token = ?",
		token,
	).Scan(&ds.Token, &jid, &name, &webhook, &workspace)

	if err != nil {
		return nil, err
	}

	ds.JID = jid.String
	ds.Name = name.String
	ds.Webhook = webhook.String
	ds.Workspace = workspace.String

	return &ds, nil
}

// GetDevices retrieves paginated device list
func (d *SQLiteDriver) GetDevices(limit, offset int, search, workspaceFilter string) ([]DeviceSummary, int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := "SELECT token, jid, push_name, webhook_url, workspace FROM account_tokens"
	countQuery := "SELECT COUNT(*) FROM account_tokens"
	var args []interface{}
	var whereClauses []string

	if search != "" {
		whereClauses = append(whereClauses, "(token LIKE ? OR push_name LIKE ?)")
		args = append(args, "%"+search+"%", "%"+search+"%")
	}
	if workspaceFilter != "" {
		whereClauses = append(whereClauses, "workspace = ?")
		args = append(args, workspaceFilter)
	}

	if len(whereClauses) > 0 {
		whereClause := " WHERE " + whereClauses[0]
		for i := 1; i < len(whereClauses); i++ {
			whereClause += " AND " + whereClauses[i]
		}
		query += whereClause
		countQuery += whereClause
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"

	// Get total count
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var total int
	if err := d.db.QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Get data
	args = append(args, limit, offset)
	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var devices []DeviceSummary
	for rows.Next() {
		var ds DeviceSummary
		var jid, name, webhook, workspace sql.NullString

		if err := rows.Scan(&ds.Token, &jid, &name, &webhook, &workspace); err != nil {
			return nil, 0, err
		}

		ds.JID = jid.String
		ds.Name = name.String
		ds.Webhook = webhook.String
		ds.Workspace = workspace.String
		devices = append(devices, ds)
	}

	return devices, total, nil
}

// UpdateWebhook updates the webhook URL for a token
func (d *SQLiteDriver) UpdateWebhook(token, url string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET webhook_url = ?, updated_at = CURRENT_TIMESTAMP WHERE token = ?",
		url, token,
	)
	return err
}

// GetWebhook retrieves the webhook URL for a token
func (d *SQLiteDriver) GetWebhook(token string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var url sql.NullString
	err := d.db.QueryRow("SELECT webhook_url FROM account_tokens WHERE token = ?", token).Scan(&url)
	if err != nil {
		return "", err
	}
	return url.String, nil
}

// UpdateWorkspace updates the workspace for a token
func (d *SQLiteDriver) UpdateWorkspace(token, workspace string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Insert if not exists, update if exists
	_, err := d.db.Exec(`
		INSERT INTO account_tokens (token, workspace) VALUES (?, ?)
		ON CONFLICT(token) DO UPDATE SET workspace = ?, updated_at = CURRENT_TIMESTAMP
	`, token, workspace, workspace)
	return err
}

// GetWorkspaces retrieves all unique workspaces
func (d *SQLiteDriver) GetWorkspaces() ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query("SELECT DISTINCT workspace FROM account_tokens WHERE workspace IS NOT NULL AND workspace != '' ORDER BY workspace")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var workspaces []string
	for rows.Next() {
		var w string
		if err := rows.Scan(&w); err == nil {
			workspaces = append(workspaces, w)
		}
	}
	return workspaces, nil
}

// SetCredentials sets admin credentials
func (d *SQLiteDriver) SetCredentials(username, password string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = d.db.Exec("INSERT OR REPLACE INTO admin (username, password_hash) VALUES (?, ?)", username, string(hashedPassword))
	return err
}

// CheckCredentials verifies admin credentials
func (d *SQLiteDriver) CheckCredentials(username, password string) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var hash string
	err := d.db.QueryRow("SELECT password_hash FROM admin WHERE username = ?", username).Scan(&hash)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil, nil
}

// IsSetupComplete checks if admin is set up
func (d *SQLiteDriver) IsSetupComplete() (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
