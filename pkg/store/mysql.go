package store

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/go-sql-driver/mysql"
	"go.mau.fi/whatsmeow/types"
	"golang.org/x/crypto/bcrypt"
)

// MySQLDriver implements DBDriver for MySQL
type MySQLDriver struct {
	db  *sql.DB
	mu  sync.RWMutex
	cfg *DBConfig
}

// NewMySQLDriver creates a new MySQL driver
func NewMySQLDriver(cfg *DBConfig) (*MySQLDriver, error) {
	// Build DSN
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci",
		cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.DBName,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open mysql: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(100)
	db.SetMaxIdleConns(10)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping mysql: %w", err)
	}

	driver := &MySQLDriver{
		db:  db,
		cfg: cfg,
	}

	// Run migrations
	if err := driver.Migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate: %w", err)
	}

	return driver, nil
}

// GetDB returns the underlying database connection
func (d *MySQLDriver) GetDB() *sql.DB {
	return d.db
}

// Close closes the database connection
func (d *MySQLDriver) Close() error {
	return d.db.Close()
}

// DriverName returns the driver name
func (d *MySQLDriver) DriverName() string {
	return "mysql"
}

// Migrate creates all necessary tables
func (d *MySQLDriver) Migrate() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Create account_tokens table
	_, err := d.db.Exec(`
		CREATE TABLE IF NOT EXISTS account_tokens (
			token VARCHAR(255) PRIMARY KEY,
			jid VARCHAR(255),
			push_name VARCHAR(255),
			webhook_url TEXT,
			workspace VARCHAR(255),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			INDEX idx_jid (jid),
			INDEX idx_workspace (workspace)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
	`)
	if err != nil {
		return fmt.Errorf("failed to create account_tokens table: %w", err)
	}

	// Create admin table
	_, err = d.db.Exec(`
		CREATE TABLE IF NOT EXISTS admin (
			username VARCHAR(255) PRIMARY KEY,
			password_hash VARCHAR(255),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
	`)
	if err != nil {
		return fmt.Errorf("failed to create admin table: %w", err)
	}

	return nil
}

// GetJID retrieves the JID for a token
func (d *MySQLDriver) GetJID(token string) (types.JID, error) {
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
func (d *MySQLDriver) InsertToken(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("INSERT IGNORE INTO account_tokens (token, jid) VALUES (?, NULL)", token)
	return err
}

// UpdateTokenJID updates the JID and push name for a token
func (d *MySQLDriver) UpdateTokenJID(token string, jid types.JID, pushName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET jid = ?, push_name = ? WHERE token = ?",
		jid.String(), pushName, token,
	)
	return err
}

// ClearTokenJID clears the JID and push name for a token
func (d *MySQLDriver) ClearTokenJID(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET jid = NULL, push_name = NULL WHERE token = ?",
		token,
	)
	return err
}

// DeleteToken deletes a token
func (d *MySQLDriver) DeleteToken(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM account_tokens WHERE token = ?", token)
	return err
}

// TokenExists checks if token exists and returns JID if present
func (d *MySQLDriver) TokenExists(token string) (bool, string, error) {
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
func (d *MySQLDriver) GetDeviceInfo(token string) (*DeviceSummary, error) {
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
func (d *MySQLDriver) GetDevices(limit, offset int, search, workspaceFilter string) ([]DeviceSummary, int, error) {
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
func (d *MySQLDriver) UpdateWebhook(token, url string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET webhook_url = ? WHERE token = ?",
		url, token,
	)
	return err
}

// GetWebhook retrieves the webhook URL for a token
func (d *MySQLDriver) GetWebhook(token string) (string, error) {
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
func (d *MySQLDriver) UpdateWorkspace(token, workspace string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO account_tokens (token, workspace) VALUES (?, ?)
		ON DUPLICATE KEY UPDATE workspace = ?
	`, token, workspace, workspace)
	return err
}

// GetWorkspaces retrieves all unique workspaces
func (d *MySQLDriver) GetWorkspaces() ([]string, error) {
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
func (d *MySQLDriver) SetCredentials(username, password string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = d.db.Exec(`
		INSERT INTO admin (username, password_hash) VALUES (?, ?)
		ON DUPLICATE KEY UPDATE password_hash = ?
	`, username, string(hashedPassword), string(hashedPassword))
	return err
}

// CheckCredentials verifies admin credentials
func (d *MySQLDriver) CheckCredentials(username, password string) (bool, error) {
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
func (d *MySQLDriver) IsSetupComplete() (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetLoggedInTokens returns all tokens with valid JIDs
func (d *MySQLDriver) GetLoggedInTokens() ([]string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query("SELECT token FROM account_tokens WHERE jid IS NOT NULL AND jid != ''")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err == nil {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}
