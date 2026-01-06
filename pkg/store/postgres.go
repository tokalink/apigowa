package store

import (
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/lib/pq"
	"go.mau.fi/whatsmeow/types"
	"golang.org/x/crypto/bcrypt"
)

// PostgresDriver implements DBDriver for PostgreSQL
type PostgresDriver struct {
	db  *sql.DB
	mu  sync.RWMutex
	cfg *DBConfig
}

// NewPostgresDriver creates a new PostgreSQL driver
func NewPostgresDriver(cfg *DBConfig) (*PostgresDriver, error) {
	// Build connection string
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.DBName,
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(100)
	db.SetMaxIdleConns(10)

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping postgres: %w", err)
	}

	driver := &PostgresDriver{
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
func (d *PostgresDriver) GetDB() *sql.DB {
	return d.db
}

// Close closes the database connection
func (d *PostgresDriver) Close() error {
	return d.db.Close()
}

// DriverName returns the driver name
func (d *PostgresDriver) DriverName() string {
	return "postgres"
}

// Migrate creates all necessary tables
func (d *PostgresDriver) Migrate() error {
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
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		CREATE INDEX IF NOT EXISTS idx_account_tokens_jid ON account_tokens(jid);
		CREATE INDEX IF NOT EXISTS idx_account_tokens_workspace ON account_tokens(workspace);
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
		);
	`)
	if err != nil {
		return fmt.Errorf("failed to create admin table: %w", err)
	}

	// Create or replace update trigger for updated_at
	_, _ = d.db.Exec(`
		CREATE OR REPLACE FUNCTION update_updated_at_column()
		RETURNS TRIGGER AS $$
		BEGIN
			NEW.updated_at = CURRENT_TIMESTAMP;
			RETURN NEW;
		END;
		$$ language 'plpgsql';
	`)

	_, _ = d.db.Exec(`
		DROP TRIGGER IF EXISTS update_account_tokens_updated_at ON account_tokens;
		CREATE TRIGGER update_account_tokens_updated_at
			BEFORE UPDATE ON account_tokens
			FOR EACH ROW
			EXECUTE FUNCTION update_updated_at_column();
	`)

	return nil
}

// GetJID retrieves the JID for a token
func (d *PostgresDriver) GetJID(token string) (types.JID, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var jidStr sql.NullString
	err := d.db.QueryRow("SELECT jid FROM account_tokens WHERE token = $1 AND jid IS NOT NULL", token).Scan(&jidStr)
	if err != nil {
		return types.EmptyJID, err
	}
	if !jidStr.Valid || jidStr.String == "" {
		return types.EmptyJID, sql.ErrNoRows
	}
	return types.ParseJID(jidStr.String)
}

// InsertToken inserts a new token
func (d *PostgresDriver) InsertToken(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("INSERT INTO account_tokens (token, jid) VALUES ($1, NULL) ON CONFLICT (token) DO NOTHING", token)
	return err
}

// UpdateTokenJID updates the JID and push name for a token
func (d *PostgresDriver) UpdateTokenJID(token string, jid types.JID, pushName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET jid = $1, push_name = $2 WHERE token = $3",
		jid.String(), pushName, token,
	)
	return err
}

// ClearTokenJID clears the JID and push name for a token
func (d *PostgresDriver) ClearTokenJID(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET jid = NULL, push_name = NULL WHERE token = $1",
		token,
	)
	return err
}

// DeleteToken deletes a token
func (d *PostgresDriver) DeleteToken(token string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM account_tokens WHERE token = $1", token)
	return err
}

// TokenExists checks if token exists and returns JID if present
func (d *PostgresDriver) TokenExists(token string) (bool, string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var jidStr sql.NullString
	err := d.db.QueryRow("SELECT jid FROM account_tokens WHERE token = $1", token).Scan(&jidStr)
	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return true, jidStr.String, nil
}

// GetDeviceInfo retrieves device info for a token
func (d *PostgresDriver) GetDeviceInfo(token string) (*DeviceSummary, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var ds DeviceSummary
	var jid, name, webhook, workspace sql.NullString

	err := d.db.QueryRow(
		"SELECT token, jid, push_name, webhook_url, workspace FROM account_tokens WHERE token = $1",
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
func (d *PostgresDriver) GetDevices(limit, offset int, search, workspaceFilter string) ([]DeviceSummary, int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := "SELECT token, jid, push_name, webhook_url, workspace FROM account_tokens"
	countQuery := "SELECT COUNT(*) FROM account_tokens"
	var args []interface{}
	argIdx := 1
	var whereClauses []string

	if search != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("(token LIKE $%d OR push_name LIKE $%d)", argIdx, argIdx+1))
		args = append(args, "%"+search+"%", "%"+search+"%")
		argIdx += 2
	}
	if workspaceFilter != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("workspace = $%d", argIdx))
		args = append(args, workspaceFilter)
		argIdx++
	}

	if len(whereClauses) > 0 {
		whereClause := " WHERE " + whereClauses[0]
		for i := 1; i < len(whereClauses); i++ {
			whereClause += " AND " + whereClauses[i]
		}
		query += whereClause
		countQuery += whereClause
	}

	// Get total count
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var total int
	if err := d.db.QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Add limit and offset
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, limit, offset)

	// Get data
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
func (d *PostgresDriver) UpdateWebhook(token, url string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(
		"UPDATE account_tokens SET webhook_url = $1 WHERE token = $2",
		url, token,
	)
	return err
}

// GetWebhook retrieves the webhook URL for a token
func (d *PostgresDriver) GetWebhook(token string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var url sql.NullString
	err := d.db.QueryRow("SELECT webhook_url FROM account_tokens WHERE token = $1", token).Scan(&url)
	if err != nil {
		return "", err
	}
	return url.String, nil
}

// UpdateWorkspace updates the workspace for a token
func (d *PostgresDriver) UpdateWorkspace(token, workspace string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT INTO account_tokens (token, workspace) VALUES ($1, $2)
		ON CONFLICT (token) DO UPDATE SET workspace = $2
	`, token, workspace)
	return err
}

// GetWorkspaces retrieves all unique workspaces
func (d *PostgresDriver) GetWorkspaces() ([]string, error) {
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
func (d *PostgresDriver) SetCredentials(username, password string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = d.db.Exec(`
		INSERT INTO admin (username, password_hash) VALUES ($1, $2)
		ON CONFLICT (username) DO UPDATE SET password_hash = $2
	`, username, string(hashedPassword))
	return err
}

// CheckCredentials verifies admin credentials
func (d *PostgresDriver) CheckCredentials(username, password string) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var hash string
	err := d.db.QueryRow("SELECT password_hash FROM admin WHERE username = $1", username).Scan(&hash)
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
func (d *PostgresDriver) IsSetupComplete() (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
