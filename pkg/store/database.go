package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type Store struct {
	Container *sqlstore.Container
	DB        *sql.DB
	// Cache mapping Token -> JID
	TokenCache map[string]types.JID
	mu         sync.RWMutex
}

func NewStore(dbPath string) (*Store, error) {
	// Set device name dari environment variable
	deviceName := os.Getenv("DEVICE_NAME")
	if deviceName == "" {
		deviceName = "ApiWago"
	}
	store.SetOSInfo(deviceName, [3]uint32{2, 2450, 0}) // Nama device, versi

	dbLog := waLog.Stdout("Database", "WARN", true)
	// Use WAL mode and busy timeout to avoid locking issues
	container, err := sqlstore.New(context.Background(), "sqlite", fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout=5000&_pragma=journal_mode=WAL", dbPath), dbLog)
	if err != nil {
		return nil, err
	}

	// Open raw DB connection for our custom table
	// Use same pragmas
	rawDB, err := sql.Open("sqlite", fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout=5000&_pragma=journal_mode=WAL", dbPath))
	if err != nil {
		return nil, err
	}

	// Create a table to map Tokens to JIDs
	_, err = rawDB.Exec(`
		CREATE TABLE IF NOT EXISTS account_tokens (
			token TEXT PRIMARY KEY,
			jid TEXT,
			push_name TEXT,
			webhook_url TEXT
		);
		CREATE TABLE IF NOT EXISTS admin (
			username TEXT PRIMARY KEY,
			password_hash TEXT
		);
	`)
	if err != nil {
		return nil, err
	}

	// Migration for existing tables (ignore errors if columns exist)
	_, _ = rawDB.Exec("ALTER TABLE account_tokens ADD COLUMN push_name TEXT;")
	_, _ = rawDB.Exec("ALTER TABLE account_tokens ADD COLUMN webhook_url TEXT;")
	if _, err := rawDB.Exec("ALTER TABLE account_tokens ADD COLUMN workspace TEXT;"); err != nil {
		fmt.Printf("[Database] Migration workspace: %v\n", err)
	} else {
		fmt.Println("[Database] Migration workspace: success")
	}

	return &Store{
		Container:  container,
		DB:         rawDB,
		TokenCache: make(map[string]types.JID),
	}, nil
}

// GetDevice returns the device store for a given token.
// If it's a new token, it creates a new device.
func (s *Store) GetDevice(token string) (*store.Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Check if we already have a JID for this token
	var jidStr sql.NullString
	err := s.DB.QueryRow("SELECT jid FROM account_tokens WHERE token = ?", token).Scan(&jidStr)
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	if jidStr.Valid && jidStr.String != "" {
		fmt.Printf("[Store] Found JID %s for token %s\n", jidStr.String, token)
		// Existing device
		jid, _ := types.ParseJID(jidStr.String)
		// Fix: Pass context
		device, err := s.Container.GetDevice(context.Background(), jid)
		if err != nil {
			fmt.Printf("[Store] Failed to load device from container for JID %s: %v. Resetting token.\n", jid, err)
			// Device mismatch? Clear JID
			s.DB.Exec("UPDATE account_tokens SET jid = NULL WHERE token = ?", token)
			return s.Container.NewDevice(), nil
		}
		if device == nil {
			fmt.Printf("[Store] Container returned nil device for JID %s\n", jid)
			return s.Container.NewDevice(), nil
		}
		return device, nil
	}

	fmt.Printf("[Store] No JID found for token %s. Creating new device.\n", token)
	// 2. New Token or Token without JID -> Create new Device
	device := s.Container.NewDevice()

	// Insert token if not exists.
	if err == sql.ErrNoRows {
		_, err = s.DB.Exec("INSERT INTO account_tokens (token, jid) VALUES (?, NULL)", token)
		if err != nil {
			return nil, err
		}
	}

	return device, nil
}

// SaveLogin associates a token with a JID after successful pairing
func (s *Store) UpdateTokenJID(token string, jid types.JID, pushName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("[Store] Updating token %s with JID %s and Name %s\n", token, jid.String(), pushName)
	_, err := s.DB.Exec("UPDATE account_tokens SET jid = ?, push_name = ? WHERE token = ?", jid.String(), pushName, token)
	return err
}

// ClearTokenJID menghapus JID dan nama dari database (dipakai saat logout)
func (s *Store) ClearTokenJID(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Printf("[Store] Clearing JID and name for token %s\n", token)
	_, err := s.DB.Exec("UPDATE account_tokens SET jid = NULL, push_name = NULL WHERE token = ?", token)
	return err
}

func (s *Store) UpdateWebhook(token, url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.DB.Exec("UPDATE account_tokens SET webhook_url = ? WHERE token = ?", url, token)
	return err
}

func (s *Store) GetWebhook(token string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var url sql.NullString
	err := s.DB.QueryRow("SELECT webhook_url FROM account_tokens WHERE token = ?", token).Scan(&url)
	if err != nil {
		return "", err
	}
	return url.String, nil
}

func (s *Store) UpdateWorkspace(token, workspace string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Insert if not exists
	var exists bool
	s.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM account_tokens WHERE token = ?)", token).Scan(&exists)
	if !exists {
		_, err := s.DB.Exec("INSERT INTO account_tokens (token, workspace) VALUES (?, ?)", token, workspace)
		return err
	}
	_, err := s.DB.Exec("UPDATE account_tokens SET workspace = ? WHERE token = ?", workspace, token)
	return err
}

func (s *Store) GetWorkspaces() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.DB.Query("SELECT DISTINCT workspace FROM account_tokens WHERE workspace IS NOT NULL AND workspace != ''")
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

func (s *Store) GetDeviceInfo(token string) (*DeviceSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var d DeviceSummary
	var jid, name, webhook, workspace sql.NullString
	err := s.DB.QueryRow("SELECT token, jid, push_name, webhook_url, workspace FROM account_tokens WHERE token = ?", token).Scan(&d.Token, &jid, &name, &webhook, &workspace)
	if err != nil {
		return nil, err
	}
	d.JID = jid.String
	d.Name = name.String
	d.Webhook = webhook.String
	d.Workspace = workspace.String
	return &d, nil
}

func (s *Store) GetJID(token string) (types.JID, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var jidStr string
	err := s.DB.QueryRow("SELECT jid FROM account_tokens WHERE token = ? AND jid IS NOT NULL", token).Scan(&jidStr)
	if err != nil {
		return types.EmptyJID, err
	}
	return types.ParseJID(jidStr)
}

func (s *Store) DeleteDevice(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get JID first to clean up container
	var jidStr sql.NullString
	err := s.DB.QueryRow("SELECT jid FROM account_tokens WHERE token = ?", token).Scan(&jidStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil // Already deleted
		}
		return err
	}

	// Delete from local table
	_, err = s.DB.Exec("DELETE FROM account_tokens WHERE token = ?", token)
	if err != nil {
		return err
	}

	// Cleanup whatsmeow store if JID was present
	if jidStr.Valid && jidStr.String != "" {
		jid, _ := types.ParseJID(jidStr.String)
		// Fix: GetDevice first then delete
		device, err := s.Container.GetDevice(context.Background(), jid)
		if err == nil && device != nil {
			return s.Container.DeleteDevice(context.Background(), device)
		}
	}
	return nil
}

func (s *Store) SetCredentials(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// upsert
	_, err = s.DB.Exec("INSERT OR REPLACE INTO admin (username, password_hash) VALUES (?, ?)", username, string(hashedPassword))
	return err
}

func (s *Store) CheckCredentials(username, password string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var hash string
	err := s.DB.QueryRow("SELECT password_hash FROM admin WHERE username = ?", username).Scan(&hash)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		return false, nil // Invalid password
	}

	return true, nil
}

func (s *Store) IsSetupDetails() (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.DB.QueryRow("SELECT COUNT(*) FROM admin").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

type DeviceSummary struct {
	Token     string `json:"token"`
	JID       string `json:"jid"`
	Name      string `json:"name"`
	Webhook   string `json:"webhook"`
	Workspace string `json:"workspace"`
}

func (s *Store) GetDevices(limit, offset int, search, workspaceFilter string) ([]DeviceSummary, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Base query
	query := "SELECT token, jid, push_name, webhook_url, workspace FROM account_tokens"
	countQuery := "SELECT COUNT(*) FROM account_tokens"
	var args []interface{}
	var whereClauses []string

	if search != "" {
		whereClauses = append(whereClauses, "token LIKE ?")
		args = append(args, "%"+search+"%")
	}
	if workspaceFilter != "" {
		whereClauses = append(whereClauses, "workspace = ?")
		args = append(args, workspaceFilter)
	}

	if len(whereClauses) > 0 {
		clause := " WHERE " + whereClauses[0]
		for i := 1; i < len(whereClauses); i++ {
			clause += " AND " + whereClauses[i]
		}
		query += clause
		countQuery += clause
	}

	query += " LIMIT ? OFFSET ?"
	// Need to duplicate args for count query? No, count uses same args less limit/offset
	// Wait, count args must match countQuery placeholders.
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	args = append(args, limit, offset)

	// Get Total Count
	var total int
	err := s.DB.QueryRow(countQuery, countArgs...).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	// Get Data
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var devices []DeviceSummary
	for rows.Next() {
		var token string
		var jid sql.NullString
		var pushName sql.NullString
		var webhook sql.NullString
		var workspace sql.NullString

		if err := rows.Scan(&token, &jid, &pushName, &webhook, &workspace); err != nil {
			return nil, 0, err
		}
		devices = append(devices, DeviceSummary{
			Token:     token,
			JID:       jid.String,
			Name:      pushName.String,
			Webhook:   webhook.String,
			Workspace: workspace.String,
		})
	}
	return devices, total, nil

}
