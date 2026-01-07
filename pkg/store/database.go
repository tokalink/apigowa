package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Store wraps the database driver and whatsmeow container
type Store struct {
	Driver    DBDriver
	Container *sqlstore.Container
}

// NewStore creates a new store with the configured database driver
func NewStore(dbPath string) (*Store, error) {
	// Load configuration from environment
	cfg := NewDBConfigFromEnv()

	// Override file path if provided (for backwards compatibility)
	if dbPath != "" && cfg.Driver == "sqlite" {
		cfg.FilePath = dbPath
	}

	// Create database driver
	driver, err := NewDriver(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create database driver: %w", err)
	}

	// Set device name from environment variable
	deviceName := os.Getenv("DEVICE_NAME")
	if deviceName == "" {
		deviceName = "ApiWago"
	}
	store.SetOSInfo(deviceName, [3]uint32{2, 2450, 0})

	// Create whatsmeow container
	// For whatsmeow, we need to use SQLite regardless of main DB
	// because whatsmeow stores encrypted session data
	waDBPath := cfg.FilePath
	if cfg.Driver != "sqlite" {
		// Use a separate SQLite file for whatsmeow session data
		waDBPath = "whatsmeow_sessions.db"
	}

	dbLog := waLog.Stdout("Database", "WARN", true)
	container, err := sqlstore.New(context.Background(), "sqlite",
		fmt.Sprintf("file:%s?_pragma=foreign_keys(1)&_pragma=busy_timeout=5000&_pragma=journal_mode=WAL", waDBPath),
		dbLog,
	)
	if err != nil {
		driver.Close()
		return nil, fmt.Errorf("failed to create whatsmeow container: %w", err)
	}

	return &Store{
		Driver:    driver,
		Container: container,
	}, nil
}

// Close closes all database connections
func (s *Store) Close() error {
	return s.Driver.Close()
}

// DB returns the underlying sql.DB for backwards compatibility
func (s *Store) DB() *sql.DB {
	return s.Driver.GetDB()
}

// GetDevice returns the device store for a given token
func (s *Store) GetDevice(token string) (*store.Device, error) {
	exists, jidStr, err := s.Driver.TokenExists(token)
	if err != nil {
		return nil, err
	}

	if exists && jidStr != "" {
		fmt.Printf("[Store] Found JID %s for token %s\n", jidStr, token)
		jid, _ := types.ParseJID(jidStr)
		device, err := s.Container.GetDevice(context.Background(), jid)
		if err != nil {
			fmt.Printf("[Store] Failed to load device from container for JID %s: %v. Resetting token.\n", jid, err)
			s.Driver.ClearTokenJID(token)
			return s.Container.NewDevice(), nil
		}
		if device == nil {
			fmt.Printf("[Store] Container returned nil device for JID %s\n", jid)
			return s.Container.NewDevice(), nil
		}
		return device, nil
	}

	fmt.Printf("[Store] No JID found for token %s. Creating new device.\n", token)
	device := s.Container.NewDevice()

	if !exists {
		if err := s.Driver.InsertToken(token); err != nil {
			return nil, err
		}
	}

	return device, nil
}

// UpdateTokenJID updates the JID for a token
func (s *Store) UpdateTokenJID(token string, jid types.JID, pushName string) error {
	fmt.Printf("[Store] Updating token %s with JID %s and Name %s\n", token, jid.String(), pushName)
	return s.Driver.UpdateTokenJID(token, jid, pushName)
}

// ClearTokenJID clears the JID for a token (used during logout)
func (s *Store) ClearTokenJID(token string) error {
	fmt.Printf("[Store] Clearing JID and name for token %s\n", token)
	return s.Driver.ClearTokenJID(token)
}

// DeleteDevice deletes a device/token
func (s *Store) DeleteDevice(token string) error {
	// Get JID first to clean up container
	jid, err := s.Driver.GetJID(token)
	if err == nil && jid != types.EmptyJID {
		device, err := s.Container.GetDevice(context.Background(), jid)
		if err == nil && device != nil {
			s.Container.DeleteDevice(context.Background(), device)
		}
	}

	return s.Driver.DeleteToken(token)
}

// GetDeviceInfo retrieves device info
func (s *Store) GetDeviceInfo(token string) (*DeviceSummary, error) {
	return s.Driver.GetDeviceInfo(token)
}

// GetDevices retrieves paginated devices
func (s *Store) GetDevices(limit, offset int, search, workspace string) ([]DeviceSummary, int, error) {
	return s.Driver.GetDevices(limit, offset, search, workspace)
}

// GetJID retrieves JID for a token
func (s *Store) GetJID(token string) (types.JID, error) {
	return s.Driver.GetJID(token)
}

// UpdateWebhook updates webhook URL
func (s *Store) UpdateWebhook(token, url string) error {
	return s.Driver.UpdateWebhook(token, url)
}

// GetWebhook retrieves webhook URL
func (s *Store) GetWebhook(token string) (string, error) {
	return s.Driver.GetWebhook(token)
}

// UpdateWorkspace updates workspace
func (s *Store) UpdateWorkspace(token, workspace string) error {
	return s.Driver.UpdateWorkspace(token, workspace)
}

// GetWorkspaces retrieves all workspaces
func (s *Store) GetWorkspaces() ([]string, error) {
	return s.Driver.GetWorkspaces()
}

// SetCredentials sets admin credentials
func (s *Store) SetCredentials(username, password string) error {
	return s.Driver.SetCredentials(username, password)
}

// CheckCredentials verifies admin credentials
func (s *Store) CheckCredentials(username, password string) (bool, error) {
	return s.Driver.CheckCredentials(username, password)
}

// IsSetupDetails checks if setup is complete
func (s *Store) IsSetupDetails() (bool, error) {
	return s.Driver.IsSetupComplete()
}

// GetLoggedInTokens returns all tokens with valid JIDs (for auto-reconnect)
func (s *Store) GetLoggedInTokens() ([]string, error) {
	return s.Driver.GetLoggedInTokens()
}
