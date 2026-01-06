package store

import (
	"database/sql"
	"fmt"
	"os"

	"go.mau.fi/whatsmeow/types"
)

// DBDriver defines the interface for database operations
type DBDriver interface {
	// Core operations
	GetDB() *sql.DB
	Close() error
	Migrate() error
	DriverName() string

	// Account Token operations
	GetJID(token string) (types.JID, error)
	InsertToken(token string) error
	UpdateTokenJID(token string, jid types.JID, pushName string) error
	ClearTokenJID(token string) error
	DeleteToken(token string) error
	GetDeviceInfo(token string) (*DeviceSummary, error)
	GetDevices(limit, offset int, search, workspace string) ([]DeviceSummary, int, error)
	TokenExists(token string) (bool, string, error) // exists, jidStr, error

	// Webhook operations
	UpdateWebhook(token, url string) error
	GetWebhook(token string) (string, error)

	// Workspace operations
	UpdateWorkspace(token, workspace string) error
	GetWorkspaces() ([]string, error)

	// Admin operations
	SetCredentials(username, password string) error
	CheckCredentials(username, password string) (bool, error)
	IsSetupComplete() (bool, error)
}

// DeviceSummary represents a device/token summary
type DeviceSummary struct {
	Token     string `json:"token"`
	JID       string `json:"jid"`
	Name      string `json:"name"`
	Webhook   string `json:"webhook"`
	Workspace string `json:"workspace"`
}

// DBConfig holds database configuration
type DBConfig struct {
	Driver   string // sqlite, mysql, postgres
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	FilePath string // For SQLite
}

// NewDBConfigFromEnv creates DBConfig from environment variables
func NewDBConfigFromEnv() *DBConfig {
	driver := os.Getenv("DB_DRIVER")
	if driver == "" {
		driver = "sqlite"
	}

	return &DBConfig{
		Driver:   driver,
		Host:     getEnvOrDefault("DB_HOST", "localhost"),
		Port:     getEnvOrDefault("DB_PORT", "3306"),
		User:     getEnvOrDefault("DB_USER", "root"),
		Password: os.Getenv("DB_PASSWORD"),
		DBName:   getEnvOrDefault("DB_NAME", "apiwago"),
		FilePath: getEnvOrDefault("DB_PATH", "store.db"),
	}
}

func getEnvOrDefault(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// NewDriver creates a new database driver based on configuration
func NewDriver(cfg *DBConfig) (DBDriver, error) {
	switch cfg.Driver {
	case "sqlite":
		return NewSQLiteDriver(cfg.FilePath)
	case "mysql":
		return NewMySQLDriver(cfg)
	case "postgres":
		return NewPostgresDriver(cfg)
	default:
		return nil, fmt.Errorf("unsupported database driver: %s", cfg.Driver)
	}
}
