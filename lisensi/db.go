package main

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type LicenseDB struct {
	db *sql.DB
}

type License struct {
	ID          int
	LicenseKey  string
	DeviceLimit int
	AccountLimit int
	CreatedAt   time.Time
	ExpiresAt   sql.NullTime // Can be null if unlimited
}

func InitDB(filepath string) (*LicenseDB, error) {
	db, err := sql.Open("sqlite", filepath)
	if err != nil {
		return nil, err
	}

	if err = db.Ping(); err != nil {
		return nil, err
	}

	// Buat tabel licenses
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS licenses (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			license_key TEXT UNIQUE NOT NULL,
			device_limit INTEGER NOT NULL,
			account_limit INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME
		);
	`)
	if err != nil {
		return nil, err
	}

	// Menambahkan kolom account_limit jika sebelumnya belum ada (ignore error)
	db.Exec(`ALTER TABLE licenses ADD COLUMN account_limit INTEGER DEFAULT 0`)

	// Buat tabel devices untuk tracking penggunaan device per lisensi
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS devices (
			license_key TEXT NOT NULL,
			device_id TEXT NOT NULL,
			last_used DATETIME DEFAULT CURRENT_TIMESTAMP,
			ip_address TEXT DEFAULT '',
			PRIMARY KEY (license_key, device_id),
			FOREIGN KEY (license_key) REFERENCES licenses(license_key) ON DELETE CASCADE
		);
	`)
	if err != nil {
		return nil, err
	}

	// Menambahkan kolom ip_address jika sebelumnya belum ada (ignore error jika sudah ada)
	db.Exec(`ALTER TABLE devices ADD COLUMN ip_address TEXT DEFAULT ''`)

	return &LicenseDB{db: db}, nil
}

func (l *LicenseDB) CreateLicense(key string, deviceLimit, accountLimit int, expiresAt sql.NullTime) error {
	_, err := l.db.Exec(`INSERT INTO licenses (license_key, device_limit, account_limit, expires_at) VALUES (?, ?, ?, ?)`,
		key, deviceLimit, accountLimit, expiresAt)
	return err
}

func (l *LicenseDB) GetLicense(key string) (*License, error) {
	row := l.db.QueryRow(`SELECT id, license_key, device_limit, account_limit, created_at, expires_at FROM licenses WHERE license_key = ?`, key)

	var lic License
	err := row.Scan(&lic.ID, &lic.LicenseKey, &lic.DeviceLimit, &lic.AccountLimit, &lic.CreatedAt, &lic.ExpiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("license not found")
		}
		return nil, err
	}
	return &lic, nil
}

func (l *LicenseDB) GetAllLicenses() ([]License, error) {
	rows, err := l.db.Query(`SELECT id, license_key, device_limit, account_limit, created_at, expires_at FROM licenses ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var licenses []License
	for rows.Next() {
		var lic License
		if err := rows.Scan(&lic.ID, &lic.LicenseKey, &lic.DeviceLimit, &lic.AccountLimit, &lic.CreatedAt, &lic.ExpiresAt); err != nil {
			return nil, err
		}
		licenses = append(licenses, lic)
	}
	return licenses, nil
}

func (l *LicenseDB) DeleteLicense(key string) error {
	_, err := l.db.Exec(`DELETE FROM licenses WHERE license_key = ?`, key)
	return err
}

func (l *LicenseDB) GetUsedDeviceCount(key string) (int, error) {
	var count int
	err := l.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE license_key = ?`, key).Scan(&count)
	return count, err
}

func (l *LicenseDB) GetLastUsed(key string) (sql.NullTime, string, error) {
	var lastUsedStr sql.NullString
	var ipAddress sql.NullString

	err := l.db.QueryRow(`
		SELECT last_used, ip_address 
		FROM devices 
		WHERE license_key = ? 
		ORDER BY last_used DESC LIMIT 1
	`, key).Scan(&lastUsedStr, &ipAddress)

	var lastUsed sql.NullTime
	if lastUsedStr.Valid && lastUsedStr.String != "" {
		// SQLite CURRENT_TIMESTAMP format is 'YYYY-MM-DD HH:MM:SS' in UTC
		t, parseErr := time.Parse("2006-01-02 15:04:05", lastUsedStr.String)
		if parseErr == nil {
			lastUsed.Time = t
			lastUsed.Valid = true
		} else {
            // Coba parse RFC3339 jika berbeda
            t2, parseErr2 := time.Parse(time.RFC3339, lastUsedStr.String)
            if parseErr2 == nil {
                lastUsed.Time = t2
                lastUsed.Valid = true
            }
        }
	}
	return lastUsed, ipAddress.String, err
}

func (l *LicenseDB) RegisterDevice(key, deviceID, ip string) error {
	_, err := l.db.Exec(`
		INSERT INTO devices (license_key, device_id, last_used, ip_address) 
		VALUES (?, ?, CURRENT_TIMESTAMP, ?)
		ON CONFLICT(license_key, device_id) 
		DO UPDATE SET last_used = CURRENT_TIMESTAMP, ip_address = ?`,
		key, deviceID, ip, ip)
	return err
}

func (l *LicenseDB) IsDeviceRegistered(key, deviceID string) bool {
	var count int
	err := l.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE license_key = ? AND device_id = ?`, key, deviceID).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func (l *LicenseDB) Close() error {
	return l.db.Close()
}
