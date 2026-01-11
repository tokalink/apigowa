package main

import (
	"fmt"
	"os"
)

// Default values untuk .env
const defaultEnvContent = `# ApiWago Configuration
# =====================

# Mode aplikasi: development (log verbose) atau production (log minimal)
# Default: production
APP_MODE=production

# Port untuk HTTP server
PORT=8080

# API Key untuk autentikasi external API calls
# Ganti dengan key yang secure
APIKEY=your-api-key-here

# Webhook URL untuk menerima notifikasi pesan masuk
# Kosongkan jika tidak digunakan
WEBHOOK=

# Nama device yang muncul di WhatsApp (Linked Devices)
# Default: ApiWago
DEVICE_NAME=ApiWago

# Nama Service Windows. Digunakan saat install sebagai service.
# Default: apiwago
# Contoh: my-whatsapp-service
SERVICE_NAME=apiwago

# =====================
# Database Configuration
# =====================

# Database driver: sqlite, mysql, postgres
# Default: sqlite
DB_DRIVER=sqlite

# SQLite file path (hanya untuk sqlite)
DB_PATH=store.db

# Database host (untuk mysql/postgres)
DB_HOST=localhost

# Database port (mysql: 3306, postgres: 5432)
DB_PORT=3306

# Database username (untuk mysql/postgres)
DB_USER=root

# Database password (untuk mysql/postgres)
DB_PASSWORD=

# Database name (untuk mysql/postgres)
DB_NAME=apiwago

# =====================
# Performance Configuration
# =====================

# Maximum concurrent connected WhatsApp clients
# Jika melebihi limit, client yang paling lama tidak aktif akan di-disconnect
# Default: 1000
MAX_CLIENTS=1000

# Interval cek koneksi otomatis (format: 2m, 1h)
# Default: 2m
RECONNECT_INTERVAL=2m

# Waktu idle timeout dalam menit sebelum client otomatis di-disconnect
# Default: 30 (menit)
CLIENT_IDLE_TIMEOUT=30

# Jumlah worker goroutine untuk memproses event
# Default: 100
WORKER_POOL_SIZE=100

# Rate limit request per token per menit (coming soon)
# Default: 60
RATE_LIMIT_PER_TOKEN=60

# HTTP connection pool size untuk download/upload media
# Default: 100
HTTP_POOL_SIZE=100
`

// runInit membuat file .env dengan default values
func runInit() error {
	envPath := ".env"

	// Cek apakah file sudah ada
	if _, err := os.Stat(envPath); err == nil {
		fmt.Println("⚠️  File .env sudah ada!")
		fmt.Print("   Apakah ingin menimpa? (y/N): ")

		var response string
		fmt.Scanln(&response)

		if response != "y" && response != "Y" {
			fmt.Println("   Dibatalkan.")
			return nil
		}
	}

	// Tulis file .env
	err := os.WriteFile(envPath, []byte(defaultEnvContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to create .env: %w", err)
	}

	fmt.Println("✅ File .env berhasil dibuat!")
	fmt.Println("   Edit file tersebut sesuai kebutuhan Anda.")
	fmt.Println("")
	fmt.Println("   Konfigurasi Dasar:")
	fmt.Println("   - PORT           : Port HTTP server (default: 8080)")
	fmt.Println("   - APIKEY         : API Key untuk autentikasi")
	fmt.Println("   - WEBHOOK        : URL webhook untuk pesan masuk")
	fmt.Println("   - DEVICE_NAME    : Nama device di WhatsApp (default: ApiWago)")
	fmt.Println("   - SERVICE_NAME   : Nama Windows Service (default: apiwago)")
	fmt.Println("")
	fmt.Println("   Konfigurasi Database:")
	fmt.Println("   - DB_DRIVER      : sqlite, mysql, atau postgres (default: sqlite)")
	fmt.Println("   - DB_PATH        : Path file SQLite (default: store.db)")
	fmt.Println("   - DB_HOST        : Host database MySQL/PostgreSQL")
	fmt.Println("   - DB_PORT        : Port database (mysql: 3306, postgres: 5432)")
	fmt.Println("   - DB_USER        : Username database")
	fmt.Println("   - DB_PASSWORD    : Password database")
	fmt.Println("   - DB_NAME        : Nama database")
	fmt.Println("")
	fmt.Println("   Konfigurasi Performance:")
	fmt.Println("   - MAX_CLIENTS         : Max connected clients (default: 1000)")
	fmt.Println("   - RECONNECT_INTERVAL  : Interval cek koneksi (default: 2m)")
	fmt.Println("   - CLIENT_IDLE_TIMEOUT : Idle timeout dalam menit (default: 30)")
	fmt.Println("   - WORKER_POOL_SIZE    : Worker goroutines (default: 100)")
	fmt.Println("   - HTTP_POOL_SIZE      : HTTP connections (default: 100)")

	return nil
}
