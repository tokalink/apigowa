package main

import (
	"fmt"
	"os"
)

// Default values untuk .env
const defaultEnvContent = `# ApiWago Configuration

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
	fmt.Println("   Konfigurasi:")
	fmt.Println("   - PORT        : Port HTTP server (default: 8080)")
	fmt.Println("   - APIKEY      : API Key untuk autentikasi")
	fmt.Println("   - WEBHOOK     : URL webhook untuk pesan masuk")
	fmt.Println("   - DEVICE_NAME : Nama device di WhatsApp (default: ApiWago)")

	return nil
}
