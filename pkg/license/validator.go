package license

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type LicenseResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// Validate checks the LICENSE_KEY against the LICENSE_SERVER_URL.
// It logs a fatal error and exits if the license is invalid.
func Validate() {
	licenseKey := os.Getenv("LICENSE_KEY")
	serverURL := os.Getenv("LICENSE_SERVER_URL")
	deviceID := os.Getenv("DEVICE_ID")

	if deviceID == "" {
		hostname, err := os.Hostname()
		if err == nil {
			deviceID = hostname
		} else {
			deviceID = "unknown-device"
		}
	}

	if licenseKey == "" {
		log.Fatalf("[FATAL] Aplikasi dihentikan: LICENSE_KEY belum disetel di .env!\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com untuk pembelian lisensi.")
	}

	if serverURL == "" {
		serverURL = "https://api-lisensi.tokalink.id/validate-license" // Default fallback URL
	}

	payload := map[string]string{
		"license_key": licenseKey,
		"device_id":   deviceID,
	}
	payloadBytes, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Fatalf("[FATAL] Gagal membuat request lisensi: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ApiWaGo-License-Validator/1.0")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("[FATAL] Gagal terhubung ke server lisensi (%s): %v", serverURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("[FATAL] Lisensi ditolak oleh server (Status: %d).\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com untuk perpanjangan atau pembelian lisensi.", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("[FATAL] Gagal membaca respons lisensi: %v\nHubungi: WA 085232843165 / khoirulh1610@gmail.com", err)
	}

	var licResp LicenseResponse
	if err := json.Unmarshal(bodyBytes, &licResp); err != nil {
		log.Fatalf("[FATAL] Respons lisensi tidak valid (bukan JSON): %s\nHubungi: WA 085232843165 / khoirulh1610@gmail.com", string(bodyBytes))
	}

	if !licResp.Valid {
		log.Fatalf("[FATAL] LISENSI TIDAK VALID: %s\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com", licResp.Message)
	}

	fmt.Printf("[INFO] Lisensi berhasil divalidasi! Sistem siap dijalankan.\n")

	// Mulai Heartbeat setiap 4 menit untuk memberi tahu server bahwa lisensi sedang online
	// Sekaligus mematikan aplikasi jika sewaktu-waktu lisensi dihapus oleh admin
	go func() {
		ticker := time.NewTicker(4 * time.Minute)
		for range ticker.C {
			resp, err := client.Post(serverURL, "application/json", bytes.NewBuffer(payloadBytes))
			if err != nil || resp.StatusCode != http.StatusOK {
				log.Fatalf("[FATAL] Koneksi lisensi terputus atau lisensi dicabut!\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com")
			}

			bodyBytes, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				var licResp LicenseResponse
				if err := json.Unmarshal(bodyBytes, &licResp); err == nil && !licResp.Valid {
					log.Fatalf("[FATAL] LISENSI DIBATALKAN OLEH ADMIN: %s\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com", licResp.Message)
				}
			}
		}
	}()
}
