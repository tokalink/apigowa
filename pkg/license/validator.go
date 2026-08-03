package license

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

type LicenseResponse struct {
	Valid        bool   `json:"valid"`
	Message      string `json:"message"`
	AccountLimit int    `json:"account_limit"`
}

const cacheFile = ".wago_sys.dat"

type LicenseCache struct {
	Valid        bool   `json:"valid"`
	Timestamp    int64  `json:"timestamp"`
	Signature    string `json:"signature"`
	AccountLimit int    `json:"account_limit"`
}

var GlobalAccountLimit int = 0 // 0 means unlimited

// GetAccountLimit returns the maximum number of WA accounts allowed by the license.
func GetAccountLimit() int {
	return GlobalAccountLimit
}

func generateSignature(valid bool, timestamp int64, licenseKey, deviceID string, accountLimit int) string {
	data := fmt.Sprintf("%v:%d:%s:%s:%d", valid, timestamp, licenseKey, deviceID, accountLimit)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func saveCache(licenseKey, deviceID string, accountLimit int) {
	ts := time.Now().Unix()
	cache := LicenseCache{
		Valid:        true,
		Timestamp:    ts,
		Signature:    generateSignature(true, ts, licenseKey, deviceID, accountLimit),
		AccountLimit: accountLimit,
	}
	b, _ := json.Marshal(cache)
	encoded := base64.StdEncoding.EncodeToString(b)
	os.WriteFile(cacheFile, []byte(encoded), 0644)
}

func clearCache() {
	os.Remove(cacheFile)
}

func loadCache(licenseKey, deviceID string) bool {
	b, err := os.ReadFile(cacheFile)
	if err != nil {
		return false
	}
	
	decoded, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		return false
	}

	var cache LicenseCache
	if err := json.Unmarshal(decoded, &cache); err != nil {
		return false
	}
	
	// Verifikasi signature agar tidak bisa dipalsukan
	expectedSig := generateSignature(cache.Valid, cache.Timestamp, licenseKey, deviceID, cache.AccountLimit)
	if cache.Signature != expectedSig {
		return false
	}

	// Kadaluwarsa cache dalam 24 jam (aplikasi harus online lagi)
	if time.Now().Unix()-cache.Timestamp > 24*3600 {
		return false
	}

	GlobalAccountLimit = cache.AccountLimit
	return cache.Valid
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
		clearCache()
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
		if loadCache(licenseKey, deviceID) {
			fmt.Printf("[WARN] Gagal terhubung ke server lisensi (%v). Menggunakan cache lisensi lokal sementara (Berlaku Max 24 Jam)...\n", err)
		} else {
			log.Fatalf("[FATAL] Gagal terhubung ke server lisensi (%s): %v\nDan tidak ada cache lisensi lokal yang valid/terpercaya.", serverURL, err)
		}
	} else {
		defer resp.Body.Close()

		// Server bisa dihubungi, evaluasi responsnya
		if resp.StatusCode != http.StatusOK {
			clearCache()
			log.Fatalf("[FATAL] Lisensi ditolak oleh server (Status: %d).\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com untuk perpanjangan atau pembelian lisensi.", resp.StatusCode)
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			if loadCache(licenseKey, deviceID) {
				fmt.Printf("[WARN] Gagal membaca respons lisensi. Menggunakan cache lisensi lokal sementara...\n")
			} else {
				log.Fatalf("[FATAL] Gagal membaca respons lisensi: %v\nHubungi: WA 085232843165 / khoirulh1610@gmail.com", err)
			}
		} else {
			var licResp LicenseResponse
			if err := json.Unmarshal(bodyBytes, &licResp); err != nil {
				if loadCache(licenseKey, deviceID) {
					fmt.Printf("[WARN] Respons lisensi bukan JSON yang valid. Menggunakan cache lisensi lokal sementara...\n")
				} else {
					log.Fatalf("[FATAL] Respons lisensi tidak valid (bukan JSON): %s\nHubungi: WA 085232843165 / khoirulh1610@gmail.com", string(bodyBytes))
				}
			} else {
				if !licResp.Valid {
					clearCache()
					log.Fatalf("[FATAL] LISENSI TIDAK VALID: %s\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com", licResp.Message)
				} else {
					// Valid! Simpan ke cache
					GlobalAccountLimit = licResp.AccountLimit
					saveCache(licenseKey, deviceID, licResp.AccountLimit)
					fmt.Printf("[INFO] Lisensi berhasil divalidasi dengan server! Sistem siap dijalankan.\n")
				}
			}
		}
	}

	// Mulai Heartbeat setiap 4 menit untuk memberi tahu server bahwa lisensi sedang online
	// Sekaligus mematikan aplikasi jika sewaktu-waktu lisensi dihapus oleh admin
	go func() {
		ticker := time.NewTicker(4 * time.Minute)
		for range ticker.C {
			resp, err := client.Post(serverURL, "application/json", bytes.NewBuffer(payloadBytes))
			if err != nil {
				fmt.Printf("[WARN] Heartbeat gagal terhubung ke server lisensi. Mencoba lagi nanti...\n")
				continue
			}

			if resp.StatusCode == http.StatusOK {
				bodyBytes, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err == nil {
					var licResp LicenseResponse
					if err := json.Unmarshal(bodyBytes, &licResp); err == nil {
						if !licResp.Valid {
							clearCache()
							log.Fatalf("[FATAL] LISENSI DIBATALKAN OLEH ADMIN: %s\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com", licResp.Message)
						} else {
							// Update AccountLimit in case it was changed by admin
							if GlobalAccountLimit != licResp.AccountLimit {
								GlobalAccountLimit = licResp.AccountLimit
								saveCache(licenseKey, deviceID, licResp.AccountLimit)
							}
						}
					}
				}
			} else {
				resp.Body.Close()
				// Kalau status code misal 401 Unauthorized (karena dihapus / expired saat sistem jalan)
				if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
					clearCache()
					log.Fatalf("[FATAL] LISENSI DICABUT ATAU KADALUWARSA (Status: %d)!\nSilakan hubungi WA 085232843165 / khoirulh1610@gmail.com", resp.StatusCode)
				} else {
					fmt.Printf("[WARN] Heartbeat server lisensi mengembalikan status %d. Mencoba lagi nanti...\n", resp.StatusCode)
				}
			}
		}
	}()
}
