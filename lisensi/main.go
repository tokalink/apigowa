package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

var db *LicenseDB

func generateRandomKey() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("axerasoft-%s", hex.EncodeToString(b))
}

func main() {
	var err error
	db, err = InitDB("lisensi.db")
	if err != nil {
		log.Fatalf("Gagal inisialisasi database: %v", err)
	}
	defer db.Close()

	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	// Endpoint validasi untuk client (tanpa auth)
	r.POST("/validate-license", validateLicenseHandler)

	// Admin UI (Dilindungi Basic Auth)
	adminUser := os.Getenv("ADMIN_USER")
	if adminUser == "" {
		adminUser = "admin"
	}
	adminPass := os.Getenv("ADMIN_PASS")
	if adminPass == "" {
		adminPass = "admin123"
	}

	authorized := r.Group("/", gin.BasicAuth(gin.Accounts{
		adminUser: adminPass,
	}))

	authorized.GET("/", dashboardHandler)
	authorized.POST("/generate", generateLicenseHandler)
	authorized.POST("/delete", deleteLicenseHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("License Server berjalan di port %s\n", port)
	r.Run(":" + port)
}

func dashboardHandler(c *gin.Context) {
	licenses, err := db.GetAllLicenses()
	if err != nil {
		c.String(http.StatusInternalServerError, "Gagal mengambil data lisensi")
		return
	}

	// Menghitung status penggunaan
	type DeviceView struct {
		DeviceID       string
		IPAddress      string
		IsOnline       bool
		LastOnlineText string
	}

	type LicenseView struct {
		License
		UsedCount        int
		Status           string
		ExpiresText      string
		AccountLimitText string
		ConnectedServers []DeviceView
	}

	var views []LicenseView
	for _, l := range licenses {
		used, _ := db.GetUsedDeviceCount(l.LicenseKey)
		status := "Aktif"

		expiresText := "Unlimited"
		if l.ExpiresAt.Valid {
			expiresText = l.ExpiresAt.Time.Format("02 Jan 2006")
			if time.Now().After(l.ExpiresAt.Time) {
				status = "Expired"
			}
		}

		if status == "Aktif" && used >= l.DeviceLimit {
			status = "Penuh (Limit Device)"
		}

		dbDevices, _ := db.GetDevicesForLicense(l.LicenseKey)
		var connectedServers []DeviceView
		for _, dd := range dbDevices {
			isOnline := false
			lastOnlineText := "Belum Pernah"
			if !dd.LastUsed.IsZero() {
				lastOnlineText = dd.LastUsed.Local().Format("02 Jan 15:04:05")
				if time.Since(dd.LastUsed) < 5*time.Minute {
					isOnline = true
				}
			}
			ip := dd.IPAddress
			if ip == "" {
				ip = "-"
			}
			connectedServers = append(connectedServers, DeviceView{
				DeviceID:       dd.DeviceID,
				IPAddress:      ip,
				IsOnline:       isOnline,
				LastOnlineText: lastOnlineText,
			})
		}

		accountLimitText := "Unlimited"
		if l.AccountLimit > 0 {
			accountLimitText = strconv.Itoa(l.AccountLimit)
		}

		views = append(views, LicenseView{
			License:          l,
			UsedCount:        used,
			Status:           status,
			ExpiresText:      expiresText,
			AccountLimitText: accountLimitText,
			ConnectedServers: connectedServers,
		})
	}

	c.HTML(http.StatusOK, "index.html", gin.H{
		"Licenses": views,
	})
}

func generateLicenseHandler(c *gin.Context) {
	limitStr := c.PostForm("device_limit")
	accountLimitStr := c.PostForm("account_limit")
	durationStr := c.PostForm("duration")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 1 // default
	}

	accountLimit, err := strconv.Atoi(accountLimitStr)
	if err != nil || accountLimit < 0 {
		accountLimit = 0 // default unlimited
	}

	var expiresAt sql.NullTime
	if durationStr == "1_month" {
		expiresAt.Time = time.Now().AddDate(0, 1, 0)
		expiresAt.Valid = true
	} else if durationStr == "1_year" {
		expiresAt.Time = time.Now().AddDate(1, 0, 0)
		expiresAt.Valid = true
	} else {
		// unlimited -> nulltime (Valid = false)
		expiresAt.Valid = false
	}

	key := generateRandomKey()
	err = db.CreateLicense(key, limit, accountLimit, expiresAt)
	if err != nil {
		c.String(http.StatusInternalServerError, "Gagal membuat lisensi")
		return
	}

	c.Redirect(http.StatusFound, "/")
}

func deleteLicenseHandler(c *gin.Context) {
	key := c.PostForm("license_key")
	if key != "" {
		db.DeleteLicense(key)
	}
	c.Redirect(http.StatusFound, "/")
}

// Endpoint untuk diakses oleh client apiwago
type ValidateRequest struct {
	LicenseKey string `json:"license_key"`
	DeviceID   string `json:"device_id"`
}

type ValidateResponse struct {
	Valid        bool   `json:"valid"`
	Message      string `json:"message"`
	AccountLimit int    `json:"account_limit"`
}

func validateLicenseHandler(c *gin.Context) {
	var req ValidateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ValidateResponse{Valid: false, Message: "Invalid request payload"})
		return
	}

	if req.LicenseKey == "" {
		c.JSON(http.StatusUnauthorized, ValidateResponse{Valid: false, Message: "License key is missing"})
		return
	}

	// Gunakan "default_device" jika client belum disetting device_id
	if req.DeviceID == "" {
		req.DeviceID = "default_device"
	}

	lic, err := db.GetLicense(req.LicenseKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, ValidateResponse{Valid: false, Message: "License key not found"})
		return
	}

	// Cek Expiration
	if lic.ExpiresAt.Valid && time.Now().After(lic.ExpiresAt.Time) {
		c.JSON(http.StatusUnauthorized, ValidateResponse{Valid: false, Message: "License expired"})
		return
	}

	// Cek Device Limit
	usedCount, _ := db.GetUsedDeviceCount(req.LicenseKey)
	isRegistered := db.IsDeviceRegistered(req.LicenseKey, req.DeviceID)
	clientIP := c.ClientIP()

	if !isRegistered {
		if usedCount >= lic.DeviceLimit {
			c.JSON(http.StatusUnauthorized, ValidateResponse{Valid: false, Message: "Device limit reached for this license"})
			return
		}
		// Register new device
		db.RegisterDevice(req.LicenseKey, req.DeviceID, clientIP)
	} else {
		// Update last used timestamp and IP
		db.RegisterDevice(req.LicenseKey, req.DeviceID, clientIP)
	}

	c.JSON(http.StatusOK, ValidateResponse{Valid: true, Message: "License active", AccountLimit: lic.AccountLimit})
}
