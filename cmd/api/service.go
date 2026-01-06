package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"apiwago/internal/api"
	"apiwago/internal/web"
	"apiwago/internal/whatsapp"
	"apiwago/pkg/store"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/kardianos/service"
)

// program mengimplementasi interface service.Interface
type program struct {
	server    *http.Server
	appStore  *store.Store
	waitGroup sync.WaitGroup
}

func (p *program) Start(s service.Service) error {
	// Start dipanggil oleh service manager
	// Jalankan server di goroutine terpisah
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	// Stop dipanggil oleh service manager
	// Graceful shutdown dengan timeout 5 detik
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if p.server != nil {
		if err := p.server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}

	if p.appStore != nil && p.appStore.DB != nil {
		p.appStore.DB.Close()
	}

	return nil
}

func (p *program) run() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using defaults")
	}

	// Initialize Store
	dbPath := "store.db"
	appStore, err := store.NewStore(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	p.appStore = appStore

	// Initialize Service
	webhookURL := os.Getenv("WEBHOOK")
	waService := whatsapp.NewService(appStore, webhookURL)

	// Initialize Server handlers
	server := api.NewServer(waService)

	// Setup Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	server.RegisterRoutes(r)

	// Serve Frontend
	r.GET("/", func(c *gin.Context) {
		index, err := web.GetIndex()
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", index)
	})
	r.StaticFS("/static", web.GetFileSystem())

	// Get port
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create HTTP Server
	p.server = &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	log.Printf("apiwago service running on port %s", port)

	// Run server
	if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Failed to run server: %v", err)
	}
}

// getServiceConfig mengembalikan konfigurasi service
func getServiceConfig() *service.Config {
	// Dapatkan path executable untuk menentukan working directory
	exePath, err := os.Executable()
	if err != nil {
		exePath = "."
	}
	workDir := filepath.Dir(exePath)

	return &service.Config{
		Name:             "apiwago",
		DisplayName:      "ApiWago WhatsApp Gateway",
		Description:      "WhatsApp Multi-Device API Gateway Service",
		WorkingDirectory: workDir,
	}
}

// runServiceCommand menjalankan command service (install/uninstall/start/stop/restart)
func runServiceCommand(cmd string) error {
	prg := &program{}
	svc, err := service.New(prg, getServiceConfig())
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	switch cmd {
	case "install":
		err = svc.Install()
		if err != nil {
			return fmt.Errorf("failed to install service: %w", err)
		}
		fmt.Println("✅ Service installed successfully")
		fmt.Println("   Use 'apiwago start' to start the service")
		return nil

	case "uninstall":
		err = svc.Uninstall()
		if err != nil {
			return fmt.Errorf("failed to uninstall service: %w", err)
		}
		fmt.Println("✅ Service uninstalled successfully")
		return nil

	case "start":
		err = svc.Start()
		if err != nil {
			return fmt.Errorf("failed to start service: %w", err)
		}
		fmt.Println("✅ Service started successfully")
		return nil

	case "stop":
		err = svc.Stop()
		if err != nil {
			return fmt.Errorf("failed to stop service: %w", err)
		}
		fmt.Println("✅ Service stopped successfully")
		return nil

	case "restart":
		err = svc.Restart()
		if err != nil {
			return fmt.Errorf("failed to restart service: %w", err)
		}
		fmt.Println("✅ Service restarted successfully")
		return nil

	case "status":
		status, err := svc.Status()
		if err != nil {
			return fmt.Errorf("failed to get service status: %w", err)
		}
		switch status {
		case service.StatusRunning:
			fmt.Println("🟢 Service is running")
		case service.StatusStopped:
			fmt.Println("🔴 Service is stopped")
		default:
			fmt.Println("⚪ Service status unknown")
		}
		return nil

	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

// runAsService menjalankan aplikasi sebagai service (dipanggil oleh service manager)
func runAsService() error {
	prg := &program{}
	svc, err := service.New(prg, getServiceConfig())
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}

	return svc.Run()
}
