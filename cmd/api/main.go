package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"apiwago/internal/api"
	"apiwago/internal/web"
	"apiwago/internal/whatsapp"
	"apiwago/pkg/store"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/kardianos/service"
)

var version = "1.0.0"

func main() {
	// Cek apakah ada command argument
	if len(os.Args) > 1 {
		cmd := os.Args[1]

		switch cmd {
		case "init":
			if err := runInit(); err != nil {
				log.Fatalf("Error: %v", err)
			}
			return

		case "install", "uninstall", "start", "stop", "restart", "status":
			if err := runServiceCommand(cmd); err != nil {
				log.Fatalf("Error: %v", err)
			}
			return

		case "version", "-v", "--version":
			fmt.Printf("apiwago version %s\n", version)
			return

		case "help", "-h", "--help":
			printHelp()
			return

		case "run":
			// Run in foreground mode (explicit)
			runForeground()
			return

		default:
			fmt.Printf("Unknown command: %s\n\n", cmd)
			printHelp()
			os.Exit(1)
		}
	}

	// Cek apakah dijalankan sebagai service atau foreground
	isInteractive := service.Interactive()

	if isInteractive {
		// Dijalankan dari terminal - foreground mode
		runForeground()
	} else {
		// Dijalankan oleh service manager
		if err := runAsService(); err != nil {
			log.Fatalf("Service error: %v", err)
		}
	}
}

func printHelp() {
	fmt.Println("ApiWago - WhatsApp Multi-Device API Gateway")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  apiwago [command]")
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("  (no command)  Run in foreground mode")
	fmt.Println("  run           Run in foreground mode (explicit)")
	fmt.Println("  init          Generate .env file with default values")
	fmt.Println("  install       Install as system service")
	fmt.Println("  uninstall     Uninstall the system service")
	fmt.Println("  start         Start the installed service")
	fmt.Println("  stop          Stop the running service")
	fmt.Println("  restart       Restart the service")
	fmt.Println("  status        Show service status")
	fmt.Println("  version       Show version information")
	fmt.Println("  help          Show this help message")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("  apiwago              # Jalankan di foreground")
	fmt.Println("  apiwago init         # Buat file .env")
	fmt.Println("  apiwago install      # Install sebagai service")
	fmt.Println("  apiwago start        # Start service")
}

func runForeground() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using defaults")
	}

	// Ensure store directory exists
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "store.db"
	}

	// Initialize Store
	appStore, err := store.NewStore(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}
	defer appStore.Close()

	// Initialize Service
	webhookURL := os.Getenv("WEBHOOK")
	waService := whatsapp.NewService(appStore, webhookURL)
	defer waService.Close()

	// Auto-reconnect previously logged-in accounts
	go waService.AutoReconnect()

	// Start periodic connectivity check
	waService.StartPeriodicCheck(context.Background())
	// Initialize Server handlers
	server := api.NewServer(waService)

	// Setup Gin berdasarkan APP_MODE
	if isProductionMode() {
		gin.SetMode(gin.ReleaseMode)
	}
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

	// Run
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server running on http://localhost:%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
