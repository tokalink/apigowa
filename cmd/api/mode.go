package main

import "os"

// isProductionMode mengembalikan true jika APP_MODE=production
func isProductionMode() bool {
	mode := os.Getenv("APP_MODE")
	return mode == "" || mode == "production"
}
