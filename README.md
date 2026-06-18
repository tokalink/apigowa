# ApiWago

WhatsApp Multi-Device API Gateway - REST API untuk integrasi WhatsApp menggunakan protokol Multi-Device.

## ✨ Fitur

- 🔐 **Multi-Device Support** - Menggunakan protokol WhatsApp terbaru
- 📱 **Multi-Token** - Kelola banyak akun WhatsApp sekaligus
- 🖥️ **Web Dashboard** - Antarmuka admin untuk manajemen device
- 🔌 **REST API** - Integrasi mudah dengan aplikasi lain
- 🪝 **Webhook** - Notifikasi pesan masuk ke URL eksternal
- 🏷️ **Workspace** - Organisasi device berdasarkan group/team
- 📞 **Auto Reject Call** - Tolak panggilan otomatis dengan pesan kustom
- 🖼️ **Media Support** - Kirim gambar dan dokumen
- 🛠️ **Smart Number Formatting** - Pencegahan double country-code (62) saat pengecekan nomor otomatis
- ⚙️ **Service Mode** - Jalankan sebagai system service (Windows/Linux/macOS)

## 🚀 Quick Start

### 1. Download & Extract

Download binary untuk platform Anda dari releases.

### 2. Initialize Configuration

```bash
./apiwago init
```

Ini akan membuat file `.env` dengan konfigurasi default.

### 3. Edit Configuration

```env
APP_MODE=production        # production/development
PORT=8080                  # Port HTTP server
APIKEY=your-secure-key     # API Key untuk autentikasi
WEBHOOK=                   # URL webhook (opsional)
DEVICE_NAME=ApiWago        # Nama device di WhatsApp

# Database Configuration (Hanya mendukung sqlite atau postgres)
DB_DRIVER=sqlite           # sqlite / postgres (MySQL TIDAK DIDUKUNG)
DB_PATH=store.db           # Path file SQLite
# DB_HOST=localhost        # Host PostgreSQL (jika pakai postgres)
# DB_PORT=5432             # Port PostgreSQL (jika pakai postgres)
# DB_USER=postgres         # User PostgreSQL (jika pakai postgres)
# DB_PASSWORD=secret       # Password PostgreSQL (jika pakai postgres)
# DB_NAME=apiwago          # Nama DB PostgreSQL (jika pakai postgres)
```

### 4. Run

```bash
# Foreground mode
./apiwago

# Atau install sebagai service
./apiwago install
./apiwago start
```

## 📖 CLI Commands

| Command | Keterangan |
|---------|------------|
| `apiwago` | Jalankan di foreground |
| `apiwago init` | Generate file .env |
| `apiwago install` | Install sebagai system service |
| `apiwago uninstall` | Uninstall service |
| `apiwago start` | Start service |
| `apiwago stop` | Stop service |
| `apiwago restart` | Restart service |
| `apiwago status` | Lihat status service |
| `apiwago log` | Monitor log service (Khusus Linux) |
| `apiwago version` | Lihat versi |
| `apiwago help` | Bantuan |

## 🗄️ Database Supported

ApiWago menggunakan library `whatsmeow` versi terbaru yang **hanya mendukung** database berikut untuk kestabilan penyimpanan session enkripsi:
1. **SQLite** (Default, direkomendasikan untuk pemakaian ringan - menengah)
2. **PostgreSQL** (Direkomendasikan untuk pemakaian skala besar / enterprise)

> ⚠️ **Catatan Penting:** Dukungan untuk **MySQL** telah dihapus secara resmi dari tingkat library karena masalah kompatibilitas dialect. Jangan gunakan MySQL/MariaDB.

## 🔌 API Endpoints

### Authentication

Sertakan API Key di header untuk semua request yang memerlukan autentikasi:

```
apikey: YOUR_API_KEY
```

### Endpoints

Semua request wajib menggunakan `Content-Type: application/json` kecuali endpoint yang mengembalikan gambar/stream.

#### 1. Device & Session Management (Requires API Key)
| Method | Endpoint | Keterangan |
|--------|----------|------------|
| POST | `/api/start` | Inisialisasi session device baru |
| GET/POST | `/api/qrcode` | Mendapatkan QR code dalam format Base64 |
| GET | `/api/devices` | Mengambil daftar semua device / token yang ada |
| DELETE | `/api/device?token=X` | Menghapus device dan seluruh session-nya |
| POST | `/api/webhook` | Mengatur URL Webhook spesifik untuk suatu token |
| POST | `/api/workspace` | Mengatur workspace untuk suatu token |
| GET | `/api/workspaces` | Mendapatkan daftar semua workspace yang ada |

#### 2. WhatsApp Operations (Token Based)
*Endpoint di bawah ini membutuhkan parameter `token` di Query URL atau di dalam body JSON.*

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| POST | `/api/send` | Mengirim pesan teks atau media (gambar, video, dll) |
| POST | `/api/pair` | Generate Pairing Code (Alternatif login tanpa QR) |
| GET/POST| `/api/status` | Mengecek status koneksi dari suatu token |
| GET | `/api/contacts` | Mengambil daftar kontak dari WhatsApp |
| GET | `/api/groups` | Mengambil daftar grup WhatsApp |
| POST | `/api/check-number` | Memeriksa apakah sebuah nomor terdaftar di WhatsApp |
| POST | `/api/presence` | Mengirim status *presence* (typing, recording, dll) ke obrolan |
| POST | `/api/profile/status` | Mengubah teks status/bio pada profil WhatsApp device tersebut |
| GET | `/api/status-analytics`| Mengambil analitik dari Status/Story WhatsApp (views & replies) |
| DELETE | `/api/story` | Menghapus Status/Story WhatsApp & data analitiknya dari database |
| POST | `/api/reconnect` | Memaksa koneksi ulang untuk session yang terputus |
| POST | `/api/logout` | Melakukan logout session (menghapus login di HP) |
| GET | `/api/login` | Mendapatkan QR Code berupa raw image (Legacy) |
| GET | `/api/login-sse` | Mendapatkan QR Code secara real-time via Server-Sent Events (SSE) |

#### 3. Admin & Dashboard Routes
*Digunakan oleh Web Dashboard untuk keperluan login admin.*

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| GET | `/api/check-setup` | Mengecek apakah akun admin sudah dibuat |
| POST | `/api/setup` | Membuat akun admin pertama kali |
| POST | `/api/login-admin`| Login admin web dashboard (mendapatkan cookie session) |
| POST | `/api/logout-admin`| Logout dari web dashboard |

### 1. Inisialisasi Session (Start)
Sebelum login, Anda wajib melakukan inisialisasi session untuk token baru.

```bash
curl -X POST http://localhost:8080/api/start \
  -H "apikey: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "my-token"
  }'
```

### 2. Login via Scan QR Code
Mendapatkan QR Code dalam format Base64 (image) untuk di-scan melalui HP.

```bash
curl -X POST http://localhost:8080/api/qrcode \
  -H "apikey: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "my-token"
  }'
```

### 3. Login via Pairing Code
Jika Anda tidak bisa melakukan scan QR, gunakan nomor HP untuk mendapatkan 8 digit kode verifikasi (kode akan muncul dari API ini, lalu masukkan ke notifikasi HP Anda).

```bash
curl -X POST http://localhost:8080/api/pair \
  -H "Content-Type: application/json" \
  -d '{
    "token": "my-token",
    "phone": "628123456789"
  }'
```

### 4. Send Message Example

```bash
curl -X POST http://localhost:8080/api/send \
  -H "apikey: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "my-token",
    "phone": "628123456789",
    "message": "Hello World!"
  }'
```

### Send Media Example

```bash
curl -X POST http://localhost:8080/api/send \
  -H "apikey: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "my-token",
    "phone": "628123456789",
    "message": "Check this image!",
    "file_url": "https://example.com/image.jpg",
    "file_name": "image.jpg"
  }'
```

## 🐳 Menjalankan dengan Docker

ApiWago dapat dengan mudah dijalankan menggunakan Docker. Anda bisa menggunakan image yang telah disediakan (`tokalink/wago:latest`) atau melakukan build sendiri.

### 1. Menggunakan Docker CLI (Terminal Langsung)

Anda bisa langsung menjalankan container dari terminal. Pastikan Anda telah membuat file `.env` sesuai panduan di atas.

```bash
docker run -d \
  --name apiwago \
  --env-file .env \
  -p 8080:8080 \
  -v $(pwd)/store.db:/app/store.db \
  -v $(pwd)/.env:/app/.env \
  tokalink/wago:latest
```

> **Catatan:** Sesuaikan pemetaan port `-p 8080:8080` dengan `PORT` di konfigurasi Anda. Jika Anda menggunakan database SQLite, sangat penting untuk me-mount `store.db` (atau path DB_PATH Anda) agar sesi login WhatsApp tidak hilang saat container di-restart.

### 2. Menggunakan Docker Compose (Direkomendasikan)

Untuk manajemen yang lebih mudah, Anda dapat menggunakan Docker Compose. Berikut adalah contoh konfigurasi `docker-compose.yml`:

```yaml
services:
  apiwago:
    image: tokalink/wago:latest
    container_name: apiwago
    env_file:
      - .env
    ports:
      - "8080:8080" # Format: "PORT_HOST:PORT_CONTAINER"
    volumes:
      - .env:/app/.env
      - ./store.db:/app/store.db # Persistensi DB SQLite
    restart: unless-stopped
```

Jika Anda menggunakan environment management server seperti **1Panel**, Anda bisa menyesuaikan konfigurasi volume dan network. Berikut contoh konfigurasi seperti file `docker-compose.yml` bawaan repository:

```yaml
services:
  apiwago:
    image: tokalink/wago:latest
    container_name: apiwago
    env_file:
      - .env
    ports:
      - "${API_PORT}:8080" # Mapping port server host (API_PORT) ke container (8080)
    volumes:
      - .env:/app/.env
      - ./data:/app/data # Jika menggunakan folder khusus /data
    networks:
      - 1panel-network

networks:
  1panel-network:
    external: true
```

Jalankan container menggunakan perintah:
```bash
docker compose up -d
```

### 3. Build Image Docker Sendiri

Jika Anda melakukan perubahan kode dan ingin mem-build image Docker, gunakan script yang telah disediakan di folder `builds`:

```bash
cd builds
.\build_and_push.bat
```

Script `build_and_push.bat` ini akan membaca `Dockerfile` dan secara otomatis:
1. Melakukan kompilasi binary Go khusus untuk OS Linux (`apiwago-linux-amd64`) menggunakan base image `alpine:latest`.
2. Melakukan proses build Docker image.
3. Memberikan versi otomatis pada image (`tokalink/wago:latest` dan `tokalink/wago:v2`).
4. Mengunggah (push) image tersebut ke Docker registry.

## 🛠️ Build from Source

### Requirements

- Go 1.21+
- CGO disabled (for portability)

### Build

```bash
# Single platform
go build -o apiwago ./cmd/api

# All platforms
bash build_all.sh
```

## 📁 Project Structure

```
apiwago/
├── cmd/api/           # Entry point & CLI
├── internal/
│   ├── api/           # HTTP handlers
│   ├── web/           # Frontend templates
│   └── whatsapp/      # WhatsApp service
├── pkg/store/         # Database layer
├── builds/            # Compiled binaries
├── .env               # Configuration
└── store.db           # SQLite database
```

## 📝 License

MIT License

## 🙏 Credits

Built with:
- [whatsmeow](https://github.com/tulir/whatsmeow) - WhatsApp Multi-Device library
- [Gin](https://github.com/gin-gonic/gin) - HTTP web framework
- [kardianos/service](https://github.com/kardianos/service) - Cross-platform service management
