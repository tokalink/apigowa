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
| `apiwago version` | Lihat versi |
| `apiwago help` | Bantuan |

## 🔌 API Endpoints

### Authentication

Sertakan API Key di header untuk semua request yang memerlukan autentikasi:

```
apikey: YOUR_API_KEY
```

### Endpoints

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| POST | `/api/start` | Initialize session |
| POST | `/api/qrcode` | Get QR code / status |
| GET | `/api/status?token=X` | Get connection status |
| POST | `/api/send` | Send message |
| GET | `/api/contacts?token=X` | Get contacts |
| GET | `/api/groups?token=X` | Get groups |
| POST | `/api/logout?token=X` | Logout session |
| POST | `/api/reconnect?token=X` | Reconnect session |
| GET | `/api/devices` | List all devices |
| DELETE | `/api/device?token=X` | Delete device |
| POST | `/api/webhook` | Set webhook URL |
| POST | `/api/workspace` | Set workspace |
| GET | `/api/workspaces` | List workspaces |

### Send Message Example

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
