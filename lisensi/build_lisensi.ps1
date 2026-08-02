# Script untuk compile Server Lisensi ke format Windows (.exe) dan Linux (binary)
# Cara Menjalankan:
# Klik kanan file ini lalu pilih "Run with PowerShell"
# ATAU buka PowerShell dan jalankan: .\build_lisensi.ps1

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  Mulai proses kompilasi Server Lisensi" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# Pindah ke direktori skrip berada agar bisa dijalankan dari mana saja
Set-Location -Path $PSScriptRoot

# Compile untuk Windows (64-bit)
Write-Host "[1/2] Sedang mem-build untuk Windows (amd64)..." -ForegroundColor Yellow
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o lisensi-windows-amd64.exe main.go db.go
if ($LASTEXITCODE -eq 0) {
    Write-Host "  -> Berhasil membuat lisensi-windows-amd64.exe" -ForegroundColor Green
} else {
    Write-Host "  -> Gagal mem-build untuk Windows!" -ForegroundColor Red
}

# Compile untuk Linux (64-bit)
Write-Host "[2/2] Sedang mem-build untuk Linux (amd64)..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o lisensi-linux-amd64 main.go db.go
if ($LASTEXITCODE -eq 0) {
    Write-Host "  -> Berhasil membuat lisensi-linux-amd64" -ForegroundColor Green
} else {
    Write-Host "  -> Gagal mem-build untuk Linux!" -ForegroundColor Red
}

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "          Proses Build Selesai!" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "File yang dihasilkan berada di folder lisensi."
Read-Host -Prompt "Tekan Enter untuk keluar"
