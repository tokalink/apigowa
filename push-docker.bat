@echo off
setlocal

:: Versioning logic
if not exist VERSION echo 1.0.1+0 > VERSION
for /f "tokens=1,2 delims=+" %%a in (VERSION) do (
    set SEMVER=%%a
    set /a BUILD_NUM=%%b+1
)
set VERSION=%SEMVER%(+%BUILD_NUM%)
echo %SEMVER%+%BUILD_NUM% > VERSION

echo ==========================================
echo Building apiwago version: %VERSION%
echo ==========================================

:: Build linux binary for docker
set GOOS=linux
set GOARCH=amd64
go build -buildvcs=false -ldflags "-X main.version=%VERSION%" -o builds/apiwago-linux-amd64 ./cmd/api

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b %ERRORLEVEL%
)

:: Build docker image from root
docker build -t tokalink/wago:v2 -t tokalink/wago:latest .
docker push tokalink/wago:v2
docker push tokalink/wago:latest

echo ==========================================
echo Build and Push Completed!
echo ==========================================
pause
