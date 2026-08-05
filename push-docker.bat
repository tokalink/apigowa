@echo off
setlocal

echo ==========================================
echo Running build_all.ps1 to build all platforms...
echo ==========================================
powershell -ExecutionPolicy Bypass -File .\build_all.ps1

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    pause
    exit /b %ERRORLEVEL%
)

echo ==========================================
echo Building Docker image...
echo ==========================================
docker build -t tokalink/wago:v4 -t tokalink/wago:latest .

echo ==========================================
echo Pushing Docker image...
echo ==========================================
docker push tokalink/wago:v4
docker push tokalink/wago:latest

echo ==========================================
echo Build and Push Completed!
echo ==========================================
pause
