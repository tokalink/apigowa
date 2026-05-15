@echo off
echo ==========================================
echo Updating whatsmeow library...
echo ==========================================

echo Running: go get -u go.mau.fi/whatsmeow@latest
go get -u go.mau.fi/whatsmeow@latest

echo Running: go mod tidy
go mod tidy

echo ==========================================
echo Update completed!
echo ==========================================
pause
