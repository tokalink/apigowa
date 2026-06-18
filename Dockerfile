FROM alpine:latest

# Instalasi library pendukung (penting untuk binary Go)
RUN apk add --no-cache ca-certificates libc6-compat

WORKDIR /app

# Copy binary dari laptop ke dalam image
COPY builds/apiwago-linux-amd64 .

# Beri izin eksekusi
RUN chmod +x apiwago-linux-amd64

EXPOSE 8080
# Jalankan
CMD ["./apiwago-linux-amd64"]