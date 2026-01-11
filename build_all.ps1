$platforms = @(
    "windows/amd64",
    "linux/amd64",
    "darwin/amd64",
    "darwin/arm64",
    "linux/arm64"
)

$outputDir = "builds"
if (-not (Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
}

$packageName = "apiwago"

foreach ($platform in $platforms) {
    $split = $platform -split "/"
    $env:GOOS = $split[0]
    $env:GOARCH = $split[1]

    $outputName = "$packageName-$($env:GOOS)-$($env:GOARCH)"
    if ($env:GOOS -eq "windows") {
        $outputName += ".exe"
    }

    Write-Host "Building for $($env:GOOS)/$($env:GOARCH)..."
    $outputPath = Join-Path $outputDir $outputName
    
    # -buildvcs=false is often needed when cross-compiling or in some git setups
    go build -buildvcs=false -o $outputPath ./cmd/api

    if ($LASTEXITCODE -ne 0) {
        Write-Error "An error occurred during build for $($env:GOOS)/$($env:GOARCH)"
        exit 1
    }
}

# Clean up env vars
$env:GOOS = ""
$env:GOARCH = ""

Write-Host "Build completed successfully! Check the '$outputDir' directory." -ForegroundColor Green
