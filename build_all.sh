#!/bin/bash

# Define platforms
platforms=(
    "windows/amd64"
    "linux/amd64"
    "darwin/amd64"
    "darwin/arm64"
    "linux/arm64"
)

# Output directory
output_dir="builds"
mkdir -p "$output_dir"

package_name="apiwago"

for platform in "${platforms[@]}"; do
    platform_split=(${platform//\// })
    GOOS=${platform_split[0]}
    GOARCH=${platform_split[1]}
    
    output_name=$package_name'-'$GOOS'-'$GOARCH
    
    if [ "$GOOS" = "windows" ]; then
        output_name+='.exe'
    fi

    echo "Building for $GOOS/$GOARCH..."
    env GOOS=$GOOS GOARCH=$GOARCH go build -o "$output_dir/$output_name" ./cmd/api
    
    if [ $? -ne 0 ]; then
        echo "An error occurred during build for $GOOS/$GOARCH"
        exit 1
    fi
done

echo "Build completed successfully! Check the '$output_dir' directory."
