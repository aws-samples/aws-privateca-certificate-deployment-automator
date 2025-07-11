#!/bin/bash
set -e

# Build Lambda layer for x86_64
echo "Building Lambda layer for cryptography..."

# Detect container runtime (Docker or Podman)
CONTAINER_CMD=""
ENTRYPOINT_OVERRIDE=""

if command -v docker &> /dev/null; then
    echo "Docker detected - using Docker commands"
    CONTAINER_CMD="docker"
    # Docker doesn't need entrypoint override for this use case
    ENTRYPOINT_OVERRIDE=""
elif command -v podman &> /dev/null; then
    echo "Podman detected - using Podman commands"
    CONTAINER_CMD="podman"
    # Podman needs entrypoint override for AWS Lambda base images
    ENTRYPOINT_OVERRIDE="--entrypoint="
else
    echo "Error: Neither Docker nor Podman is installed or available in PATH"
    echo "Please install Docker or Podman to build the Lambda layer"
    exit 1
fi

# Create output directory in the layer directory
mkdir -p output

# Build for x86_64
echo "Building for x86_64 using ${CONTAINER_CMD}..."
${CONTAINER_CMD} build --platform linux/amd64 -t lambda-layer-x86 .

# Run container to copy the layer file
echo "Extracting layer from container..."
if [ "$CONTAINER_CMD" = "docker" ]; then
    # Docker command (no entrypoint override needed)
    ${CONTAINER_CMD} run --platform linux/amd64 --rm -v $(pwd)/output:/output lambda-layer-x86 cp /tmp/lambda-layer.zip /output/
else
    # Podman command (with entrypoint override)
    ${CONTAINER_CMD} run --platform linux/amd64 --rm ${ENTRYPOINT_OVERRIDE} -v $(pwd)/output:/output lambda-layer-x86 cp /tmp/lambda-layer.zip /output/
fi

# Copy to root directory with generic name for CloudFormation
echo "Copying layer to project root..."
cp output/lambda-layer.zip ../../lambda-layer.zip

# Clean up local output directory
echo "Cleaning up temporary files..."
rm -rf output

echo ""
echo "Layer build complete!"
echo "Container runtime used: ${CONTAINER_CMD}"
echo "Layer file: $(ls -lh ../../lambda-layer.zip | awk '{print $5, $9}')"
echo ""
