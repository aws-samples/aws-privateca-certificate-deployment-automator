#!/bin/bash
set -e

# Build Lambda layer for x86_64
echo "Building Lambda layer for cryptography..."

# Detect container runtime (Docker, Finch, or Podman).
# Set CONTAINER_RUNTIME to force a specific runtime, e.g.:
#   CONTAINER_RUNTIME=finch ./build.sh
# When unset, the script auto-detects in order: docker, finch, podman.
CONTAINER_CMD=""
ENTRYPOINT_OVERRIDE=""

if [ -n "$CONTAINER_RUNTIME" ]; then
    if ! command -v "$CONTAINER_RUNTIME" &> /dev/null; then
        echo "Error: CONTAINER_RUNTIME is set to '$CONTAINER_RUNTIME' but it is not installed or available in PATH"
        exit 1
    fi
    echo "Using container runtime from CONTAINER_RUNTIME: $CONTAINER_RUNTIME"
    CONTAINER_CMD="$CONTAINER_RUNTIME"
elif command -v docker &> /dev/null; then
    echo "Docker detected - using Docker commands"
    CONTAINER_CMD="docker"
elif command -v finch &> /dev/null; then
    echo "Finch detected - using Finch commands"
    CONTAINER_CMD="finch"
elif command -v podman &> /dev/null; then
    echo "Podman detected - using Podman commands"
    CONTAINER_CMD="podman"
else
    echo "Error: No supported container runtime (docker, finch, or podman) is installed or available in PATH"
    echo "Please install Docker, Finch, or Podman to build the Lambda layer"
    exit 1
fi

# Podman needs an entrypoint override for AWS Lambda base images; docker/finch do not.
if [ "$CONTAINER_CMD" = "podman" ]; then
    ENTRYPOINT_OVERRIDE="--entrypoint="
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
elif [ "$CONTAINER_CMD" = "finch" ]; then
    ${CONTAINER_CMD}  run --platform linux/amd64 --rm \
      -v $(pwd)/output:/output \
      --entrypoint cp \
      lambda-layer-x86 \
      /tmp/lambda-layer.zip /output/
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
echo "Layer build complete"
echo "Container runtime used: ${CONTAINER_CMD}"
echo "Layer file: $(ls -lh ../../lambda-layer.zip | awk '{print $5, $9}')"
echo ""
