#!/bin/bash
# ============================================================
# ABHIMANYU X Platform - Portable Archive Builder
# Creates self-extracting archives for all platforms
# ============================================================

set -e

VERSION="2.0.0"
BUILD_DIR=$(pwd)/build
OUTPUT_DIR=$(pwd)/output
SENTINELX_DIR=$(pwd)/..

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "============================================================"
echo "ABHIMANYU X Platform - Portable Archive Builder"
echo "============================================================"
echo -e "${NC}"

# Clean previous builds
rm -rf "$BUILD_DIR" "$OUTPUT_DIR"
mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

# Copy ABHIMANYU X source
echo "[*] Copying ABHIMANYU X source..."
cp -r "$SENTINELX_DIR"/core "$BUILD_DIR/"
cp -r "$SENTINELX_DIR"/platform "$BUILD_DIR/"
cp -r "$SENTINELX_DIR"/rewind "$BUILD_DIR/"
cp -r "$SENTINELX_DIR"/fuzzer "$BUILD_DIR/"
cp -r "$SENTINELX_DIR"/anvil "$BUILD_DIR/"
cp -r "$SENTINELX_DIR"/verifier "$BUILD_DIR/"
cp -r "$SENTINELX_DIR"/memory "$BUILD_DIR/"
cp -r "$SENTINELX_DIR"/models "$BUILD_DIR/"
cp "$SENTINELX_DIR"/requirements.txt "$BUILD_DIR/"
cp "$SENTINELX_DIR"/README.md "$BUILD_DIR/"

# Create config
cat > "$BUILD_DIR/config.json" << 'EOF'
{
  "model_name": "auto",
  "auto_select_model": true,
  "enable_cvss_scoring": true,
  "enable_exploit_tracing": true,
  "enable_immune_memory": true
}
EOF

# =============================================
# Build Linux/Mac Archive (tar.gz)
# =============================================
echo "[*] Building Linux/Mac archive..."

LINUX_DIR="$BUILD_DIR/abhimanyux-linux"
mkdir -p "$LINUX_DIR"

# Copy source
cp -r "$BUILD_DIR"/{core,platform,rewind,fuzzer,anvil,verifier,memory,models} "$LINUX_DIR/"
cp "$BUILD_DIR"/{requirements.txt,README.md,config.json} "$LINUX_DIR/"

# Copy launcher
cp abhimanyux_launcher.sh "$LINUX_DIR/install.sh"
chmod +x "$LINUX_DIR/install.sh"

# Create archive
cd "$BUILD_DIR"
tar -czf "$OUTPUT_DIR/abhimanyux-${VERSION}-linux-mac.tar.gz" abhimanyux-linux/
cd ..

echo -e "${GREEN}[✓] Linux/Mac archive created${NC}"

# =============================================
# Build Windows Archive (zip)
# =============================================
echo "[*] Building Windows archive..."

WINDOWS_DIR="$BUILD_DIR/abhimanyux-windows"
mkdir -p "$WINDOWS_DIR"

# Copy source
cp -r "$BUILD_DIR"/{core,platform,rewind,fuzzer,anvil,verifier,memory,models} "$WINDOWS_DIR/"
cp "$BUILD_DIR"/{requirements.txt,README.md,config.json} "$WINDOWS_DIR/"

# Copy Windows launcher
cp abhimanyux_launcher.bat "$WINDOWS_DIR/install.bat"

# Create archive
cd "$BUILD_DIR"
zip -r "$OUTPUT_DIR/abhimanyux-${VERSION}-windows.zip" abhimanyux-windows/
cd ..

echo -e "${GREEN}[✓] Windows archive created${NC}"

# =============================================
# Build Docker image
# =============================================
echo "[*] Building Docker image..."

if command -v docker &> /dev/null; then
    cd "$SENTINELX_DIR"
    docker build -f iso/Dockerfile.portable -t abhimanyux:${VERSION} .
    docker save abhimanyux:${VERSION} | gzip > "$OUTPUT_DIR/abhimanyux-${VERSION}-docker.tar.gz"
    cd -
    echo -e "${GREEN}[✓] Docker image created${NC}"
else
    echo "[!] Docker not found, skipping Docker image"
fi

# =============================================
# Create ISO (if tools available)
# =============================================
echo "[*] Checking ISO tools..."

if command -v xorriso &> /dev/null && command -v mksquashfs &> /dev/null; then
    echo "Building ISO..."
    chmod +x build_iso.sh
    ./build_iso.sh
    echo -e "${GREEN}[✓] ISO created${NC}"
else
    echo "[!] ISO tools not found (xorriso, mksquashfs)"
    echo "    Install: apt-get install xorriso squashfs-tools"
    echo "    Skipping ISO build"
fi

# =============================================
# Summary
# =============================================
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}BUILD COMPLETE${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "Output files:"
ls -lh "$OUTPUT_DIR/"
echo ""
echo "============================================================"
echo "DOWNLOAD LINKS"
echo "============================================================"
echo ""
echo "Linux/Mac:"
echo "  tar -xzf abhimanyux-${VERSION}-linux-mac.tar.gz"
echo "  cd abhimanyux-linux"
echo "  ./install.sh"
echo ""
echo "Windows:"
echo "  Extract abhimanyux-${VERSION}-windows.zip"
echo "  Run install.bat"
echo ""
echo "Docker:"
echo "  gunzip -c abhimanyux-${VERSION}-docker.tar.gz | docker load"
echo "  docker run -it abhimanyux:${VERSION}"
echo ""
echo "ISO (for air-gapped environments):"
echo "  dd if=abhimanyux-${VERSION}.iso of=/dev/sdX bs=4M"
echo ""
