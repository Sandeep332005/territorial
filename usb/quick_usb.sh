#!/bin/bash
# ============================================================
# ABHIMANYU X Quick USB Creator
# Uses existing Ubuntu ISO - fastest method
# ============================================================

set -e

VERSION="2.0"
SENTINELX_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR=$(pwd)/output

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "============================================================"
echo "ABHIMANYU X Quick USB Creator"
echo "============================================================"
echo -e "${NC}"

# Check if Ubuntu ISO exists
UBUNTU_ISO=""
for iso in ubuntu-*.iso Ubuntu*.iso; do
    if [ -f "$iso" ]; then
        UBUNTU_ISO="$iso"
        break
    fi
done

if [ -z "$UBUNTU_ISO" ]; then
    echo "No Ubuntu ISO found in current directory."
    echo ""
    echo "Please download Ubuntu 22.04 LTS Desktop:"
    echo "  https://releases.ubuntu.com/22.04/ubuntu-22.04.4-desktop-amd64.iso"
    echo ""
    echo "Then place it in: $(pwd)"
    echo ""
    exit 1
fi

echo "Found Ubuntu ISO: $UBUNTU_ISO"
echo ""

# Create build directory
BUILD_DIR=$(pwd)/build
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Extract ISO
echo "[1/4] Extracting Ubuntu ISO..."
mkdir -p "$BUILD_DIR/iso"
bsdtar xf "$UBUNTU_ISO" -C "$BUILD_DIR/iso"

# Add ABHIMANYU X
echo "[2/4] Adding ABHIMANYU X..."
mkdir -p "$BUILD_DIR/iso/abhimanyux"

# Copy ABHIMANYU X
cp -r "$SENTINELX_SRC"/{core,platform,rewind,fuzzer,anvil,verifier,memory,models} "$BUILD_DIR/iso/abhimanyux/"
cp "$SENTINELX_SRC"/requirements.txt "$BUILD_DIR/iso/abhimanyux/"

# Create installer script
cat > "$BUILD_DIR/iso/abhimanyux/install.sh" << 'INSTALL'
#!/bin/bash
# ABHIMANYU X Installer for Live USB

echo "Installing ABHIMANYU X..."

# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Setup SENTINELX
cd /abhimanyux
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Start services
ollama serve &
sleep 3

# Pull model
echo "Pulling AI model..."
ollama pull qwen2.5-coder:7b-instruct-q4_K_M

echo ""
echo "ABHIMANYU X installed!"
echo "Run: cd /abhimanyux && source venv/bin/activate && PYTHONPATH=. python -m abhimanyux.platform.abhimanyux_platform"
INSTALL
chmod +x "$BUILD_DIR/iso/abhimanyux/install.sh"

# Create autostart
mkdir -p "$BUILD_DIR/iso/etc/xdg/autostart"
cat > "$BUILD_DIR/iso/etc/xdg/autostart/abhimanyux.desktop" << 'AUTOSTART'
[Desktop Entry]
Type=Application
Name=ABHIMANYU X Setup
Exec=/abhimanyux/install.sh
Terminal=true
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
AUTOSTART

echo "[3/4] Rebuilding ISO..."

# Update MD5
cd "$BUILD_DIR/iso"
find . -name "md5sum.txt" -delete
find . -type f -not -path "./isolinux/*" -not -path "./boot/grub/*" -exec md5sum {} \; > md5sum.txt

# Create new ISO
mkdir -p "$OUTPUT_DIR"
xorriso -as mkisofs \
    -r -V "SENTINELX-Live" \
    -o "$OUTPUT_DIR/ABHIMANYU X-Live-${VERSION}.iso" \
    -b isolinux/isolinux.bin \
    -c isolinux/boot.cat \
    -no-emul-boot \
    -boot-load-size 4 \
    -boot-info-table \
    -eltorito-alt-boot \
    -e boot/grub/efi.img \
    -no-emul-boot \
    "$BUILD_DIR/iso"

echo "[4/4] Done!"
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}BOOTABLE USB ISO CREATED${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "ISO: $OUTPUT_DIR/ABHIMANYU X-Live-${VERSION}.iso"
echo "Size: $(du -h "$OUTPUT_DIR/ABHIMANYU X-Live-${VERSION}.iso" | cut -f1)"
echo ""
echo "To create bootable USB:"
echo ""
echo "  Windows: Use Rufus (https://rufus.ie)"
echo "  Mac:     sudo dd if=$OUTPUT_DIR/ABHIMANYU X-Live-${VERSION}.iso of=/dev/diskN bs=4M"
echo "  Linux:   sudo dd if=$OUTPUT_DIR/ABHIMANYU X-Live-${VERSION}.iso of=/dev/sdX bs=4M"
echo ""
echo "Boot from USB and ABHIMANYU X will auto-install!"
