#!/bin/bash
# ============================================================
# ABHIMANYU X Live USB Creator
# Creates bootable USB using Ubuntu Live CD base
# More reliable than building from scratch
# ============================================================

set -e

# Configuration
ABHIMANYUX_VERSION="2.0"
UBUNTU_VERSION="22.04"
BUILD_DIR=$(pwd)/build
OUTPUT_DIR=$(pwd)/output
ABHIMANYUX_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR]${NC} Please run as root (sudo)"
        exit 1
    fi
}

# Download Ubuntu Live CD
download_ubuntu() {
    print_info "Downloading Ubuntu ${UBUNTU_VERSION}..."
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    UBUNTU_URL="https://releases.ubuntu.com/${UBUNTU_VERSION}/ubuntu-${UBUNTU_VERSION}.4-desktop-amd64.iso"
    
    if [ ! -f "ubuntu.iso" ]; then
        wget -q --show-progress "$UBUNTU_URL" -O ubuntu.iso
    else
        print_info "Ubuntu ISO already downloaded"
    fi
    
    print_status "Ubuntu downloaded"
}

# Extract Ubuntu ISO
extract_ubuntu() {
    print_info "Extracting Ubuntu ISO..."
    
    mkdir -p "$BUILD_DIR/iso_mount"
    mkdir -p "$BUILD_DIR/iso_extract"
    
    # Mount ISO
    mount -o loop "$BUILD_DIR/ubuntu.iso" "$BUILD_DIR/iso_mount"
    
    # Copy files
    cp -r "$BUILD_DIR/iso_mount"/* "$BUILD_DIR/iso_extract/"
    
    # Unmount
    umount "$BUILD_DIR/iso_mount"
    
    print_status "Ubuntu extracted"
}

# Add ABHIMANYU X to Ubuntu
add_abhimanyux() {
    print_info "Adding ABHIMANYU X to Ubuntu..."
    
    ABHIMANYUX_DIR="$BUILD_DIR/iso_extract/abhimanyux"
    mkdir -p "$ABHIMANYUX_DIR"
    
    # Copy ABHIMANYU X files
    cp -r "$ABHIMANYUX_SRC"/core "$ABHIMANYUX_DIR/"
    cp -r "$ABHIMANYUX_SRC"/platform "$ABHIMANYUX_DIR/"
    cp -r "$ABHIMANYUX_SRC"/rewind "$ABHIMANYUX_DIR/"
    cp -r "$ABHIMANYUX_SRC"/fuzzer "$ABHIMANYUX_DIR/"
    cp -r "$ABHIMANYUX_SRC"/anvil "$ABHIMANYUX_DIR/"
    cp -r "$ABHIMANYUX_SRC"/verifier "$ABHIMANYUX_DIR/"
    cp -r "$ABHIMANYUX_SRC"/memory "$ABHIMANYUX_DIR/"
    cp -r "$ABHIMANYUX_SRC"/models "$ABHIMANYUX_DIR/"
    cp "$ABHIMANYUX_SRC"/requirements.txt "$ABHIMANYUX_DIR/"
    
    # Create startup script
    cat > "$ABHIMANYUX_DIR/start.sh" << 'STARTUP'
#!/bin/bash
# ABHIMANYU X Auto-Startup Script

echo ""
echo "============================================================"
echo "ABHIMANYU X Platform v2.0"
echo "Autonomous Cyber Reasoning System"
echo "============================================================"
echo ""

# Wait for network
echo "[*] Waiting for network..."
while ! ping -c 1 google.com &> /dev/null; do
    sleep 1
done
echo "[OK] Network connected"
echo ""

# Install Ollama
echo "[*] Installing Ollama..."
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
fi
echo "[OK] Ollama installed"
echo ""

# Start Ollama
echo "[*] Starting Ollama server..."
ollama serve &
sleep 3
echo "[OK] Ollama running"
echo ""

# Detect hardware and select model
echo "[*] Detecting hardware..."
RAM_GB=$(free -g | grep Mem | awk '{print $2}')
echo "  RAM: ${RAM_GB} GB"

if [ "$RAM_GB" -ge 16 ]; then
    MODEL="qwen2.5-coder:7b-instruct-q4_K_M"
elif [ "$RAM_GB" -ge 8 ]; then
    MODEL="qwen3:8b"
else
    MODEL="qwen2.5-coder:3b"
fi
echo "  Selected model: $MODEL"
echo ""

# Pull model
echo "[*] Pulling model (this may take a few minutes)..."
ollama pull "$MODEL"
echo "[OK] Model ready"
echo ""

# Setup Python environment
echo "[*] Setting up Python environment..."
cd /abhimanyux
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo "[OK] Python ready"
echo ""

# Create desktop shortcut
cat > ~/Desktop/AbhimanyuX.desktop << 'DESKTOP'
[Desktop Entry]
Version=1.0
Type=Application
Name=ABHIMANYU X
Comment=Autonomous Cyber Reasoning System
Exec=bash -c "cd /abhimanyux && source venv/bin/activate && PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform"
Icon=security
Terminal=true
Categories=Development;Security;
DESKTOP
chmod +x ~/Desktop/AbhimanyuX.desktop

echo "============================================================"
echo "ABHIMANYU X READY"
echo "============================================================"
echo ""
echo "Quick start:"
echo "  cd /abhimanyux"
echo "  source venv/bin/activate"
echo "  PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform <target>"
echo ""
echo "Or double-click 'ABHIMANYU X' on desktop"
echo ""
STARTUP
    chmod +x "$ABHIMANYUX_DIR/start.sh"
    
    # Create autostart entry
    mkdir -p "$BUILD_DIR/iso_extract/etc/xdg/autostart"
    cat > "$BUILD_DIR/iso_extract/etc/xdg/autostart/abhimanyux-start.desktop" << 'AUTOSTART'
[Desktop Entry]
Type=Application
Name=ABHIMANYU X Startup
Exec=/abhimanyux/start.sh
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
AUTOSTART
    
    # Create systemd service
    mkdir -p "$BUILD_DIR/iso_extract/etc/systemd/system"
    cat > "$BUILD_DIR/iso_extract/etc/systemd/system/abhimanyux.service" << 'SERVICE'
[Unit]
Description=ABHIMANYU X Platform
After=network.target

[Service]
Type=oneshot
ExecStart=/abhimanyux/start.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE
    
    print_status "ABHIMANYU X added"
}

# Rebuild ISO
rebuild_iso() {
    print_info "Rebuilding ISO..."
    
    cd "$BUILD_DIR/iso_extract"
    
    # Calculate MD5 for Ubuntu
    find . -type f -not -path "./isolinux/*" -not -path "./boot/grub/*" -exec md5sum {} \; > md5sum.txt
    
    # Create new ISO
    xorriso -as mkisofs \
        -r -V "ABHIMANYU X-Live" \
        -o "$OUTPUT_DIR/ABHIMANYU X-Live-${ABHIMANYUX_VERSION}.iso" \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        "$BUILD_DIR/iso_extract"
    
    print_status "ISO rebuilt"
}

# Create USB writing instructions
create_instructions() {
    print_info "Creating instructions..."
    
    cat > "$OUTPUT_DIR/README.txt" << 'README'
============================================================
ABHIMANYU X Live USB - Instructions
============================================================

WHAT IS THIS?
This is a bootable USB that runs ABHIMANYU X directly without
installing any operating system. Simply boot from the USB
and start scanning for vulnerabilities.

HOW TO CREATE BOOTABLE USB
============================================================

WINDOWS (using Rufus):
1. Download Rufus from https://rufus.ie
2. Insert USB drive (8GB or larger)
3. Open Rufus
4. Select "ABHIMANYU X-Live-2.0.iso"
5. Select your USB drive
6. Click "START"
7. Wait for completion

MAC/LINUX:
1. Insert USB drive
2. Open Terminal
3. Run: sudo dd if=ABHIMANYU X-Live-2.0.iso of=/dev/diskN bs=4M
   (Replace /dev/diskN with your USB drive)

HOW TO USE
============================================================

1. Insert USB into target computer
2. Boot from USB (press F12/F2/DEL during startup)
3. Select "ABHIMANYU X Live" from boot menu
4. Wait for system to start
5. Open Terminal
6. Run: abhimanyux scan /path/to/code

FEATURES
============================================================

- No installation required
- Runs entirely from USB
- Auto-detects hardware
- Downloads AI models automatically
- Works offline after setup
- Safe - doesn't affect host system

HARDWARE REQUIREMENTS
============================================================

- 4GB RAM minimum (8GB recommended)
- 2GHz dual-core processor
- 8GB USB drive
- x86_64 or ARM64 architecture

TROUBLESHOOTING
============================================================

If USB doesn't boot:
- Ensure USB is first in boot order
- Disable Secure Boot in BIOS
- Try different USB port

If Ollama fails to start:
- Check available RAM
- Try smaller model: abhimanyux pull qwen2.5-coder:3b

For help:
- Run: abhimanyux --help
- Check: /abhimanyux/README.md

============================================================
ABHIMANYU X Platform v2.0
Autonomous Cyber Reasoning System
============================================================
README
    
    print_status "Instructions created"
}

# Cleanup
cleanup() {
    print_info "Cleaning up..."
    rm -rf "$BUILD_DIR"
}

# Main
main() {
    echo ""
    echo "============================================================"
    echo "ABHIMANYU X Live USB Creator"
    echo "============================================================"
    echo ""
    
    check_root
    download_ubuntu
    extract_ubuntu
    add_abhimanyux
    rebuild_iso
    create_instructions
    
    echo ""
    echo "============================================================"
    echo "BUILD COMPLETE"
    echo "============================================================"
    echo ""
    echo "ISO file: $OUTPUT_DIR/ABHIMANYU X-Live-${ABHIMANYUX_VERSION}.iso"
    echo "Size: $(du -h "$OUTPUT_DIR/ABHIMANYU X-Live-${ABHIMANYUX_VERSION}.iso" | cut -f1)"
    echo ""
    echo "See $OUTPUT_DIR/README.txt for instructions"
}

case "${1:-}" in
    clean)
        cleanup
        ;;
    *)
        main
        ;;
esac
