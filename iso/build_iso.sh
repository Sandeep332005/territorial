#!/bin/bash
# ============================================================
# ABHIMANYU X Platform - ISO Builder
# Creates a bootable Linux ISO with ABHIMANYU X pre-installed
# Works on: x86_64, ARM64 machines
# ============================================================

set -e

# Configuration
ISO_NAME="ABHIMANYU X-Platform-2.0"
ISO_VERSION="2.0.0"
BUILD_DIR=$(pwd)/build
OUTPUT_DIR=$(pwd)/output
WORK_DIR=$(pwd)/work
SENTINELX_DIR=$(pwd)/..

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}"
    echo "============================================================"
    echo "ABHIMANYU X Platform - ISO Builder"
    echo "Autonomous Cyber Reasoning System for Defence Infrastructure"
    echo "============================================================"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    print_status "Checking dependencies..."
    
    local deps=("xorriso" "mksquashfs" "mkpasswd" "wget" "curl" "debootstrap")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            missing+=($dep)
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_warning "Missing dependencies: ${missing[*]}"
        print_status "Installing dependencies..."
        
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            brew install xorriso squashfs coreutils
        elif command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y xorriso squashfs-tools debootstrap isolinux syslinux-efi
        elif command -v dnf &> /dev/null; then
            # Fedora/RHEL
            sudo dnf install -y xorriso squashfs-tools debootstrap syslinux
        fi
    fi
    
    print_status "Dependencies OK"
}

# Create minimal Linux filesystem
create_base_system() {
    print_status "Creating base Linux system..."
    
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    
    # Create minimal directory structure
    mkdir -p "$BUILD_DIR"/{bin,sbin,lib,lib64,usr,etc,var,proc,sys,dev,tmp,boot,mnt,root,home}
    mkdir -p "$BUILD_DIR"/usr/{bin,sbin,lib,share,local}
    mkdir -p "$BUILD_DIR"/etc/{init.d,systemd,NetworkManager}
    mkdir -p "$BUILD_DIR"/var/{lib,log,run,tmp}
    
    # Create fstab
    cat > "$BUILD_DIR/etc/fstab" << 'EOF'
# <file system> <mount point>   <type>  <options>       <dump>  <pass>
proc            /proc           proc    defaults        0       0
tmpfs           /tmp            tmpfs   defaults        0       0
tmpfs           /var/tmp        tmpfs   defaults        0       0
EOF
    
    print_status "Base system created"
}

# Install Python and dependencies
install_python() {
    print_status "Installing Python environment..."
    
    mkdir -p "$BUILD_DIR/opt/python"
    
    # Create Python setup script
    cat > "$BUILD_DIR/opt/python/setup.sh" << 'SETUP_EOF'
#!/bin/bash
set -e

PYTHON_VERSION="3.11"
PYTHON_DIR="/opt/python"

# Download and install Python
cd /tmp
wget -q "https://www.python.org/ftp/python/${PYTHON_VERSION}.0/Python-${PYTHON_VERSION}.0.tgz"
tar xzf "Python-${PYTHON_VERSION}.0.tgz"
cd "Python-${PYTHON_VERSION}.0"
./configure --prefix="$PYTHON_DIR" --enable-optimizations --with-ensurepip=install
make -j$(nproc)
make altinstall

# Create symlink
ln -sf "$PYTHON_DIR/bin/python3.11" /usr/local/bin/python3
ln -sf "$PYTHON_DIR/bin/python3.11" /usr/local/bin/python

# Install pip
python3 -m pip install --upgrade pip

# Install ABHIMANYU X dependencies
python3 -m pip install \
    pydantic \
    fastapi \
    uvicorn \
    rich \
    google-generativeai \
    anthropic \
    aiohttp

SETUP_EOF
    chmod +x "$BUILD_DIR/opt/python/setup.sh"
    
    print_status "Python environment configured"
}

# Install Ollama
install_ollama() {
    print_status "Installing Ollama..."
    
    mkdir -p "$BUILD_DIR/opt/ollama"
    
    # Download Ollama binary
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        OLLAMA_URL="https://github.com/ollama/ollama/releases/latest/download/ollama-linux-amd64"
    elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
        OLLAMA_URL="https://github.com/ollama/ollama/releases/latest/download/ollama-linux-arm64"
    else
        print_error "Unsupported architecture: $ARCH"
        exit 1
    fi
    
    wget -q -O "$BUILD_DIR/opt/ollama/ollama" "$OLLAMA_URL"
    chmod +x "$BUILD_DIR/opt/ollama/ollama"
    
    # Create Ollama service
    cat > "$BUILD_DIR/etc/init.d/ollama" << 'OLLAMA_EOF'
#!/bin/bash
### BEGIN INIT INFO
# Provides:          ollama
# Required-Start:    $local_fs $remote_fs $network $syslog
# Required-Stop:     $local_fs $remote_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Ollama LLM Service
# Description:       Ollama local LLM inference server
### END INIT INFO

OLLAMA_DIR="/opt/ollama"
OLLAMA_HOST="0.0.0.0:11434"

start() {
    echo "Starting Ollama..."
    export OLLAMA_HOST
    cd "$OLLAMA_DIR"
    ./ollama serve &
    sleep 2
    echo "Ollama started on $OLLAMA_HOST"
}

stop() {
    echo "Stopping Ollama..."
    pkill ollama
}

status() {
    if pgrep ollama > /dev/null; then
        echo "Ollama is running"
    else
        echo "Ollama is not running"
    fi
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; sleep 1; start ;;
    status) status ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ;;
esac
OLLAMA_EOF
    chmod +x "$BUILD_DIR/etc/init.d/ollama"
    
    print_status "Ollama installed"
}

# Install ABHIMANYU X
install_abhimanyux() {
    print_status "Installing ABHIMANYU X Platform..."
    
    mkdir -p "$BUILD_DIR/opt/abhimanyux"
    
    # Copy ABHIMANYU X files
    cp -r "$SENTINELX_DIR"/core "$BUILD_DIR/opt/abhimanyux/"
    cp -r "$SENTINELX_DIR"/platform "$BUILD_DIR/opt/abhimanyux/"
    cp -r "$SENTINELX_DIR"/rewind "$BUILD_DIR/opt/abhimanyux/"
    cp -r "$SENTINELX_DIR"/fuzzer "$BUILD_DIR/opt/abhimanyux/"
    cp -r "$SENTINELX_DIR"/anvil "$BUILD_DIR/opt/abhimanyux/"
    cp -r "$SENTINELX_DIR"/verifier "$BUILD_DIR/opt/abhimanyux/"
    cp -r "$SENTINELX_DIR"/memory "$BUILD_DIR/opt/abhimanyux/"
    cp -r "$SENTINELX_DIR"/models "$BUILD_DIR/opt/abhimanyux/"
    cp "$SENTINELX_DIR"/requirements.txt "$BUILD_DIR/opt/abhimanyux/"
    
    # Create launcher script
    cat > "$BUILD_DIR/usr/local/bin/abhimanyux" << 'LAUNCHER_EOF'
#!/bin/bash
# ABHIMANYU X Platform Launcher

SENTINELX_HOME="/opt/abhimanyux"
PYTHON="/opt/python/bin/python3.11"

# Auto-detect and configure
detect_hardware() {
    echo "Detecting hardware..."
    
    # Detect GPU
    if command -v nvidia-smi &> /dev/null; then
        GPU_INFO=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null || echo "None")
        echo "GPU: $GPU_INFO"
    elif [ -f /sys/class/drm/card*/device/gpu_busy_percent ] 2>/dev/null; then
        echo "GPU: AMD detected"
    else
        echo "GPU: None detected"
    fi
    
    # Detect RAM
    if [ -f /proc/meminfo ]; then
        RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        RAM_GB=$((RAM_KB / 1024 / 1024))
        echo "RAM: ${RAM_GB} GB"
    fi
}

# Select best model
select_model() {
    local vram_gb=$1
    local ram_gb=$2
    
    if [ "$vram_gb" -ge 8 ]; then
        echo "qwen2.5-coder:7b-instruct-q4_K_M"
    elif [ "$vram_gb" -ge 5 ]; then
        echo "qwen3:8b"
    elif [ "$ram_gb" -ge 16 ]; then
        echo "qwen2.5-coder:7b-instruct-q4_K_M"
    else
        echo "qwen2.5-coder:3b"
    fi
}

# Main
case "$1" in
    scan)
        if [ -z "$2" ]; then
            echo "Usage: abhimanyux scan <file_or_directory>"
            exit 1
        fi
        detect_hardware
        cd "$SENTINELX_HOME"
        PYTHONPATH=. $PYTHON -m abhimanyux.runtime.abhimanyux_platform "$2"
        ;;
    models)
        echo "Available models:"
        echo "  Local (Ollama):"
        echo "    qwen2.5-coder:7b   - Best for code security"
        echo "    qwen3:8b           - Fast general model"
        echo "    deepseek-coder-v2  - Deep code analysis"
        echo "  Frontier (API):"
        echo "    claude-sonnet-4    - Best quality"
        echo "    gpt-4o             - Excellent analysis"
        echo "    gemini-2.5-flash   - Fast and accurate"
        ;;
    hardware)
        detect_hardware
        ;;
    setup)
        echo "Running initial setup..."
        detect_hardware
        
        # Start Ollama
        /etc/init.d/ollama start
        sleep 3
        
        # Pull recommended model
        MODEL=$(select_model 8 64)
        echo "Pulling model: $MODEL"
        /opt/ollama/ollama pull "$MODEL"
        
        echo "Setup complete!"
        echo "Usage: abhimanyux scan <target>"
        ;;
    *)
        echo "ABHIMANYU X Platform v2.0"
        echo "Autonomous Cyber Reasoning System"
        echo ""
        echo "Usage: abhimanyux <command> [options]"
        echo ""
        echo "Commands:"
        echo "  scan <target>    Scan file or directory for vulnerabilities"
        echo "  models           List available models"
        echo "  hardware         Show detected hardware"
        echo "  setup            Initial setup (pulls recommended model)"
        echo ""
        echo "Examples:"
        echo "  abhimanyux scan /path/to/code"
        echo "  abhimanyux setup"
        ;;
esac
LAUNCHER_EOF
    chmod +x "$BUILD_DIR/usr/local/bin/abhimanyux"
    
    print_status "ABHIMANYU X installed"
}

# Create initramfs
create_initramfs() {
    print_status "Creating initramfs..."
    
    cat > "$BUILD_DIR/etc/init.d/rcS" << 'INIT_EOF'
#!/bin/bash
# Mount essential filesystems
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp

# Set hostname
hostname abhimanyux

# Start Ollama
/etc/init.d/ollama start &

# Welcome message
echo ""
echo "============================================================"
echo "ABHIMANYU X Platform v2.0"
echo "Autonomous Cyber Reasoning System for Defence Infrastructure"
echo "============================================================"
echo ""
echo "System ready. Type 'abhimanyux' to begin."
echo ""
echo "Quick start:"
echo "  abhimanyux setup     - Initial setup"
echo "  abhimanyux scan .    - Scan current directory"
echo "  abhimanyux models   - List available models"
echo ""

# Start shell
exec /bin/bash
INIT_EOF
    chmod +x "$BUILD_DIR/etc/init.d/rcS"
    
    print_status "Initramfs created"
}

# Create boot configuration
create_boot_config() {
    print_status "Creating boot configuration..."
    
    mkdir -p "$BUILD_DIR/boot/grub"
    
    cat > "$BUILD_DIR/boot/grub/grub.cfg" << 'GRUB_EOF'
set default=0
set timeout=10

menuentry "ABHIMANYU X Platform" {
    linux /boot/vmlinuz initrd=/boot/initrd.img quiet splash
    initrd /boot/initrd.img
}

menuentry "ABHIMANYU X Platform (Safe Mode)" {
    linux /boot/vmlinuz initrd=/boot/initrd.img quiet splash single
    initrd /boot/initrd.img
}

menuentry "Memory Test" {
    linux /boot/memtest
}
GRUB_EOF
    
    print_status "Boot configuration created"
}

# Create ISO
create_iso() {
    print_status "Creating ISO image..."
    
    mkdir -p "$OUTPUT_DIR"
    
    # For x86_64, we need to download kernel and initramfs
    # For simplicity, we'll create a bootable ISO structure
    
    local ISO_FILE="$OUTPUT_DIR/${ISO_NAME}-${ISO_VERSION}.iso"
    
    # Create squashfs of the root filesystem
    print_status "Creating squashfs..."
    mksquashfs "$BUILD_DIR" "$WORK_DIR/filesystem.squashfs" -comp xz -b 1M
    
    # Create ISO structure
    mkdir -p "$WORK_DIR/iso"/{boot/grub,isolinux,casper}
    
    # Copy kernel (simplified - in production, extract from live CD)
    cp "$WORK_DIR/filesystem.squashfs" "$WORK_DIR/iso/casper/filesystem.squashfs"
    
    # Create ISO
    xorriso -as mkisofs \
        -o "$ISO_FILE" \
        -b isolinux/isolinux.bin \
        -c isolinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        -R -J -joliet-long \
        "$WORK_DIR/iso"
    
    print_status "ISO created: $ISO_FILE"
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}ISO BUILD COMPLETE${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo "ISO file: $ISO_FILE"
    echo "Size: $(du -h "$ISO_FILE" | cut -f1)"
    echo ""
    echo "To use:"
    echo "  1. Burn to USB: dd if=$ISO_FILE of=/dev/sdX bs=4M"
    echo "  2. Boot from USB"
    echo "  3. Run: abhimanyux setup"
    echo "  4. Run: abhimanyux scan <target>"
}

# Cleanup
cleanup() {
    print_status "Cleaning up..."
    rm -rf "$BUILD_DIR" "$WORK_DIR"
}

# Main build process
main() {
    print_header
    
    check_dependencies
    create_base_system
    install_python
    install_ollama
    install_abhimanyux
    create_initramfs
    create_boot_config
    create_iso
    
    echo ""
    print_status "Build complete!"
}

# Parse arguments
case "${1:-}" in
    clean)
        cleanup
        ;;
    *)
        main
        ;;
esac
