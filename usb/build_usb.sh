#!/bin/bash
# ============================================================
# ABHIMANYU X Live USB Builder
# Creates a bootable USB that runs without any OS
# ============================================================

set -e

# Configuration
SENTINELX_VERSION="2.0"
BUILD_DIR=$(pwd)/build
OUTPUT_DIR=$(pwd)/output
ROOTFS_DIR=$(pwd)/rootfs
ALPINE_VERSION="3.19"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "ABHIMANYU X Live USB Builder"
    echo "Creates bootable USB - No OS Required"
    echo "============================================================"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check dependencies
check_dependencies() {
    print_info "Checking dependencies..."
    
    local deps=("wget" "curl" "gzip" "tar" "xorriso" "mksquashfs")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            missing+=($dep)
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_warning "Missing dependencies: ${missing[*]}"
        print_info "Installing dependencies..."
        
        if [[ "$OSTYPE" == "darwin"* ]]; then
            brew install xorriso squashfs coreutils
        elif command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y xorriso squashfs-tools syslinux syslinux-efi
        fi
    fi
    
    print_status "Dependencies OK"
}

# Download Alpine Linux minimal
download_alpine() {
    print_info "Downloading Alpine Linux minimal..."
    
    mkdir -p "$BUILD_DIR/alpine"
    cd "$BUILD_DIR/alpine"
    
    # Download Alpine minirootfs
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}.0-x86_64.tar.gz"
    elif [ "$ARCH" = "aarch64" ]; then
        ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/aarch64/alpine-minirootfs-${ALPINE_VERSION}.0-aarch64.tar.gz"
    else
        print_error "Unsupported architecture: $ARCH"
        exit 1
    fi
    
    if [ ! -f "alpine-rootfs.tar.gz" ]; then
        wget -q "$ALPINE_URL" -O alpine-rootfs.tar.gz
    fi
    
    print_status "Alpine Linux downloaded"
}

# Build rootfs
build_rootfs() {
    print_info "Building root filesystem..."
    
    rm -rf "$BUILD_DIR/rootfs"
    mkdir -p "$BUILD_DIR/rootfs"
    
    # Extract Alpine rootfs
    cd "$BUILD_DIR/rootfs"
    tar -xzf "$BUILD_DIR/alpine/alpine-rootfs.tar.gz"
    
    # Setup package manager
    chroot "$BUILD_DIR/rootfs" /bin/sh -c "
        echo 'https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/main' > /etc/apk/repositories
        echo 'https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/community' >> /etc/apk/repositories
        apk update
    "
    
    # Install essential packages
    print_info "Installing essential packages..."
    chroot "$BUILD_DIR/rootfs" /bin/sh -c "
        apk add --no-cache \
            bash \
            python3 \
            py3-pip \
            py3-virtualenv \
            curl \
            wget \
            git \
            build-base \
            linux-headers \
            util-linux \
            pciutils \
            usbutils \
            net-tools \
            iproute2 \
            openssh-client \
            screen \
            htop
    "
    
    print_status "Base packages installed"
}

# Install Ollama
install_ollama_rootfs() {
    print_info "Installing Ollama in rootfs..."
    
    mkdir -p "$BUILD_DIR/rootfs/opt/ollama"
    
    # Download Ollama binary
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        OLLAMA_URL="https://github.com/ollama/ollama/releases/latest/download/ollama-linux-amd64"
    elif [ "$ARCH" = "aarch64" ]; then
        OLLAMA_URL="https://github.com/ollama/ollama/releases/latest/download/ollama-linux-arm64"
    fi
    
    wget -q "$OLLAMA_URL" -O "$BUILD_DIR/rootfs/opt/ollama/ollama"
    chmod +x "$BUILD_DIR/rootfs/opt/ollama/ollama"
    
    # Create symlink
    ln -sf /opt/ollama/ollama "$BUILD_DIR/rootfs/usr/local/bin/ollama"
    
    print_status "Ollama installed"
}

# Install ABHIMANYU X
install_abhimanyux_rootfs() {
    print_info "Installing ABHIMANYU X in rootfs..."
    
    SENTINELX_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    
    mkdir -p "$BUILD_DIR/rootfs/opt/abhimanyux"
    
    # Copy ABHIMANYU X files
    cp -r "$SENTINELX_SRC"/core "$BUILD_DIR/rootfs/opt/abhimanyux/"
    cp -r "$SENTINELX_SRC"/platform "$BUILD_DIR/rootfs/opt/abhimanyux/"
    cp -r "$SENTINELX_SRC"/rewind "$BUILD_DIR/rootfs/opt/abhimanyux/"
    cp -r "$SENTINELX_SRC"/fuzzer "$BUILD_DIR/rootfs/opt/abhimanyux/"
    cp -r "$SENTINELX_SRC"/anvil "$BUILD_DIR/rootfs/opt/abhimanyux/"
    cp -r "$SENTINELX_SRC"/verifier "$BUILD_DIR/rootfs/opt/abhimanyux/"
    cp -r "$SENTINELX_SRC"/memory "$BUILD_DIR/rootfs/opt/abhimanyux/"
    cp -r "$SENTINELX_SRC"/models "$BUILD_DIR/rootfs/opt/abhimanyux/"
    cp "$SENTINELX_SRC"/requirements.txt "$BUILD_DIR/rootfs/opt/abhimanyux/"
    
    # Create virtual environment and install dependencies
    chroot "$BUILD_DIR/rootfs" /bin/sh -c "
        cd /opt/abhimanyux
        python3 -m venv venv
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r requirements.txt
    "
    
    # Copy init script
    cp "$(dirname "${BASH_SOURCE[0]}")/rootfs/init" "$BUILD_DIR/rootfs/init"
    chmod +x "$BUILD_DIR/rootfs/init"
    
    # Create abhimanyux launcher
    cp "$(dirname "${BASH_SOURCE[0]}")/rootfs/usr/local/bin/abhimanyux" "$BUILD_DIR/rootfs/usr/local/bin/abhimanyux" 2>/dev/null || true
    chmod +x "$BUILD_DIR/rootfs/usr/local/bin/abhimanyux" 2>/dev/null || true
    
    print_status "ABHIMANYU X installed"
}

# Create initramfs
create_initramfs() {
    print_info "Creating initramfs..."
    
    cd "$BUILD_DIR/rootfs"
    
    # Create device nodes
    mkdir -p dev
    mknod -m 622 dev/console c 5 1 2>/dev/null || true
    mknod -m 666 dev/null c 1 3 2>/dev/null || true
    mknod -m 666 dev/zero c 1 5 2>/dev/null || true
    mknod -m 444 dev/random c 1 8 2>/dev/null || true
    mknod -m 444 dev/urandom c 1 9 2>/dev/null || true
    
    # Create initramfs
    cd "$BUILD_DIR"
    find rootfs -print0 | cpio --null -ov --format=newc 2>/dev/null | gzip -9 > "$BUILD_DIR/initramfs.cpio.gz"
    
    print_status "Initramfs created"
}

# Download Linux kernel
download_kernel() {
    print_info "Downloading Linux kernel..."
    
    mkdir -p "$BUILD_DIR/kernel"
    cd "$BUILD_DIR/kernel"
    
    # Download pre-built kernel
    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.tar.xz"
        # For simplicity, we'll use Alpine's kernel
        wget -q "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION}/releases/x86_64/alpine-virt-${ALPINE_VERSION}.0-x86_64.iso" -O alpine-virt.iso 2>/dev/null || true
    fi
    
    print_status "Kernel ready"
}

# Create boot configuration
create_boot_config() {
    print_info "Creating boot configuration..."
    
    mkdir -p "$BUILD_DIR/boot/grub"
    mkdir -p "$BUILD_DIR/boot/syslinux"
    
    # GRUB configuration
    cat > "$BUILD_DIR/boot/grub/grub.cfg" << 'EOF'
set default=0
set timeout=10

set menu_color_normal=cyan/blue
set menu_color_highlight=white/blue

menuentry "ABHIMANYU X Live" {
    linux /boot/vmlinuz-virt quiet initrd=/boot/initramfs.cpio.gz
    initrd /boot/initramfs.cpio.gz
}

menuentry "ABHIMANYU X Live (Verbose)" {
    linux /boot/vmlinuz-virt debug initrd=/boot/initramfs.cpio.gz
    initrd /boot/initramfs.cpio.gz
}

menuentry "ABHIMANYU X Live (RAM Test)" {
    linux /boot/memtest86+
}
EOF
    
    # SYSLINUX configuration (for BIOS boot)
    cat > "$BUILD_DIR/boot/syslinux/syslinux.cfg" << 'EOF'
DEFAULT abhimanyux
PROMPT 1
TIMEOUT 100

LABEL abhimanyux
    LINUX /boot/vmlinuz-virt
    INITRD /boot/initramfs.cpio.gz
    APPEND quiet

LABEL abhimanyux-verbose
    LINUX /boot/vmlinuz-virt
    INITRD /boot/initramfs.cpio.gz
    APPEND debug
EOF
    
    # GRUB EFI configuration
    mkdir -p "$BUILD_DIR/boot/grub/EFI/BOOT"
    cat > "$BUILD_DIR/boot/grub/EFI/BOOT/grub.cfg" << 'EOF'
set default=0
set timeout=5

menuentry "ABHIMANYU X Live" {
    linux /boot/vmlinuz-virt quiet initrd=/boot/initramfs.cpio.gz
    initrd /boot/initramfs.cpio.gz
}
EOF
    
    print_status "Boot configuration created"
}

# Create ISO
create_iso() {
    print_info "Creating bootable ISO..."
    
    mkdir -p "$OUTPUT_DIR"
    
    local ISO_FILE="$OUTPUT_DIR/ABHIMANYU X-Live-${SENTINELX_VERSION}.iso"
    
    # Check if we have the kernel
    if [ ! -f "$BUILD_DIR/kernel/vmlinuz-virt" ]; then
        print_warning "Kernel not found, using Alpine kernel..."
        
        # Extract kernel from Alpine ISO
        if [ -f "$BUILD_DIR/kernel/alpine-virt.iso" ]; then
            mkdir -p "$BUILD_DIR/kernel/extract"
            cd "$BUILD_DIR/kernel/extract"
            bsdtar xf "$BUILD_DIR/kernel/alpine-virt.iso" 2>/dev/null || true
            
            # Copy kernel
            find "$BUILD_DIR/kernel/extract" -name "vmlinuz*" -exec cp {} "$BUILD_DIR/boot/vmlinuz-virt" \;
            find "$BUILD_DIR/kernel/extract" -name "initramfs*" -exec cp {} "$BUILD_DIR/boot/initramfs-alpine" \;
        fi
    fi
    
    # Create ISO structure
    mkdir -p "$BUILD_DIR/iso"/{boot/grub,boot/syslinux,EFI/BOOT}
    
    # Copy boot files
    cp "$BUILD_DIR/initramfs.cpio.gz" "$BUILD_DIR/iso/boot/"
    cp "$BUILD_DIR/boot/vmlinuz-virt" "$BUILD_DIR/iso/boot/" 2>/dev/null || true
    cp -r "$BUILD_DIR/boot/grub" "$BUILD_DIR/iso/boot/"
    cp -r "$BUILD_DIR/boot/syslinux" "$BUILD_DIR/iso/boot/"
    
    # Create ISO
    xorriso -as mkisofs \
        -o "$ISO_FILE" \
        -b boot/syslinux/isolinux.bin \
        -c boot/syslinux/boot.cat \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        -eltorito-alt-boot \
        -e boot/grub/efi.img \
        -no-emul-boot \
        -R -J -joliet-long \
        "$BUILD_DIR/iso"
    
    print_status "ISO created: $ISO_FILE"
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}BUILD COMPLETE${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo "ISO file: $ISO_FILE"
    echo "Size: $(du -h "$ISO_FILE" | cut -f1)"
    echo ""
    echo "To create bootable USB:"
    echo ""
    echo "  Linux/Mac:"
    echo "    sudo dd if=$ISO_FILE of=/dev/sdX bs=4M status=progress"
    echo ""
    echo "  Windows (Rufus):"
    echo "    1. Download Rufus: https://rufus.ie"
    echo "    2. Select ISO file"
    echo "    3. Select USB drive"
    echo "    4. Click Start"
    echo ""
    echo "  Etcher (Any OS):"
    echo "    1. Download Etcher: https://etcher.balena.io"
    echo "    2. Select ISO file"
    echo "    3. Select USB drive"
    echo "    4. Flash!"
}

# Create USB creation script for Windows
create_windows_usb_tool() {
    print_info "Creating Windows USB tool..."
    
    cat > "$OUTPUT_DIR/create_usb.bat" << 'BATCH_EOF'
@echo off
REM ============================================================
REM ABHIMANYU X USB Creator for Windows
REM ============================================================

title ABHIMANYU X USB Creator

echo.
echo    _____ ____  ___    _    ______   _______   ____ 
echo   / ____/ ___^|_ _^|  / \  ^| __ ) \ / / ____^| / ___^|
echo  ^| ^|    \___ \ ^| ^|  / _ \ ^| _ \\\ V /^|  _|   \___ \ 
echo  ^| ^|___  ___) ^| ^| / ___ \^| |_) /^| ^| ^| ^|___   ___) ^|
echo   \____^|^|____/___^|_/   \_\____/ ^|_^|  ^|_____^| ^|____/
echo.
echo   USB Creator
echo.
echo ============================================================
echo.

REM Check for administrator
net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM List disks
echo Available disks:
echo.
listdisk
echo.
set /p DISK_NUM="Enter disk number: "

echo.
echo WARNING: ALL DATA ON DISK %DISK_NUM% WILL BE ERASED!
echo.
set /p CONFIRM="Type YES to confirm: "
if not "%CONFIRM%"=="YES" (
    echo Aborted.
    pause
    exit /b 1
)

echo.
echo Creating bootable USB...

REM Clean disk
diskpart /s "%~dp0diskpart.txt" >nul

REM Create partitions
echo create partition primary > "%~dp0diskpart.txt"
echo select partition 1 >> "%~dp0diskpart.txt"
echo active >> "%~dp0diskpart.txt"
echo format fs=fat32 quick label="SENTINELX" >> "%~dp0diskpart.txt"
echo assign >> "%~dp0diskpart.txt"
echo exit >> "%~dp0diskpart.txt"

diskpart /s "%~dp0diskpart.txt" >nul

REM Copy files
echo Copying files...
xcopy /E /I /Y "%~dp0image\*" E:\

echo.
echo ============================================================
echo USB CREATED SUCCESSFULLY
echo ============================================================
echo.
echo Remove USB and boot from it.
echo.
pause
BATCH_EOF
    
    print_status "Windows USB tool created"
}

# Cleanup
cleanup() {
    print_info "Cleaning up build files..."
    rm -rf "$BUILD_DIR"
}

# Main build
main() {
    print_header
    
    check_dependencies
    download_alpine
    build_rootfs
    install_ollama_rootfs
    install_abhimanyux_rootfs
    create_initramfs
    download_kernel
    create_boot_config
    create_iso
    create_windows_usb_tool
    
    echo ""
    print_status "All builds complete!"
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
