#!/bin/bash
# ============================================================
# ABHIMANYU X Platform - Universal Launcher
# Self-contained setup for any Linux/Mac system
# ============================================================

set -e

# Configuration
ABHIMANYUX_VERSION="2.0"
INSTALL_DIR="${HOME}/abhimanyux"
PYTHON_MIN_VERSION="3.9"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'
    _____ ____  ___    _    ______   _______   ____
   / ____/ ___||_ _|  / \  | __ ) \ / / ____| / ___|
  | |    \___ \ | |  / _ \ |  _ \\ V /|  _|   \___ \
  | |___  ___) || | / ___ \| |_) || | | |___   ___) |
   \____||____/___/_/   \_\____/ |_|  |_____| |____/
                                                         
   v2.0 - Autonomous Cyber Reasoning System
   For Defence Infrastructure Security
BANNER
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

# Detect OS and architecture
detect_system() {
    print_info "Detecting system..."
    
    OS=$(uname -s)
    ARCH=$(uname -m)
    
    echo "  OS: $OS"
    echo "  Architecture: $ARCH"
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
    elif command -v brew &> /dev/null; then
        PKG_MANAGER="brew"
    else
        PKG_MANAGER="none"
    fi
    echo "  Package Manager: $PKG_MANAGER"
}

# Check and install Python
check_python() {
    print_info "Checking Python..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
        print_status "Python $PYTHON_VERSION found"
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
        print_status "Python $PYTHON_VERSION found"
        PYTHON_CMD="python"
    else
        print_warning "Python not found. Installing..."
        install_python
    fi
}

install_python() {
    case "$PKG_MANAGER" in
        apt-get)
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
            ;;
        dnf)
            sudo dnf install -y python3 python3-pip
            ;;
        brew)
            brew install python@3.11
            ;;
        *)
            print_error "Cannot auto-install Python. Please install Python 3.9+ manually."
            exit 1
            ;;
    esac
    PYTHON_CMD="python3"
}

# Check and install Ollama
check_ollama() {
    print_info "Checking Ollama..."
    
    if command -v ollama &> /dev/null; then
        OLLAMA_VERSION=$(ollama --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
        print_status "Ollama $OLLAMA_VERSION found"
    else
        print_warning "Ollama not found. Installing..."
        install_ollama
    fi
}

install_ollama() {
    print_info "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
    print_status "Ollama installed"
}

# Detect hardware
detect_hardware() {
    print_info "Detecting hardware..."
    
    # RAM
    if [ "$OS" = "Darwin" ]; then
        RAM_BYTES=$(sysctl -n hw.memsize 2>/dev/null || echo "8589934592")
        RAM_GB=$((RAM_BYTES / 1024 / 1024 / 1024))
    elif [ -f /proc/meminfo ]; then
        RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        RAM_GB=$((RAM_KB / 1024 / 1024))
    else
        RAM_GB=16
    fi
    echo "  RAM: ${RAM_GB} GB"
    
    # GPU
    if command -v nvidia-smi &> /dev/null; then
        GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
        GPU_VRAM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader 2>/dev/null | head -1 | grep -oE '[0-9]+')
        GPU_VRAM_GB=$((GPU_VRAM / 1024))
        echo "  GPU: $GPU_NAME"
        echo "  VRAM: ${GPU_VRAM_GB} GB"
    elif [ "$OS" = "Darwin" ]; then
        echo "  GPU: Apple Silicon (Unified Memory)"
        GPU_VRAM_GB=$((RAM_GB * 7 / 10))
        echo "  Estimated VRAM: ~${GPU_VRAM_GB} GB"
    else
        echo "  GPU: None detected"
        GPU_VRAM_GB=0
    fi
    
    # CPU cores
    if [ "$OS" = "Darwin" ]; then
        CPU_CORES=$(sysctl -n hw.ncpu 2>/dev/null || echo "8")
    else
        CPU_CORES=$(nproc 2>/dev/null || echo "8")
    fi
    echo "  CPU Cores: $CPU_CORES"
}

# Select best model based on hardware
select_model() {
    print_info "Selecting optimal model..."
    
    if [ "$GPU_VRAM_GB" -ge 8 ]; then
        MODEL="qwen2.5-coder:7b-instruct-q4_K_M"
        echo "  Selected: $MODEL (fits in GPU)"
    elif [ "$GPU_VRAM_GB" -ge 5 ]; then
        MODEL="qwen3:8b"
        echo "  Selected: $MODEL (fits in GPU)"
    elif [ "$RAM_GB" -ge 16 ]; then
        MODEL="qwen2.5-coder:7b-instruct-q4_K_M"
        echo "  Selected: $MODEL (CPU mode)"
    else
        MODEL="qwen2.5-coder:3b"
        echo "  Selected: $MODEL (lightweight)"
    fi
}

# Install ABHIMANYU X
install_abhimanyux() {
    print_info "Installing ABHIMANYU X Platform..."
    
    # Create install directory
    mkdir -p "$INSTALL_DIR"
    
    # Check if running from extracted archive
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    if [ -f "$SCRIPT_DIR/abhimanyux_platform.py" ]; then
        # Running from source
        cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    else
        # Download from GitHub (placeholder)
        print_warning "Please copy abhimanyux/ folder to $INSTALL_DIR"
        print_info "Or run this script from the abhimanyux directory"
    fi
    
    # Create virtual environment
    cd "$INSTALL_DIR"
    $PYTHON_CMD -m venv venv
    source venv/bin/activate
    
    # Install dependencies
    pip install --upgrade pip -q
    pip install -r requirements.txt -q
    
    # Create launcher
    cat > "$HOME/.local/bin/abhimanyux" << 'LAUNCHER'
#!/bin/bash
ABHIMANYUX_HOME="$HOME/abhimanyux"
source "$ABHIMANYUX_HOME/venv/bin/activate"
cd "$ABHIMANYUX_HOME"
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform "$@"
LAUNCHER
    chmod +x "$HOME/.local/bin/abhimanyux"
    
    # Add to PATH if needed
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
    fi
    
    print_status "ABHIMANYU X installed to $INSTALL_DIR"
}

# Pull model
pull_model() {
    print_info "Pulling model: $MODEL"
    ollama pull "$MODEL"
    print_status "Model ready"
}

# Test installation
test_installation() {
    print_info "Testing installation..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    PYTHONPATH=. python -c "
from abhimanyux.runtime.abhimanyux_platform import AbhimanyuXPlatform
p = AbhimanyuXPlatform()
print('Platform initialized successfully')
print(f'Model: {p.config.model_name}')
" 
    
    if [ $? -eq 0 ]; then
        print_status "Installation test passed"
    else
        print_error "Installation test failed"
        exit 1
    fi
}

# Print usage
print_usage() {
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}INSTALLATION COMPLETE${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo "Usage:"
    echo "  abhimanyux scan <target>    Scan file or directory"
    echo "  abhimanyux models          List available models"
    echo "  abhimanyux hardware        Show detected hardware"
    echo "  abhimanyux setup           Re-run setup"
    echo ""
    echo "Examples:"
    echo "  abhimanyux scan /path/to/project"
    echo "  abhimanyux scan main.py"
    echo ""
    echo "Configuration file: $INSTALL_DIR/abhimanyux_config.json"
    echo ""
}

# Main installation
main() {
    print_banner
    
    echo "============================================================"
    echo "ABHIMANYU X Platform - Installation Wizard"
    echo "============================================================"
    echo ""
    
    detect_system
    echo ""
    
    check_python
    check_ollama
    echo ""
    
    detect_hardware
    echo ""
    
    select_model
    echo ""
    
    install_abhimanyux
    pull_model
    test_installation
    
    print_usage
}

# Run main
main
