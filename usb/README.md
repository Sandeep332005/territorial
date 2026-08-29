# ABHIMANYU X Bootable USB

Create a bootable USB that runs ABHIMANYU X **without installing any operating system**.

## What is this?

A self-contained security scanning platform that:
- Boots directly from USB
- No installation on host computer required
- Auto-detects hardware
- Downloads AI models automatically
- Works offline after initial setup
- Safe - doesn't modify host system

## Quick Start

### Option 1: Windows (Easiest)

1. Download Ubuntu 22.04 LTS Desktop ISO:
   ```
   https://releases.ubuntu.com/22.04/ubuntu-22.04.4-desktop-amd64.iso
   ```

2. Download Rufus:
   ```
   https://rufus.ie
   ```

3. Open Rufus and:
   - Select Ubuntu ISO
   - Select USB drive (8GB+)
   - Click START

4. After Ubuntu boots, open Terminal and run:
   ```bash
   sudo apt update && sudo apt install -y git
   git clone https://github.com/abhimanyux/abhimanyux.git
   cd abhimanyux/usb
   sudo bash quick_usb.sh
   ```

5. Reboot and select ABHIMANYU X from boot menu

### Option 2: Mac/Linux

```bash
# Clone repository
git clone https://github.com/abhimanyux/abhimanyux.git
cd abhimanyux/usb

# Download Ubuntu ISO
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.4-desktop-amd64.iso

# Make script executable
chmod +x quick_usb.sh

# Create bootable USB (run as root)
sudo bash quick_usb.sh
```

### Option 3: Pre-built ISO

Download pre-built ISO from releases:
```
https://github.com/abhimanyux/abhimanyux/releases
```

Then use Rufus (Windows) or dd (Mac/Linux) to write to USB.

## Booting from USB

### Windows PCs
1. Insert USB drive
2. Restart computer
3. Press **F12** during startup (or F2, DEL, ESC)
4. Select USB drive from boot menu
5. Choose "ABHIMANYU X Live"

### Mac
1. Insert USB drive
2. Restart while holding **Option** key
3. Select USB drive
4. Choose "ABHIMANYU X Live"

### Linux
1. Insert USB drive
2. Restart computer
3. Press boot menu key (F12, F8, or ESC)
4. Select USB drive

## First Boot Setup

On first boot, ABHIMANYU X will automatically:

1. Detect your hardware (CPU, RAM, GPU)
2. Install Python and dependencies
3. Install Ollama (local AI server)
4. Download optimal AI model based on your hardware
5. Configure settings

This takes 5-15 minutes depending on internet speed.

## Usage

After setup, open Terminal and run:

```bash
# Navigate to ABHIMANYU X
cd /abhimanyux

# Activate Python environment
source venv/bin/activate

# Scan a directory
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform /path/to/project

# Scan a file
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform target.py

# Show hardware info
abhimanyux hardware

# List available models
abhimanyux models

# Download different model
abhimanyux pull qwen2.5-coder:32b
```

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| RAM | 4 GB | 16+ GB |
| CPU | 2 cores | 4+ cores |
| USB | 8 GB | 16 GB |
| Network | Required for setup | Optional after |

## Auto-Selected Models

Based on detected hardware:

| RAM | GPU VRAM | Model Selected |
|-----|----------|----------------|
| 4-8 GB | None | `qwen2.5-coder:3b` |
| 8-16 GB | None | `qwen3:8b` |
| 16+ GB | 5+ GB | `qwen2.5-coder:7b` ⭐ |
| 32+ GB | 8+ GB | `qwen2.5-coder:14b` |
| 64+ GB | 12+ GB | `qwen2.5-coder:32b` |

## Features

- **25+ vulnerability patterns** detected
- **CVSS scoring** for severity assessment
- **Exploit tracing** with attack vectors
- **AI-powered patch generation**
- **Immune memory** learns from scans
- **14+ programming languages** supported
- **Works offline** after initial setup

## Troubleshooting

### USB doesn't boot
- Ensure USB is first in boot order
- Disable Secure Boot in BIOS
- Try different USB port
- Try different USB drive

### Ollama fails to start
- Check available RAM
- Try smaller model: `abhimanyux pull qwen2.5-coder:3b`
- Restart Ollama: `ollama serve`

### Slow performance
- Use USB 3.0 port
- Use faster USB drive
- Close other applications
- Use smaller model

### Network issues
- Check internet connection
- Try different network
- Use mobile hotspot
- Models can be transferred via USB

## Advanced: Air-Gapped Deployment

For environments without internet:

1. On connected machine:
   ```bash
   ollama pull qwen2.5-coder:7b
   ollama save qwen2.5-coder:7b > model.tar
   ```

2. Copy `model.tar` to USB drive

3. On air-gapped machine:
   ```bash
   ollama load < /media/usb/model.tar
   ```

## Files on USB

```
/
├── abhimanyux/           # ABHIMANYU X platform
│   ├── core/           # Main orchestrator
│   ├── platform/       # Multi-provider LLM
│   ├── rewind/         # Static analysis
│   ├── fuzzer/         # AI-guided fuzzing
│   ├── anvil/          # Patch generation
│   ├── verifier/       # Verification
│   ├── memory/         # Immune memory
│   └── models/         # Data models
├── install.sh          # Auto-installer
└── README.txt          # Instructions
```

## Security Notes

- USB runs in RAM - no changes to host
- All scans are local - no data sent externally
- Models run locally - no API keys required
- Immune memory stored on USB only

## Support

- Documentation: `abhimanyux/README.md`
- Issues: GitHub Issues
- Community: Discord server

## License

ABHIMANYU X Platform - Defence Infrastructure Security
