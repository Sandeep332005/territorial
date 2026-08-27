# ABHIMANYU X Platform - Portable Distribution

## Download Links

### Pre-built Archives

| Platform | File | Size | Installation |
|----------|------|------|--------------|
| **Linux/Mac** | `abhimanyux-2.0.0-linux-mac.tar.gz` | 150 KB | Extract and run `install.sh` |
| **Windows** | `abhimanyux-2.0.0-windows.zip` | 169 KB | Extract and run `install.bat` |

---

## Quick Installation

### Linux/Mac

```bash
# Download and extract
tar -xzf abhimanyux-2.0.0-linux-mac.tar.gz
cd abhimanyux-linux

# Run installer
./install.sh
```

### Windows

```
1. Extract abhimanyux-2.0.0-windows.zip
2. Double-click install.bat
3. Follow the prompts
```

### Docker (Any Platform)

```bash
# Pull the image
docker pull abhimanyux/abhimanyux:2.0

# Run
docker run -it abhimanyux/abhimanyux:2.0
```

---

## What's Included

```
abhimanyux/
├── core/              # Main orchestrator
├── platform/          # Multi-provider LLM platform
├── rewind/            # Static analysis engine (25+ patterns)
├── fuzzer/            # AI-guided fuzzing (10 strategies)
├── anvil/             # LLM patch generation
├── verifier/          # Verification pipeline
├── memory/            # Immune memory store (SQLite)
├── models/            # Data models
├── requirements.txt   # Python dependencies
├── config.json        # Default configuration
└── install.sh/.bat    # Installer script
```

---

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **RAM** | 4 GB | 16+ GB |
| **GPU VRAM** | 0 GB (CPU mode) | 8+ GB |
| **Storage** | 500 MB | 2 GB |
| **Python** | 3.9+ | 3.11+ |

---

## Supported Models

### Local Models (via Ollama)

| Model | VRAM Needed | Best For |
|-------|-------------|----------|
| `qwen2.5-coder:3b` | 2 GB | Lightweight/CPU |
| `qwen2.5-coder:7b` | 5 GB | Code security ⭐ |
| `qwen3:8b` | 5 GB | Fast analysis |
| `deepseek-coder-v2:16b` | 10 GB | Deep analysis |
| `qwen2.5-coder:32b` | 20 GB | Maximum quality |

### Frontier Models (API keys required)

| Model | Provider | Cost |
|-------|----------|------|
| `claude-sonnet-4` | Anthropic | $0.015/1K tokens |
| `gpt-4o` | OpenAI | $0.005/1K tokens |
| `gemini-2.5-flash` | Google | $0.00015/1K tokens |
| `deepseek-v3` | DeepSeek | $0.001/1K tokens |

---

## Usage

### Command Line

```bash
# Scan a file
abhimanyux scan target.py

# Scan a directory
abhimanyux scan /path/to/project

# List available models
abhimanyux models

# Show hardware info
abhimanyux hardware

# Setup (pull recommended model)
abhimanyux setup
```

### Python API

```python
from abhimanyux.platform.abhimanyux_platform import AbhimanyuXPlatform

# Auto-detect hardware and select best model
platform = AbhimanyuXPlatform()

# Scan a file
result = platform.scan_file("target.py")
platform.print_report(result)

# Scan code directly
code = """
import os
def vulnerable(path):
    return os.popen("cat " + path).read()
"""
result = platform.scan_code(code, "example.py")
platform.print_report(result)
```

---

## Auto-Configuration

The installer automatically:

1. **Detects your hardware** (CPU, RAM, GPU, VRAM)
2. **Selects the best model** for your system
3. **Installs all dependencies** (Python, Ollama, packages)
4. **Configures optimal settings** for security scanning

### Manual Configuration

Edit `config.json`:

```json
{
  "model_name": "qwen2.5-coder-7b",
  "auto_select_model": true,
  "enable_cvss_scoring": true,
  "enable_exploit_tracing": true,
  "enable_immune_memory": true
}
```

---

## Building from Source

### Create Portable Archives

```bash
cd abhimanyux/iso
chmod +x build_portable.sh
./build_portable.sh
```

### Create Bootable ISO

```bash
cd abhimanyux/iso
chmod +x build_iso.sh
./build_iso.sh
```

---

## Air-Gapped Deployment

For environments without internet:

1. Download archives on a connected machine
2. Transfer via USB/external drive
3. Extract and install offline
4. Models must be pre-downloaded:
   ```bash
   # On connected machine
   ollama pull qwen2.5-coder:7b-instruct-q4_K_M
   ollama save qwen2.5-coder:7b > model.tar
   
   # On air-gapped machine
   ollama load < model.tar
   ```

---

## Support

- **Documentation**: See `abhimanyux/README.md`
- **Tests**: Run `python -m pytest abhimanyux/tests/`
- **Issues**: Check logs in `abhimanyux/logs/`

---

## License

ABHIMANYU X Platform - Defence Infrastructure Security
Autonomous Cyber Reasoning System
