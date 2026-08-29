# ABHIMANYU X - Enhanced LLM Provider System

## Overview

ABHIMANYU X v2.0 supports **three types of LLM providers**:

| Category | Description | Examples |
|----------|-------------|----------|
| **LOCAL** | Runs on your hardware | Ollama, vLLM, LM Studio |
| **API** | Cloud-based services | Claude, GPT, Gemini, DeepSeek |
| **CUSTOM** | User-configured endpoints | Self-hosted, proxied, enterprise |

---

## Quick Start

### 1. Check Available Providers

```bash
# Show hardware and available models
python abhimanyux/cli/providers_cli.py status

# List all models
python abhimanyux/cli/providers_cli.py list

# Check provider health
python abhimanyux/cli/providers_cli.py check
```

### 2. Use Local Model (Default)

```bash
# Auto-selects best local model
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform_v2 target.py

# Force specific model
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform_v2 target.py --model qwen2.5-coder-7b
```

### 3. Use API Model

```bash
# Set API key
export ANTHROPIC_API_KEY=your_key_here

# Use Claude
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform_v2 target.py --model claude-sonnet-4

# Or force API provider
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform_v2 target.py --provider api
```

### 4. Use Custom Endpoint

```bash
# Add custom endpoint
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform_v2 target.py \
  --add-endpoint my-server http://192.168.1.100:8080/v1/chat/completions my-model

# Or use the CLI
python abhimanyux/cli/providers_cli.py add my-server http://192.168.1.100:8080/v1/chat/completions my-model
```

---

## Provider Details

### LOCAL Models

Run entirely on your hardware. No API keys needed.

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model
ollama pull qwen2.5-coder:7b-instruct-q4_K_M

# Models are auto-detected
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform_v2 target.py
```

**Best models by hardware:**

| RAM | VRAM | Model |
|-----|------|-------|
| 4 GB | - | `qwen2.5-coder-3b` |
| 8 GB | 5 GB | `qwen3-8b` |
| 16 GB | 5 GB | `qwen2.5-coder-7b` ⭐ |
| 32 GB | 8 GB | `qwen2.5-coder-14b` |
| 64 GB | 12 GB | `qwen2.5-coder-32b` |

### API Models

Cloud-based services. Requires API key.

```bash
# Supported providers
export ANTHROPIC_API_KEY=...    # Claude
export OPENAI_API_KEY=...       # GPT
export GEMINI_API_KEY=...       # Gemini
export DEEPSEEK_API_KEY=...     # DeepSeek
export GROQ_API_KEY=...         # Groq (free tier)
export MISTRAL_API_KEY=...      # Mistral
export TOGETHER_API_KEY=...     # Together AI
```

**Cost comparison:**

| Model | Input Cost | Output Cost | Best For |
|-------|------------|-------------|----------|
| `claude-sonnet-4` | $0.003/1K | $0.015/1K | Best balanced |
| `gpt-4o` | $0.0025/1K | $0.01/1K | Multimodal |
| `gemini-2.5-flash` | $0.000075/1K | $0.0003/1K | Cheapest |
| `deepseek-v3` | $0.00014/1K | $0.00028/1K | Best value |
| `groq-llama-8b` | $0.00005/1K | $0.00008/1K | Free tier |

### CUSTOM Models

Any OpenAI-compatible endpoint.

```bash
# Examples of custom endpoints:
# - Self-hosted vLLM
# - Text Generation WebUI
# - KoboldCpp
# - llama.cpp server
# - Enterprise AI proxy

# Add custom endpoint
python abhimanyux/cli/providers_cli.py add \
  my-model \
  http://192.168.1.100:8080/v1/chat/completions \
  model-name
```

**Supported formats:**
- OpenAI-compatible API (`/v1/chat/completions`)
- Ollama API (`/api/generate`)
- Custom format (user-configurable)

---

## Intelligent Selection

ABHIMANYU X automatically selects the best model based on:

1. **Hardware capabilities** (RAM, GPU, VRAM)
2. **Available providers** (local vs API keys)
3. **Task requirements** (code, reasoning, general)
4. **Cost preferences** (cheap vs quality)

```bash
# Auto-select (default)
--model auto

# Prefer local models
--prefer-local

# Prefer cheap models
--prefer-cheap

# Prefer API models
--prefer-api
```

---

## Fallback Chain

If the primary model fails, ABHIMANYU X automatically falls back:

1. **Primary model** (selected or specified)
2. **Same category alternatives** (other local/API models)
3. **Other categories** (local → API → custom)

```python
from abhimanyux.runtime.abhimanyux_platform_v2 import AbhimanyuXPlatform

platform = AbhimanyuXPlatform()
result, model_used = platform.provider_manager.generate_with_fallback(
    system_prompt="You are a security expert.",
    user_prompt="Analyze this code...",
    primary_model="claude-sonnet-4"  # Falls back to alternatives if fails
)
```

---

## Configuration File

Edit `config/providers.json` to configure providers:

```json
{
  "local": {
    "ollama": {
      "enabled": true,
      "endpoint": "http://localhost:11434"
    }
  },
  "api": {
    "anthropic": {
      "enabled": true,
      "api_key_env": "ANTHROPIC_API_KEY"
    }
  },
  "custom": {
    "endpoints": [
      {
        "name": "my-server",
        "api_url": "http://192.168.1.100:8080/v1/chat/completions",
        "model_id": "my-model"
      }
    ]
  }
}
```

---

## CLI Commands

```bash
# List all models
python abhimanyux/cli/providers_cli.py list

# Show status
python abhimanyux/cli/providers_cli.py status

# Check health
python abhimanyux/cli/providers_cli.py check

# Test a model
python abhimanyux/cli/providers_cli.py test qwen2.5-coder-7b

# Add custom endpoint
python abhimanyux/cli/providers_cli.py add my-server http://url model
```

---

## Python API

```python
from abhimanyux.runtime.abhimanyux_platform_v2 import (
    AbhimanyuXPlatform, PlatformConfig
)

# Auto-select best model
config = PlatformConfig(model_name="auto")
platform = AbhimanyuXPlatform(config)

# Use specific model
config = PlatformConfig(model_name="claude-sonnet-4", api_key="...")
platform = AbhimanyuXPlatform(config)

# Add custom endpoint
platform.add_custom_endpoint(
    name="my-server",
    api_url="http://192.168.1.100:8080/v1/chat/completions",
    model_id="my-model",
    api_key="optional-key"
)

# Scan with fallback
result = platform.scan_file("target.py")
```

---

## For Your AI15-DT (i9-13900 + 64GB + RTX 4060 12GB)

```bash
# Best local model for your hardware
ollama pull qwen2.5-coder:32b-instruct-q4_K_M

# Run scan
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform_v2 target.py --model qwen2.5-coder-32b

# Or use API for best quality
export ANTHROPIC_API_KEY=your_key
PYTHONPATH=. python -m abhimanyux.runtime.abhimanyux_platform_v2 target.py --model claude-sonnet-4
```
