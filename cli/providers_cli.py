#!/usr/bin/env python3
"""
ABHIMANYU X Provider CLI - Manage Local/API/Custom LLM Providers

Usage:
    abhimanyux-providers list              List all available models
    abhimanyux-providers status            Show provider status
    abhimanyux-providers check             Check provider health
    abhimanyux-providers add <name> <url> <model>  Add custom endpoint
    abhimanyux-providers remove <name>     Remove custom endpoint
    abhimanyux-providers test <model>      Test a model
"""

import sys
import os
import json

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(project_root))

from abhimanyux.platform.providers_v2 import (
    ModelSelector, MODEL_REGISTRY, ProviderCategory, ProviderType
)


def list_models():
    """List all available models grouped by category"""
    selector = ModelSelector()
    available = selector.get_available_providers()
    
    print("\n" + "="*70)
    print("ABHIMANYU X - Available LLM Models")
    print("="*70)
    
    for category in [ProviderCategory.LOCAL, ProviderCategory.API, ProviderCategory.CUSTOM]:
        models = available[category]
        print(f"\n{category.value.upper()} MODELS ({len(models)} available)")
        print("-"*70)
        
        for name in models:
            config = MODEL_REGISTRY[name]
            tags = ", ".join(config.tags[:4]) if config.tags else "-"
            
            # Add hardware info for local models
            if category == ProviderCategory.LOCAL:
                hw_info = f"RAM:{config.min_ram_gb}GB VRAM:{config.min_vram_gb}GB"
                print(f"  {name:30} {hw_info:20} [{tags}]")
            else:
                cost = f"${config.cost_per_1k_tokens:.4f}/1K" if config.cost_per_1k_tokens > 0 else "free"
                print(f"  {name:30} {cost:20} [{tags}]")
    
    print("\n" + "="*70)
    print("Use: abhimanyux-providers test <model> to test a model")
    print("="*70)


def show_status():
    """Show provider status and hardware"""
    selector = ModelSelector()
    hw = selector.hardware
    
    print("\n" + "="*70)
    print("ABHIMANYU X - Provider Status")
    print("="*70)
    
    print("\nHARDWARE:")
    print(f"  RAM:           {hw.total_ram_gb:.1f} GB ({hw.available_ram_gb:.1f} GB available)")
    print(f"  GPU:           {hw.gpu_name or 'None detected'}")
    print(f"  GPU VRAM:      {hw.gpu_vram_gb:.1f} GB")
    print(f"  CPU Cores:     {hw.cpu_cores}")
    print(f"  GPU Type:      {hw.gpu_type or 'Unknown'}")
    
    # Check which API keys are available
    api_keys = {
        "ANTHROPIC_API_KEY": os.getenv("ANTHROPIC_API_KEY"),
        "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY"),
        "GEMINI_API_KEY": os.getenv("GEMINI_API_KEY"),
        "DEEPSEEK_API_KEY": os.getenv("DEEPSEEK_API_KEY"),
        "GROQ_API_KEY": os.getenv("GROQ_API_KEY"),
        "MISTRAL_API_KEY": os.getenv("MISTRAL_API_KEY"),
        "TOGETHER_API_KEY": os.getenv("TOGETHER_API_KEY"),
    }
    
    print("\nAPI KEYS:")
    for key, value in api_keys.items():
        status = "✓ Set" if value else "✗ Not set"
        print(f"  {key:25} {status}")
    
    # Best model recommendations
    print("\nRECOMMENDED MODELS:")
    for task in ["vulnerability_detection", "patch_generation", "root_cause_analysis"]:
        best = selector.select_best(prefer_local=True, task=task)
        print(f"  {task:25} → {best}")
    
    print("\n" + "="*70)


def check_health():
    """Check health of all providers"""
    import urllib.request
    
    print("\n" + "="*70)
    print("ABHIMANYU X - Provider Health Check")
    print("="*70)
    
    # Check Ollama
    print("\nLOCAL PROVIDERS:")
    try:
        req = urllib.request.Request("http://localhost:11434/api/tags")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            models = [m["name"] for m in data.get("models", [])]
            print(f"  Ollama:      ✓ Running ({len(models)} models)")
            for m in models[:5]:
                print(f"               - {m}")
    except:
        print(f"  Ollama:      ✗ Not running")
    
    # Check vLLM
    try:
        req = urllib.request.Request("http://localhost:8000/v1/models")
        with urllib.request.urlopen(req, timeout=3) as resp:
            print(f"  vLLM:        ✓ Running")
    except:
        print(f"  vLLM:        ✗ Not running")
    
    # Check API providers
    print("\nAPI PROVIDERS:")
    api_providers = [
        ("Anthropic", "ANTHROPIC_API_KEY"),
        ("OpenAI", "OPENAI_API_KEY"),
        ("Google", "GEMINI_API_KEY"),
        ("DeepSeek", "DEEPSEEK_API_KEY"),
        ("Groq", "GROQ_API_KEY"),
        ("Mistral", "MISTRAL_API_KEY"),
    ]
    
    for name, key in api_providers:
        if os.getenv(key):
            print(f"  {name:12} ✓ API key set")
        else:
            print(f"  {name:12} ✗ No API key")
    
    print("\n" + "="*70)


def test_model(model_name: str):
    """Test a specific model"""
    from abhimanyux.platform.providers_v2 import ProviderFactory
    
    print(f"\nTesting model: {model_name}")
    print("-"*40)
    
    try:
        provider = ProviderFactory.create(model_name)
        print(f"Provider created: {provider.config.provider.value}")
        
        print("Generating test response...")
        start = time.time()
        
        response = provider.generate(
            "You are a security expert.",
            "What are the top 3 security vulnerabilities in Python code? Be brief.",
            max_tokens=200
        )
        
        elapsed = time.time() - start
        print(f"\nResponse ({elapsed:.1f}s):")
        print(response[:500])
        
        # Show usage
        usage = provider.get_usage()
        print(f"\nTokens used: {usage['total_tokens']}")
        
    except Exception as e:
        print(f"Error: {e}")


def add_endpoint(name: str, url: str, model: str):
    """Add a custom endpoint"""
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "providers.json")
    
    # Load existing config
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
    except:
        config = {"custom": {"endpoints": []}}
    
    # Add new endpoint
    endpoint = {
        "name": name,
        "enabled": True,
        "api_url": url,
        "model_id": model,
        "api_key": None
    }
    
    if "custom" not in config:
        config["custom"] = {"endpoints": []}
    if "endpoints" not in config["custom"]:
        config["custom"]["endpoints"] = []
    
    config["custom"]["endpoints"].append(endpoint)
    
    # Save config
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✓ Added custom endpoint: {name}")
    print(f"  URL: {url}")
    print(f"  Model: {model}")


def main():
    import time
    
    if len(sys.argv) < 2:
        print(__doc__)
        return
    
    command = sys.argv[1]
    
    if command == "list":
        list_models()
    elif command == "status":
        show_status()
    elif command == "check":
        check_health()
    elif command == "test":
        if len(sys.argv) < 3:
            print("Usage: abhimanyux-providers test <model_name>")
            return
        test_model(sys.argv[2])
    elif command == "add":
        if len(sys.argv) < 5:
            print("Usage: abhimanyux-providers add <name> <url> <model_id>")
            return
        add_endpoint(sys.argv[2], sys.argv[3], sys.argv[4])
    else:
        print(f"Unknown command: {command}")
        print(__doc__)


if __name__ == "__main__":
    main()
