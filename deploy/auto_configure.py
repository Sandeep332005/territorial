#!/usr/bin/env python3
"""
ABHIMANYU X Platform - Auto-Configuration Script
Automatically detects hardware and configures optimal settings
"""

import os
import sys
import json
import platform
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from abhimanyux.platform.providers import ModelSelector, MODEL_REGISTRY, ProviderType


def detect_hardware():
    """Detect system hardware"""
    selector = ModelSelector()
    return selector.hardware


def get_system_info():
    """Get detailed system information"""
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
    }
    
    # Detect GPU
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total,memory.free", "--format=csv,noheader"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                gpu_info = result.stdout.strip().split("\n")[0]
                name, total, free = gpu_info.split(", ")
                info["gpu"] = name.strip()
                info["gpu_vram_total_mb"] = int(total.replace(" MiB", "").strip())
                info["gpu_vram_free_mb"] = int(free.replace(" MiB", "").strip())
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True, text=True
            )
            if "Apple" in result.stdout:
                info["gpu"] = "Apple Silicon"
                info["gpu_vram_total_mb"] = int(detect_hardware().total_ram_gb * 1024 * 0.7)
    except Exception:
        pass
    
    # Detect RAM
    try:
        if platform.system() == "Darwin":
            result = subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True)
            info["ram_bytes"] = int(result.stdout.strip())
            info["ram_gb"] = info["ram_bytes"] / (1024**3)
        elif platform.system() == "Linux":
            with open("/proc/meminfo") as f:
                for line in f:
                    if "MemTotal" in line:
                        info["ram_kb"] = int(line.split()[1])
                        info["ram_gb"] = info["ram_kb"] / (1024**2)
                        break
        elif platform.system() == "Windows":
            result = subprocess.run(
                ["wmic", "memorychip", "get", "capacity"],
                capture_output=True, text=True
            )
            # Parse Windows output
            total = 0
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line and line.isdigit():
                    total += int(line)
            info["ram_gb"] = total / (1024**3) if total > 0 else 64
    except Exception:
        info["ram_gb"] = 16
    
    # CPU cores
    try:
        info["cpu_cores"] = os.cpu_count()
    except Exception:
        info["cpu_cores"] = 8
    
    return info


def recommend_model(hardware_info):
    """Recommend best model based on hardware"""
    vram = hardware_info.get("gpu_vram_total_mb", 0) / 1024  # Convert to GB
    ram = hardware_info.get("ram_gb", 16)
    
    recommendations = []
    
    # Local models
    local_models = [
        ("qwen2.5-coder-7b", 5, 5, "Best for code security, fits in 8GB VRAM"),
        ("qwen3-8b", 5, 5, "Fast general model, fully fits in GPU"),
        ("deepseek-coder-16b", 10, 12, "Best code quality, partial GPU offload"),
        ("qwen2.5-coder-14b", 8, 10, "Good balance of speed and quality"),
        ("qwen2.5-coder-32b", 20, 20, "Maximum quality, mostly CPU"),
    ]
    
    for model_name, vram_needed, ram_needed, note in local_models:
        fits_gpu = vram >= vram_needed
        fits_ram = ram >= ram_needed
        
        if fits_gpu and fits_ram:
            recommendations.append({
                "model": model_name,
                "fits_gpu": True,
                "speed": "Fast" if fits_gpu else "Medium",
                "quality": "High" if "32b" in model_name else "Medium",
                "note": note
            })
    
    # Frontier models
    frontier_models = [
        ("claude-sonnet-4", "Best overall quality"),
        ("gpt-4o", "Excellent code analysis"),
        ("gemini-2.5-flash", "Fast and accurate"),
        ("deepseek-v3", "Good code understanding"),
    ]
    
    for model_name, note in frontier_models:
        recommendations.append({
            "model": model_name,
            "fits_gpu": False,
            "speed": "API-dependent",
            "quality": "Very High",
            "note": note
        })
    
    return recommendations


def configure_abhimanyux(hardware_info, recommendations):
    """Generate optimal ABHIMANYU X configuration"""
    vram = hardware_info.get("gpu_vram_total_mb", 0) / 1024
    ram = hardware_info.get("ram_gb", 16)
    
    # Select best local model
    best_local = None
    for rec in recommendations:
        if rec["fits_gpu"] and rec["speed"] == "Fast":
            best_local = rec["model"]
            break
    
    if not best_local:
        best_local = "qwen2.5-coder-7b"
    
    config = {
        "model_name": best_local,
        "auto_select_model": True,
        "prefer_local": True,
        "enable_cvss_scoring": True,
        "enable_exploit_tracing": True,
        "enable_immune_memory": True,
        "ollama_endpoint": "http://localhost:11434",
        "hardware": {
            "gpu_vram_gb": round(vram, 1),
            "ram_gb": round(ram, 1),
            "cpu_cores": hardware_info.get("cpu_cores", 8)
        }
    }
    
    return config


def main():
    """Main auto-configuration function"""
    print("=" * 60)
    print("ABHIMANYU X Platform - Auto-Configuration")
    print("=" * 60)
    print()
    
    # Detect hardware
    print("[1/4] Detecting hardware...")
    hw = detect_hardware()
    sys_info = get_system_info()
    
    print(f"  OS: {sys_info['os']} {sys_info['os_version']}")
    print(f"  CPU: {sys_info.get('processor', 'Unknown')}")
    print(f"  CPU Cores: {hw.cpu_cores}")
    print(f"  RAM: {hw.total_ram_gb:.1f} GB")
    print(f"  GPU: {hw.gpu_name or 'None detected'}")
    print(f"  GPU VRAM: {hw.gpu_vram_gb:.1f} GB")
    print()
    
    # Get recommendations
    print("[2/4] Analyzing optimal models...")
    recommendations = recommend_model({
        "gpu_vram_total_mb": hw.gpu_vram_gb * 1024,
        "ram_gb": hw.total_ram_gb,
        "cpu_cores": hw.cpu_cores
    })
    
    print("  Recommended models:")
    for i, rec in enumerate(recommendations[:5], 1):
        fits = "✓ GPU" if rec["fits_gpu"] else "⚠ CPU"
        print(f"    {i}. {rec['model']} ({fits}) - {rec['note']}")
    print()
    
    # Generate config
    print("[3/4] Generating configuration...")
    config = configure_abhimanyux({
        "gpu_vram_total_mb": hw.gpu_vram_gb * 1024,
        "ram_gb": hw.total_ram_gb,
        "cpu_cores": hw.cpu_cores
    }, recommendations)
    
    print(f"  Default model: {config['model_name']}")
    print(f"  Auto-select: {config['auto_select_model']}")
    print()
    
    # Save configuration
    print("[4/4] Saving configuration...")
    config_path = Path(__file__).parent / "abhimanyux_config.json"
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"  Saved to: {config_path}")
    print()
    
    print("=" * 60)
    print("CONFIGURATION COMPLETE")
    print("=" * 60)
    print()
    print("Next steps:")
    print("  1. Install Ollama: https://ollama.com/download")
    print(f"  2. Pull model: ollama pull {config['model_name']}")
    print("  3. Run scan: python -m abhimanyux.platform.abhimanyux_platform target.py")
    print()
    
    return config


if __name__ == "__main__":
    main()
