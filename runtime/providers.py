"""
ABHIMANYU X Platform - Multi-Provider LLM Registry

Based on research:
- MalCodeAI: Language-agnostic multi-stage AI pipeline (arXiv:2507.10898)
- Antares: Foundation models for agentic vulnerability localization (arXiv:2608.02407)
- The Path To Autonomous Cyber Defense (arXiv:2404.10788)

Supports:
- Frontier models: Claude, GPT-4, Gemini, DeepSeek
- Local models: Ollama, vLLM, LM Studio
- Model selection based on hardware capabilities
"""

import os
import json
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class ProviderType(Enum):
    """Supported LLM provider types"""
    # Frontier models (API-based)
    ANTHROPIC = "anthropic"      # Claude
    OPENAI = "openai"            # GPT-4, GPT-5
    GOOGLE = "google"            # Gemini
    DEEPSEEK = "deepseek"        # DeepSeek-Coder
    
    # Local models
    OLLAMA = "ollama"            # Ollama local models
    VLLM = "vllm"                # vLLM server
    LM_STUDIO = "lm_studio"     # LM Studio


@dataclass
class ModelConfig:
    """Configuration for a specific model"""
    name: str
    provider: ProviderType
    model_id: str
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.2
    context_window: int = 8192
    supports_vision: bool = False
    supports_tools: bool = False
    cost_per_1k_tokens: float = 0.0  # For tracking costs
    
    # Hardware requirements (for local models)
    min_ram_gb: float = 0
    min_vram_gb: float = 0
    quantization: str = "Q4_K_M"


@dataclass
class HardwareProfile:
    """Detected hardware capabilities"""
    total_ram_gb: float = 0
    available_ram_gb: float = 0
    gpu_vram_gb: float = 0
    gpu_name: str = ""
    cpu_cores: int = 0
    has_gpu: bool = False


# ============================================================
# Provider Registry - All supported models
# ============================================================

MODEL_REGISTRY: Dict[str, ModelConfig] = {
    # --------------------------------------------------------
    # ANTHROPIC CLAUDE MODELS
    # --------------------------------------------------------
    "claude-opus-4": ModelConfig(
        name="Claude Opus 4",
        provider=ProviderType.ANTHROPIC,
        model_id="claude-opus-4-20250514",
        api_url="https://api.anthropic.com/v1/messages",
        context_window=200000,
        cost_per_1k_tokens=0.075,
        supports_tools=True,
    ),
    "claude-sonnet-4": ModelConfig(
        name="Claude Sonnet 4",
        provider=ProviderType.ANTHROPIC,
        model_id="claude-sonnet-4-20250514",
        api_url="https://api.anthropic.com/v1/messages",
        context_window=200000,
        cost_per_1k_tokens=0.015,
        supports_tools=True,
    ),
    "claude-haiku-3.5": ModelConfig(
        name="Claude 3.5 Haiku",
        provider=ProviderType.ANTHROPIC,
        model_id="claude-3-5-haiku-20241022",
        api_url="https://api.anthropic.com/v1/messages",
        context_window=200000,
        cost_per_1k_tokens=0.001,
        supports_tools=True,
    ),
    
    # --------------------------------------------------------
    # OPENAI GPT MODELS
    # --------------------------------------------------------
    "gpt-5": ModelConfig(
        name="GPT-5",
        provider=ProviderType.OPENAI,
        model_id="gpt-5",
        api_url="https://api.openai.com/v1/chat/completions",
        context_window=128000,
        cost_per_1k_tokens=0.03,
        supports_tools=True,
        supports_vision=True,
    ),
    "gpt-4o": ModelConfig(
        name="GPT-4o",
        provider=ProviderType.OPENAI,
        model_id="gpt-4o",
        api_url="https://api.openai.com/v1/chat/completions",
        context_window=128000,
        cost_per_1k_tokens=0.005,
        supports_tools=True,
        supports_vision=True,
    ),
    "gpt-4o-mini": ModelConfig(
        name="GPT-4o Mini",
        provider=ProviderType.OPENAI,
        model_id="gpt-4o-mini",
        api_url="https://api.openai.com/v1/chat/completions",
        context_window=128000,
        cost_per_1k_tokens=0.00015,
        supports_tools=True,
    ),
    
    # --------------------------------------------------------
    # GOOGLE GEMINI MODELS
    # --------------------------------------------------------
    "gemini-2.5-pro": ModelConfig(
        name="Gemini 2.5 Pro",
        provider=ProviderType.GOOGLE,
        model_id="gemini-2.5-pro",
        api_url="https://generativelanguage.googleapis.com/v1beta/models",
        context_window=1000000,
        cost_per_1k_tokens=0.00125,
        supports_tools=True,
        supports_vision=True,
    ),
    "gemini-2.5-flash": ModelConfig(
        name="Gemini 2.5 Flash",
        provider=ProviderType.GOOGLE,
        model_id="gemini-2.5-flash",
        api_url="https://generativelanguage.googleapis.com/v1beta/models",
        context_window=1000000,
        cost_per_1k_tokens=0.00015,
        supports_tools=True,
        supports_vision=True,
    ),
    
    # --------------------------------------------------------
    # DEEPSEEK MODELS
    # --------------------------------------------------------
    "deepseek-coder-v2": ModelConfig(
        name="DeepSeek-Coder V2",
        provider=ProviderType.DEEPSEEK,
        model_id="deepseek-coder",
        api_url="https://api.deepseek.com/v1/chat/completions",
        context_window=128000,
        cost_per_1k_tokens=0.001,
        supports_tools=True,
    ),
    "deepseek-v3": ModelConfig(
        name="DeepSeek V3",
        provider=ProviderType.DEEPSEEK,
        model_id="deepseek-chat",
        api_url="https://api.deepseek.com/v1/chat/completions",
        context_window=128000,
        cost_per_1k_tokens=0.001,
        supports_tools=True,
    ),
    
    # --------------------------------------------------------
    # LOCAL MODELS (Ollama)
    # --------------------------------------------------------
    "qwen2.5-coder-32b": ModelConfig(
        name="Qwen2.5-Coder 32B",
        provider=ProviderType.OLLAMA,
        model_id="qwen2.5-coder:32b-instruct-q4_K_M",
        min_ram_gb=20,
        min_vram_gb=12,
        context_window=32768,
        quantization="Q4_K_M",
    ),
    "qwen2.5-coder-14b": ModelConfig(
        name="Qwen2.5-Coder 14B",
        provider=ProviderType.OLLAMA,
        model_id="qwen2.5-coder:14b-instruct-q4_K_M",
        min_ram_gb=10,
        min_vram_gb=8,
        context_window=32768,
        quantization="Q4_K_M",
    ),
    "qwen2.5-coder-7b": ModelConfig(
        name="Qwen2.5-Coder 7B",
        provider=ProviderType.OLLAMA,
        model_id="qwen2.5-coder:7b-instruct-q4_K_M",
        min_ram_gb=6,
        min_vram_gb=5,
        context_window=32768,
        quantization="Q4_K_M",
    ),
    "deepseek-coder-16b": ModelConfig(
        name="DeepSeek-Coder 16B",
        provider=ProviderType.OLLAMA,
        model_id="deepseek-coder-v2:16b",
        min_ram_gb=12,
        min_vram_gb=10,
        context_window=128000,
        quantization="Q4_K_M",
    ),
    "qwen3-8b": ModelConfig(
        name="Qwen3 8B",
        provider=ProviderType.OLLAMA,
        model_id="qwen3:8b",
        min_ram_gb=6,
        min_vram_gb=5,
        context_window=32768,
        quantization="Q4_K_M",
    ),
    "llama3.1-8b": ModelConfig(
        name="Llama 3.1 8B",
        provider=ProviderType.OLLAMA,
        model_id="llama3.1:8b-instruct-q4_K_M",
        min_ram_gb=6,
        min_vram_gb=5,
        context_window=128000,
        quantization="Q4_K_M",
    ),
    
    # --------------------------------------------------------
    # SPECIALIZED SECURITY MODELS (Antares-style)
    # --------------------------------------------------------
    "antares-3b": ModelConfig(
        name="Antares 3B (Security)",
        provider=ProviderType.OLLAMA,
        model_id="antares-3b:latest",
        min_ram_gb=4,
        min_vram_gb=3,
        context_window=8192,
        quantization="Q4_K_M",
    ),
}


class LLMProvider:
    """Base class for LLM providers"""
    
    def __init__(self, config: ModelConfig):
        self.config = config
    
    def generate(self, system_prompt: str, user_prompt: str, 
                 max_tokens: Optional[int] = None) -> str:
        raise NotImplementedError


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        import urllib.request
        
        api_key = self.config.api_key or os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")
        
        payload = json.dumps({
            "model": self.config.model_id,
            "max_tokens": max_tokens or self.config.max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}]
        }).encode('utf-8')
        
        req = urllib.request.Request(
            self.config.api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01"
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data["content"][0]["text"]


class OpenAIProvider(LLMProvider):
    """OpenAI GPT API provider"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        import urllib.request
        
        api_key = self.config.api_key or os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not set")
        
        payload = json.dumps({
            "model": self.config.model_id,
            "max_tokens": max_tokens or self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }).encode('utf-8')
        
        req = urllib.request.Request(
            self.config.api_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            },
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data["choices"][0]["message"]["content"]


class OllamaProvider(LLMProvider):
    """Ollama local model provider"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        import urllib.request
        
        api_url = self.config.api_url or "http://localhost:11434/api/generate"
        
        payload = json.dumps({
            "model": self.config.model_id,
            "prompt": f"{system_prompt}\n\n{user_prompt}",
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": max_tokens or self.config.max_tokens
            }
        }).encode('utf-8')
        
        req = urllib.request.Request(
            api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data["response"]


class ProviderFactory:
    """Factory for creating LLM providers"""
    
    _providers = {
        ProviderType.ANTHROPIC: AnthropicProvider,
        ProviderType.OPENAI: OpenAIProvider,
        ProviderType.GOOGLE: OpenAIProvider,  # Gemini uses OpenAI-compatible API
        ProviderType.DEEPSEEK: OpenAIProvider,
        ProviderType.OLLAMA: OllamaProvider,
        ProviderType.VLLM: OllamaProvider,
        ProviderType.LM_STUDIO: OllamaProvider,
    }
    
    @classmethod
    def create(cls, model_name: str, api_key: Optional[str] = None,
               api_url: Optional[str] = None) -> LLMProvider:
        """Create a provider for the specified model"""
        if model_name not in MODEL_REGISTRY:
            raise ValueError(f"Unknown model: {model_name}. Available: {list(MODEL_REGISTRY.keys())}")
        
        config = MODEL_REGISTRY[model_name].copy()
        
        if api_key:
            config.api_key = api_key
        if api_url:
            config.api_url = api_url
        
        provider_class = cls._providers.get(config.provider)
        if not provider_class:
            raise ValueError(f"Unsupported provider: {config.provider}")
        
        return provider_class(config)


class ModelSelector:
    """Intelligent model selection based on hardware and requirements"""
    
    def __init__(self):
        self.hardware = self._detect_hardware()
    
    def _detect_hardware(self) -> HardwareProfile:
        """Detect system hardware capabilities"""
        import platform
        import subprocess
        
        profile = HardwareProfile()
        
        # Detect RAM
        try:
            if platform.system() == "Darwin":
                result = subprocess.run(["sysctl", "-n", "hw.memsize"], 
                                       capture_output=True, text=True)
                profile.total_ram_gb = int(result.stdout.strip()) / (1024**3)
            elif platform.system() == "Linux":
                with open("/proc/meminfo") as f:
                    for line in f:
                        if "MemTotal" in line:
                            profile.total_ram_gb = int(line.split()[1]) / (1024**2)
                            break
            elif platform.system() == "Windows":
                result = subprocess.run(["wmic", "memorychip", "get", "capacity"],
                                       capture_output=True, text=True)
                # Parse Windows output
                profile.total_ram_gb = 64  # Default fallback
        except Exception:
            profile.total_ram_gb = 16  # Conservative default
        
        # Detect GPU
        try:
            if platform.system() == "Darwin":
                # Apple Silicon
                result = subprocess.run(["system_profiler", "SPDisplaysDataType"],
                                       capture_output=True, text=True)
                if "Apple" in result.stdout:
                    profile.gpu_name = "Apple Silicon"
                    profile.has_gpu = True
                    # Estimate VRAM (unified memory)
                    profile.gpu_vram_gb = min(profile.total_ram_gb * 0.7, 16)
            else:
                # NVIDIA GPU
                result = subprocess.run(["nvidia-smi", "--query-gpu=name,memory.total",
                                        "--format=csv,noheader"],
                                       capture_output=True, text=True)
                if result.returncode == 0:
                    parts = result.stdout.strip().split(", ")
                    profile.gpu_name = parts[0]
                    profile.gpu_vram_gb = float(parts[1].replace(" MiB", "")) / 1024
                    profile.has_gpu = True
        except Exception:
            pass
        
        # Detect CPU cores
        try:
            import multiprocessing
            profile.cpu_cores = multiprocessing.cpu_count()
        except Exception:
            profile.cpu_cores = 8
        
        profile.available_ram_gb = profile.total_ram_gb * 0.8  # Leave 20% for OS
        
        return profile
    
    def get_recommended_models(self, 
                               prefer_local: bool = False,
                               prefer_frontier: bool = False,
                               max_cost_per_1k: float = 0.1) -> List[str]:
        """Get recommended models based on hardware and preferences"""
        recommendations = []
        
        for name, config in MODEL_REGISTRY.items():
            # Skip if hardware requirements not met
            if config.min_ram_gb > 0 and config.min_ram_gb > self.hardware.available_ram_gb:
                continue
            if config.min_vram_gb > 0 and config.min_vram_gb > self.hardware.gpu_vram_gb:
                continue
            
            # Filter by preference
            is_local = config.provider in [ProviderType.OLLAMA, ProviderType.VLLM, ProviderType.LM_STUDIO]
            is_frontier = not is_local
            
            if prefer_local and not is_local:
                continue
            if prefer_frontier and not is_frontier:
                continue
            
            # Filter by cost
            if config.cost_per_1k_tokens > max_cost_per_1k:
                continue
            
            recommendations.append(name)
        
        # Sort by quality (context window * 1/cost)
        recommendations.sort(
            key=lambda n: MODEL_REGISTRY[n].context_window * (1 / max(MODEL_REGISTRY[n].cost_per_1k_tokens, 0.00001)),
            reverse=True
        )
        
        return recommendations
    
    def get_best_model_for_task(self, task: str = "vulnerability_detection") -> str:
        """Get the best model for a specific task"""
        # For vulnerability detection, prefer code-specialized models
        if task == "vulnerability_detection":
            preferred = [
                "qwen2.5-coder-32b",  # Best local code model
                "deepseek-coder-v2",   # Best API code model
                "claude-sonnet-4",     # Best general model
                "gpt-4o",             # Alternative
            ]
        elif task == "patch_generation":
            preferred = [
                "qwen2.5-coder-32b",
                "claude-sonnet-4",
                "deepseek-coder-v2",
                "gpt-4o",
            ]
        elif task == "root_cause_analysis":
            preferred = [
                "claude-opus-4",      # Best reasoning
                "gpt-5",
                "qwen2.5-coder-32b",
                "claude-sonnet-4",
            ]
        else:
            preferred = ["claude-sonnet-4", "gpt-4o", "qwen2.5-coder-32b"]
        
        # Return first available
        for model in preferred:
            if model in MODEL_REGISTRY:
                config = MODEL_REGISTRY[model]
                if config.min_ram_gb <= self.hardware.available_ram_gb:
                    return model
        
        # Fallback to smallest available
        return "qwen2.5-coder-7b"


def print_hardware_info():
    """Print detected hardware information"""
    selector = ModelSelector()
    hw = selector.hardware
    
    print("\n" + "="*60)
    print("HARDWARE DETECTION")
    print("="*60)
    print(f"  CPU Cores:      {hw.cpu_cores}")
    print(f"  Total RAM:      {hw.total_ram_gb:.1f} GB")
    print(f"  Available RAM:  {hw.available_ram_gb:.1f} GB")
    print(f"  GPU:            {hw.gpu_name or 'None detected'}")
    print(f"  GPU VRAM:       {hw.gpu_vram_gb:.1f} GB")
    print()
    
    # Show recommended models
    local_models = selector.get_recommended_models(prefer_local=True)
    frontier_models = selector.get_recommended_models(prefer_frontier=True)
    
    print("RECOMMENDED LOCAL MODELS:")
    for model in local_models[:5]:
        config = MODEL_REGISTRY[model]
        print(f"  • {config.name} ({config.model_id})")
        print(f"    RAM: {config.min_ram_gb}GB, VRAM: {config.min_vram_gb}GB")
    
    print("\nRECOMMENDED FRONTIER MODELS:")
    for model in frontier_models[:5]:
        config = MODEL_REGISTRY[model]
        print(f"  • {config.name} (${config.cost_per_1k_tokens}/1K tokens)")
    
    print("="*60)


if __name__ == "__main__":
    print_hardware_info()
