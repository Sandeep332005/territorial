"""
ABHIMANYU X Platform - Enhanced Multi-Provider LLM System v2.0

Supports three provider categories:
1. LOCAL   - Ollama, vLLM, LM Studio (runs on your hardware)
2. API     - Claude, GPT, Gemini, DeepSeek (cloud-based)
3. CUSTOM  - Any OpenAI-compatible endpoint (self-hosted, proxied)

Features:
- Intelligent provider selection based on hardware
- Automatic fallback chain (Local → API → Custom)
- Cost tracking and optimization
- Custom endpoint configuration
- Provider health checks
- Model caching and pooling
"""

import os
import json
import time
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


# ============================================================
# Provider Categories
# ============================================================

class ProviderCategory(Enum):
    """Provider category classification"""
    LOCAL = "local"        # Runs on local hardware
    API = "api"           # Cloud API (paid/free tier)
    CUSTOM = "custom"     # User-configured endpoint


class ProviderType(Enum):
    """Specific provider types"""
    # LOCAL providers
    OLLAMA = "ollama"
    VLLM = "vllm"
    LM_STUDIO = "lm_studio"
    LLAMACPP = "llamacpp"
    
    # API providers
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    DEEPSEEK = "deepseek"
    MISTRAL = "mistral"
    COHERE = "cohere"
    TOGETHER = "together"
    GROQ = "groq"
    FIREWORKS = "fireworks"
    REPLICATE = "replicate"
    
    # CUSTOM providers
    CUSTOM_OPENAI = "custom_openai"      # OpenAI-compatible
    CUSTOM_API = "custom_api"            # Custom API format


# ============================================================
# Data Classes
# ============================================================

@dataclass
class ModelConfig:
    """Configuration for a specific model"""
    name: str
    provider: ProviderType
    category: ProviderCategory
    model_id: str
    
    # API settings
    api_url: Optional[str] = None
    api_key_env: Optional[str] = None  # Environment variable for API key
    api_key: Optional[str] = None
    
    # Model capabilities
    max_tokens: int = 4096
    temperature: float = 0.2
    context_window: int = 8192
    supports_vision: bool = False
    supports_tools: bool = False
    supports_streaming: bool = True
    
    # Cost tracking
    cost_per_1k_input: float = 0.0
    cost_per_1k_output: float = 0.0
    
    # Hardware requirements (for local models)
    min_ram_gb: float = 0
    min_vram_gb: float = 0
    quantization: str = "Q4_K_M"
    
    # Metadata
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    @property
    def cost_per_1k_tokens(self) -> float:
        """Average cost per 1K tokens"""
        return (self.cost_per_1k_input + self.cost_per_1k_output) / 2


@dataclass
class HardwareProfile:
    """Detected hardware capabilities"""
    total_ram_gb: float = 0
    available_ram_gb: float = 0
    gpu_vram_gb: float = 0
    gpu_name: str = ""
    cpu_cores: int = 0
    has_gpu: bool = False
    gpu_type: str = ""  # nvidia, amd, apple, none


@dataclass
class ProviderHealth:
    """Provider health status"""
    provider: ProviderType
    is_available: bool = False
    latency_ms: float = 0
    last_check: float = 0
    error_message: str = ""


# ============================================================
# Model Registry - All Supported Models
# ============================================================

MODEL_REGISTRY: Dict[str, ModelConfig] = {

    # ================================================================
    # LOCAL MODELS - Ollama
    # ================================================================
    
    # Qwen2.5 Coder series (Best for code)
    "qwen2.5-coder-32b": ModelConfig(
        name="Qwen2.5-Coder 32B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="qwen2.5-coder:32b-instruct-q4_K_M",
        min_ram_gb=20, min_vram_gb=12,
        context_window=32768,
        description="Best local code model",
        tags=["code", "security", "best-local"]
    ),
    "qwen2.5-coder-14b": ModelConfig(
        name="Qwen2.5-Coder 14B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="qwen2.5-coder:14b-instruct-q4_K_M",
        min_ram_gb=10, min_vram_gb=8,
        context_window=32768,
        description="Balanced code model",
        tags=["code", "balanced"]
    ),
    "qwen2.5-coder-7b": ModelConfig(
        name="Qwen2.5-Coder 7B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="qwen2.5-coder:7b-instruct-q4_K_M",
        min_ram_gb=6, min_vram_gb=5,
        context_window=32768,
        description="Fast code model",
        tags=["code", "fast", "recommended"]
    ),
    "qwen2.5-coder-3b": ModelConfig(
        name="Qwen2.5-Coder 3B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="qwen2.5-coder:3b-instruct-q4_K_M",
        min_ram_gb=3, min_vram_gb=2,
        context_window=32768,
        description="Lightweight code model",
        tags=["code", "lightweight"]
    ),
    
    # Qwen3 series
    "qwen3-32b": ModelConfig(
        name="Qwen3 32B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="qwen3:32b",
        min_ram_gb=20, min_vram_gb=12,
        context_window=32768,
        description="Best reasoning model",
        tags=["reasoning", "best-local"]
    ),
    "qwen3-14b": ModelConfig(
        name="Qwen3 14B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="qwen3:14b",
        min_ram_gb=10, min_vram_gb=8,
        context_window=32768,
        description="Good reasoning model",
        tags=["reasoning", "balanced"]
    ),
    "qwen3-8b": ModelConfig(
        name="Qwen3 8B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="qwen3:8b",
        min_ram_gb=6, min_vram_gb=5,
        context_window=32768,
        description="Fast reasoning model",
        tags=["reasoning", "fast"]
    ),
    "qwen3-4b": ModelConfig(
        name="Qwen3 4B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="qwen3:4b",
        min_ram_gb=4, min_vram_gb=3,
        context_window=32768,
        description="Lightweight reasoning",
        tags=["reasoning", "lightweight"]
    ),
    
    # DeepSeek Coder (Local)
    "deepseek-coder-16b": ModelConfig(
        name="DeepSeek-Coder 16B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="deepseek-coder-v2:16b",
        min_ram_gb=12, min_vram_gb=10,
        context_window=128000,
        description="Deep code analysis",
        tags=["code", "deep-analysis"]
    ),
    
    # Llama series
    "llama3.1-8b": ModelConfig(
        name="Llama 3.1 8B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="llama3.1:8b-instruct-q4_K_M",
        min_ram_gb=6, min_vram_gb=5,
        context_window=128000,
        description="General purpose",
        tags=["general", "fast"]
    ),
    "llama3.1-70b": ModelConfig(
        name="Llama 3.1 70B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="llama3.1:70b-instruct-q4_K_M",
        min_ram_gb=42, min_vram_gb=40,
        context_window=128000,
        description="Best open model (needs 64GB+ RAM)",
        tags=["general", "best-open"]
    ),
    
    # Mistral (Local)
    "mistral-7b": ModelConfig(
        name="Mistral 7B",
        provider=ProviderType.OLLAMA,
        category=ProviderCategory.LOCAL,
        model_id="mistral:7b-instruct-q4_K_M",
        min_ram_gb=6, min_vram_gb=5,
        context_window=32768,
        description="Fast instruction following",
        tags=["general", "fast"]
    ),

    # ================================================================
    # API MODELS - Anthropic Claude
    # ================================================================
    
    "claude-opus-4": ModelConfig(
        name="Claude Opus 4",
        provider=ProviderType.ANTHROPIC,
        category=ProviderCategory.API,
        model_id="claude-opus-4-20250514",
        api_url="https://api.anthropic.com/v1/messages",
        api_key_env="ANTHROPIC_API_KEY",
        context_window=200000, max_tokens=8192,
        cost_per_1k_input=0.015, cost_per_1k_output=0.075,
        supports_tools=True, supports_vision=True,
        description="Best reasoning and analysis",
        tags=["best", "reasoning", "expensive"]
    ),
    "claude-sonnet-4": ModelConfig(
        name="Claude Sonnet 4",
        provider=ProviderType.ANTHROPIC,
        category=ProviderCategory.API,
        model_id="claude-sonnet-4-20250514",
        api_url="https://api.anthropic.com/v1/messages",
        api_key_env="ANTHROPIC_API_KEY",
        context_window=200000, max_tokens=8192,
        cost_per_1k_input=0.003, cost_per_1k_output=0.015,
        supports_tools=True, supports_vision=True,
        description="Best balanced API model",
        tags=["balanced", "recommended", "code"]
    ),
    "claude-haiku-3.5": ModelConfig(
        name="Claude 3.5 Haiku",
        provider=ProviderType.ANTHROPIC,
        category=ProviderCategory.API,
        model_id="claude-3-5-haiku-20241022",
        api_url="https://api.anthropic.com/v1/messages",
        api_key_env="ANTHROPIC_API_KEY",
        context_window=200000, max_tokens=8192,
        cost_per_1k_input=0.0008, cost_per_1k_output=0.004,
        supports_tools=True,
        description="Fast and cheap",
        tags=["fast", "cheap"]
    ),
    
    # ================================================================
    # API MODELS - OpenAI GPT
    # ================================================================
    
    "gpt-4o": ModelConfig(
        name="GPT-4o",
        provider=ProviderType.OPENAI,
        category=ProviderCategory.API,
        model_id="gpt-4o",
        api_url="https://api.openai.com/v1/chat/completions",
        api_key_env="OPENAI_API_KEY",
        context_window=128000, max_tokens=4096,
        cost_per_1k_input=0.0025, cost_per_1k_output=0.01,
        supports_tools=True, supports_vision=True,
        description="Best multimodal model",
        tags=["multimodal", "code"]
    ),
    "gpt-4o-mini": ModelConfig(
        name="GPT-4o Mini",
        provider=ProviderType.OPENAI,
        category=ProviderCategory.API,
        model_id="gpt-4o-mini",
        api_url="https://api.openai.com/v1/chat/completions",
        api_key_env="OPENAI_API_KEY",
        context_window=128000, max_tokens=4096,
        cost_per_1k_input=0.00015, cost_per_1k_output=0.0006,
        supports_tools=True,
        description="Fast and cheap",
        tags=["fast", "cheap"]
    ),
    "gpt-4-turbo": ModelConfig(
        name="GPT-4 Turbo",
        provider=ProviderType.OPENAI,
        category=ProviderCategory.API,
        model_id="gpt-4-turbo",
        api_url="https://api.openai.com/v1/chat/completions",
        api_key_env="OPENAI_API_KEY",
        context_window=128000, max_tokens=4096,
        cost_per_1k_input=0.01, cost_per_1k_output=0.03,
        supports_tools=True, supports_vision=True,
        description="Previous gen, still powerful",
        tags=["reasoning"]
    ),
    "o1-preview": ModelConfig(
        name="o1 Preview",
        provider=ProviderType.OPENAI,
        category=ProviderCategory.API,
        model_id="o1-preview",
        api_url="https://api.openai.com/v1/chat/completions",
        api_key_env="OPENAI_API_KEY",
        context_window=128000, max_tokens=32768,
        cost_per_1k_input=0.015, cost_per_1k_output=0.06,
        supports_tools=False,
        description="Best reasoning model",
        tags=["reasoning", "best", "expensive"]
    ),
    
    # ================================================================
    # API MODELS - Google Gemini
    # ================================================================
    
    "gemini-2.5-pro": ModelConfig(
        name="Gemini 2.5 Pro",
        provider=ProviderType.GOOGLE,
        category=ProviderCategory.API,
        model_id="gemini-2.5-pro",
        api_url="https://generativelanguage.googleapis.com/v1beta/models",
        api_key_env="GEMINI_API_KEY",
        context_window=1000000, max_tokens=8192,
        cost_per_1k_input=0.00125, cost_per_1k_output=0.005,
        supports_tools=True, supports_vision=True,
        description="Largest context window",
        tags=["multimodal", "large-context"]
    ),
    "gemini-2.5-flash": ModelConfig(
        name="Gemini 2.5 Flash",
        provider=ProviderType.GOOGLE,
        category=ProviderCategory.API,
        model_id="gemini-2.5-flash",
        api_url="https://generativelanguage.googleapis.com/v1beta/models",
        api_key_env="GEMINI_API_KEY",
        context_window=1000000, max_tokens=8192,
        cost_per_1k_input=0.000075, cost_per_1k_output=0.0003,
        supports_tools=True, supports_vision=True,
        description="Fast and cheap with huge context",
        tags=["fast", "cheap", "large-context"]
    ),
    "gemini-1.5-pro": ModelConfig(
        name="Gemini 1.5 Pro",
        provider=ProviderType.GOOGLE,
        category=ProviderCategory.API,
        model_id="gemini-1.5-pro",
        api_url="https://generativelanguage.googleapis.com/v1beta/models",
        api_key_env="GEMINI_API_KEY",
        context_window=2000000, max_tokens=8192,
        cost_per_1k_input=0.00125, cost_per_1k_output=0.005,
        supports_tools=True, supports_vision=True,
        description="2M context window",
        tags=["large-context"]
    ),
    
    # ================================================================
    # API MODELS - DeepSeek
    # ================================================================
    
    "deepseek-v3": ModelConfig(
        name="DeepSeek V3",
        provider=ProviderType.DEEPSEEK,
        category=ProviderCategory.API,
        model_id="deepseek-chat",
        api_url="https://api.deepseek.com/v1/chat/completions",
        api_key_env="DEEPSEEK_API_KEY",
        context_window=128000, max_tokens=4096,
        cost_per_1k_input=0.00014, cost_per_1k_output=0.00028,
        supports_tools=True,
        description="Best value code model",
        tags=["code", "cheap", "recommended"]
    ),
    "deepseek-r1": ModelConfig(
        name="DeepSeek R1",
        provider=ProviderType.DEEPSEEK,
        category=ProviderCategory.API,
        model_id="deepseek-reasoner",
        api_url="https://api.deepseek.com/v1/chat/completions",
        api_key_env="DEEPSEEK_API_KEY",
        context_window=128000, max_tokens=4096,
        cost_per_1k_input=0.00055, cost_per_1k_output=0.00219,
        supports_tools=False,
        description="Reasoning model",
        tags=["reasoning", "cheap"]
    ),
    
    # ================================================================
    # API MODELS - Mistral
    # ================================================================
    
    "mistral-large": ModelConfig(
        name="Mistral Large",
        provider=ProviderType.MISTRAL,
        category=ProviderCategory.API,
        model_id="mistral-large-latest",
        api_url="https://api.mistral.ai/v1/chat/completions",
        api_key_env="MISTRAL_API_KEY",
        context_window=128000, max_tokens=4096,
        cost_per_1k_input=0.002, cost_per_1k_output=0.006,
        supports_tools=True,
        description="Best Mistral model",
        tags=["code", "reasoning"]
    ),
    "mistral-small": ModelConfig(
        name="Mistral Small",
        provider=ProviderType.MISTRAL,
        category=ProviderCategory.API,
        model_id="mistral-small-latest",
        api_url="https://api.mistral.ai/v1/chat/completions",
        api_key_env="MISTRAL_API_KEY",
        context_window=32000, max_tokens=4096,
        cost_per_1k_input=0.001, cost_per_1k_output=0.003,
        supports_tools=True,
        description="Fast Mistral model",
        tags=["fast", "cheap"]
    ),
    
    # ================================================================
    # API MODELS - Groq (Fast inference)
    # ================================================================
    
    "groq-llama-70b": ModelConfig(
        name="Groq Llama 3.1 70B",
        provider=ProviderType.GROQ,
        category=ProviderCategory.API,
        model_id="llama-3.1-70b-versatile",
        api_url="https://api.groq.com/openai/v1/chat/completions",
        api_key_env="GROQ_API_KEY",
        context_window=128000, max_tokens=4096,
        cost_per_1k_input=0.00059, cost_per_1k_output=0.00079,
        supports_tools=True,
        description="Fastest inference (free tier)",
        tags=["fast", "free-tier"]
    ),
    "groq-llama-8b": ModelConfig(
        name="Groq Llama 3.1 8B",
        provider=ProviderType.GROQ,
        category=ProviderCategory.API,
        model_id="llama-3.1-8b-instant",
        api_url="https://api.groq.com/openai/v1/chat/completions",
        api_key_env="GROQ_API_KEY",
        context_window=128000, max_tokens=4096,
        cost_per_1k_input=0.00005, cost_per_1k_output=0.00008,
        supports_tools=True,
        description="Ultra fast, free tier",
        tags=["fast", "free-tier", "recommended"]
    ),
    
    # ================================================================
    # API MODELS - Together AI
    # ================================================================
    
    "together-qwen-72b": ModelConfig(
        name="Together Qwen 2.5 72B",
        provider=ProviderType.TOGETHER,
        category=ProviderCategory.API,
        model_id="Qwen/Qwen2.5-72B-Instruct-Turbo",
        api_url="https://api.together.xyz/v1/chat/completions",
        api_key_env="TOGETHER_API_KEY",
        context_window=32768, max_tokens=4096,
        cost_per_1k_input=0.0009, cost_per_1k_output=0.0009,
        supports_tools=False,
        description="Cloud 72B model",
        tags=["code", "large"]
    ),
    
    # ================================================================
    # CUSTOM MODELS - User-configured endpoints
    # ================================================================
    
    "custom-openai": ModelConfig(
        name="Custom OpenAI-Compatible",
        provider=ProviderType.CUSTOM_OPENAI,
        category=ProviderCategory.CUSTOM,
        model_id="custom-model",
        api_url="http://localhost:8080/v1/chat/completions",
        context_window=8192, max_tokens=4096,
        description="Any OpenAI-compatible API",
        tags=["custom", "self-hosted"]
    ),
    "custom-api": ModelConfig(
        name="Custom API Endpoint",
        provider=ProviderType.CUSTOM_API,
        category=ProviderCategory.CUSTOM,
        model_id="custom",
        api_url="http://localhost:8080/api/generate",
        context_window=8192, max_tokens=4096,
        description="Custom API format",
        tags=["custom"]
    ),
}


# ============================================================
# Provider Classes
# ============================================================

class LLMProvider:
    """Base class for LLM providers"""
    
    def __init__(self, config: ModelConfig):
        self.config = config
        self._request_count = 0
        self._total_tokens = 0
        self._total_cost = 0.0
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        raise NotImplementedError
    
    def health_check(self) -> ProviderHealth:
        """Check if provider is available"""
        raise NotImplementedError
    
    def get_usage(self) -> Dict[str, Any]:
        """Get usage statistics"""
        return {
            "requests": self._request_count,
            "total_tokens": self._total_tokens,
            "total_cost": self._total_cost
        }
    
    def _track_usage(self, input_tokens: int, output_tokens: int):
        """Track token usage and cost"""
        self._request_count += 1
        self._total_tokens += input_tokens + output_tokens
        
        cost = (input_tokens * self.config.cost_per_1k_input / 1000 +
                output_tokens * self.config.cost_per_1k_output / 1000)
        self._total_cost += cost


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        api_key = self.config.api_key or os.getenv(self.config.api_key_env or "ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(f"API key not set. Set {self.config.api_key_env} environment variable.")
        
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
            
            # Track usage
            if "usage" in data:
                self._track_usage(
                    data["usage"].get("input_tokens", 0),
                    data["usage"].get("output_tokens", 0)
                )
            
            return data["content"][0]["text"]
    
    def health_check(self) -> ProviderHealth:
        api_key = self.config.api_key or os.getenv(self.config.api_key_env or "ANTHROPIC_API_KEY")
        return ProviderHealth(
            provider=self.config.provider,
            is_available=bool(api_key),
            error_message="" if api_key else "API key not set"
        )


class OpenAIProvider(LLMProvider):
    """OpenAI-compatible API provider (works with many services)"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        # Get API key from config or environment
        api_key_env = self.config.api_key_env or "OPENAI_API_KEY"
        api_key = self.config.api_key or os.getenv(api_key_env)
        
        # Some providers don't need API key (e.g., local endpoints)
        if not api_key and "localhost" not in (self.config.api_url or ""):
            raise ValueError(f"API key not set. Set {api_key_env} environment variable.")
        
        headers = {
            "Content-Type": "application/json",
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
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
            headers=headers,
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            
            # Track usage
            if "usage" in data:
                self._track_usage(
                    data["usage"].get("prompt_tokens", 0),
                    data["usage"].get("completion_tokens", 0)
                )
            
            return data["choices"][0]["message"]["content"]
    
    def health_check(self) -> ProviderHealth:
        api_key_env = self.config.api_key_env or "OPENAI_API_KEY"
        api_key = self.config.api_key or os.getenv(api_key_env)
        is_local = "localhost" in (self.config.api_url or "")
        
        return ProviderHealth(
            provider=self.config.provider,
            is_available=bool(api_key or is_local),
            error_message="" if (api_key or is_local) else f"{api_key_env} not set"
        )


class GoogleProvider(LLMProvider):
    """Google Gemini API provider"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        api_key = self.config.api_key or os.getenv(self.config.api_key_env or "GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not set")
        
        # Use OpenAI-compatible endpoint
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.model_id}:generateContent?key={api_key}"
        
        payload = json.dumps({
            "contents": [{"parts": [{"text": f"{system_prompt}\n\n{user_prompt}"}]}],
            "generationConfig": {
                "maxOutputTokens": max_tokens or self.config.max_tokens,
                "temperature": self.config.temperature
            }
        }).encode('utf-8')
        
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data["candidates"][0]["content"]["parts"][0]["text"]
    
    def health_check(self) -> ProviderHealth:
        api_key = self.config.api_key or os.getenv(self.config.api_key_env or "GEMINI_API_KEY")
        return ProviderHealth(
            provider=self.config.provider,
            is_available=bool(api_key),
            error_message="" if api_key else "GEMINI_API_KEY not set"
        )


class OllamaProvider(LLMProvider):
    """Ollama local model provider"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
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
            
            # Track usage
            if "eval_count" in data:
                self._track_usage(0, data["eval_count"])
            
            return data["response"]
    
    def health_check(self) -> ProviderHealth:
        api_url = self.config.api_url or "http://localhost:11434"
        try:
            req = urllib.request.Request(f"{api_url}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                return ProviderHealth(
                    provider=self.config.provider,
                    is_available=True
                )
        except Exception as e:
            return ProviderHealth(
                provider=self.config.provider,
                is_available=False,
                error_message=str(e)
            )


class VLLMProvider(LLMProvider):
    """vLLM server provider (OpenAI-compatible)"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        api_url = self.config.api_url or "http://localhost:8000/v1/chat/completions"
        
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
            api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data["choices"][0]["message"]["content"]
    
    def health_check(self) -> ProviderHealth:
        api_url = self.config.api_url or "http://localhost:8000"
        try:
            req = urllib.request.Request(f"{api_url}/v1/models")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return ProviderHealth(
                    provider=self.config.provider,
                    is_available=True
                )
        except Exception as e:
            return ProviderHealth(
                provider=self.config.provider,
                is_available=False,
                error_message=str(e)
            )


class CustomOpenAIProvider(LLMProvider):
    """Custom OpenAI-compatible endpoint"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        if not self.config.api_url:
            raise ValueError("Custom API URL not configured")
        
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        
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
            headers=headers,
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            
            # Handle different response formats
            if "choices" in data:
                return data["choices"][0]["message"]["content"]
            elif "response" in data:
                return data["response"]
            elif "generated_text" in data:
                return data["generated_text"]
            else:
                return str(data)
    
    def health_check(self) -> ProviderHealth:
        if not self.config.api_url:
            return ProviderHealth(
                provider=self.config.provider,
                is_available=False,
                error_message="API URL not configured"
            )
        
        try:
            # Try to list models
            models_url = self.config.api_url.replace("/chat/completions", "/models")
            req = urllib.request.Request(models_url)
            with urllib.request.urlopen(req, timeout=5) as resp:
                return ProviderHealth(
                    provider=self.config.provider,
                    is_available=True
                )
        except:
            # Endpoint might exist but not support /models
            return ProviderHealth(
                provider=self.config.provider,
                is_available=True,
                error_message="Could not verify (endpoint may still work)"
            )


class CustomAPIProvider(LLMProvider):
    """Custom API with user-defined format"""
    
    def generate(self, system_prompt: str, user_prompt: str,
                 max_tokens: Optional[int] = None) -> str:
        if not self.config.api_url:
            raise ValueError("Custom API URL not configured")
        
        # Generic payload - user should customize this
        payload = json.dumps({
            "prompt": f"{system_prompt}\n\n{user_prompt}",
            "max_tokens": max_tokens or self.config.max_tokens
        }).encode('utf-8')
        
        req = urllib.request.Request(
            self.config.api_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return str(data)
    
    def health_check(self) -> ProviderHealth:
        return ProviderHealth(
            provider=self.config.provider,
            is_available=bool(self.config.api_url),
            error_message="" if self.config.api_url else "API URL not configured"
        )


# ============================================================
# Provider Factory
# ============================================================

class ProviderFactory:
    """Factory for creating LLM providers"""
    
    _providers = {
        # Local providers
        ProviderType.OLLAMA: OllamaProvider,
        ProviderType.VLLM: VLLMProvider,
        ProviderType.LM_STUDIO: OllamaProvider,  # Uses Ollama-compatible API
        ProviderType.LLAMACPP: OllamaProvider,   # Uses Ollama-compatible API
        
        # API providers
        ProviderType.ANTHROPIC: AnthropicProvider,
        ProviderType.OPENAI: OpenAIProvider,
        ProviderType.GOOGLE: GoogleProvider,
        ProviderType.DEEPSEEK: OpenAIProvider,
        ProviderType.MISTRAL: OpenAIProvider,
        ProviderType.COHERE: OpenAIProvider,
        ProviderType.TOGETHER: OpenAIProvider,
        ProviderType.GROQ: OpenAIProvider,
        ProviderType.FIREWORKS: OpenAIProvider,
        ProviderType.REPLICATE: OpenAIProvider,
        
        # Custom providers
        ProviderType.CUSTOM_OPENAI: CustomOpenAIProvider,
        ProviderType.CUSTOM_API: CustomAPIProvider,
    }
    
    @classmethod
    def create(cls, model_name: str, api_key: Optional[str] = None,
               api_url: Optional[str] = None, **kwargs) -> LLMProvider:
        """Create a provider for the specified model"""
        
        # Check if it's a registered model
        if model_name in MODEL_REGISTRY:
            config = ModelConfig(**MODEL_REGISTRY[model_name].__dict__)
        else:
            # Try to auto-detect provider type
            config = cls._auto_detect_config(model_name, api_key, api_url)
        
        # Override with provided values
        if api_key:
            config.api_key = api_key
        if api_url:
            config.api_url = api_url
        
        # Apply any additional kwargs
        for key, value in kwargs.items():
            if hasattr(config, key):
                setattr(config, key, value)
        
        provider_class = cls._providers.get(config.provider)
        if not provider_class:
            raise ValueError(f"Unsupported provider: {config.provider}")
        
        return provider_class(config)
    
    @classmethod
    def _auto_detect_config(cls, model_name: str, api_key: Optional[str] = None,
                           api_url: Optional[str] = None) -> ModelConfig:
        """Auto-detect model configuration from name and URL"""
        
        # If URL provided, assume custom OpenAI-compatible
        if api_url:
            return ModelConfig(
                name=model_name,
                provider=ProviderType.CUSTOM_OPENAI,
                category=ProviderCategory.CUSTOM,
                model_id=model_name,
                api_url=api_url,
                api_key=api_key
            )
        
        # Auto-detect by model name patterns
        model_lower = model_name.lower()
        
        if "claude" in model_lower:
            return ModelConfig(
                name=model_name,
                provider=ProviderType.ANTHROPIC,
                category=ProviderCategory.API,
                model_id=model_name,
                api_key_env="ANTHROPIC_API_KEY"
            )
        elif "gpt" in model_lower or "o1" in model_lower:
            return ModelConfig(
                name=model_name,
                provider=ProviderType.OPENAI,
                category=ProviderCategory.API,
                model_id=model_name,
                api_key_env="OPENAI_API_KEY"
            )
        elif "gemini" in model_lower:
            return ModelConfig(
                name=model_name,
                provider=ProviderType.GOOGLE,
                category=ProviderCategory.API,
                model_id=model_name,
                api_key_env="GEMINI_API_KEY"
            )
        elif "deepseek" in model_lower:
            return ModelConfig(
                name=model_name,
                provider=ProviderType.DEEPSEEK,
                category=ProviderCategory.API,
                model_id=model_name,
                api_key_env="DEEPSEEK_API_KEY"
            )
        else:
            # Default to Ollama (local)
            return ModelConfig(
                name=model_name,
                provider=ProviderType.OLLAMA,
                category=ProviderCategory.LOCAL,
                model_id=model_name
            )


# ============================================================
# Intelligent Model Selector
# ============================================================

class ModelSelector:
    """Intelligent model selection with fallback chain"""
    
    def __init__(self):
        self.hardware = self._detect_hardware()
        self._health_cache: Dict[ProviderType, ProviderHealth] = {}
    
    def _detect_hardware(self) -> HardwareProfile:
        """Detect system hardware capabilities"""
        import platform
        import subprocess
        import multiprocessing
        
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
                result = subprocess.run(
                    ["wmic", "memorychip", "get", "capacity"],
                    capture_output=True, text=True
                )
                total = sum(int(l) for l in result.stdout.strip().split("\n")[1:] if l.strip().isdigit())
                profile.total_ram_gb = total / (1024**3) if total > 0 else 16
        except Exception:
            profile.total_ram_gb = 16
        
        # Detect GPU
        try:
            if platform.system() == "Darwin":
                result = subprocess.run(["system_profiler", "SPDisplaysDataType"],
                                       capture_output=True, text=True)
                if "Apple" in result.stdout:
                    profile.gpu_name = "Apple Silicon"
                    profile.gpu_type = "apple"
                    profile.has_gpu = True
                    profile.gpu_vram_gb = min(profile.total_ram_gb * 0.7, 16)
            else:
                result = subprocess.run(
                    ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    parts = result.stdout.strip().split(", ")
                    profile.gpu_name = parts[0]
                    profile.gpu_vram_gb = float(parts[1].replace(" MiB", "")) / 1024
                    profile.has_gpu = True
                    profile.gpu_type = "nvidia"
        except Exception:
            pass
        
        profile.cpu_cores = multiprocessing.cpu_count()
        profile.available_ram_gb = profile.total_ram_gb * 0.8
        
        return profile
    
    def get_available_providers(self) -> Dict[ProviderCategory, List[str]]:
        """Get available models grouped by category"""
        result = {
            ProviderCategory.LOCAL: [],
            ProviderCategory.API: [],
            ProviderCategory.CUSTOM: []
        }
        
        for name, config in MODEL_REGISTRY.items():
            # Check hardware requirements
            if config.min_ram_gb > 0 and config.min_ram_gb > self.hardware.available_ram_gb:
                continue
            if config.min_vram_gb > 0 and config.min_vram_gb > self.hardware.gpu_vram_gb:
                continue
            
            # Check if API key is available
            if config.category == ProviderCategory.API and config.api_key_env:
                if not os.getenv(config.api_key_env):
                    continue
            
            result[config.category].append(name)
        
        return result
    
    def select_best(self, 
                    prefer_local: bool = True,
                    prefer_cheap: bool = False,
                    require_tools: bool = False,
                    task: str = "vulnerability_detection") -> str:
        """Select the best model based on requirements"""
        
        available = self.get_available_providers()
        
        # Build preference list
        candidates = []
        
        if prefer_local:
            candidates.extend(available.get(ProviderCategory.LOCAL, []))
        
        candidates.extend(available.get(ProviderCategory.API, []))
        candidates.extend(available.get(ProviderCategory.CUSTOM, []))
        
        # If no preference, add all
        if not candidates:
            candidates = list(MODEL_REGISTRY.keys())
        
        # Filter by requirements
        if require_tools:
            candidates = [c for c in candidates if MODEL_REGISTRY[c].supports_tools]
        
        # Sort by quality/cost
        def score_model(name: str) -> float:
            config = MODEL_REGISTRY[name]
            score = 0
            
            # Prefer code-specialized for security tasks
            if task in ["vulnerability_detection", "patch_generation", "code_analysis"]:
                if "code" in config.tags:
                    score += 100
            
            # Prefer recommended models
            if "recommended" in config.tags:
                score += 50
            
            # Prefer local if requested
            if prefer_local and config.category == ProviderCategory.LOCAL:
                score += 30
            
            # Prefer cheap if requested
            if prefer_cheap:
                score -= config.cost_per_1k_tokens * 1000
            
            # Prefer larger context
            score += min(config.context_window / 10000, 50)
            
            return score
        
        candidates.sort(key=score_model, reverse=True)
        
        return candidates[0] if candidates else "qwen2.5-coder-7b"
    
    def get_fallback_chain(self, primary_model: str) -> List[str]:
        """Get a chain of fallback models"""
        chain = [primary_model]
        
        available = self.get_available_providers()
        all_models = available.get(ProviderCategory.LOCAL, []) + \
                    available.get(ProviderCategory.API, []) + \
                    available.get(ProviderCategory.CUSTOM, [])
        
        # Add alternatives from same category
        primary_config = MODEL_REGISTRY.get(primary_model)
        if primary_config:
            for name in all_models:
                if name != primary_model:
                    config = MODEL_REGISTRY[name]
                    if config.category == primary_config.category:
                        chain.append(name)
        
        # Add from other categories
        for name in all_models:
            if name not in chain:
                chain.append(name)
        
        return chain[:5]  # Limit to 5 fallbacks


# ============================================================
# Provider Manager (combines everything)
# ============================================================

class ProviderManager:
    """Manages multiple providers with automatic fallback"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.selector = ModelSelector()
        self._providers: Dict[str, LLMProvider] = {}
        self._custom_models: Dict[str, ModelConfig] = {}
        
        # Load custom configuration if provided
        if config_path and os.path.exists(config_path):
            self._load_config(config_path)
    
    def _load_config(self, config_path: str):
        """Load custom configuration from file"""
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Load custom endpoints
        if "custom_endpoints" in config:
            for endpoint in config["custom_endpoints"]:
                name = endpoint.get("name", "custom")
                self.register_custom_model(
                    name=name,
                    model_id=endpoint.get("model_id", name),
                    api_url=endpoint["api_url"],
                    api_key=endpoint.get("api_key"),
                    **endpoint.get("options", {})
                )
    
    def register_custom_model(self, name: str, model_id: str, api_url: str,
                             api_key: Optional[str] = None, **kwargs):
        """Register a custom model endpoint"""
        config = ModelConfig(
            name=name,
            provider=ProviderType.CUSTOM_OPENAI,
            category=ProviderCategory.CUSTOM,
            model_id=model_id,
            api_url=api_url,
            api_key=api_key,
            **kwargs
        )
        self._custom_models[name] = config
        MODEL_REGISTRY[name] = config
    
    def get_provider(self, model_name: str) -> LLMProvider:
        """Get or create a provider"""
        if model_name not in self._providers:
            # Check custom models first
            if model_name in self._custom_models:
                config = self._custom_models[model_name]
                provider_class = ProviderFactory._providers.get(config.provider)
                if provider_class:
                    self._providers[model_name] = provider_class(config)
            else:
                self._providers[model_name] = ProviderFactory.create(model_name)
        
        return self._providers[model_name]
    
    def generate_with_fallback(self, system_prompt: str, user_prompt: str,
                              primary_model: str, **kwargs) -> Tuple[str, str]:
        """Generate with automatic fallback to other providers"""
        chain = self.selector.get_fallback_chain(primary_model)
        
        last_error = None
        for model_name in chain:
            try:
                provider = self.get_provider(model_name)
                result = provider.generate(system_prompt, user_prompt, **kwargs)
                return result, model_name
            except Exception as e:
                last_error = e
                continue
        
        raise RuntimeError(f"All providers failed. Last error: {last_error}")
    
    def check_all_providers(self) -> Dict[str, ProviderHealth]:
        """Check health of all configured providers"""
        results = {}
        
        for name in MODEL_REGISTRY:
            try:
                provider = self.get_provider(name)
                results[name] = provider.health_check()
            except Exception as e:
                results[name] = ProviderHealth(
                    provider=MODEL_REGISTRY[name].provider,
                    is_available=False,
                    error_message=str(e)
                )
        
        return results
    
    def get_usage_summary(self) -> Dict[str, Any]:
        """Get usage summary across all providers"""
        total_requests = 0
        total_tokens = 0
        total_cost = 0.0
        
        for name, provider in self._providers.items():
            usage = provider.get_usage()
            total_requests += usage["requests"]
            total_tokens += usage["total_tokens"]
            total_cost += usage["total_cost"]
        
        return {
            "total_requests": total_requests,
            "total_tokens": total_tokens,
            "total_cost": total_cost,
            "providers_used": list(self._providers.keys())
        }


# ============================================================
# CLI Interface
# ============================================================

def print_provider_status():
    """Print status of all providers"""
    selector = ModelSelector()
    hw = selector.hardware
    
    print("\n" + "="*70)
    print("ABHIMANYU X - LLM Provider Status")
    print("="*70)
    
    print("\nHardware:")
    print(f"  RAM: {hw.total_ram_gb:.1f} GB ({hw.available_ram_gb:.1f} GB available)")
    print(f"  GPU: {hw.gpu_name or 'None detected'} ({hw.gpu_vram_gb:.1f} GB VRAM)")
    print(f"  CPU: {hw.cpu_cores} cores")
    
    # Group by category
    for category in ProviderCategory:
        models = []
        for name, config in MODEL_REGISTRY.items():
            if config.category == category:
                # Check if available
                if config.min_ram_gb > 0 and config.min_ram_gb > hw.available_ram_gb:
                    continue
                if config.min_vram_gb > 0 and config.min_vram_gb > hw.gpu_vram_gb:
                    continue
                if config.api_key_env and not os.getenv(config.api_key_env):
                    continue
                models.append(name)
        
        print(f"\n{category.value.upper()} Models ({len(models)} available):")
        for name in models[:10]:  # Show top 10
            config = MODEL_REGISTRY[name]
            tags = ", ".join(config.tags[:3])
            print(f"  {name:30} [{config.provider.value:10}] {tags}")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    print_provider_status()
