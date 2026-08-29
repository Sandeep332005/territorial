# ============================================================
# ABHIMANYU X Platform - PowerShell Deployment Script
# For: AI15-DT (i9-13900 + 64GB RAM + RTX 4060 12GB)
# ============================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "ABHIMANYU X Platform - Windows PowerShell Deployment" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Check for Python
Write-Host "[1/8] Checking Python..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Python not found. Install Python 3.11+ from:" -ForegroundColor Red
    Write-Host "         https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Create virtual environment
Write-Host "[2/8] Creating virtual environment..." -ForegroundColor Yellow
if (-not (Test-Path "venv")) {
    python -m venv venv
    Write-Host "  Created venv" -ForegroundColor Green
} else {
    Write-Host "  venv already exists" -ForegroundColor Green
}
& .\venv\Scripts\Activate.ps1

# Install dependencies
Write-Host "[3/8] Installing dependencies..." -ForegroundColor Yellow
pip install --upgrade pip -q
pip install -r requirements.txt -q
Write-Host "  Dependencies installed" -ForegroundColor Green

# Check for Ollama
Write-Host "[4/8] Checking Ollama..." -ForegroundColor Yellow
try {
    $ollamaVersion = ollama --version 2>&1
    Write-Host "  Found: $ollamaVersion" -ForegroundColor Green
} catch {
    Write-Host "  [WARNING] Ollama not found" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Install Ollama from: https://ollama.com/download/windows" -ForegroundColor Cyan
    Write-Host "  Then run:" -ForegroundColor Cyan
    Write-Host "    ollama pull qwen2.5-coder:7b-instruct-q4_K_M" -ForegroundColor White
    Write-Host ""
}

# Check for NVIDIA GPU
Write-Host "[5/8] Checking GPU..." -ForegroundColor Yellow
try {
    $gpuInfo = nvidia-smi --query-gpu=name,memory.total,memory.free --format=csv,noheader 2>&1
    Write-Host "  GPU detected:" -ForegroundColor Green
    Write-Host "    $gpuInfo" -ForegroundColor White
    
    # Check if Ollama is using GPU
    $ollamaRunning = Get-Process ollama -ErrorAction SilentlyContinue
    if ($ollamaRunning) {
        Write-Host "  Ollama is running (using GPU)" -ForegroundColor Green
    }
} catch {
    Write-Host "  [WARNING] NVIDIA driver not detected" -ForegroundColor Yellow
    Write-Host "  Install from: https://www.nvidia.com/Download/index.aspx" -ForegroundColor Cyan
}

# Start Ollama if not running
Write-Host "[6/8] Starting Ollama..." -ForegroundColor Yellow
$ollamaRunning = Get-Process ollama -ErrorAction SilentlyContinue
if (-not $ollamaRunning) {
    Start-Process ollama -ArgumentList "serve" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    Write-Host "  Ollama started" -ForegroundColor Green
} else {
    Write-Host "  Ollama already running" -ForegroundColor Green
}

# Test hardware detection
Write-Host "[7/8] Testing hardware detection..." -ForegroundColor Yellow
python -c @"
from abhimanyux.runtime.providers import ModelSelector
s = ModelSelector()
hw = s.hardware
print(f'  CPU: {hw.cpu_cores} cores')
print(f'  RAM: {hw.total_ram_gb:.1f} GB')
print(f'  GPU: {hw.gpu_name or \"None\"}')
print(f'  VRAM: {hw.gpu_vram_gb:.1f} GB')
print()
print('RECOMMENDED MODELS:')
models = s.get_recommended_models(prefer_local=True)
for m in models[:5]:
    print(f'  - {m}')
"@

# Test platform
Write-Host "[8/8] Testing platform..." -ForegroundColor Yellow
python -c "from abhimanyux.runtime.abhimanyux_platform import AbhimanyuXPlatform; p=AbhimanyuXPlatform(); print('  Platform initialized successfully')"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Your AI15-DT specs:" -ForegroundColor Cyan
Write-Host "  - i9-13900 (24C/32T)" -ForegroundColor White
Write-Host "  - 64 GB DDR5 RAM" -ForegroundColor White
Write-Host "  - RTX 4060 (12 GB VRAM)" -ForegroundColor White
Write-Host "  - 954 GB SSD" -ForegroundColor White
Write-Host ""
Write-Host "Quick start:" -ForegroundColor Yellow
Write-Host "  .\venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "  python -m abhimanyux.runtime.abhimanyux_platform --list-hardware" -ForegroundColor White
Write-Host "  python -m abhimanyux.runtime.abhimanyux_platform target.py" -ForegroundColor White
