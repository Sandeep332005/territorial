@echo off
REM ============================================================
REM ABHIMANYU X Platform - Windows Deployment Script
REM For: AI15-DT (i9-13900 + 64GB RAM + RTX 4060 12GB)
REM ============================================================

echo ============================================================
echo ABHIMANYU X Platform - Windows Deployment
echo ============================================================
echo.

REM Check for Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.11+ from:
    echo        https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Create virtual environment
echo [1/6] Creating virtual environment...
python -m venv venv
call venv\Scripts\activate.bat

REM Install dependencies
echo [2/6] Installing dependencies...
pip install --upgrade pip
pip install -r requirements.txt

REM Check for Ollama
echo [3/6] Checking Ollama...
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Ollama not found.
    echo.
    echo Install Ollama from: https://ollama.com/download/windows
    echo Then run: ollama pull qwen2.5-coder:7b-instruct-q4_K_M
    echo.
)

REM Check for NVIDIA GPU
echo [4/6] Checking GPU...
nvidia-smi >nul 2>&1
if errorlevel 1 (
    echo [WARNING] NVIDIA driver not detected.
    echo Install from: https://www.nvidia.com/Download/index.aspx
) else (
    nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
)

REM Test hardware detection
echo [5/6] Testing hardware detection...
python -c "from abhimanyux.platform.providers import ModelSelector; s=ModelSelector(); hw=s.hardware; print(f'  CPU: {hw.cpu_cores} cores'); print(f'  RAM: {hw.total_ram_gb:.1f} GB'); print(f'  GPU: {hw.gpu_name or \"None\"}'); print(f'  VRAM: {hw.gpu_vram_gb:.1f} GB')"

REM Test platform
echo [6/6] Testing platform...
python -c "from abhimanyux.platform.abhimanyux_platform import AbhimanyuXPlatform; p=AbhimanyuXPlatform(); print('  Platform initialized successfully')"

echo.
echo ============================================================
echo DEPLOYMENT COMPLETE
echo ============================================================
echo.
echo Your AI15-DT specs:
echo   - i9-13900 (24C/32T)
echo   - 64 GB DDR5 RAM
echo   - RTX 4060 (12 GB VRAM)
echo   - 954 GB SSD
echo.
echo Recommended models for your hardware:
echo.
echo   BEST FOR CODE SECURITY (fits entirely in GPU):
echo     ollama pull qwen2.5-coder:7b-instruct-q4_K_M
echo.
echo   BEST QUALITY (partial GPU offload):
echo     ollama pull qwen2.5-coder:32b-instruct-q4_K_M
echo.
echo   FAST OPTION (fully fits in GPU):
echo     ollama pull qwen3:8b
echo.
echo Usage:
echo   venv\Scripts\activate
echo   python -m abhimanyux.platform.abhimanyux_platform target.py
echo   python -m abhimanyux.platform.abhimanyux_platform --list-models
echo   python -m abhimanyux.platform.abhimanyux_platform --list-hardware
echo.
echo For API keys (optional - for frontier models):
echo   set ANTHROPIC_API_KEY=your_key
echo   set OPENAI_API_KEY=your_key
echo   set GEMINI_API_KEY=your_key
echo   set DEEPSEEK_API_KEY=your_key
echo.
pause
