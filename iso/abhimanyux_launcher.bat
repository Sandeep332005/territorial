@echo off
REM ============================================================
REM ABHIMANYU X Platform - Windows Universal Launcher
REM Self-contained setup for any Windows system
REM ============================================================

title ABHIMANYU X Platform v2.0

echo.
echo    _____ ____  ___    _    ______   _______   ____
echo   / ____/ ___^|_ _^|  / \  ^| __ ) \ / / ____^| / ___^|
echo  ^| ^|    \___ \ ^| ^|  / _ \ ^|  _ \\ V /^|  _|   \___ \
echo  ^| ^|___  ___) ^| ^| / ___ \^| |_) /^| ^| ^| ^|___   ___) ^
echo   \____^|^|____/___^|_/   \_\____/ ^|_^|  ^|_____^| ^|____/
echo.
echo    v2.0 - Autonomous Cyber Reasoning System
echo    For Defence Infrastructure Security
echo.
echo ============================================================
echo.

REM Set installation directory
set INSTALL_DIR=%USERPROFILE%\abhimanyux
set ABHIMANYUX_SRC=%~dp0

echo [*] Installation directory: %INSTALL_DIR%
echo.

REM Check Python
echo [1/6] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python not found.
    echo     Please install Python 3.9+ from:
    echo     https://www.python.org/downloads/
    echo.
    echo     Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
) else (
    python --version
    echo [OK] Python found
)
echo.

REM Check pip
echo [2/6] Checking pip...
pip --version >nul 2>&1
if errorlevel 1 (
    echo [!] pip not found. Installing...
    python -m ensurepip --upgrade
)
echo [OK] pip ready
echo.

REM Check Ollama
echo [3/6] Checking Ollama...
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [!] Ollama not found.
    echo     Installing Ollama...
    echo.
    echo     Please download Ollama from:
    echo     https://ollama.com/download/windows
    echo.
    echo     After installation, re-run this script.
    pause
    
    REM Try to install via winget
    winget install Ollama.Ollama --silent --accept-package-agreements --accept-source-agreements
    if errorlevel 1 (
        echo [!] Automatic installation failed.
        echo     Please install manually from https://ollama.com/download/windows
        pause
        exit /b 1
    )
)
echo [OK] Ollama found
echo.

REM Detect hardware
echo [4/6] Detecting hardware...
echo.

REM Detect GPU
nvidia-smi --query-gpu=name,memory.total --format=csv,noheader >nul 2>&1
if errorlevel 1 (
    echo GPU: Not detected or no NVIDIA driver
    set GPU_VRAM_GB=0
) else (
    for /f "tokens=1,2" %%a in ('nvidia-smi --query-gpu=name,memory.total --format^=csv,noheader') do (
        echo GPU: %%a
        echo VRAM: %%b
    )
)

REM Detect RAM (simplified)
echo RAM: 64 GB ^(assumed^)
echo CPU: %NUMBER_OF_PROCESSORS% cores
echo.

REM Create installation directory
echo [5/6] Installing ABHIMANYU X...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Copy files
echo Copying files...
xcopy /E /I /Y "%ABHIMANYUX_SRC%.." "%INSTALL_DIR%" >nul 2>&1

REM Create virtual environment
echo Creating virtual environment...
cd /d "%INSTALL_DIR%"
python -m venv venv
call venv\Scripts\activate.bat

REM Install dependencies
echo Installing dependencies...
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo [OK] ABHIMANYU X installed
echo.

REM Create launcher
echo [6/6] Creating launcher...
(
echo @echo off
echo cd /d "%INSTALL_DIR%"
echo call venv\Scripts\activate.bat
echo set PYTHONPATH=.
echo python -m abhimanyux.runtime.abhimanyux_platform %%*
) > "%USERPROFILE%\abhimanyux.bat"

REM Add to PATH (user level)
setx PATH "%PATH%;%USERPROFILE%" >nul 2>&1

echo [OK] Launcher created: %USERPROFILE%\abhimanyux.bat
echo.

REM Pull model
echo Pulling recommended model...
echo.
echo Select model based on your GPU:
echo   1. qwen2.5-coder:7b  (Best for code security, needs 5GB VRAM)
echo   2. qwen3:8b          (Fast general model, needs 5GB VRAM)
echo   3. qwen2.5-coder:3b  (Lightweight, runs on CPU)
echo.
set /p MODEL_CHOICE="Enter choice (1-3, default=1): "

if "%MODEL_CHOICE%"=="2" (
    set MODEL=qwen3:8b
) else if "%MODEL_CHOICE%"=="3" (
    set MODEL=qwen2.5-coder:3b
) else (
    set MODEL=qwen2.5-coder:7b-instruct-q4_K_M
)

echo Pulling %MODEL%...
ollama pull %MODEL%

echo.
echo ============================================================
echo INSTALLATION COMPLETE
echo ============================================================
echo.
echo Usage:
echo   abhimanyux scan <target>    Scan file or directory
echo   abhimanyux models          List available models
echo   abhimanyux hardware        Show hardware info
echo.
echo Examples:
echo   abhimanyux scan C:\path\to\project
echo   abhimanyux scan main.py
echo.
echo Configuration: %INSTALL_DIR%\abhimanyux_config.json
echo.
echo Press any key to exit...
pause >nul
