@echo off
setlocal
rem Abhimanyu X installer (Windows). Run from the mounted ISO:
rem   install.bat [target-directory, default: %USERPROFILE%\abhimanyux-install]

set "SRC_DIR=%~dp0"
if "%~1"=="" (
    set "TARGET=%USERPROFILE%\abhimanyux-install"
) else (
    set "TARGET=%~1"
)

echo ============================================================
echo Abhimanyu X - Installer
echo ============================================================
echo Installing to: %TARGET%
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo ERROR: python not found on PATH. Install Python 3.10+ first.
    exit /b 1
)

if not exist "%TARGET%" mkdir "%TARGET%"
xcopy /E /I /Y "%SRC_DIR%abhimanyux" "%TARGET%\abhimanyux" >nul

cd /d "%TARGET%\abhimanyux"
echo [*] Creating virtual environment...
python -m venv venv
echo [*] Installing dependencies...
venv\Scripts\pip install -q --upgrade pip
venv\Scripts\pip install -q -r requirements.txt

echo.
echo Installed: %TARGET%\abhimanyux
echo.
echo Next steps:
echo.
echo   1. Install Ollama (https://ollama.com) and pull a local model:
echo        ollama pull dolphin-llama3:8b
echo.
echo   2. Scan a file or directory:
echo        cd /d %TARGET%
echo        set PYTHONPATH=.
echo        abhimanyux\venv\Scripts\python -m abhimanyux.core.orchestrator ^<target^>
echo.
echo   3. Confirm the install works (runs the real test suite):
echo        cd /d %TARGET%
echo        set PYTHONPATH=.
echo        abhimanyux\venv\Scripts\python -m pytest abhimanyux\tests -q
echo.
echo Note: this installs the source and its Python dependencies. It does not
echo install Ollama or a language model for you.
