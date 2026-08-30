@echo off
REM ============================================================
REM ABHIMANYU X USB Creator for Windows
REM Creates bootable USB without any external tools
REM ============================================================

title ABHIMANYU X USB Creator

echo.
echo    _____ ____  ___    _    ______   _______   ____ 
echo   / ____/ ___^|_ _^|  / \  ^| __ ) \ / / ____^| / ___^|
echo  ^| ^|    \___ \ ^| ^|  / _ \ ^| _ \\\ V /^|  _|   \___ \ 
echo  ^| ^|___  ___) ^| ^| / ___ \^| |_) /^| ^| ^| ^|___   ___) ^|
echo   \____^|^|____/___^|_/   \_\____/ ^|_^|  ^|_____^| ^|____/
echo.
echo   USB Creator v2.0
echo.
echo ============================================================
echo.

REM Check for administrator
net session >nul 2>&1
if errorlevel 1 (
    echo [ERROR] This script requires Administrator privileges.
    echo.
    echo Right-click on this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

REM Check for ABHIMANYU X ISO
if not exist "ABHIMANYU X-Live-*.iso" (
    echo [ERROR] ABHIMANYU X ISO file not found.
    echo.
    echo Please ensure ABHIMANYU X-Live-2.0.iso is in this folder.
    echo.
    echo If you don't have the ISO, download it from:
    echo https://github.com/abhimanyux/abhimanyux/releases
    echo.
    pause
    exit /b 1
)

REM List available disks
echo Available disks:
echo.
listdisk
echo.

REM Get disk number
set /p DISK_NUM="Enter USB disk number (e.g., 1): "

echo.
echo ============================================================
echo WARNING: ALL DATA ON DISK %DISK_NUM% WILL BE DESTROYED!
echo ============================================================
echo.
set /p CONFIRM="Type YES to continue: "

if not "%CONFIRM%"=="YES" (
    echo Operation cancelled.
    pause
    exit /b 0
)

echo.
echo [1/5] Cleaning disk...
echo select disk %DISK_NUM% > "%TEMP%\diskpart.txt"
echo clean >> "%TEMP%\diskpart.txt"
echo create partition primary >> "%TEMP%\diskpart.txt"
echo select partition 1 >> "%TEMP%\diskpart.txt"
echo active >> "%TEMP%\diskpart.txt"
echo format fs=fat32 quick label="ABHIMANYUX" >> "%TEMP%\diskpart.txt"
echo assign >> "%TEMP%\diskpart.txt"
echo exit >> "%TEMP%\diskpart.txt"

diskpart /s "%TEMP%\diskpart.txt" >nul 2>&1

echo [2/5] Mounting ISO...

REM Find the ISO file
for %%f in (ABHIMANYU X-Live-*.iso) do set ISO_FILE=%%f

REM Mount ISO using PowerShell
powershell -Command "Mount-DiskImage -ImagePath '%ISO_FILE%'" >nul 2>&1

REM Get drive letter
set USB_DRIVE=
for /f "tokens=1" %%a in ('powershell -Command "(Get-DiskImage -ImagePath '%ISO_FILE%' | Get-Volume).DriveLetter"') do set ISO_DRIVE=%%a

echo [3/5] Copying files...

REM Copy ISO contents to USB
xcopy /E /I /Y "%ISO_DRIVE%:\*" "E:\"

echo [4/5] Making USB bootable...

REM Write boot sector
bootsect /nt60 E: /mbr >nul 2>&1

echo [5/5] Finalizing...

REM Dismount ISO
powershell -Command "Dismount-DiskImage -ImagePath '%ISO_FILE%'" >nul 2>&1

echo.
echo ============================================================
echo USB CREATION COMPLETE
echo ============================================================
echo.
echo Your bootable ABHIMANYU X USB is ready!
echo.
echo To use:
echo   1. Insert USB into target computer
echo   2. Restart computer
echo   3. Press F12/F2/DEL during startup to enter boot menu
echo   4. Select USB drive
echo   5. Choose "ABHIMANYU X Live" from boot menu
echo.
echo ABHIMANYU X will auto-install on first boot.
echo.
pause
