@echo off
title p0f - Passive OS Fingerprinter
cd /d "%~dp0"

echo.
echo  ============================================
echo   p0f - Passive OS Fingerprinter
echo   Windows Edition (Python Port)
echo  ============================================
echo.

:: Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Please install Python 3.x
    echo          https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Check Scapy is installed
python -c "import scapy" >nul 2>&1
if errorlevel 1 (
    echo  [!] Scapy not found. Installing now...
    pip install scapy
    echo.
)

:: Launch GUI
echo  [+] Starting p0f GUI...
echo  [+] Make sure Npcap is installed for live capture:
echo      https://npcap.com/
echo.
python p0f_gui.py

if errorlevel 1 (
    echo.
    echo  [ERROR] p0f GUI exited with an error.
    pause
)
