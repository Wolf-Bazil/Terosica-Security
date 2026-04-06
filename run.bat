@echo off
REM SafeGuard AI - Quick Start Script for Windows

echo.
echo ╔═══════════════════════════════════════════════════════════════╗
echo ║               SafeGuard AI - Startup Script                  ║
echo ║          Enterprise Cyber Safety Platform v1.0.0             ║
echo ╚═══════════════════════════════════════════════════════════════╝
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo ✓ Python detected

REM Check if we're in the right directory
if not exist "backend.py" (
    echo ❌ ERROR: backend.py not found
    echo Please run this script from the cyber-safety directory
    pause
    exit /b 1
)

echo ✓ Project files found

REM Install/update dependencies
echo.
echo 📦 Installing dependencies...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo ⚠ Warning: Some dependencies may not have installed correctly
) else (
    echo ✓ Dependencies installed
)

REM Start the backend
echo.
echo 🚀 Starting SafeGuard AI Backend Service...
echo.
echo ─────────────────────────────────────────────────────────────
python backend.py
echo ─────────────────────────────────────────────────────────────
echo.

if errorlevel 1 (
    echo ❌ Backend failed to start
    pause
    exit /b 1
)

pause
