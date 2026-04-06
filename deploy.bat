@echo off
setlocal enabledelayedexpansion

title Terosica AI - Live Deployment
color 0B

echo.
echo ==========================================
echo   Terosica AI - Live Deployment Script
echo ==========================================
echo.

where ngrok >nul 2>nul
if errorlevel 1 (
    color 0C
    echo ERROR: ngrok is not installed or not in PATH
    echo.
    echo To install ngrok:
    echo   1. Download from: https://ngrok.com/download
    echo   2. Extract ngrok.exe to a folder in PATH
    echo   3. Or add its folder to your PATH environment variable
    echo   4. Connect your account: ngrok config add-authtoken [token]
    echo.
    pause
    exit /b 1
)

color 0B
echo Starting Terosica AI Backend Server...
echo Backend Directory: %CD%
echo.

start "Terosica AI Backend" /D "%CD%" python backend.py

echo Waiting for backend to initialize ^(5 seconds^)...
timeout /t 5 /nobreak

echo.
echo Starting ngrok tunnel on port 5000...
echo.

ngrok http 5000 --bind-tls=False

echo.
echo Deployment stopped.
pause
