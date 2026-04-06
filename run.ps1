#!/usr/bin/env powershell

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗"
Write-Host "║               SafeGuard AI - Startup Script                  ║"
Write-Host "║          Enterprise Cyber Safety Platform v1.0.0             ║"
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python detected: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8+ from python.org"
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if we're in the right directory
if (-not (Test-Path "backend.py")) {
    Write-Host "❌ ERROR: backend.py not found" -ForegroundColor Red
    Write-Host "Please run this script from the cyber-safety directory"
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "✓ Project files found" -ForegroundColor Green

# Install/update dependencies
Write-Host ""
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
pip install -q -r requirements.txt

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "⚠ Warning: Some dependencies may not have installed correctly" -ForegroundColor Yellow
}

# Start the backend
Write-Host ""
Write-Host "🚀 Starting SafeGuard AI Backend Service..." -ForegroundColor Cyan
Write-Host ""
Write-Host "─────────────────────────────────────────────────────────────" -ForegroundColor Gray
Write-Host ""

python backend.py

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "❌ Backend failed to start" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Read-Host "Press Enter to exit"
