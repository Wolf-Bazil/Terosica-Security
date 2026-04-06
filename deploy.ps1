# Terosica AI - Deployment Script with ngrok

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Terosica AI - Live Deployment Script  " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

$ngrokPath = Get-Command ngrok -ErrorAction SilentlyContinue
if (-not $ngrokPath) {
    Write-Host "ERROR: ngrok is not installed or not in PATH" -ForegroundColor Red
    Write-Host ""
    Write-Host "To install ngrok:" -ForegroundColor Yellow
    Write-Host "  1. Download from: https://ngrok.com/download" -ForegroundColor Yellow
    Write-Host "  2. Extract and add to PATH" -ForegroundColor Yellow
    Write-Host "  3. Connect your account: ngrok config add-authtoken <token>" -ForegroundColor Yellow
    Write-Host ""
    Exit 1
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendDir = $scriptDir

Write-Host "Starting Terosica AI Backend Server..." -ForegroundColor Green
Write-Host "Backend Directory: $backendDir" -ForegroundColor Gray
Write-Host ""

Push-Location $backendDir
$process = Start-Process python -ArgumentList "backend.py" -PassThru -WindowStyle Minimized
$backendPid = $process.Id
Write-Host "✓ Backend process started (PID: $backendPid)" -ForegroundColor Green

Write-Host "Waiting for backend to initialize (5 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "Starting ngrok tunnel on port 5000..." -ForegroundColor Green
Write-Host "This will expose your local backend to the internet" -ForegroundColor Gray
Write-Host ""

$ngrokJob = Start-Job -ScriptBlock {
    ngrok http 5000 --bind-tls=False 2>&1
}

Start-Sleep -Seconds 3

Write-Host "Retrieving ngrok public URL..." -ForegroundColor Yellow
$ngrokResponse = $null
try {
    $ngrokResponse = Invoke-WebRequest -Uri "http://localhost:4040/api/tunnels" -TimeoutSec 5 -ErrorAction Stop
    $tunnels = ($ngrokResponse.Content | ConvertFrom-Json).tunnels
    $publicUrl = $tunnels[0].public_url
    
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host "  ✓ DEPLOYMENT SUCCESSFUL!" -ForegroundColor Green
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Public URL: $publicUrl" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Access your application at:" -ForegroundColor Yellow
    Write-Host "  Live URL: $publicUrl/index.html" -ForegroundColor Cyan
    Write-Host "  Local URL: http://localhost:5000/index.html" -ForegroundColor Gray
    Write-Host ""
    Write-Host "API Key: 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" -ForegroundColor Gray
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Backend Endpoints:" -ForegroundColor Green
    Write-Host "  • POST $publicUrl/api/v2/phishing/analyze" -ForegroundColor Gray
    Write-Host "  • POST $publicUrl/api/v2/credentials/score" -ForegroundColor Gray
    Write-Host "  • POST $publicUrl/api/v2/profiles/verify" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To view ngrok dashboard: http://localhost:4040" -ForegroundColor Yellow
    Write-Host "Press Ctrl+C to stop the deployment" -ForegroundColor Yellow
    
}
catch {
    Write-Host "Could not retrieve ngrok URL automatically" -ForegroundColor Yellow
    Write-Host "Check ngrok dashboard at http://localhost:4040" -ForegroundColor Gray
}

try {
    Pop-Location
    Write-Host "Deployment running. Press Ctrl+C to stop..." -ForegroundColor Cyan
    while ($true) {
        Start-Sleep -Seconds 1
    }
}
finally {
    Write-Host ""
    Write-Host "Stopping services..." -ForegroundColor Yellow
    
    Stop-Job -Job $ngrokJob -Force -ErrorAction SilentlyContinue
    
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $backendPid -Force -ErrorAction SilentlyContinue
        Write-Host "✓ Backend stopped" -ForegroundColor Green
    }
    
    Write-Host "✓ Deployment stopped" -ForegroundColor Green
}
