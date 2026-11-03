# ==============================================================================
# AI Model 2: EMBER2024 Deep Binary Classifier Launcher
# ==============================================================================

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  AI Model 2: EMBER2024 Cross-Platform Deep Binary Classifier" -ForegroundColor White
Write-Host "  Champion: LightGBM (95.08% Accuracy, 0.9906 ROC-AUC)" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Cyan

$pyCmd = "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe"
if (-not (Test-Path $pyCmd)) {
    try {
        & py --version | Out-Null
        $pyCmd = "py"
    } catch {
        $pyCmd = "python"
    }
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $scriptDir "AI model 2")

Write-Host "[*] Python executable detected: $pyCmd" -ForegroundColor Gray
Write-Host "[*] Launching AI Model 2 Streamlit on http://localhost:8502..." -ForegroundColor Yellow
Write-Host "[*] Press Ctrl+C in this terminal to terminate the server.`n" -ForegroundColor DarkGray

& $pyCmd -m streamlit run streamlit_app.py --server.port 8502

