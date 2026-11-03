o# ==============================================================================
# CertiScan Studio // MalDetect-AI PowerShell Launcher
# Group IA3: Members 1, 2, 3, 4 + AI Model 2 Master Portal
# ==============================================================================

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  CertiScan Studio // MalDetect-AI Master Defense-in-Depth Suite" -ForegroundColor White -NoNewline
Write-Host " [IA3]" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Cyan

$pyCmd = "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe"
if (-not (Test-Path $pyCmd)) {
    try {
        & py --version | Out-Null
        $pyCmd = "py"
    }
    catch {
        $pyCmd = "python"
    }
}

Write-Host "[*] Python executable detected: $pyCmd" -ForegroundColor Gray
Write-Host "[*] Launching Streamlit Master Application on http://localhost:8501..." -ForegroundColor Yellow
Write-Host "[*] Press Ctrl+C in this terminal to terminate the server.`n" -ForegroundColor DarkGray

& $pyCmd -m streamlit run app.py
