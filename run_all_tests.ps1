# ==============================================================================
# IA3 Automated Test Suite PowerShell Runner (All 21 Tests)
# Validates Member 1, Member 2, Member 3, Member 4, and AI Model 2
# ==============================================================================

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  IA3 Defense-in-Depth Suite: Executing 21 Automated Tests..." -ForegroundColor White
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

Write-Host "[*] Executing pytest across all modules..." -ForegroundColor Gray
& $pyCmd -m pytest Jerom/trustshield-member2/tests Krishanth/threatfuse-member3/tests Rohith/certiscan-maldetect-ai/tests "AI model 2/tests" -v
