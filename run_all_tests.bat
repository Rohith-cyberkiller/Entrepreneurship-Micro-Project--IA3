@echo off
title IA3 End-to-End Test Suite Runner (All 21 Tests)
echo ========================================================================
echo   CertiScan Studio // MalDetect-AI Automated Test Suite
echo   Executing 21 Unit & Full-Pipeline Integration Tests
echo   (Members 1, 2, 3, 4 + AI Model 2 Deep Binary Classifier)
echo ========================================================================
echo.

set PY_CMD=
if exist "%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Python\pythoncore-3.14-64\python.exe"
) else (
    py --version >nul 2>&1
    if %errorlevel% equ 0 (
        set PY_CMD=py
    ) else (
        python --version >nul 2>&1
        if %errorlevel% equ 0 (
            set PY_CMD=python
        ) else (
            echo [!] Error: Python 3 is not installed or not in PATH.
            pause
            exit /b 1
        )
    )
)

echo [*] Using Python: %PY_CMD%
echo.
"%PY_CMD%" -m pytest Jerom\trustshield-member2\tests Krishanth\threatfuse-member3\tests Rohith\certiscan-maldetect-ai\tests "AI model 2\tests" -v
pause
