@echo off
title CertiScan Studio // MalDetect-AI Unified Dashboard
echo ========================================================================
echo   CertiScan Studio // MalDetect-AI Defense-in-Depth Suite
echo   Group IA3: Members 1, 2, 3, 4 + AI Model 2 Unified Master Application
echo ========================================================================
echo.
echo [*] Checking Python environment...

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

echo [*] Python executable detected: %PY_CMD%
echo [*] Launching Master Streamlit Web Application...
echo [*] URL: http://localhost:8501
echo [*] Press Ctrl+C in this terminal to stop the application.
echo.
"%PY_CMD%" -m streamlit run app.py
pause
