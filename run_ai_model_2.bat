@echo off
title AI Model 2: EMBER2024 Deep Binary Malware Classifier
echo ========================================================================
echo   AI Model 2: EMBER2024 Cross-Platform Deep Binary Classifier
echo   Modality: ELF / Linux / Android / Cross-Platform Executables
echo   Champion: LightGBM (95.08%% Accuracy, 0.9906 ROC-AUC)
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
echo [*] Launching AI Model 2 Streamlit Portal on http://localhost:8502...
echo [*] Press Ctrl+C in this terminal to stop the application.
echo.
cd /d "%~dp0AI model 2"
"%PY_CMD%" -m streamlit run streamlit_app.py --server.port 8502
pause

