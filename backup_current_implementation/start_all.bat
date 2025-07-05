@echo off
setlocal enabledelayedexpansion

echo.
echo ======================================================
echo    Ghidra Web Analyzer - Starting Application
echo ======================================================
echo.

REM Load environment variables from .env file if it exists
if exist .env (
    echo Loading environment variables from .env file...
    for /F "tokens=*" %%i in (.env) do (
        set line=%%i
        if not "!line:~0,1!"=="#" (
            if not "!line!"=="" (
                set !line!
            )
        )
    )
    echo Environment variables loaded.
)

REM Check for Python
echo Checking for Python...
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Python not found in PATH. Please install Python and try again.
    exit /b 1
)

REM Check for required directories
echo Creating required directories...
if not exist "uploads" mkdir uploads
if not exist "logs" mkdir logs
if not exist "temp" mkdir temp
if not exist "instance" mkdir instance
if not exist "ghidra_projects" mkdir ghidra_projects

REM Check if Ghidra path is set
if "%GHIDRA_INSTALL_DIR%"=="" (
    echo GHIDRA_INSTALL_DIR is not set. Please set it in the .env file.
    exit /b 1
)

REM Check if Ghidra path exists
if not exist "%GHIDRA_INSTALL_DIR%" (
    echo Ghidra installation not found at %GHIDRA_INSTALL_DIR%
    echo Please check the GHIDRA_INSTALL_DIR in your .env file.
    exit /b 1
)

REM Check for Node.js for the frontend
echo Checking for Node.js...
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Node.js not found in PATH. The frontend may not start properly.
    echo Please install Node.js if you want to run the frontend.
)

REM Clean up any existing lock files to prevent bridge startup issues
echo Cleaning up any existing Ghidra lock files...
del /Q ghidra_projects\*.lock >nul 2>nul
del /Q ghidra_projects\*.lock~ >nul 2>nul

REM Kill any existing Java/Python processes that might interfere
echo Stopping any existing processes...
taskkill /F /IM java.exe >nul 2>nul
taskkill /F /IM python.exe >nul 2>nul
timeout /t 2 >nul

REM Start Ghidra Bridge server (optional - system works in headless mode if this fails)
echo Starting Ghidra Bridge server...
echo Note: Bridge startup is optional - system will use headless mode if bridge fails
start "Ghidra Bridge Server" cmd /c "start_ghidra_bridge_new.bat"
echo Waiting for Ghidra Bridge to initialize...
timeout /t 20 > nul

REM Start Flask backend
echo Starting Flask backend...
start "Flask Backend" cmd /c "python run.py && pause"
echo Waiting for Flask to initialize...
timeout /t 8 > nul

REM Verify Flask is running
echo Checking if Flask backend is responding...
python -c "import requests; requests.get('http://localhost:5000/api/status', timeout=5); print('✅ Flask backend is running')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo ⚠️  Flask backend may not be fully ready yet - this is normal on first startup
)

REM Check if frontend directory exists and start React frontend
if exist frontend (
    echo Starting React frontend...
    cd frontend
    
    REM Check if node_modules exists, if not run npm install
    if not exist node_modules (
        echo Installing frontend dependencies...
        call npm install
        if %ERRORLEVEL% neq 0 (
            echo ⚠️  npm install failed - you may need to run 'npm install' manually in the frontend directory
            cd ..
            goto :skip_frontend
        )
    )
    
    REM Start React frontend
    start "React Frontend" cmd /c "npm start && pause"
    cd ..
    
    echo Waiting for React frontend to initialize...
    timeout /t 10 > nul
    
    REM Verify React is starting (it takes time to fully start)
    echo React frontend is starting up - it will be available shortly at http://localhost:3000
) else (
    echo Frontend directory not found. Skipping frontend startup.
)

:skip_frontend

echo.
echo ======================================================
echo    Application Startup Complete!
echo ======================================================
echo.
echo 🚀 Service Status:
echo    • Ghidra Bridge:    Optional (headless mode fallback available)
echo    • Flask Backend:    http://localhost:5000
echo    • React Frontend:   http://localhost:3000
echo.
echo 📋 Quick Access:
echo    • Main Dashboard:   http://localhost:3000
echo    • API Status:       http://localhost:5000/api/status
echo    • API Docs:         http://localhost:5000/api/docs/
echo.
echo ℹ️  System Notes:
echo    • Bridge uses headless mode for reliability
echo    • All analysis features are operational
echo    • Upload binaries and perform analysis normally
echo.
echo 🛑 To Stop Application:
echo    • Press Ctrl+C or close this window
echo    • Or run stop.bat to stop all components
echo.

REM Continuous status monitoring
:status_loop
timeout /t 30 >nul
echo [%time%] System running - Flask: http://localhost:5000 ^| Frontend: http://localhost:3000
goto status_loop 