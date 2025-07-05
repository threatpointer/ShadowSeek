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

REM Start Ghidra Bridge server using batch script
echo Starting Ghidra Bridge server...
start "Ghidra Bridge Server" cmd /c "start_ghidra_bridge_new.bat"
echo Waiting for Ghidra Bridge to initialize...
timeout /t 15 > nul

REM Start Flask backend
echo Starting Flask backend...
start "Flask Backend" cmd /c "python run.py && pause"
echo Waiting for Flask to initialize...
timeout /t 5 > nul

REM Check if frontend directory exists
if exist frontend (
    echo Starting React frontend...
    cd frontend
    
    REM Check if node_modules exists, if not run npm install
    if not exist node_modules (
        echo Installing frontend dependencies...
        call npm install
    )
    
    REM Start React frontend
    start "React Frontend" cmd /c "npm start && pause"
    cd ..
) else (
    echo Frontend directory not found. Skipping frontend startup.
)

echo.
echo ======================================================
echo    Application started successfully!
echo ======================================================
echo.
echo Ghidra Bridge server: Running on port 4768
echo Flask backend running at: http://localhost:5000
echo React frontend running at: http://localhost:3000
echo.
echo Press Ctrl+C to stop the application.
echo Or run stop.bat to stop all components.
echo.

REM Keep the window open
pause 