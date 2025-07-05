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

REM Start Flask backend in a new window
echo Starting Flask backend...
start "Flask Backend" cmd /c "python -m flask_app.app && pause"
echo Waiting for Flask to initialize...
timeout /t 5 > nul

REM Start ghidra-bridge server using Ghidra's headless analyzer
echo Starting Ghidra Bridge server...
set GHIDRA_HEADLESS=%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat
set BRIDGE_SCRIPT_PATH=

REM Try to find the bridge script in the Python package
for /f "tokens=*" %%i in ('python -c "import ghidra_bridge; import os; print(os.path.join(os.path.dirname(ghidra_bridge.__file__), 'server', 'ghidra_bridge_server.py'))"') do (
    set BRIDGE_SCRIPT_PATH=%%i
)

if exist "!BRIDGE_SCRIPT_PATH!" (
    echo Found bridge script at: !BRIDGE_SCRIPT_PATH!
    
    REM Copy the script to Ghidra's scripts directory
    set GHIDRA_SCRIPTS_DIR=%USERPROFILE%\.ghidra
    if not exist "!GHIDRA_SCRIPTS_DIR!" mkdir "!GHIDRA_SCRIPTS_DIR!"
    
    copy "!BRIDGE_SCRIPT_PATH!" "!GHIDRA_SCRIPTS_DIR!\ghidra_bridge_server.py" >nul
    echo Copied bridge script to !GHIDRA_SCRIPTS_DIR!\ghidra_bridge_server.py
    
    REM Start Ghidra headless with the bridge script
    start "Ghidra Bridge Server" cmd /c "!GHIDRA_HEADLESS! . temp -import- -scriptPath "!GHIDRA_SCRIPTS_DIR!" -postScript ghidra_bridge_server.py %GHIDRA_BRIDGE_PORT% && pause"
    echo Waiting for Ghidra Bridge to initialize...
    timeout /t 10 > nul
) else (
    echo Error: Could not find ghidra_bridge_server.py
    exit /b 1
)

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
echo Flask backend running at: http://localhost:5000
echo React frontend running at: http://localhost:3000
echo.
echo Press Ctrl+C to stop the application.
echo Or run stop.bat to stop all components.
echo.

REM Keep the window open
pause 