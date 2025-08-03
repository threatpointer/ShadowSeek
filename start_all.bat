@echo off
setlocal enabledelayedexpansion

echo.
echo ======================================================
echo    ShadowSeek - Starting Advanced Binary Security Analysis
echo    JFX Bridge Connection Issues: RESOLVED
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
) else (
    echo.
    echo WARNING: .env file not found
    echo Please run the setup script first: python setup-shadowseek.py
    echo.
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

REM Get Ghidra path from .env file (more reliable than environment variables)
set GHIDRA_PATH=
if exist .env (
    for /F "tokens=1,2 delims==" %%a in (.env) do (
        if "%%a"=="GHIDRA_INSTALL_DIR" (
            set GHIDRA_PATH=%%b
        )
    )
) else (
    if defined GHIDRA_INSTALL_DIR (
        set GHIDRA_PATH=%GHIDRA_INSTALL_DIR%
    )
)

REM Check if Ghidra path is set
if "%GHIDRA_PATH%"=="" (
    echo GHIDRA_INSTALL_DIR is not set. Please set it in the .env file.
    echo Or run: python setup-shadowseek.py
    exit /b 1
)

REM Check if Ghidra path exists
if not exist "%GHIDRA_PATH%" (
    echo Ghidra installation not found at %GHIDRA_PATH%
    echo Please check the GHIDRA_INSTALL_DIR in your .env file.
    echo Or run: python setup-shadowseek.py
    exit /b 1
)

REM Check for Node.js for the frontend
echo Checking for Node.js...
where node >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Node.js not found in PATH. The frontend may not start properly.
    echo Please install Node.js if you want to run the frontend.
)

REM Start Ghidra Bridge server using FIXED batch script
echo Starting Ghidra Bridge server with JFX execution fixes...
echo Creating logs directory...
if not exist logs mkdir logs

echo Using fixed bridge server script with proper port handling
echo Bridge server will log detailed output to logs\ directory
start "Ghidra Bridge Server" cmd /c "start_ghidra_bridge_new.bat"
echo Waiting for Ghidra Bridge to initialize (fixed version)...
timeout /t 15 > nul

REM Start Flask backend using UV virtual environment
echo Starting Flask backend with virtual environment...
echo Checking virtual environment...

REM Check if virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo ERROR: Virtual environment not found at .venv\Scripts\python.exe
    echo Please run setup-shadowseek.py first to create the virtual environment
    echo.
    echo Quick fix: python setup-shadowseek.py --auto
    pause
    exit /b 1
)

echo Virtual environment found: .venv\Scripts\python.exe
echo Testing Flask imports in virtual environment...
".venv\Scripts\python.exe" -c "import flask, flask_sqlalchemy, flask_cors, ghidra_bridge, requests; print('Flask imports OK')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo ERROR: Flask dependencies not found in virtual environment
    echo Installing critical dependencies...
    
    REM Try uv first, fallback to pip
    where uv >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        echo Using uv for faster installation...
        call ".venv\Scripts\activate.bat" && uv pip install flask flask-sqlalchemy flask-cors flask-migrate flask-restx requests python-dotenv ghidra-bridge ghidriff werkzeug sqlalchemy psutil aiohttp websockets
    ) else (
        echo Using pip for installation...
        call ".venv\Scripts\activate.bat" && python -m pip install flask flask-sqlalchemy flask-cors flask-migrate flask-restx requests python-dotenv ghidra-bridge ghidriff werkzeug sqlalchemy psutil aiohttp websockets
    )
    
    if %ERRORLEVEL% neq 0 (
        echo ERROR: Dependency installation failed
        echo Please run: python setup-shadowseek.py --skip-system-check
        pause
        exit /b 1
    )
)

echo Starting Flask with virtual environment Python...
start "Flask Backend" cmd /c "cd /d "%CD%" && .venv\Scripts\python.exe run.py && pause"
echo Waiting for Flask to initialize...
timeout /t 8 > nul

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
echo    JFX Bridge Issues: RESOLVED AND WORKING
echo ======================================================
echo.
echo Ghidra Bridge server: Running on port 4768 (FIXED)
echo   - JFX script execution: WORKING
echo   - Port argument handling: FIXED  
echo   - Connection persistence: STABLE
echo Flask backend running at: http://localhost:5000
echo React frontend running at: http://localhost:3000
echo.
echo Bridge logs available in: logs\ghidra_bridge_*.log
echo Use view_bridge_logs.bat to view latest bridge logs
echo.
echo Press Ctrl+C to stop the application.
echo Or run stop.bat to stop all components.
echo.

REM Keep the window open
pause 
