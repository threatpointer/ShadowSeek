@echo off
echo Starting Ghidra Bridge server...

:: Set Ghidra path from .env file or use default
set GHIDRA_PATH=D:\1132-Ghidra\ghidra_11.3.2_PUBLIC
if exist .env (
    for /F "tokens=1,2 delims==" %%a in (.env) do (
        if "%%a"=="GHIDRA_INSTALL_DIR" set GHIDRA_PATH=%%b
    )
)

:: Create projects directory if it doesn't exist
set PROJECTS_DIR=ghidra_projects
if not exist %PROJECTS_DIR% mkdir %PROJECTS_DIR%

:: Create logs directory if it doesn't exist
if not exist logs mkdir logs

:: Create a unique project name based on timestamp
set PROJECT_NAME=GhidraBridge_%random%

:: Set port
set PORT=4768

:: Create a dummy file if it doesn't exist
if not exist %PROJECTS_DIR%\dummy.bin (
    echo dummy > %PROJECTS_DIR%\dummy.bin
)

:: Create log file with timestamp
set LOG_FILE=logs\ghidra_bridge_%date:~10,4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.log
set LOG_FILE=%LOG_FILE: =0%

echo.
echo ====================================================== 
echo Starting Ghidra Bridge server with DETAILED LOGGING
echo ======================================================
echo Project: %PROJECT_NAME%
echo Port: %PORT%
echo Ghidra Path: %GHIDRA_PATH%
echo Log File: %LOG_FILE%
echo Using: ghidra-bridge (mature solution)
echo ======================================================
echo.

:: Start Ghidra Bridge server with comprehensive logging
echo [%time%] Starting Ghidra Bridge server... >> %LOG_FILE%
echo [%time%] Project: %PROJECT_NAME% >> %LOG_FILE%
echo [%time%] Port: %PORT% >> %LOG_FILE%
echo [%time%] Ghidra Path: %GHIDRA_PATH% >> %LOG_FILE%
echo [%time%] Using ghidra_bridge_server.py from ghidra-bridge package >> %LOG_FILE%
echo [%time%] Command: "%GHIDRA_PATH%\support\analyzeHeadless.bat" "%PROJECTS_DIR%" "%PROJECT_NAME%" -scriptPath "C:\Users\moham\ghidra_scripts" -postScript ghidra_bridge_server.py "%PORT%" >> %LOG_FILE%
echo. >> %LOG_FILE%

:: Use the mature ghidra-bridge server script
"%GHIDRA_PATH%\support\analyzeHeadless.bat" "%PROJECTS_DIR%" "%PROJECT_NAME%" -scriptPath "C:\Users\moham\ghidra_scripts" -postScript ghidra_bridge_server.py "%PORT%" >> %LOG_FILE% 2>&1

:: Capture exit code
set BRIDGE_EXIT_CODE=%ERRORLEVEL%
echo. >> %LOG_FILE%
echo [%time%] Ghidra Bridge server exited with code: %BRIDGE_EXIT_CODE% >> %LOG_FILE%

:: Display results
echo.
echo ======================================================
echo Ghidra Bridge server stopped with exit code: %BRIDGE_EXIT_CODE%
echo ======================================================
echo.
echo Log file created: %LOG_FILE%
echo.

if %BRIDGE_EXIT_CODE% neq 0 (
    echo ❌ Bridge server failed to start properly
    echo 📋 Displaying last 20 lines of log file:
    echo ======================================================
    for /f "skip=1 delims=" %%i in ('powershell "Get-Content '%LOG_FILE%' | Select-Object -Last 20"') do echo %%i
    echo ======================================================
) else (
    echo ✅ Bridge server started successfully
)

echo.
echo Press any key to view the complete log file...
pause
type %LOG_FILE% 