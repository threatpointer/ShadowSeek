@echo off
echo Starting Ghidra Bridge server...

:: Create logs directory if it doesn't exist
if not exist logs mkdir logs

:: Set timestamp for log file
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "YY=%dt:~2,2%" & set "YYYY=%dt:~0,4%" & set "MM=%dt:~4,2%" & set "DD=%dt:~6,2%"
set "HH=%dt:~8,2%" & set "Min=%dt:~10,2%" & set "Sec=%dt:~12,2%"
set "datestamp=%YYYY%-%MM%-%DD%_%HH%-%Min%-%Sec%"

:: Set log file path
set LOG_FILE=logs\ghidra_bridge_%datestamp%.log

echo ======================================== >> %LOG_FILE%
echo Ghidra Bridge Startup Log >> %LOG_FILE%
echo Started at: %datestamp% >> %LOG_FILE%
echo ======================================== >> %LOG_FILE%

:: Set Ghidra path from .env file or environment variable
if defined GHIDRA_INSTALL_DIR (
    set GHIDRA_PATH=%GHIDRA_INSTALL_DIR%
    echo Using GHIDRA_INSTALL_DIR from environment: %GHIDRA_PATH% >> %LOG_FILE%
) else (
    echo GHIDRA_INSTALL_DIR not set in environment, checking .env file... >> %LOG_FILE%
    set GHIDRA_PATH=
    if exist .env (
        echo Loading GHIDRA_INSTALL_DIR from .env file... >> %LOG_FILE%
        for /F "tokens=1,2 delims==" %%a in (.env) do (
            if "%%a"=="GHIDRA_INSTALL_DIR" (
                set GHIDRA_PATH=%%b
                echo Found GHIDRA_INSTALL_DIR: %%b >> %LOG_FILE%
            )
        )
    )
)

if "%GHIDRA_PATH%"=="" (
    echo ERROR: GHIDRA_INSTALL_DIR not found in environment or .env file >> %LOG_FILE%
    echo ERROR: GHIDRA_INSTALL_DIR not found in environment or .env file
    echo Please set GHIDRA_INSTALL_DIR environment variable or add it to .env file
    pause
    exit /b 1
)

echo Using Ghidra path: %GHIDRA_PATH% >> %LOG_FILE%

:: Create projects directory if it doesn't exist
set PROJECTS_DIR=ghidra_projects
if not exist %PROJECTS_DIR% (
    mkdir %PROJECTS_DIR%
    echo Created projects directory: %PROJECTS_DIR% >> %LOG_FILE%
)

:: Create a unique project name based on timestamp
set PROJECT_NAME=GhidraBridge_%random%
echo Using project name: %PROJECT_NAME% >> %LOG_FILE%

:: Set port
set PORT=4768
echo Using port: %PORT% >> %LOG_FILE%

:: Create a dummy file if it doesn't exist
if not exist %PROJECTS_DIR%\dummy.bin (
    echo dummy > %PROJECTS_DIR%\dummy.bin
    echo Created dummy file >> %LOG_FILE%
)

:: Start Ghidra Bridge server
echo Starting Ghidra Bridge server with project %PROJECT_NAME% on port %PORT%...
echo ======================================== >> %LOG_FILE%
echo STARTING GHIDRA BRIDGE SERVER >> %LOG_FILE%
echo Command: "%GHIDRA_PATH%\support\analyzeHeadless.bat" "%PROJECTS_DIR%" "%PROJECT_NAME%" -postScript ghidra_bridge_server.py "%PORT%" >> %LOG_FILE%
echo ======================================== >> %LOG_FILE%

:: The correct syntax for running a script with arguments - capture ALL output
"%GHIDRA_PATH%\support\analyzeHeadless.bat" "%PROJECTS_DIR%" "%PROJECT_NAME%" -postScript ghidra_bridge_server.py "%PORT%" >> %LOG_FILE% 2>&1

:: Log completion
echo ======================================== >> %LOG_FILE%
echo Ghidra Bridge server process completed >> %LOG_FILE%
echo Exit code: %ERRORLEVEL% >> %LOG_FILE%
echo ======================================== >> %LOG_FILE%

echo Ghidra Bridge server stopped.
echo Full log saved to: %LOG_FILE%
echo.
echo Press any key to view the log file...
pause
type %LOG_FILE% 