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

:: Create a unique project name based on timestamp
set PROJECT_NAME=GhidraBridge_%random%

:: Set port
set PORT=4768

:: Create a dummy file if it doesn't exist
if not exist %PROJECTS_DIR%\dummy.bin (
    echo dummy > %PROJECTS_DIR%\dummy.bin
)

:: Start Ghidra Bridge server
echo Starting Ghidra Bridge server with project %PROJECT_NAME% on port %PORT%...

:: The correct syntax for running a script with arguments
"%GHIDRA_PATH%\support\analyzeHeadless.bat" "%PROJECTS_DIR%" "%PROJECT_NAME%" -postScript ghidra_bridge_server.py "%PORT%"

echo Ghidra Bridge server stopped.
pause 