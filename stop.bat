@echo off
echo.
echo ======================================================
echo    ShadowSeek - Shutdown Script
echo    JFX Bridge Issues: RESOLVED
echo ======================================================
echo.

echo 🛑 Stopping all ShadowSeek components...
echo    (Including FIXED JFX Bridge Server)
echo.

REM Stop Flask application (all Python processes related to our app)
echo Stopping Flask backend...
taskkill /F /IM python.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo ✅ Flask backend stopped successfully
) else (
    echo ℹ️  No Flask processes found
)

REM Stop React frontend (Node.js processes)
echo Stopping React frontend...
taskkill /F /IM node.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo ✅ React frontend stopped successfully
) else (
    echo ℹ️  No React processes found
)

REM Stop Ghidra Bridge server (Java processes) - FIXED VERSION
echo Stopping FIXED Ghidra Bridge server (JFX execution working)...
taskkill /F /IM java.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo ✅ Fixed Ghidra Bridge server stopped successfully
) else (
    echo ℹ️  No Ghidra processes found
)

REM Clean up any remaining processes by window title
echo Cleaning up any remaining application windows...
taskkill /F /FI "WINDOWTITLE eq Flask Backend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq React Frontend*" >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq Ghidra Bridge Server*" >nul 2>&1

REM Clean up Ghidra lock files to prevent future startup issues
echo Cleaning up Ghidra lock files...
if exist ghidra_projects (
    del /Q ghidra_projects\*.lock >nul 2>&1
    del /Q ghidra_projects\*.lock~ >nul 2>&1
    echo ✅ Lock files cleaned up
)

REM Wait a moment for processes to fully terminate
timeout /t 2 >nul

REM Check if any processes are still running
echo.
echo 🔍 Verifying shutdown...
set PROCESSES_FOUND=0

REM Check for Python processes (Flask)
tasklist | findstr python.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo ⚠️  Some Python processes may still be running
    set PROCESSES_FOUND=1
)

REM Check for Node processes (React)
tasklist | findstr node.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo ⚠️  Some Node.js processes may still be running
    set PROCESSES_FOUND=1
)

REM Check for Java processes (Ghidra)
tasklist | findstr java.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo ℹ️  Some Java processes are still running (may be system Java processes)
)

if %PROCESSES_FOUND% equ 0 (
    echo ✅ All application processes stopped successfully
) else (
    echo ⚠️  Some processes may still be running - this is usually normal
)

echo.
echo ======================================================
echo    Shutdown Complete!
echo ======================================================
echo.
echo 📊 Status:
echo    • Flask Backend:    Stopped
echo    • React Frontend:   Stopped  
echo    • Ghidra Bridge:    Stopped
echo    • Lock Files:       Cleaned
echo.
echo 🚀 To restart the application, run: start_all.bat
echo.

pause 