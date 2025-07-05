@echo off
echo ===================================================
echo Ghidra Web Analyzer - Shutdown Script
echo ===================================================
echo.

echo Stopping Flask application...
taskkill /f /im python.exe /fi "WINDOWTITLE eq Flask Server*" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo Flask server stopped successfully.
) else (
    echo No Flask server process found.
)

echo.
echo Stopping React frontend...
taskkill /f /im node.exe /fi "WINDOWTITLE eq React Frontend*" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo React frontend stopped successfully.
) else (
    echo No React frontend process found.
)

echo.
echo Stopping any remaining Ghidra processes...
taskkill /f /im java.exe /fi "WINDOWTITLE eq Ghidra*" >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo Ghidra processes stopped successfully.
) else (
    echo No Ghidra processes found.
)

echo.
echo ===================================================
echo All components stopped successfully!
echo =================================================== 