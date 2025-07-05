@echo off
echo ================================================
echo         Ghidra Bridge Log Viewer
echo ================================================
echo.

if not exist logs (
    echo No logs directory found. Please run start_all.bat first.
    pause
    exit /b 1
)

echo Available log files:
echo.
dir /b /o:-d logs\*.log 2>nul
echo.

echo ================================================
echo Showing latest Ghidra Bridge log:
echo ================================================

REM Find the most recent ghidra_bridge log file
for /f %%i in ('dir /b /o:-d logs\ghidra_bridge_*.log 2^>nul') do (
    set LATEST_LOG=%%i
    goto :found
)

:found
if "%LATEST_LOG%"=="" (
    echo No ghidra_bridge log files found.
    echo.
    echo Showing latest main startup log instead:
    for /f %%i in ('dir /b /o:-d logs\main_startup_*.log 2^>nul') do (
        set LATEST_LOG=%%i
        goto :show
    )
    echo No log files found at all.
    pause
    exit /b 1
)

:show
echo.
echo Viewing: logs\%LATEST_LOG%
echo ================================================
echo.
type "logs\%LATEST_LOG%"
echo.
echo ================================================
echo End of log file
echo.
pause 