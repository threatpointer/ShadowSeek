@echo off
echo.
echo ======================================================
echo    ShadowSeek Environment Reset Utility
echo    Use this when encountering setup issues
echo ======================================================
echo.

echo 🧹 Cleaning up corrupted environments...
echo.

:: Remove virtual environment if it exists
if exist ".venv" (
    echo Removing corrupted virtual environment...
    rmdir /s /q .venv
    echo ✅ Virtual environment removed
) else (
    echo ℹ️ No virtual environment found
)

:: Remove Python cache
if exist "__pycache__" (
    echo Removing Python cache...
    for /d %%i in (__pycache__) do rmdir /s /q "%%i" 2>nul
)

if exist "*.pyc" (
    echo Removing .pyc files...
    del /s *.pyc >nul 2>&1
)

:: Remove UV cache if it exists
if exist ".uv" (
    echo Removing UV cache...
    rmdir /s /q .uv 2>nul
)

echo.
echo 🔧 Running fresh setup with pip fallback...
echo.

:: Run setup with clean environment and pip fallback
python setup_environment.py --force-clean --use-pip --auto

echo.
echo ======================================================
echo Reset complete! 
echo If issues persist, try manual installation:
echo   pip install --user flask flask-sqlalchemy flask-cors requests python-dotenv ghidra-bridge werkzeug
echo ======================================================
echo.

pause 