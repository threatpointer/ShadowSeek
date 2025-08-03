@echo off
title ShadowSeek Flask Backend
echo ===== ShadowSeek Flask Backend =====
echo Python: .venv\Scripts\python.exe
echo Working Directory: C:\ShadowSeek
echo Log File: logs\flask_startup.log
echo =====================================
echo.

echo Testing Python executable...
".venv\Scripts\python.exe" --version
if errorlevel 1 (
    echo ERROR: Python executable failed
    pause
    exit /b 1
)

echo Testing Flask imports...
".venv\Scripts\python.exe" -c "import flask, flask_app; print('Flask imports OK')"
if errorlevel 1 (
    echo ERROR: Flask import failed
    pause
    exit /b 1
)

echo Starting Flask application...
".venv\Scripts\python.exe" run.py 2>&1 | ".venv\Scripts\python.exe" -c "import sys; import os; [print(line.rstrip(), flush=True) or (open(r'logs\flask_startup.log', 'a').write(line) if os.path.exists('logs') else None) for line in sys.stdin]"

echo.
echo Flask application stopped.
pause
