@echo off
REM ShadowSeek Environment Setup Script for Windows
REM This script configures the ShadowSeek environment by:
REM - Installing missing Python dependencies automatically
REM - Auto-detecting Ghidra installations 
REM - Creating .env configuration file
REM - Starting ShadowSeek components automatically
REM - Testing all connections and validations

setlocal EnableDelayedExpansion

echo =====================================================
echo 🚀 ShadowSeek Environment Setup (Windows)
echo =====================================================
echo.

REM Check Python installation
echo 🐍 Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

python --version
echo ✅ Python is available

REM Check system requirements
echo.
echo 🔍 Checking System Requirements...

REM Check Node.js
echo Checking Node.js...
node --version >nul 2>&1
if errorlevel 1 (
    echo ⚠️ Node.js not found - required for React frontend
    echo Please install from https://nodejs.org/
    set "missing_deps=true"
) else (
    for /f %%i in ('node --version') do set "node_version=%%i"
    echo ✅ Node.js !node_version! found
    
    REM Check npm
    npm --version >nul 2>&1
    if errorlevel 1 (
        echo ⚠️ npm not found
        set "missing_deps=true"
    ) else (
        for /f %%i in ('npm --version') do set "npm_version=%%i"
        echo ✅ npm !npm_version! found
    )
)

REM Check Java
echo Checking Java JDK...
java -version >nul 2>&1
if errorlevel 1 (
    echo ⚠️ Java not found - required for Ghidra operations
    echo Please install from https://adoptium.net/
    set "missing_deps=true"
) else (
    for /f %%i in ('java -version 2^>^&1 ^| findstr "version"') do (
        echo ✅ Java found: %%i
    )
    
    REM Check if JDK is available (has javac)
    javac -version >nul 2>&1
    if errorlevel 1 (
        echo ⚠️ Java JRE found, but JDK recommended for development
    ) else (
        echo ✅ Java JDK available
    )
)

REM Check Git (optional)
echo Checking Git...
git --version >nul 2>&1
if errorlevel 1 (
    echo ⚠️ Git not found - recommended for development
) else (
    for /f %%i in ('git --version') do echo ✅ %%i
)

if defined missing_deps (
    echo.
    echo ⚠️ Some system requirements are missing
    echo The setup will continue, but some features may not work properly
    echo.
    pause
)

REM Install/upgrade pip and dependencies
echo.
echo 🔧 Installing Python dependencies...
echo Upgrading pip...
python -m pip install --upgrade pip --quiet
if errorlevel 1 (
    echo ⚠️ pip upgrade failed, continuing with existing pip
) else (
    echo ✅ pip upgraded successfully
)

echo Installing required packages...
set "packages=flask>=2.0 flask-sqlalchemy>=3.0 flask-cors>=4.0 requests>=2.28 python-dotenv>=1.0 ghidra-bridge>=0.2 werkzeug>=2.0"

for %%p in (%packages%) do (
    echo Installing %%p...
    python -m pip install "%%p" --quiet
    if errorlevel 1 (
        echo ❌ Failed to install %%p
        set "failed=true"
    ) else (
        echo ✅ %%p installed
    )
)

REM Try requirements.txt as fallback if any packages failed
if defined failed (
    if exist requirements.txt (
        echo.
        echo 🔄 Trying requirements.txt as fallback...
        python -m pip install -r requirements.txt --quiet
        if errorlevel 1 (
            echo ❌ requirements.txt installation also failed
            echo You may need to install dependencies manually
        ) else (
            echo ✅ requirements.txt installation completed
        )
    )
)

REM Test installed packages
echo.
echo 🧪 Testing Python dependencies...
python -c "import flask" 2>nul && echo ✅ ✓ flask || echo ❌ ✗ flask
python -c "import flask_sqlalchemy" 2>nul && echo ✅ ✓ flask_sqlalchemy || echo ❌ ✗ flask_sqlalchemy  
python -c "import flask_cors" 2>nul && echo ✅ ✓ flask_cors || echo ❌ ✗ flask_cors
python -c "import requests" 2>nul && echo ✅ ✓ requests || echo ❌ ✗ requests
python -c "import dotenv" 2>nul && echo ✅ ✓ python-dotenv || echo ❌ ✗ python-dotenv
python -c "import ghidra_bridge" 2>nul && echo ✅ ✓ ghidra_bridge || echo ❌ ✗ ghidra_bridge

echo.
echo 🔍 Searching for Ghidra installations...

REM Search for Ghidra in common locations
set "ghidra_found="
set "ghidra_path="

REM Check common Windows paths for Ghidra
for %%d in ("C:\ghidra*" "C:\Program Files\ghidra*" "C:\Program Files (x86)\ghidra*" "D:\ghidra*" "%USERPROFILE%\ghidra*" "%USERPROFILE%\Downloads\ghidra*") do (
    if exist "%%~d\support\analyzeHeadless.bat" (
        set "ghidra_path=%%~d"
        set "ghidra_found=true"
        echo ✅ Found Ghidra: %%~d
        goto :found_ghidra
    ) else if exist "%%~d\support\ghidra.jar" (
        set "ghidra_path=%%~d"
        set "ghidra_found=true"
        echo ✅ Found Ghidra: %%~d
        goto :found_ghidra
    )
)

REM If not found, check for directories and validate them
for /d %%d in ("C:\ghidra*") do (
    if exist "%%d\support\analyzeHeadless.bat" (
        set "ghidra_path=%%d"
        set "ghidra_found=true"
        echo ✅ Found Ghidra: %%d
        goto :found_ghidra
    ) else if exist "%%d\support\ghidra.jar" (
        set "ghidra_path=%%d"
        set "ghidra_found=true"
        echo ✅ Found Ghidra: %%d
        goto :found_ghidra
    )
)

for /d %%d in ("C:\Program Files\ghidra*") do (
    if exist "%%d\support\analyzeHeadless.bat" (
        set "ghidra_path=%%d"
        set "ghidra_found=true"  
        echo ✅ Found Ghidra: %%d
        goto :found_ghidra
    ) else if exist "%%d\support\ghidra.jar" (
        set "ghidra_path=%%d"
        set "ghidra_found=true"  
        echo ✅ Found Ghidra: %%d
        goto :found_ghidra
    )
)

for /d %%d in ("D:\ghidra*") do (
    if exist "%%d\support\analyzeHeadless.bat" (
        set "ghidra_path=%%d"
        set "ghidra_found=true"
        echo ✅ Found Ghidra: %%d
        goto :found_ghidra
    ) else if exist "%%d\support\ghidra.jar" (
        set "ghidra_path=%%d"
        set "ghidra_found=true"
        echo ✅ Found Ghidra: %%d
        goto :found_ghidra
    )
)

for /d %%d in ("%USERPROFILE%\ghidra*") do (
    if exist "%%d\support\analyzeHeadless.bat" (
        set "ghidra_path=%%d"
        set "ghidra_found=true"
        echo ✅ Found Ghidra: %%d
        goto :found_ghidra
    ) else if exist "%%d\support\ghidra.jar" (
        set "ghidra_path=%%d"
        set "ghidra_found=true"
        echo ✅ Found Ghidra: %%d
        goto :found_ghidra
    )
)

:found_ghidra
if not defined ghidra_found (
    echo ⚠️ No Ghidra installation found automatically
    echo.
    set /p "ghidra_path=Enter Ghidra installation path (or press Enter to skip): "
)

echo.
echo ⚙️ Configuration Setup
echo.

REM Use found path or get from user
if defined ghidra_found (
    echo Using found Ghidra installation: !ghidra_path!
    echo Press Enter to use this path, or type a different path:
    set /p "user_ghidra=Ghidra path [!ghidra_path!]: "
    if not "!user_ghidra!"=="" (
        set "ghidra_path=!user_ghidra!"
    )
)

REM Validate Ghidra path if provided
if not "!ghidra_path!"=="" (
    if exist "!ghidra_path!\support\analyzeHeadless.bat" (
        echo ✅ Ghidra installation validated ^(analyzeHeadless.bat found^)
    ) else if exist "!ghidra_path!\support\ghidra.jar" (
        echo ✅ Ghidra installation validated ^(ghidra.jar found^)
    ) else (
        echo ❌ Invalid Ghidra installation: !ghidra_path!
        echo The path should contain a 'support' directory with analyzeHeadless.bat or ghidra.jar
        if exist "!ghidra_path!\support" (
            echo ℹ️ Support directory exists, but missing key Ghidra files
        ) else (
            echo ℹ️ Missing 'support' directory in Ghidra installation
        )
        pause
        exit /b 1
    )
)

REM Get other configuration with defaults
set /p "bridge_port=Ghidra Bridge port [4768]: "
if "!bridge_port!"=="" set "bridge_port=4768"

set /p "flask_port=Flask server port [5000]: "
if "!flask_port!"=="" set "flask_port=5000"

set /p "temp_dir=Ghidra temp directory [./temp/ghidra_temp]: "
if "!temp_dir!"=="" set "temp_dir=./temp/ghidra_temp"

set /p "projects_dir=Ghidra projects directory [./ghidra_projects]: "
if "!projects_dir!"=="" set "projects_dir=./ghidra_projects"

set /p "upload_dir=Upload folder [./uploads]: "
if "!upload_dir!"=="" set "upload_dir=./uploads"

set /p "log_dir=Log folder [./logs]: "
if "!log_dir!"=="" set "log_dir=./logs"

echo.
echo 📝 Creating .env file...

REM Create .env file
(
echo # ShadowSeek Environment Configuration
echo # Generated on %DATE% %TIME%
echo.
echo # Core Configuration  
echo GHIDRA_INSTALL_DIR=!ghidra_path!
echo GHIDRA_BRIDGE_PORT=!bridge_port!
echo FLASK_PORT=!flask_port!
echo.
echo # Directory Configuration
echo GHIDRA_TEMP_DIR=!temp_dir!
echo GHIDRA_PROJECTS_DIR=!projects_dir!
echo UPLOAD_FOLDER=!upload_dir!
echo TEMP_FOLDER=./temp
echo LOG_FOLDER=!log_dir!
echo.
echo # Network Configuration
echo GHIDRA_BRIDGE_HOST=127.0.0.1
echo FLASK_HOST=127.0.0.1
echo.
echo # AI Service Configuration ^(Optional^)
echo LLM_PROVIDER=openai
echo # OPENAI_API_KEY=your_key_here
echo # OPENAI_MODEL=gpt-3.5-turbo
echo # LLM_TEMPERATURE=0.3
echo.
echo # Database Configuration
echo DATABASE_URL=sqlite:///instance/shadowseek.db
) > .env

echo ✅ .env file created successfully

REM Create required directories
echo.
echo 📁 Creating directories...

for %%d in ("!temp_dir!" "!projects_dir!" "!upload_dir!" "./temp" "!log_dir!" "./instance") do (
    if not exist "%%~d" (
        mkdir "%%~d" 2>nul
        if exist "%%~d" (
            echo ✅ ✓ %%~d
        ) else (
            echo ❌ ✗ Failed to create %%~d
        )
    ) else (
        echo ✅ ✓ %%~d ^(already exists^)
    )
)

REM Start ShadowSeek components
echo.
echo 🚀 Starting ShadowSeek components...

if exist "start_all.bat" (
    echo Starting all components automatically...
    start "" "start_all.bat"
    
    echo Components starting up... ^(waiting 3 seconds^)
    timeout /t 3 /nobreak >nul
    
    echo ✅ ShadowSeek components started successfully
) else (
    echo ⚠️ start_all.bat not found - components not started automatically
)

REM Test component connectivity
echo.
echo 🌐 Testing Component Connectivity

REM Test Flask backend
echo Testing Flask backend...
powershell -Command "try { $test = New-Object System.Net.Sockets.TcpClient('127.0.0.1', !flask_port!); $test.Close(); Write-Host '✅ ✓ Flask backend (127.0.0.1:!flask_port!)' } catch { Write-Host '⚠️ ✗ Flask backend (127.0.0.1:!flask_port!) - Not running or not ready yet' }" 

REM Test Ghidra Bridge  
echo Testing Ghidra Bridge...
powershell -Command "try { $test = New-Object System.Net.Sockets.TcpClient('127.0.0.1', !bridge_port!); $test.Close(); Write-Host '✅ ✓ Ghidra Bridge (127.0.0.1:!bridge_port!)' } catch { Write-Host '⚠️ ✗ Ghidra Bridge (127.0.0.1:!bridge_port!) - Not running or not ready yet' }"

REM Test Frontend
echo Testing Frontend...
powershell -Command "try { $test = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 3000); $test.Close(); Write-Host '✅ ✓ Frontend (127.0.0.1:3000)' } catch { Write-Host '⚠️ ✗ Frontend (127.0.0.1:3000) - Not running or not ready yet' }"

REM Final summary
echo.
echo =====================================================
echo ✅ Setup Complete!
echo =====================================================
echo Configuration saved to .env
echo.
echo Access ShadowSeek:
echo   - Frontend: http://localhost:3000
echo   - Backend:  http://localhost:!flask_port!
echo.
echo Note: Some components may still be starting up.
echo If any components show as not ready, wait a moment
echo and check the opened command windows for status.
echo =====================================================

pause 