# ShadowSeek Setup Scripts Guide

## 🚀 **Enhanced Setup System with Auto-Installation**

The ShadowSeek setup scripts now feature **automatic dependency installation**, making the setup process completely streamlined. No more manual package installation required!

## 📋 **Available Scripts**

### **1. Primary Setup Script: `setup_environment.py`**

**Complete automated setup with dependency installation**

```bash
# Basic setup - installs dependencies and configures everything
python setup_environment.py

# Automated mode - no prompts, uses smart defaults
python setup_environment.py --auto

# Advanced options
python setup_environment.py --ghidra-path "/path/to/ghidra"
python setup_environment.py --skip-install    # Skip dependency installation
python setup_environment.py --skip-startup    # Skip automatic startup
```

**✨ New Features**:
- **🔧 Auto-Installation**: Automatically installs missing Python packages
- **📊 Progress Tracking**: Real-time installation progress
- **🛡️ Error Recovery**: Multiple fallback strategies
- **✅ Package Validation**: Tests packages immediately after installation
- **🎯 Smart Defaults**: Auto-detects Ghidra and uses sensible defaults

### **2. Windows Batch Script: `setup_environment.bat`**

**Windows-native setup with dependency installation**

```batch
# Simply run the batch file
setup_environment.bat
```

**✨ Enhanced Features**:
- **🔧 Auto-Install**: Automatic pip package installation
- **📋 Individual Tracking**: Installs packages one-by-one with progress
- **🔄 Fallback Strategy**: Uses requirements.txt if individual installs fail  
- **✅ Real-time Testing**: Tests each package immediately
- **🌐 Network Testing**: PowerShell-based connectivity validation

## 🎯 **System Requirements Checking & Auto-Installation**

The setup scripts now perform **comprehensive system dependency checking** and can automatically install missing components:

### **🔍 What Gets Checked**

#### **System Dependencies**:
- **Python 3.8+**: Core runtime environment
- **Node.js 16+**: Required for React frontend development and building
- **npm**: Package manager for frontend dependencies  
- **Java JDK 11+**: Required for Ghidra operations
- **Git**: Recommended for development (optional)

#### **Python Dependencies** (via UV or pip):
- **Flask ecosystem**: flask, flask-sqlalchemy, flask-cors, werkzeug
- **Environment management**: python-dotenv
- **Ghidra integration**: ghidra-bridge
- **HTTP/Network**: requests

### **🚀 What Gets Auto-Installed**

#### **System Tools** (where supported):
- **Node.js + npm**: Via winget, chocolatey, brew, apt, yum
- **Java JDK**: Via winget, chocolatey, brew, apt, yum  
- **Python packages**: Via UV sync or individual pip installation

#### **Installation Methods by Platform**:

**Windows**:
- **winget**: `winget install OpenJS.NodeJS`, `winget install Microsoft.OpenJDK.17`
- **chocolatey**: `choco install nodejs openjdk -y`

**macOS**:
- **Homebrew**: `brew install node openjdk@17`

**Linux**:
- **apt** (Ubuntu/Debian): `sudo apt install nodejs npm openjdk-17-jdk`
- **yum** (CentOS/RHEL): `sudo yum install nodejs npm java-17-openjdk-devel`

### **📋 Command Options**

```bash
# Complete system check and setup
python setup_environment.py

# Skip system requirements check
python setup_environment.py --skip-system-check

# Auto mode - automatically install missing dependencies
python setup_environment.py --auto

# Skip specific types of installation
python setup_environment.py --skip-install    # Skip Python packages
```

## 🎯 **Usage Examples**

### **Complete Automated Setup**
```bash
# One command does everything:
# - Installs missing dependencies
# - Detects Ghidra installation
# - Creates .env configuration
# - Starts all components
# - Tests connectivity
python setup_environment.py --auto
```

### **Custom Ghidra Path**
```bash
# Specify Ghidra installation location
python setup_environment.py --ghidra-path "D:\Tools\ghidra_11.3.2"
```

### **Advanced Users**
```bash
# Skip automatic dependency installation
python setup_environment.py --skip-install

# Skip component startup (configure only)
python setup_environment.py --skip-startup
```

### **Troubleshooting Mode**
```bash
# Install dependencies only
python setup_environment.py --skip-startup --ghidra-path ""
```

## ✨ **What Gets Installed/Configured**

### **🔧 Dependencies Automatically Installed**:
- **Flask ecosystem**: Flask, SQLAlchemy, CORS, Werkzeug
- **HTTP/Network**: Requests library
- **Environment**: python-dotenv for .env file management
- **Ghidra Integration**: ghidra-bridge for Ghidra communication

### **📁 Files Created**:
- `.env` - Complete environment configuration
- Required directories (uploads, temp, logs, etc.)
- Database directory structure

### **⚙️ Configuration Generated**:
```bash
# Core Configuration
GHIDRA_INSTALL_DIR=/detected/or/specified/path
GHIDRA_BRIDGE_PORT=4768
FLASK_PORT=5000

# Directory Structure  
GHIDRA_TEMP_DIR=./temp/ghidra_temp
GHIDRA_PROJECTS_DIR=./ghidra_projects
UPLOAD_FOLDER=./uploads
TEMP_FOLDER=./temp
LOG_FOLDER=./logs

# Network Configuration
GHIDRA_BRIDGE_HOST=127.0.0.1
FLASK_HOST=127.0.0.1

# Database
DATABASE_URL=sqlite:///instance/shadowseek.db
```

## 🚀 **Component Startup**

After configuration, the scripts automatically:

1. **🌉 Start Ghidra Bridge**: Background bridge server
2. **🐍 Start Flask Backend**: API server on configured port  
3. **⚛️ Start React Frontend**: Development server on port 3000
4. **🔍 Test Connectivity**: Validate all components are running

## 🛠️ **Troubleshooting**

### **System Dependency Issues**

#### **Problem**: Node.js not found
```bash
⚠️ Node.js not found - required for React frontend
```

**Solutions**:
1. **Auto-install**: Let the script install it automatically
2. **Manual install**: Download from https://nodejs.org/
3. **Package manager**: 
   - Windows: `winget install OpenJS.NodeJS` or `choco install nodejs`
   - macOS: `brew install node`
   - Linux: `sudo apt install nodejs npm`

#### **Problem**: Java JDK not found
```bash
⚠️ Java not found - required for Ghidra operations
```

**Solutions**:
1. **Auto-install**: Let the script install OpenJDK 17 automatically
2. **Manual install**: Download from https://adoptium.net/
3. **Package manager**:
   - Windows: `winget install Microsoft.OpenJDK.17`
   - macOS: `brew install openjdk@17`
   - Linux: `sudo apt install openjdk-17-jdk`

#### **Problem**: System installation fails
```bash
❌ Automatic Node.js installation failed
```

**Solutions**:
1. **Check permissions**: Run as administrator/sudo if needed
2. **Install package manager**: Install winget, chocolatey, brew, etc.
3. **Manual installation**: Follow manual installation links provided
4. **Network issues**: Check internet connection and proxy settings

### **Ghidra Detection Issues**

#### **Problem**: Ghidra not found automatically
```bash
⚠️ No Ghidra installation found automatically
```

**Solutions**:
1. **Specify path**: Use `--ghidra-path` option
2. **Check installation**: Ensure `support/ghidra.jar` exists in Ghidra directory
3. **Common locations**: Check C:\ghidra*, Program Files, Downloads folders
4. **Download Ghidra**: Get latest version from NSA GitHub

### **Component Startup Issues**

#### **Problem**: Components not starting
```bash
⚠️ start_all.bat not found - components not started automatically
```

**Solutions**:
1. **Check files**: Ensure `start_all.bat` exists in project root
2. **Manual startup**: Run `start_all.bat` manually
3. **Platform issues**: Use `start_all.sh` on Linux/macOS

#### **Problem**: Network connectivity test fails  
```bash
⚠️ ✗ Flask backend (127.0.0.1:5000) - Not running or not ready yet
```

**Solutions**:
1. **Wait longer**: Components may still be starting up
2. **Check logs**: Look in logs/ directory for error messages
3. **Port conflicts**: Ensure ports 5000, 4768, 3000 are available
4. **Firewall**: Check Windows/antivirus firewall settings

### **Windows-Specific Issues**

#### **Problem**: PowerShell execution policy
```batch
PowerShell execution policy prevents network testing
```

**Solutions**:
1. **Run as administrator**: Use elevated command prompt
2. **Set policy**: `powershell -ExecutionPolicy Bypass`
3. **Alternative**: Use Python script instead of batch

#### **Problem**: Path with spaces
```batch
❌ Invalid Ghidra installation: C:\Program Files\Ghidra 11.3.2
```

**Solutions**:
1. **Quote paths**: Ensure paths with spaces are properly quoted
2. **Use forward slashes**: Try `C:/Program Files/Ghidra 11.3.2`
3. **Short paths**: Use `C:\PROGRA~1\GHIDRA~1.2` format if needed

## 🎉 **Success Indicators**

### **Successful Setup**:
```bash
✅ All dependencies installed successfully
✅ Ghidra installation validated  
✅ .env file created successfully
✅ All directories created
✅ ShadowSeek components started successfully
🎉 All 3 components are running!
✅ Setup Complete!
```

### **Ready to Use**:
- **Frontend**: http://localhost:3000
- **Backend**: http://localhost:5000  
- **Components**: All running in background

### **Configuration Files**:
- `.env` - Your environment configuration
- `logs/` - Component logs for troubleshooting
- Generated directory structure ready for use

## 📚 **Additional Resources**

- **Environment Variables**: `ENVIRONMENT_VARIABLES.md`
- **User Documentation**: `user-docs/`
- **Quick Testing**: `quick_test.py`
- **Comprehensive Validation**: `test_configuration.py`

## 🔄 **Updates and Maintenance**

### **Updating Dependencies**
```bash
# Re-run setup to update packages
python setup_environment.py --skip-startup

# Or manually update
pip install -r requirements.txt --upgrade
```

### **Reconfiguration**
```bash
# Reconfigure without affecting dependencies
python setup_environment.py --skip-install
```

The enhanced setup scripts with automatic dependency installation make ShadowSeek much easier to deploy and get running quickly! 🚀 