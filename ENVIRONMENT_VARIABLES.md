# Environment Variables Configuration Guide

This document outlines all the environment variables you need to configure for ShadowSeek to work on your system. **All system-dependent hardcoded paths have been removed** to ensure the application works across different systems.

## 🔧 Required Environment Variables

### Ghidra Configuration
```bash
# REQUIRED: Path to your Ghidra installation directory
GHIDRA_INSTALL_DIR=/path/to/your/ghidra/installation

# Examples:
# Windows: GHIDRA_INSTALL_DIR=C:\Program Files\Ghidra
# Linux: GHIDRA_INSTALL_DIR=/opt/ghidra
# macOS: GHIDRA_INSTALL_DIR=/Applications/ghidra
```

### Optional System Configuration
```bash
# Optional: Custom temp directory for Ghidra analysis (defaults to ./temp)
GHIDRA_TEMP_DIR=/path/to/temp/directory

# Optional: Custom projects directory (defaults to ./ghidra_projects) 
GHIDRA_PROJECTS_DIR=/path/to/projects


```

## 📝 Setting Environment Variables

### Windows
```cmd
# Temporary (current session only)
set GHIDRA_INSTALL_DIR=C:\Program Files\Ghidra

# Permanent (system-wide)
setx GHIDRA_INSTALL_DIR "C:\Program Files\Ghidra"

# Or add to your .env file:
echo GHIDRA_INSTALL_DIR=C:\Program Files\Ghidra >> .env
```

### Linux/macOS
```bash
# Temporary (current session only)
export GHIDRA_INSTALL_DIR=/opt/ghidra

# Permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra' >> ~/.bashrc

# Or add to your .env file:
echo 'GHIDRA_INSTALL_DIR=/opt/ghidra' >> .env
```

## 🏗️ System Setup Steps

1. **Install Ghidra** on your system
2. **Set GHIDRA_INSTALL_DIR** environment variable to point to your Ghidra installation
3. **Copy .env.example to .env** and configure your paths
4. **Run the application** - it will now use your configured paths

## 🚫 What Was Removed

The following hardcoded paths were removed to make the system portable:

- `D:\1132-Ghidra\ghidra_11.3.2_PUBLIC` (specific user installation)
- `D:\Projects\ShadowSeek\instance\shadowseek.db` (specific project path)
- `~/ghidra_temp` (hardcoded user temp directory)
- Various fallback path arrays with system-specific paths

## 🔍 Troubleshooting

### "Ghidra installation not found" Error
- Ensure GHIDRA_INSTALL_DIR is set correctly
- Verify the path exists and contains a valid Ghidra installation
- Check that the path doesn't have trailing spaces or quotes

### "Bridge connection failed" Error  
- Verify Ghidra Bridge is installed in your Ghidra installation
- Check that GHIDRA_BRIDGE_PORT is not blocked by firewall
- Ensure no other applications are using the bridge port

### Path Issues on Windows
- Use double backslashes: `C:\\Program Files\\Ghidra`
- Or use forward slashes: `C:/Program Files/Ghidra`
- Wrap paths with spaces in quotes

## 📋 Example .env Configuration

```bash
# Ghidra Configuration
GHIDRA_INSTALL_DIR=/opt/ghidra
GHIDRA_MAX_PROCESSES=4
GHIDRA_TIMEOUT=3600
GHIDRA_TEMP_DIR=/tmp/ghidra_temp

# Ghidra Bridge Configuration  
GHIDRA_BRIDGE_HOST=127.0.0.1
GHIDRA_BRIDGE_PORT=4768

# Flask Configuration
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_ENV=development
FLASK_SECRET_KEY=your-secret-key-here

# File Upload Configuration
MAX_FILE_SIZE=1073741824
UPLOAD_FOLDER=./uploads
TEMP_FOLDER=./temp


```

Now your ShadowSeek installation will work on any system with proper environment variable configuration! 🎉 