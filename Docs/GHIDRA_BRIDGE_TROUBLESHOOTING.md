# Ghidra Bridge Connection Troubleshooting Guide

This document provides troubleshooting steps for resolving Ghidra Bridge connection issues in the ShadowSeek application.

## Quick Status Check

1. **Check API Status**: Visit http://localhost:5000/api/status
   - Should show `"ghidra_bridge_connected": true` when working
   - If `false`, the bridge is not connected

2. **Check Frontend Status**: Visit http://localhost:3000
   - System Management section should show "Ghidra Bridge: Connected"
   - If showing "Disconnected", there's a connection issue

## Common Issues and Solutions

### 1. Bridge Server Not Starting

**Symptoms:**
- API status shows `ghidra_bridge_connected: false`
- Bridge server window closes immediately
- Error messages about missing files

**Solutions:**

#### Check Ghidra Installation Path
```bash
# Verify GHIDRA_INSTALL_DIR in .env file
echo $GHIDRA_INSTALL_DIR  # Linux/Mac
echo %GHIDRA_INSTALL_DIR%  # Windows

# Common correct paths:
# Windows: D:\1132-Ghidra\ghidra_11.3.2_PUBLIC
# Linux: /opt/ghidra
# Mac: /Applications/ghidra
```

#### Verify Required Files Exist
```bash
# Check if analyzeHeadless exists
ls "$GHIDRA_INSTALL_DIR/support/analyzeHeadless.bat"  # Windows
ls "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"     # Linux/Mac

# Check if bridge script exists
ls "$GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts/jfx_bridge/ghidra_bridge_server.py"
```

### 2. Wrong Connection Parameters

**Symptoms:**
- Bridge starts but Python client can't connect
- Connection timeout errors
- "Connection refused" errors

**Solutions:**

#### Use Correct GhidraBridge Parameters
```python
# CORRECT - Use these parameters
from ghidra_bridge import GhidraBridge
bridge = GhidraBridge(connect_to_host="localhost", connect_to_port=4768)

# INCORRECT - Don't use these
bridge = GhidraBridge(host="localhost", port=4768)  # Wrong parameter names
```

#### Verify Port is Available
```bash
# Check if port 4768 is in use
netstat -an | grep 4768  # Linux/Mac
netstat -an | findstr 4768  # Windows

# If port is in use, kill the process or change port
```

### 3. Script Execution Issues

**Symptoms:**
- Bridge starts but immediately exits
- Ghidra headless analyzer errors
- Script not found errors

**Solutions:**

#### Use Correct Script Parameters
```bash
# CORRECT - Use -postScript
analyzeHeadless.bat projects BridgeProject -postScript ghidra_bridge_server.py 4768

# INCORRECT - Don't use -script
analyzeHeadless.bat projects BridgeProject -script ghidra_bridge_server.py 4768
```

#### Ensure Script is in Correct Location
The `ghidra_bridge_server.py` should be in:
- `$GHIDRA_INSTALL_DIR/Ghidra/Features/Base/ghidra_scripts/jfx_bridge/`

### 4. Startup Sequence Issues

**Symptoms:**
- Services start but can't communicate
- Frontend shows "Network Error"
- Intermittent connection issues

**Solutions:**

#### Follow Correct Startup Order
1. Start Ghidra Bridge server first
2. Wait 15-20 seconds for full initialization
3. Start Flask backend
4. Start React frontend

#### Use Proper Startup Script
```batch
REM Use the working batch script approach
start "Ghidra Bridge Server" cmd /c "start_ghidra_bridge_new.bat"
timeout /t 15 > nul
start "Flask Backend" cmd /c "python run.py && pause"
```

## Testing Connection Manually

### Test Bridge Server
```python
# Test script to verify bridge connection
from ghidra_bridge import GhidraBridge
import time

try:
    print("Connecting to Ghidra Bridge...")
    bridge = GhidraBridge(connect_to_host="localhost", connect_to_port=4768)
    
    # Test basic functionality
    result = bridge.remote_eval("str(state)")
    print(f"Connected successfully: {result}")
    
except Exception as e:
    print(f"Connection failed: {e}")
```

### Test Flask API
```bash
# Test API endpoints
curl http://localhost:5000/api/status
curl http://localhost:5000/api/bridge/status
```

## Architecture Notes

### Working Configuration
- **Bridge Server**: Started via batch script using `analyzeHeadless.bat`
- **Connection**: Uses `connect_to_host` and `connect_to_port` parameters
- **Script Execution**: Uses `-postScript` flag, not `-script`
- **Port**: Default 4768 (configurable)

### File Structure
```
project/
├── start_all.bat                    # Main startup script
├── start_ghidra_bridge_new.bat     # Bridge server startup
├── flask_app/
│   ├── ghidra_bridge_manager.py     # Bridge connection manager
│   └── routes.py                    # API endpoints
└── .env                             # Environment configuration
```

## Environment Setup

### Required Environment Variables
```bash
# .env file
GHIDRA_INSTALL_DIR=D:\1132-Ghidra\ghidra_11.3.2_PUBLIC
GHIDRA_BRIDGE_PORT=4768
```

### Required Python Packages
```bash
pip install ghidra-bridge
pip install flask
pip install python-dotenv
```

## Debugging Tips

### Enable Debug Logging
```python
# In flask_app/ghidra_bridge_manager.py
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Check Process Status
```bash
# Windows - Check if Ghidra processes are running
tasklist | findstr java

# Linux/Mac - Check if Ghidra processes are running
ps aux | grep ghidra
```

### Common Error Messages

| Error | Cause | Solution |
|-------|-------|----------|
| "Connection refused" | Bridge not started or wrong port | Start bridge, check port |
| "Module not found" | Missing ghidra-bridge package | `pip install ghidra-bridge` |
| "Path not found" | Wrong GHIDRA_INSTALL_DIR | Update .env file |
| "Script not found" | Missing bridge script | Check script location |
| "Process exited" | Ghidra startup failure | Check Ghidra installation |

## Recovery Steps

If the bridge becomes unresponsive:

1. **Stop All Processes**
   ```bash
   # Windows
   taskkill /f /im java.exe
   
   # Linux/Mac
   pkill -f ghidra
   ```

2. **Clean Up Projects**
   ```bash
   rm -rf ghidra_projects/*
   ```

3. **Restart Services**
   ```bash
   ./start_all.bat  # Windows
   ```

## Performance Optimization

### Connection Caching
The Flask app caches bridge connections for 10 seconds to reduce overhead:
```python
self.connection_check_interval = 10  # seconds
```

### Timeout Settings
```python
# Adjust response timeout if needed
bridge = GhidraBridge(
    connect_to_host="localhost", 
    connect_to_port=4768,
    response_timeout=5  # seconds
)
```

---

**Last Updated**: Based on successful resolution of connection issues using batch script approach with `-postScript` parameter and correct `connect_to_host`/`connect_to_port` parameters. 