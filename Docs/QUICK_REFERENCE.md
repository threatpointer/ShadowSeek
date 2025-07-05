# ShadowSeek Quick Reference Guide

**Version:** 2.0 with JFX Bridge Fixes + Enhanced Task Management  
**Status:** ✅ Production Ready

## New in Version 2.0 🆕

### Enhanced Binary Management
- **🛑 Stop Tasks**: Stop all running tasks for any binary (even during processing)
- **🗑️ Smart Delete**: Delete any binary regardless of status (automatically stops tasks first)
- **📊 Auto Status Updates**: Binary status automatically updates to "processed" when all functions are decompiled
- **⚙️ Improved Analysis**: "Restart Analysis" now uses comprehensive analysis for consistency

### UI Improvements
- **Simple Fuzzing Interface**: Clean, focused fuzzing interface in binary details (comprehensive dashboard still available in navigation)
- **Better Confirmations**: Enhanced delete confirmation with warnings for processing binaries
- **Real-time Feedback**: Toast notifications for all operations with detailed status updates
- **Visual Indicators**: Clear status indicators and tooltips for all actions

## Starting the System

### 🚀 Complete Startup
```bash
.\start_all.bat
```
**What it does:**
- Starts FIXED Ghidra Bridge server (port 4768)
- Starts Flask backend (port 5000)  
- Starts React frontend (port 3000)
- Creates timestamped logs in `logs/` directory

### Expected Output:
```
======================================================
   ShadowSeek - Starting Advanced Binary Security Analysis
   JFX Bridge Connection Issues: RESOLVED
======================================================

Starting Ghidra Bridge server with JFX execution fixes...
Using fixed bridge server script with proper port handling
Bridge server will log detailed output to logs\ directory
Waiting for Ghidra Bridge to initialize (fixed version)...

Starting Flask backend...
Starting React frontend...

======================================================
   Application started successfully!
   JFX Bridge Issues: RESOLVED AND WORKING
======================================================

Ghidra Bridge server: Running on port 4768 (FIXED)
  - JFX script execution: WORKING
  - Port argument handling: FIXED  
  - Connection persistence: STABLE
Flask backend running at: http://localhost:5000
React frontend running at: http://localhost:3000

Bridge logs available in: logs\ghidra_bridge_*.log
Use view_bridge_logs.bat to view latest bridge logs
```

---

## Stopping the System

### 🛑 Complete Shutdown
```bash
.\stop.bat
```
**What it does:**
- Stops all Python processes (Flask)
- Stops all Node.js processes (React)
- Stops all Java processes (Ghidra Bridge)
- Cleans up lock files
- Verifies shutdown completion

---

## Monitoring & Debugging

### 📋 View Bridge Logs
```bash
.\view_bridge_logs.bat
```
**Shows:** Latest bridge server startup and execution logs

### 🔍 Check System Status
```bash
python check_status.py
```
**Expected for working system:**
```json
{
  "binaries": 9,
  "ghidra_bridge": "connected",  ✅
  "ghidra_bridge_connected": true,
  "status": "ok"
}
```

### 🧪 Test Bridge Connection
```bash
python -c "from ghidra_bridge import GhidraBridge; bridge = GhidraBridge(connect_to_host='localhost', connect_to_port=4768); print('BRIDGE WORKING:'); print(bridge.remote_eval('str(state)'))"
```

---

## Task Management & Binary Operations

### 🛑 Stop Processing Tasks
If a binary is stuck in "Processing" status:
1. **In Dashboard**: Click the 🛑 **Stop** button next to the binary
2. **Result**: All running/queued tasks for that binary will be cancelled
3. **Status**: Binary status automatically updates to "processed"

### 🗑️ Delete Any Binary (New Feature)
You can now delete binaries even when they're processing:
1. **Click Delete Button**: Available for all binaries (no longer disabled for processing)
2. **Enhanced Confirmation**: Shows warning if binary is processing
3. **Automatic Task Stopping**: System automatically stops all tasks before deletion
4. **Complete Cleanup**: Removes binary, tasks, analysis data, security findings, and fuzzing harnesses

### 📊 Automatic Status Updates
- **Smart Detection**: System automatically detects when all functions are decompiled
- **Status Update**: Binary status changes from "analyzing" to "processed" automatically
- **Real-time**: Updates happen immediately when decompilation completes

### ⚙️ Analysis Operations
- **Restart Analysis**: Now uses comprehensive analysis (same as upload)
- **Simple Fuzzing**: Focused interface in binary details for quick harness generation
- **Comprehensive Fuzzing**: Full dashboard available via navigation menu

---

## Accessing the System

### 🌐 Web Interfaces
- **React Frontend:** http://localhost:3000
- **Flask API:** http://localhost:5000
- **API Status:** http://localhost:5000/api/status
- **Swagger Docs:** http://localhost:5000/api/docs

### 📁 Important Directories
- **Logs:** `logs/` - Bridge and system logs
- **Uploads:** `uploads/` - Binary file uploads
- **Projects:** `ghidra_projects/` - Ghidra analysis projects
- **Docs:** `Docs/` - System documentation

---

## Troubleshooting

### ❌ If Bridge Shows "disconnected"
1. Check bridge logs: `.\view_bridge_logs.bat`
2. Verify Java process running: `tasklist | findstr java`
3. Test direct connection (see above)
4. Restart system: `.\stop.bat` then `.\start_all.bat`

### ❌ If Flask won't start
1. Check Python process: `tasklist | findstr python`
2. Check port 5000: `netstat -an | findstr 5000`
3. Manual start: `python run.py`

### ❌ If React won't start
1. Check Node processes: `tasklist | findstr node`
2. Manual start: `cd frontend && npm start`

---

## Key Files

### 🔧 Core Scripts
- `start_all.bat` - Main startup script (UPDATED)
- `stop.bat` - Complete shutdown script (UPDATED)
- `start_ghidra_bridge_new.bat` - Bridge server startup with logging
- `view_bridge_logs.bat` - Log viewer utility

### 🔌 Bridge Components
- `ghidra_bridge_server_fixed.py` - Our fixed bridge server (source)
- `D:\1132-Ghidra\...\ghidra_bridge_server.py` - Deployed fixed version
- `ghidra_bridge_port.py` - Port configuration

### 📚 Documentation
- `Docs/JFX_BRIDGE_FIX_DOCUMENTATION.md` - Complete fix documentation
- `Docs/QUICK_REFERENCE.md` - This guide

---

## Success Indicators

### ✅ System Working Properly
- Bridge logs show: `INFO:jfx_bridge.bridge:serving!`
- Status API shows: `"ghidra_bridge": "connected"`
- Direct bridge test succeeds
- Flask backend responds on port 5000
- React frontend loads on port 3000

### ✅ JFX Bridge Fixed
- No immediate connection closures
- Scripts execute via `bridge.remote_eval()`
- Port arguments properly handled
- Background server mode working
- Persistent connections maintained

---

**The JFX Bridge connection issues have been completely resolved! 🎉** 