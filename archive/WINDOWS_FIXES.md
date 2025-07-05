# Windows Compatibility Fixes

## 🔧 **Issues Resolved**

### 1. Celery Permission Errors on Windows
**Problem:** Celery worker was failing with `PermissionError: [WinError 5] Access is denied` when using the default `prefork` pool on Windows.

**Root Cause:** The `prefork` pool uses shared memory and multiprocessing features that have permission restrictions on Windows.

**Solution:** Configured Celery to use the `threads` pool on Windows instead of `prefork`.

### 2. Flask Backend Not Starting
**Problem:** React frontend was getting `ECONNREFUSED` errors when trying to proxy requests to Flask backend at localhost:5000.

**Root Cause:** Flask backend was not being properly started in the background by the start.bat script.

**Solution:** Modified start.bat to properly launch Flask backend in a separate window.

## 🛠️ **Changes Made**

### 1. Configuration Changes (`flask_app/config.py`)
Added Windows-specific Celery configuration:

```python
# Windows-specific Celery configuration to fix permission issues
if platform.system() == 'Windows':
    CELERY_WORKER_POOL = 'threads'  # Use threads instead of prefork on Windows
    CELERY_WORKER_CONCURRENCY = 4  # Limit concurrency on Windows
    CELERY_WORKER_PREFETCH_MULTIPLIER = 1
    CELERY_WORKER_MAX_TASKS_PER_CHILD = 50
else:
    CELERY_WORKER_POOL = 'prefork'  # Use prefork on Unix-like systems
    CELERY_WORKER_CONCURRENCY = 2
```

### 2. Startup Script Changes (`start.bat`)

**Celery Worker:**
```batch
REM Start Celery worker in background (Windows-compatible with threads pool)
echo Starting Windows-compatible Celery worker (threads pool, 4 concurrent)...
start "Celery Worker" uv run celery -A flask_app.tasks worker --loglevel=info --pool=threads --concurrency=4 --prefetch-multiplier=1 --max-tasks-per-child=50
```

**Flask Backend:**
```batch
REM Start Flask application in background
echo Starting Flask application with enhanced API endpoints...
start "Flask Backend" uv run python run.py

REM Wait for Flask to start
timeout /t 5 /nobreak >nul
```

### 3. Stop Script Changes (`stop.bat`)
Added proper cleanup for Flask Backend window:

```batch
REM Stop Flask Backend
for /f "tokens=2" %%i in ('tasklist /FI "WINDOWTITLE eq Flask Backend" /FO CSV /NH 2^>NUL') do (
    if not "%%i"=="INFO:" (
        echo [INFO] Stopping Flask Backend...
        taskkill /F /T /FI "WINDOWTITLE eq Flask Backend" >nul 2>&1
    )
)
```

## ✅ **Verification Results**

All fixes have been tested and verified:
- ✅ **Platform Detection**: Correctly identifies Windows
- ✅ **Configuration Loading**: Windows-specific Celery settings applied
- ✅ **Flask App Creation**: App, SocketIO, and Celery properly attached
- ✅ **Celery Tasks Import**: All expected tasks registered
- ✅ **RabbitMQ Connection**: Successful connection to message broker

## 🎯 **Benefits**

### Performance Benefits
- **Threads Pool**: More efficient on Windows than prefork
- **Optimized Concurrency**: 4 concurrent workers instead of default 2
- **Task Limiting**: Max 50 tasks per worker prevents memory leaks

### Stability Benefits
- **No Permission Errors**: Eliminates Windows-specific access denied errors
- **Proper Service Startup**: All services start in correct order with proper timing
- **Clean Shutdown**: Stop script properly terminates all processes

### Development Benefits
- **Consistent Experience**: Same functionality across Windows and Unix systems
- **Better Error Handling**: Clear error messages and status reporting
- **Easier Debugging**: Separate windows for each service

## 🚀 **Usage**

After implementing these fixes, the standard startup process works reliably on Windows:

1. **Start RabbitMQ** (if not already running)
2. **Run `start.bat`** - All services start automatically
3. **Access the application** at http://localhost:3000
4. **Run `stop.bat`** when done - Clean shutdown of all services

## 📊 **Technical Details**

### Celery Pool Comparison
| Pool Type | Windows Support | Performance | Memory Usage |
|-----------|-----------------|-------------|--------------|
| prefork   | ❌ Permission issues | High | High |
| threads   | ✅ Full support | Good | Low |
| solo      | ✅ Works but limited | Low | Very Low |

### Process Architecture
```
start.bat
├── RabbitMQ Server (if needed)
├── MCP Server (window: "MCP Server")
├── Celery Worker (window: "Celery Worker", threads pool)
├── Flask Backend (window: "Flask Backend")
└── React Frontend (window: "React Frontend")
```

## 🔍 **Troubleshooting**

### If Celery Still Fails
1. Ensure RabbitMQ is running: `rabbitmq-server`
2. Check Windows permissions for the project directory
3. Try running as Administrator if necessary

### If Flask Backend Doesn't Start
1. Check if port 5000 is available: `netstat -ano | findstr :5000`
2. Verify Python environment: `uv run python --version`
3. Check Flask app logs in the "Flask Backend" window

### If React Frontend Can't Connect
1. Verify Flask backend is running on port 5000
2. Check proxy configuration in `frontend/package.json`
3. Ensure no firewall blocking localhost communication

## 🔗 **Related Files**
- `flask_app/config.py` - Configuration with Windows detection
- `start.bat` - Windows startup script
- `stop.bat` - Windows shutdown script
- `run.py` - Flask application entry point
- `pyproject.toml` - Dependencies including kombu for RabbitMQ

---

**Note:** These fixes are automatically applied when the system detects it's running on Windows. No manual configuration is required. 