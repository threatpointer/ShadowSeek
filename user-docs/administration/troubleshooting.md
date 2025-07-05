# Troubleshooting Guide

## 🔧 ShadowSeek Troubleshooting

This comprehensive guide helps diagnose and resolve common issues in ShadowSeek deployment and operation.

---

## 🚨 **Quick Diagnosis**

### **System Health Check**
```bash
# Quick system health check
curl -s http://localhost:5000/api/health | jq

# Expected healthy response
{
  "status": "healthy",
  "timestamp": "2024-01-20T10:30:00Z",
  "services": {
    "database": "connected",
    "ghidra": "running",
    "ai": "available",
    "cache": "ready"
  },
  "version": "2.0.0"
}
```

### **Service Status Check**
```bash
# Check all services
./scripts/check_services.sh

# Individual service checks
curl http://localhost:3000/  # Frontend
curl http://localhost:5000/api/health  # Backend
curl http://localhost:9100/status  # Ghidra Bridge
```

### **Log Quick Check**
```bash
# Check for errors in logs
tail -f logs/shadowseek.log | grep -E "(ERROR|CRITICAL|EXCEPTION)"

# Check recent log entries
tail -n 50 logs/shadowseek.log
```

---

## 🖥️ **Frontend Issues**

### **Frontend Won't Start**
```bash
# Problem: npm start fails
# Solution 1: Clear node_modules
rm -rf node_modules package-lock.json
npm install

# Solution 2: Check Node.js version
node --version  # Should be >= 16.x
npm --version   # Should be >= 8.x

# Solution 3: Check for port conflicts
lsof -i :3000
netstat -tulpn | grep 3000

# Solution 4: Check environment variables
echo $REACT_APP_API_URL
export REACT_APP_API_URL=http://localhost:5000
```

### **Build Failures**
```bash
# Problem: npm run build fails
# Solution 1: Check for TypeScript errors
npm run type-check

# Solution 2: Clear cache and rebuild
npm run clean
npm run build

# Solution 3: Check for missing dependencies
npm audit
npm audit fix

# Solution 4: Memory issues during build
export NODE_OPTIONS="--max-old-space-size=4096"
npm run build
```

### **Runtime JavaScript Errors**
```javascript
// Common React errors and solutions

// Error: "Cannot read property 'map' of undefined"
// Solution: Add null/undefined checks
const BinaryList = ({ binaries }) => {
  if (!binaries || !Array.isArray(binaries)) {
    return <div>Loading...</div>;
  }
  
  return (
    <div>
      {binaries.map(binary => (
        <BinaryItem key={binary.id} binary={binary} />
      ))}
    </div>
  );
};

// Error: "Maximum update depth exceeded"
// Solution: Fix infinite re-renders
const ComponentWithEffect = () => {
  const [data, setData] = useState(null);
  
  // BAD: Causes infinite loop
  // useEffect(() => {
  //   setData(fetchData());
  // });
  
  // GOOD: Proper dependency array
  useEffect(() => {
    fetchData().then(setData);
  }, []); // Empty dependency array
  
  return <div>{data}</div>;
};
```

### **Performance Issues**
```bash
# Problem: Frontend is slow
# Solution 1: Check bundle size
npm run build -- --analyze

# Solution 2: Enable React DevTools Profiler
# Install React DevTools browser extension
# Profile component render times

# Solution 3: Check for memory leaks
# Use browser DevTools Memory tab
# Look for growing heap size

# Solution 4: Optimize images
# Convert to WebP format
# Use appropriate image sizes
```

---

## 🔧 **Backend Issues**

### **Flask Application Won't Start**
```bash
# Problem: Flask app fails to start
# Solution 1: Check Python version
python --version  # Should be >= 3.8

# Solution 2: Check dependencies
pip check
pip install -r requirements.txt

# Solution 3: Check port availability
lsof -i :5000
netstat -tulpn | grep 5000

# Solution 4: Check environment variables
echo $FLASK_APP
echo $FLASK_ENV
export FLASK_APP=app.py
export FLASK_ENV=development

# Solution 5: Check for syntax errors
python -m py_compile app.py
```

### **Database Connection Issues**
```python
# Problem: Database connection fails
# Solution 1: Test database connection
python -c "
from flask_app.database import db
try:
    result = db.session.execute('SELECT 1').scalar()
    print('Database connection successful')
except Exception as e:
    print(f'Database connection failed: {e}')
"

# Solution 2: Check database service
systemctl status postgresql  # PostgreSQL
systemctl status mysql       # MySQL

# Solution 3: Check connection parameters
echo $DATABASE_URL
# Should be: postgresql://user:pass@host:port/database

# Solution 4: Check database exists
psql -U postgres -c "\l" | \
  grep shadowseek
```

### **Migration Issues**
```bash
# Problem: Database migrations fail
# Solution 1: Check migration status
python manage.py db current
python manage.py db history

# Solution 2: Rollback problematic migration
python manage.py db downgrade
python manage.py db migrate \
  -m "Fix migration"
python manage.py db upgrade

# Solution 3: Reset migrations (development only)
rm -rf migrations/
python manage.py db init
python manage.py db migrate \
  -m "Initial migration"
python manage.py db upgrade

# Solution 4: Manual migration repair
python manage.py db stamp head
```

### **API Response Issues**
```python
# Problem: API returns 500 errors
# Solution 1: Check logs for exceptions
tail -f logs/shadowseek.log | grep ERROR

# Solution 2: Test API endpoints
curl -v http://localhost:5000/api/health
curl -v http://localhost:5000/api/binary

# Solution 3: Check for missing imports
python -c "
import flask_app.app
print('App imports successful')
"

# Solution 4: Validate JSON responses
import json
response = requests.get('http://localhost:5000/api/binary')
try:
    json.loads(response.text)
    print('Valid JSON response')
except json.JSONDecodeError as e:
    print(f'Invalid JSON: {e}')
```

---

## 🗄️ **Database Issues**

### **Connection Pool Exhaustion**
```python
# Problem: "Pool timeout" errors
# Solution 1: Monitor connection pool
from flask_app.database import db
print(f"Pool size: {db.engine.pool.size()}")
print(f"Checked out: {db.engine.pool.checkedout()}")
print(f"Overflow: {db.engine.pool.overflow()}")

# Solution 2: Increase pool size
DATABASE_CONFIG = {
    'pool_size': 20,
    'max_overflow': 30,
    'pool_timeout': 30,
    'pool_recycle': 3600
}

# Solution 3: Check for connection leaks
# Find long-running connections
SELECT 
    pid,
    usename,
    application_name,
    state,
    query_start,
    now() - query_start AS duration
FROM pg_stat_activity
WHERE state = 'active'
ORDER BY duration DESC;
```

### **Slow Query Issues**
```sql
-- Problem: Database queries are slow
-- Solution 1: Identify slow queries
SELECT 
    query,
    mean_time,
    calls,
    total_time,
    rows
FROM pg_stat_statements
WHERE calls > 10
ORDER BY mean_time DESC
LIMIT 10;

-- Solution 2: Check missing indexes
SELECT 
    schemaname,
    tablename,
    attname,
    n_distinct,
    correlation
FROM pg_stats
WHERE schemaname = 'public'
AND n_distinct > 100;

-- Solution 3: Update table statistics
ANALYZE binary;
ANALYZE function;
ANALYZE security_finding;
```

### **Database Lock Issues**
```sql
-- Problem: Database locks/deadlocks
-- Solution 1: Check for locks
SELECT 
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocked_activity.query AS blocked_statement,
    blocking_activity.query AS blocking_statement
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;

-- Solution 2: Kill blocking queries
SELECT pg_terminate_backend(pid);
```

---

## 🤖 **AI Service Issues**

### **AI Provider Connection Issues**
```python
# Problem: AI service unavailable
# Solution 1: Test API keys
import openai
openai.api_key = "your-api-key"

try:
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": "Hello"}],
        max_tokens=10
    )
    print("OpenAI connection successful")
except Exception as e:
    print(f"OpenAI connection failed: {e}")

# Solution 2: Check rate limits
# OpenAI: 3 requests per minute (free tier)
# Anthropic: 5 requests per minute (free tier)
# Add rate limiting to requests

# Solution 3: Implement fallback providers
def get_ai_analysis(prompt):
    providers = ['openai', 'anthropic', 'ollama']
    
    for provider in providers:
        try:
            return analyze_with_provider(provider, prompt)
        except Exception as e:
            print(f"Provider {provider} failed: {e}")
            continue
    
    return "AI analysis unavailable"
```

### **AI Response Issues**
```python
# Problem: AI responses are malformed
# Solution 1: Validate AI responses
def validate_ai_response(response):
    required_fields = ['analysis', 'confidence', 'findings']
    
    if not isinstance(response, dict):
        return False
    
    for field in required_fields:
        if field not in response:
            return False
    
    if not isinstance(response['confidence'], (int, float)):
        return False
    
    if not 0 <= response['confidence'] <= 1:
        return False
    
    return True

# Solution 2: Implement response retry
def get_ai_analysis_with_retry(prompt, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = call_ai_service(prompt)
            if validate_ai_response(response):
                return response
            else:
                print(f"Invalid response format, retry {attempt + 1}")
        except Exception as e:
            print(f"AI service error: {e}, retry {attempt + 1}")
            time.sleep(2 ** attempt)  # Exponential backoff
    
    return None
```

---

## 🔍 **Analysis Engine Issues**

### **Ghidra Bridge Issues**
```bash
# Problem: Ghidra Bridge not responding
# Solution 1: Check Ghidra process
ps aux | grep ghidra
pgrep -f ghidra_bridge

# Solution 2: Check Ghidra Bridge logs
tail -f logs/ghidra_bridge.log

# Solution 3: Restart Ghidra Bridge
pkill -f ghidra_bridge
cd ghidra_bridge
python bridge.py &

# Solution 4: Check Ghidra installation
echo $GHIDRA_HOME
ls -la $GHIDRA_HOME/ghidra.jar

# Solution 5: Check Java version
java -version  # Should be >= 11
```

### **Binary Analysis Failures**
```python
# Problem: Binary analysis fails
# Solution 1: Check file format
import magic
file_type = magic.from_file(binary_path)
print(f"File type: {file_type}")

# Solution 2: Check file permissions
import os
print(f"File exists: {os.path.exists(binary_path)}")
print(f"File readable: {os.access(binary_path, os.R_OK)}")

# Solution 3: Check file size
file_size = os.path.getsize(binary_path)
print(f"File size: {file_size} bytes")

# Large files may cause issues
if file_size > 100 * 1024 * 1024:  # 100MB
    print("Warning: Large file may cause memory issues")

# Solution 4: Validate binary format
def validate_binary(binary_path):
    try:
        import pefile
        pe = pefile.PE(binary_path)
        return True
    except:
        pass
    
    try:
        import elftools.elf.elffile
        with open(binary_path, 'rb') as f:
            elffile = elftools.elf.elffile.ELFFile(f)
        return True
    except:
        pass
    
    return False
```

### **Pattern Detection Issues**
```python
# Problem: Security patterns not detected
# Solution 1: Check pattern compilation
import re

def test_pattern(pattern, test_string):
    try:
        compiled = re.compile(pattern)
        matches = compiled.findall(test_string)
        print(f"Pattern '{pattern}' matches: {matches}")
        return True
    except re.error as e:
        print(f"Pattern compilation error: {e}")
        return False

# Solution 2: Test with known vulnerable code
test_code = """
strcpy(buffer, user_input);
printf(user_format);
malloc(size * count);
"""

test_pattern(r'strcpy\s*\([^)]+\)', test_code)
test_pattern(r'printf\s*\([^,)]*[^"\'][^,)]*\)', test_code)
```

---

## 🎯 **Fuzzing Issues**

### **Fuzzer Setup Issues**
```bash
# Problem: AFL++ not working
# Solution 1: Check AFL++ installation
afl-fuzz --version
which afl-gcc

# Solution 2: Check system configuration
echo core | \
  sudo tee /proc/sys/kernel/core_pattern
echo never | \
  sudo tee /sys/kernel/mm/transparent_hugepage/enabled

# Solution 3: Check CPU scaling
echo performance | \
  sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Solution 4: Check for QEMU mode
afl-qemu-trace --version
```

### **Harness Generation Issues**
```python
# Problem: Harness compilation fails
# Solution 1: Check compiler
gcc --version
clang --version

# Solution 2: Check compilation flags
test_compile = """
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char buffer[100];
    strcpy(buffer, "test");
    printf("%s\\n", buffer);
    return 0;
}
"""

# Save to test.c and compile
gcc -o test test.c -fsanitize=address -g

# Solution 3: Check for missing headers
# Add appropriate includes to harness
```

### **Fuzzing Campaign Issues**
```python
# Problem: Fuzzing campaign fails
# Solution 1: Check fuzzer logs
def check_fuzzer_logs(campaign_id):
    log_file = f"fuzzing_campaigns/{campaign_id}/fuzzer.log"
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            return f.read()
    return "Log file not found"

# Solution 2: Monitor fuzzer statistics
def get_fuzzer_stats(campaign_id):
    stats_file = f"fuzzing_campaigns/{campaign_id}/fuzzer_stats"
    if os.path.exists(stats_file):
        with open(stats_file, 'r') as f:
            lines = f.readlines()
            stats = {}
            for line in lines:
                if ':' in line:
                    key, value = line.strip().split(':', 1)
                    stats[key.strip()] = value.strip()
            return stats
    return {}
```

---

## 🔄 **Task Queue Issues**

### **Task Queue Stuck**
```python
# Problem: Tasks stuck in queue
# Solution 1: Check task status
def check_task_status():
    stuck_tasks = Task.query.filter(
        Task.status == 'running',
        Task.started_at < datetime.utcnow() - timedelta(hours=1)
    ).all()
    
    for task in stuck_tasks:
        print(f"Stuck task: {task.id}, started: {task.started_at}")
    
    return stuck_tasks

# Solution 2: Reset stuck tasks
def reset_stuck_tasks():
    stuck_tasks = check_task_status()
    for task in stuck_tasks:
        task.status = 'failed'
        task.error_message = 'Task timeout - reset by admin'
        db.session.commit()

# Solution 3: Check worker processes
import psutil

def check_worker_processes():
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if 'worker' in proc.info['name'].lower():
                print(f"Worker process: {proc.info['pid']} - {proc.info['cmdline']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
```

### **Memory Issues**
```bash
# Problem: High memory usage
# Solution 1: Check memory usage
free -h
ps aux --sort=-%mem | head -20

# Solution 2: Monitor Python memory
python -c "
import psutil
import os
process = psutil.Process(os.getpid())
print(f'Memory usage: {process.memory_info().rss / 1024 / 1024:.2f} MB')
"

# Solution 3: Check for memory leaks
# Use memory profiler
pip install memory-profiler
python -m memory_profiler app.py
```

---

## 🛠️ **System Recovery**

### **Emergency Recovery**
```bash
# Complete system recovery procedure
# 1. Stop all services
./stop_all.sh

# 2. Backup current state
cp -r . ../shadowseek_backup_$(date +%Y%m%d_%H%M%S)

# 3. Check database integrity
python manage.py db-check --integrity

# 4. Restore from backup if needed
# pg_restore -d shadowseek backup.dump

# 5. Reset stuck tasks
python manage.py reset-stuck-tasks

# 6. Clear cache
python manage.py clear-cache

# 7. Restart services
./start_all.sh

# 8. Verify system health
curl http://localhost:5000/api/health
```

### **Data Recovery**
```python
# Recover lost data
def recover_lost_data():
    # Check for orphaned files
    orphaned_files = []
    upload_dir = 'uploads'
    
    for file_path in os.listdir(upload_dir):
        full_path = os.path.join(upload_dir, file_path)
        binary = Binary.query.filter_by(file_path=full_path).first()
        
        if not binary:
            orphaned_files.append(full_path)
    
    print(f"Found {len(orphaned_files)} orphaned files")
    
    # Recover database from filesystem
    for file_path in orphaned_files:
        try:
            # Create binary record
            binary = Binary(
                name=os.path.basename(file_path),
                file_path=file_path,
                size=os.path.getsize(file_path),
                upload_date=datetime.utcnow(),
                analysis_status='pending'
            )
            db.session.add(binary)
            db.session.commit()
            print(f"Recovered: {file_path}")
        except Exception as e:
            print(f"Failed to recover {file_path}: {e}")
```

---

## 📞 **Getting Help**

### **Log Collection**
```bash
# Collect logs for support
./scripts/collect_logs.sh

# Script contents:
#!/bin/bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="logs_$TIMESTAMP"
mkdir -p $LOG_DIR

# Copy all log files
cp logs/*.log $LOG_DIR/
cp -r fuzzing_campaigns/*/fuzzer.log $LOG_DIR/

# System information
uname -a > $LOG_DIR/system_info.txt
df -h > $LOG_DIR/disk_usage.txt
free -h > $LOG_DIR/memory_usage.txt
ps aux > $LOG_DIR/processes.txt

# Database information
python manage.py db-info > $LOG_DIR/database_info.txt

# Create archive
tar -czf shadowseek_logs_$TIMESTAMP.tar.gz $LOG_DIR/
echo "Logs collected in shadowseek_logs_$TIMESTAMP.tar.gz"
```

### **Support Information**
- **Documentation**: Check `/docs` directory for detailed guides
- **Logs**: Always include relevant log files when reporting issues
- **System Info**: Include OS version, Python version, and hardware specs
- **Error Messages**: Copy exact error messages and stack traces
- **Reproduction Steps**: Provide steps to reproduce the issue

### **Common Support Requests**
1. **Performance Issues**: Include system metrics and slow query logs
2. **Connection Issues**: Include network configuration and firewall settings
3. **Analysis Failures**: Include binary file information and Ghidra logs
4. **AI Service Issues**: Include API key status and provider-specific error messages
5. **Fuzzing Issues**: Include fuzzer logs and campaign configuration

Remember to check the logs first and try the suggested solutions before escalating to support. 