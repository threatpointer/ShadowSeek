# System Management

## 🛠️ ShadowSeek System Management

This guide covers system-level administration tasks for managing and maintaining your ShadowSeek deployment.

---

## 📊 **System Overview**

### **System Architecture**
```mermaid
graph TB
    subgraph "Frontend Layer"
        FE[React Frontend]
        WS[WebSocket Connection]
    end
    
    subgraph "Backend Layer"
        API[Flask API Server]
        WK[Worker Processes]
        SCH[Task Scheduler]
    end
    
    subgraph "Analysis Layer"
        GH[Ghidra Bridge]
        AI[AI Service]
        FZ[Fuzzing Engine]
    end
    
    subgraph "Data Layer"
        DB[(SQLite/PostgreSQL)]
        FS[File System]
        CACHE[Redis Cache]
    end
    
    FE --> API
    WS --> API
    API --> WK
    API --> SCH
    WK --> GH
    WK --> AI
    WK --> FZ
    API --> DB
    API --> FS
    API --> CACHE
```

### **Service Components**
- **Frontend Server**: React development server (port 3000)
- **API Server**: Flask backend (port 5000)
- **Ghidra Bridge**: Binary analysis service (port 9100)
- **AI Service**: OpenAI/Anthropic/Ollama integration
- **Database**: SQLite (development) / PostgreSQL (production)
- **File Storage**: Local filesystem or cloud storage
- **Cache**: Redis for session and result caching

---

## 🚀 **Service Management**

### **Starting Services**
```bash
# Start all services
./start_all.bat          # Windows
./start_all.sh           # Linux/macOS

# Individual service startup
cd frontend && npm start              # Frontend
cd flask_app && python app.py        # Backend
cd ghidra_bridge && python bridge.py # Ghidra
```

### **Service Status Monitoring**
```bash
# Check service status
curl -s http://localhost:5000/api/health | jq

# Response format
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

# Check individual components
curl http://localhost:5000/api/system/status
curl http://localhost:9100/status
```

### **Service Logs**
```bash
# View logs
tail -f logs/shadowseek.log
tail -f logs/ghidra_bridge.log
tail -f logs/ai_service.log

# Log rotation
logrotate /etc/logrotate.d/shadowseek

# Configure logging levels
export LOG_LEVEL=INFO    # DEBUG, INFO, WARNING, ERROR
```

---

## 🔧 **Configuration Management**

### **Environment Variables**
```bash
# Core configuration
export SHADOWSEEK_ENV=production
export DATABASE_URL=sqlite:///shadowseek.db
export SECRET_KEY=your-secret-key-here

# AI Service Configuration
export OPENAI_API_KEY=your-openai-key
export ANTHROPIC_API_KEY=your-anthropic-key
export OLLAMA_BASE_URL=http://localhost:11434

# Ghidra Configuration
export GHIDRA_HOME=/opt/ghidra
export GHIDRA_BRIDGE_PORT=9100
export GHIDRA_TIMEOUT=300

# Storage Configuration
export UPLOAD_FOLDER=/data/uploads
export MAX_UPLOAD_SIZE=100MB
export STORAGE_TYPE=local  # local, s3, azure

# Performance Settings
export WORKER_PROCESSES=4
export MAX_CONCURRENT_ANALYSIS=10
export CACHE_TTL=3600
```

### **Configuration Files**
```yaml
# config/production.yaml
database:
  url: postgresql://user:pass@localhost/shadowseek
  pool_size: 20
  max_overflow: 30

ai:
  default_provider: openai
  model: gpt-4
  max_tokens: 4096
  temperature: 0.1

ghidra:
  home: /opt/ghidra
  bridge_port: 9100
  timeout: 300
  max_memory: 8G

security:
  secret_key: !ENV SECRET_KEY
  jwt_expiry: 3600
  cors_origins: ["https://yourapp.com"]

logging:
  level: INFO
  file: logs/shadowseek.log
  max_size: 100MB
  backup_count: 10
```

---

## 👥 **User Management**

### **User Administration**
```bash
# Create admin user
python manage.py create-user \
  --email admin@company.com \
  --role admin

# List users
python manage.py list-users

# Update user role
python manage.py update-user \
  --email user@company.com \
  --role analyst

# Deactivate user
python manage.py deactivate-user \
  --email user@company.com
```

### **Role Management**
```python
# Available roles
ROLES = {
    'admin': {
        'permissions': ['*'],
        'description': 'Full system access'
    },
    'analyst': {
        'permissions': ['binary.*', 'analysis.*', 'dashboard.*'],
        'description': 'Security analysis access'
    },
    'viewer': {
        'permissions': ['binary.read', 'analysis.read', 'dashboard.read'],
        'description': 'Read-only access'
    }
}
```

### **Session Management**
```bash
# View active sessions
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/admin/sessions

# Terminate session
curl -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/admin/sessions/{session_id}

# Clear all sessions
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:5000/api/admin/sessions/clear
```

---

## 🔐 **Security Management**

### **Access Control**
```yaml
# security/access_control.yaml
endpoints:
  - path: /api/admin/*
    roles: [admin]
    methods: [GET, POST, PUT, DELETE]
    
  - path: /api/binary/*
    roles: [admin, analyst]
    methods: [GET, POST, PUT, DELETE]
    
  - path: /api/analysis/*
    roles: [admin, analyst, viewer]
    methods: [GET]
```

### **API Security**
```bash
# Generate API key
python manage.py generate-api-key \
  --user admin@company.com

# Revoke API key
python manage.py revoke-api-key \
  --key-id 12345

# List API keys
python manage.py list-api-keys
```

### **Audit Logging**
```bash
# Enable audit logging
export AUDIT_LOGGING=true
export AUDIT_LOG_FILE=logs/audit.log

# View audit log
tail -f logs/audit.log | jq

# Audit log format
{
  "timestamp": "2024-01-20T10:30:00Z",
  "user": "admin@company.com",
  "action": "binary.upload",
  "resource": "malware.exe",
  "ip": "192.168.1.100",
  "status": "success"
}
```

---

## 📈 **System Monitoring**

### **Performance Metrics**
```bash
# System metrics endpoint
curl http://localhost:5000/api/metrics

# Response format
{
  "cpu_usage": 45.2,
  "memory_usage": 78.5,
  "disk_usage": 62.3,
  "active_connections": 12,
  "queue_depth": 5,
  "analysis_rate": 3.2
}
```

### **Health Checks**
```bash
# Comprehensive health check
curl http://localhost:5000/api/health/full

# Component-specific checks
curl http://localhost:5000/api/health/database
curl http://localhost:5000/api/health/ghidra
curl http://localhost:5000/api/health/ai
```

### **Alerting Configuration**
```yaml
# alerts/config.yaml
alerts:
  - name: high_cpu_usage
    condition: cpu_usage > 80
    duration: 300
    severity: warning
    
  - name: database_connection_failure
    condition: database_status != "connected"
    duration: 60
    severity: critical
    
  - name: analysis_queue_backup
    condition: queue_depth > 50
    duration: 600
    severity: warning
```

---

## 🔄 **Backup and Recovery**

### **Database Backup**
```bash
# SQLite backup
sqlite3 shadowseek.db \
  ".backup backup_$(date +%Y%m%d_%H%M%S).db"

# PostgreSQL backup
pg_dump -U postgres shadowseek > \
  backup_$(date +%Y%m%d_%H%M%S).sql

# Automated backup script
#!/bin/bash
BACKUP_DIR=/backups
DATE=$(date +%Y%m%d_%H%M%S)

pg_dump -U postgres shadowseek | \
  gzip > $BACKUP_DIR/shadowseek_$DATE.sql.gz

find $BACKUP_DIR -name "*.sql.gz" \
  -mtime +7 -delete
```

### **File System Backup**
```bash
# Binary files backup
rsync -av --delete \
  /data/uploads/ \
  /backups/uploads/

# Configuration backup
tar -czf /backups/config_$(date +%Y%m%d).tar.gz \
  config/

# Complete system backup
tar -czf /backups/shadowseek_full_$(date +%Y%m%d).tar.gz \
  --exclude=node_modules \
  --exclude=__pycache__ \
  --exclude=logs \
  .
```

### **Recovery Procedures**
```bash
# Database recovery
# SQLite
sqlite3 shadowseek.db \
  ".restore backup_20240120_103000.db"

# PostgreSQL
psql -U postgres -d shadowseek < \
  backup_20240120_103000.sql

# File system recovery
rsync -av \
  /backups/uploads/ \
  /data/uploads/

tar -xzf /backups/config_20240120.tar.gz \
  -C /
```

---

## 🚨 **Troubleshooting**

### **Common Issues**
1. **Service Won't Start**
   ```bash
   # Check port availability
   netstat -tulpn | grep :5000
   
   # Check logs
   tail -f logs/shadowseek.log
   
   # Verify dependencies
   pip list | grep -E "(flask|sqlalchemy|requests)"
   ```

2. **Database Connection Issues**
   ```bash
   # Test connection
   python -c "from flask_app.database import db; \
             print(db.session.execute('SELECT 1').scalar())"
   
   # Check database status
   systemctl status postgresql
   ```

3. **Ghidra Bridge Problems**
   ```bash
   # Check Ghidra process
   ps aux | grep ghidra
   
   # Test bridge connection
   curl http://localhost:9100/status
   
   # Restart bridge
   pkill -f ghidra_bridge
   cd ghidra_bridge && python bridge.py
   ```

### **Performance Issues**
```bash
# Check system resources
top -p $(pgrep -f "python.*app.py")
htop

# Monitor database performance
# PostgreSQL
SELECT * FROM pg_stat_activity;

# Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
ORDER BY mean_time DESC 
LIMIT 10;
```

### **Log Analysis**
```bash
# Error pattern analysis
grep -i error logs/shadowseek.log | tail -20
grep -i "exception" logs/shadowseek.log | tail -20

# Performance analysis
grep -i "slow" logs/shadowseek.log
grep -P "took \d+\.\d+ seconds" logs/shadowseek.log
```

---

## 📋 **Maintenance Tasks**

### **Regular Maintenance**
```bash
# Weekly tasks
./scripts/weekly_maintenance.sh

# Monthly tasks
./scripts/monthly_maintenance.sh

# Maintenance script example
#!/bin/bash
# Clean temporary files
find /tmp -name "shadowseek_*" -mtime +1 -delete

# Rotate logs
logrotate /etc/logrotate.d/shadowseek

# Update statistics
python manage.py update-stats

# Vacuum database
python manage.py vacuum-db
```

### **Update Procedures**
```bash
# Update ShadowSeek
git pull origin main
pip install -r requirements.txt
python manage.py migrate
npm install
npm run build

# Restart services
systemctl restart shadowseek
```

### **Cleanup Tasks**
```bash
# Clean old analysis results
python manage.py cleanup --older-than 30d

# Remove orphaned files
python manage.py cleanup-files

# Clear cache
python manage.py clear-cache
```

---

## 🔍 **System Information**

### **Version Information**
```bash
# Check versions
python manage.py version
curl http://localhost:5000/api/version

# Component versions
python --version
node --version
npm --version
```

### **System Requirements**
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Disk**: 50GB minimum, SSD recommended
- **Network**: Stable internet for AI services
- **OS**: Linux, macOS, or Windows 10+

### **Port Usage**
- **3000**: React frontend
- **5000**: Flask API
- **9100**: Ghidra Bridge
- **5432**: PostgreSQL (if used)
- **6379**: Redis (if used)
- **11434**: Ollama (if used)

---

## 📞 **Support Information**

### **Getting Help**
- **Documentation**: [Internal docs](http://localhost:3000/docs)
- **Logs**: Check `/logs/` directory
- **Health Status**: http://localhost:5000/api/health
- **System Status**: http://localhost:5000/api/system/status

### **Support Resources**
- **Documentation**: Complete guides available in user-docs/
- **GitHub Issues**: Report technical issues and bugs
- **Community**: Join discussions for peer support

Remember to customize these configurations based on your specific deployment environment and security requirements. 