# Database Administration

## 🗄️ ShadowSeek Database Administration

This guide covers database management, optimization, and maintenance for ShadowSeek's data layer.

---

## 📊 **Database Architecture**

### **Database Schema Overview**
```mermaid
erDiagram
    Binary {
        id INTEGER PK
        name VARCHAR(255)
        size INTEGER
        md5_hash VARCHAR(32)
        sha1_hash VARCHAR(40)
        sha256_hash VARCHAR(64)
        file_type VARCHAR(100)
        upload_date TIMESTAMP
        analysis_status VARCHAR(50)
        file_path VARCHAR(500)
        metadata TEXT
        created_at TIMESTAMP
        updated_at TIMESTAMP
    }
    
    Function {
        id INTEGER PK
        binary_id INTEGER FK
        name VARCHAR(255)
        address VARCHAR(20)
        size INTEGER
        decompiled_code TEXT
        assembly_code TEXT
        function_type VARCHAR(100)
        complexity_score FLOAT
        created_at TIMESTAMP
        updated_at TIMESTAMP
    }
    
    SecurityFinding {
        id INTEGER PK
        binary_id INTEGER FK
        function_id INTEGER FK
        finding_type VARCHAR(100)
        severity VARCHAR(20)
        confidence FLOAT
        description TEXT
        cwe_id VARCHAR(20)
        location VARCHAR(200)
        evidence TEXT
        remediation TEXT
        created_at TIMESTAMP
        updated_at TIMESTAMP
    }
    
    AIAnalysis {
        id INTEGER PK
        binary_id INTEGER FK
        function_id INTEGER FK
        analysis_type VARCHAR(100)
        provider VARCHAR(50)
        model VARCHAR(100)
        confidence FLOAT
        summary TEXT
        detailed_analysis TEXT
        security_assessment TEXT
        created_at TIMESTAMP
        updated_at TIMESTAMP
    }
    
    FuzzingCampaign {
        id INTEGER PK
        binary_id INTEGER FK
        name VARCHAR(255)
        fuzzer VARCHAR(50)
        status VARCHAR(50)
        target_function VARCHAR(255)
        harness_code TEXT
        config TEXT
        start_time TIMESTAMP
        end_time TIMESTAMP
        created_at TIMESTAMP
        updated_at TIMESTAMP
    }
    
    FuzzingResult {
        id INTEGER PK
        campaign_id INTEGER FK
        iteration INTEGER
        status VARCHAR(50)
        coverage FLOAT
        crashes INTEGER
        unique_crashes INTEGER
        execution_time FLOAT
        memory_usage INTEGER
        created_at TIMESTAMP
    }
    
    Task {
        id INTEGER PK
        task_id VARCHAR(50)
        binary_id INTEGER FK
        task_type VARCHAR(100)
        status VARCHAR(50)
        priority INTEGER
        progress FLOAT
        result TEXT
        error_message TEXT
        created_at TIMESTAMP
        updated_at TIMESTAMP
        started_at TIMESTAMP
        completed_at TIMESTAMP
    }
    
    Binary ||--o{ Function : "contains"
    Binary ||--o{ SecurityFinding : "has"
    Binary ||--o{ AIAnalysis : "analyzed_by"
    Binary ||--o{ FuzzingCampaign : "fuzzed_by"
    Binary ||--o{ Task : "processed_by"
    Function ||--o{ SecurityFinding : "contains"
    Function ||--o{ AIAnalysis : "analyzed_by"
    FuzzingCampaign ||--o{ FuzzingResult : "produces"
```

### **Database Configuration**
```yaml
# config/database.yaml
development:
  url: sqlite:///shadowseek_dev.db
  pool_size: 5
  max_overflow: 10
  pool_timeout: 30
  pool_recycle: 3600

production:
  url: postgresql://shadowseek:password@localhost/shadowseek
  pool_size: 20
  max_overflow: 30
  pool_timeout: 30
  pool_recycle: 3600
  echo: false
  connect_args:
    sslmode: require
    connect_timeout: 10
```

---

## 🔧 **Database Setup and Migration**

### **Initial Setup**
```bash
# Create database (PostgreSQL)
createdb shadowseek

psql -d shadowseek \
  -c "CREATE USER shadowseek WITH PASSWORD 'secure_password';"

psql -d shadowseek \
  -c "GRANT ALL PRIVILEGES ON DATABASE shadowseek TO shadowseek;"

# Initialize schema
python manage.py db init
python manage.py db migrate -m "Initial migration"
python manage.py db upgrade
```

### **Migration Management**
```bash
# Create migration
python manage.py db migrate \
  -m "Add new column to binary table"

# Apply migrations
python manage.py db upgrade

# Rollback migration
python manage.py db downgrade

# Show migration history
python manage.py db history

# Check current revision
python manage.py db current

# Stamp database with specific revision
python manage.py db stamp head
```

### **Database Seeding**
```bash
# Seed with sample data
python manage.py seed-db

# Seed with specific data
python manage.py seed-db --type security_patterns
python manage.py seed-db --type test_binaries
```

---

## 📈 **Performance Optimization**

### **Index Management**
```sql
-- Core indexes for performance
CREATE INDEX idx_binary_md5 ON binary(md5_hash);
CREATE INDEX idx_binary_sha256 ON binary(sha256_hash);
CREATE INDEX idx_binary_upload_date ON binary(upload_date);
CREATE INDEX idx_binary_analysis_status ON binary(analysis_status);

CREATE INDEX idx_function_binary_id ON function(binary_id);
CREATE INDEX idx_function_address ON function(address);
CREATE INDEX idx_function_type ON function(function_type);

CREATE INDEX idx_security_finding_binary_id ON security_finding(binary_id);
CREATE INDEX idx_security_finding_function_id ON security_finding(function_id);
CREATE INDEX idx_security_finding_severity ON security_finding(severity);
CREATE INDEX idx_security_finding_type ON security_finding(finding_type);

CREATE INDEX idx_ai_analysis_binary_id ON ai_analysis(binary_id);
CREATE INDEX idx_ai_analysis_function_id ON ai_analysis(function_id);
CREATE INDEX idx_ai_analysis_provider ON ai_analysis(provider);

CREATE INDEX idx_task_status ON task(status);
CREATE INDEX idx_task_binary_id ON task(binary_id);
CREATE INDEX idx_task_type ON task(task_type);
CREATE INDEX idx_task_created_at ON task(created_at);

-- Composite indexes for common queries
CREATE INDEX idx_binary_type_status ON binary(file_type, analysis_status);
CREATE INDEX idx_finding_severity_confidence ON security_finding(severity, confidence);
CREATE INDEX idx_task_status_type ON task(status, task_type);
```

### **Query Optimization**
```sql
-- Analyze query performance
EXPLAIN ANALYZE SELECT * FROM binary WHERE file_type = 'PE' AND analysis_status = 'completed';

-- Update table statistics
ANALYZE binary;
ANALYZE function;
ANALYZE security_finding;
ANALYZE ai_analysis;

-- Vacuum tables (PostgreSQL)
VACUUM ANALYZE binary;
VACUUM ANALYZE function;
VACUUM ANALYZE security_finding;
```

### **Connection Pooling**
```python
# config/database.py
from sqlalchemy import create_engine
from sqlalchemy.pool import QueuePool

DATABASE_CONFIG = {
    'pool_size': 20,
    'max_overflow': 30,
    'pool_timeout': 30,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
    'poolclass': QueuePool
}

engine = create_engine(
    DATABASE_URL,
    **DATABASE_CONFIG
)
```

---

## 🔍 **Monitoring and Maintenance**

### **Database Health Monitoring**
```bash
# Check database size
python manage.py db-info --size

# Check table sizes
python manage.py db-info --table-sizes

# Check index usage
python manage.py db-info --index-usage

# Check connection status
python manage.py db-info --connections
```

### **Performance Monitoring**
```sql
-- PostgreSQL performance queries
-- Check slow queries
SELECT query, mean_time, calls, total_time
FROM pg_stat_statements
WHERE calls > 100
ORDER BY mean_time DESC
LIMIT 10;

-- Check table sizes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(tablename::regclass)) as size,
    pg_total_relation_size(tablename::regclass) as size_bytes
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY size_bytes DESC;

-- Check index usage
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan,
    idx_tup_read,
    idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;

-- Active connections
SELECT
    pid,
    usename,
    application_name,
    state,
    query_start,
    query
FROM pg_stat_activity
WHERE state = 'active';
```

### **Health Check Scripts**
```python
# scripts/db_health_check.py
import time
from sqlalchemy import text
from flask_app.database import db

def check_database_health():
    """Comprehensive database health check"""
    health_status = {
        'connection': False,
        'tables': {},
        'performance': {}
    }
    
    try:
        # Test connection
        result = db.session.execute(text('SELECT 1')).scalar()
        health_status['connection'] = result == 1
        
        # Check table row counts
        tables = ['binary', 'function', 'security_finding', 'ai_analysis', 'task']
        for table in tables:
            count = db.session.execute(text(f'SELECT COUNT(*) FROM {table}')).scalar()
            health_status['tables'][table] = count
        
        # Performance metrics
        start_time = time.time()
        db.session.execute(text('SELECT COUNT(*) FROM binary WHERE analysis_status = \'completed\''))
        query_time = time.time() - start_time
        health_status['performance']['sample_query_time'] = query_time
        
    except Exception as e:
        health_status['error'] = str(e)
    
    return health_status
```

---

## 🔄 **Backup and Recovery**

### **Automated Backup Strategy**
```bash
#!/bin/bash
# backup_database.sh

BACKUP_DIR="/backups/database"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="shadowseek"
DB_USER="shadowseek"

# Create backup directory
mkdir -p $BACKUP_DIR

# Full database backup
pg_dump -U $DB_USER -h localhost -d $DB_NAME \
  --format=custom \
  --compress=9 \
  --file=$BACKUP_DIR/shadowseek_full_$DATE.dump

# Schema-only backup
pg_dump -U $DB_USER -h localhost -d $DB_NAME \
  --schema-only \
  --file=$BACKUP_DIR/shadowseek_schema_$DATE.sql

# Data-only backup
pg_dump -U $DB_USER -h localhost -d $DB_NAME \
  --data-only \
  --file=$BACKUP_DIR/shadowseek_data_$DATE.sql

# Clean old backups (keep 7 days)
find $BACKUP_DIR -name "*.dump" -mtime +7 -delete
find $BACKUP_DIR -name "*.sql" -mtime +7 -delete

# Verify backup
if [ -f "$BACKUP_DIR/shadowseek_full_$DATE.dump" ]; then
    echo "Backup completed successfully: $BACKUP_DIR/shadowseek_full_$DATE.dump"
else
    echo "Backup failed!" >&2
    exit 1
fi
```

### **Point-in-Time Recovery (PostgreSQL)**
```bash
# Configure WAL archiving in postgresql.conf
wal_level = archive
archive_mode = on
archive_command = 'cp %p /backups/wal/%f'

# Create base backup
pg_basebackup -U shadowseek -h localhost -D /backups/base -Ft -z -P

# Recovery configuration
# recovery.conf
restore_command = 'cp /backups/wal/%f %p'
recovery_target_time = '2024-01-20 14:30:00'
```

### **Disaster Recovery Procedures**
```bash
# Complete database restore
# 1. Stop application
systemctl stop shadowseek

# 2. Drop existing database
dropdb shadowseek

# 3. Create new database
createdb shadowseek

# 4. Restore from backup
pg_restore -U shadowseek -h localhost -d shadowseek \
  /backups/database/shadowseek_full_20240120_143000.dump

# 5. Restart application
systemctl start shadowseek

# 6. Verify restoration
python manage.py db-info --health
```

---

## 🧹 **Data Maintenance**

### **Data Cleanup Tasks**
```python
# scripts/cleanup_old_data.py
from datetime import datetime, timedelta
from flask_app.database import db
from flask_app.models import Binary, Task, FuzzingResult

def cleanup_old_data(days_old=30):
    """Clean up old data from database"""
    cutoff_date = datetime.utcnow() - timedelta(days=days_old)
    
    # Clean up old tasks
    old_tasks = Task.query.filter(
        Task.created_at < cutoff_date,
        Task.status.in_(['completed', 'failed'])
    ).all()
    
    for task in old_tasks:
        db.session.delete(task)
    
    # Clean up old fuzzing results
    old_fuzzing_results = FuzzingResult.query.filter(
        FuzzingResult.created_at < cutoff_date
    ).all()
    
    for result in old_fuzzing_results:
        db.session.delete(result)
    
    db.session.commit()
    
    print(f"Cleaned up {len(old_tasks)} old tasks and {len(old_fuzzing_results)} old fuzzing results")
```

### **Data Integrity Checks**
```sql
-- Check for orphaned records
SELECT f.id, f.binary_id
FROM function f
LEFT JOIN binary b ON f.binary_id = b.id
WHERE b.id IS NULL;

-- Check for missing files
SELECT id, name, file_path
FROM binary
WHERE file_path IS NOT NULL
AND NOT EXISTS (
    SELECT 1 FROM information_schema.files 
    WHERE filename = binary.file_path
);

-- Check data consistency
SELECT 
    b.id,
    b.name,
    COUNT(f.id) as function_count,
    COUNT(sf.id) as finding_count
FROM binary b
LEFT JOIN function f ON b.id = f.binary_id
LEFT JOIN security_finding sf ON b.id = sf.binary_id
GROUP BY b.id, b.name
HAVING COUNT(f.id) = 0 AND b.analysis_status = 'completed';
```

### **Database Maintenance Scripts**
```bash
# Weekly maintenance script
#!/bin/bash
# weekly_db_maintenance.sh

echo "Starting weekly database maintenance..."

# Update statistics
echo "Updating database statistics..."
python manage.py db-maintenance --update-stats

# Vacuum and analyze
echo "Vacuuming database..."
python manage.py db-maintenance --vacuum

# Check integrity
echo "Checking data integrity..."
python manage.py db-maintenance --integrity-check

# Clean up old data
echo "Cleaning up old data..."
python manage.py cleanup-old-data --days 30

# Optimize indexes
echo "Optimizing indexes..."
python manage.py db-maintenance --optimize-indexes

echo "Weekly maintenance completed."
```

---

## 🔐 **Security and Access Control**

### **Database Security Configuration**
```bash
# PostgreSQL security settings
# pg_hba.conf
host    shadowseek    shadowseek    127.0.0.1/32    md5
host    shadowseek    shadowseek    ::1/128         md5

# postgresql.conf
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'ca.crt'
password_encryption = scram-sha-256
```

### **User Management**
```sql
-- Create read-only user
CREATE USER shadowseek_readonly WITH PASSWORD 'readonly_password';
GRANT CONNECT ON DATABASE shadowseek TO shadowseek_readonly;
GRANT USAGE ON SCHEMA public TO shadowseek_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO shadowseek_readonly;

-- Create backup user
CREATE USER shadowseek_backup WITH PASSWORD 'backup_password';
GRANT CONNECT ON DATABASE shadowseek TO shadowseek_backup;
GRANT USAGE ON SCHEMA public TO shadowseek_backup;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO shadowseek_backup;
```

### **Audit Logging**
```sql
-- Enable audit logging (PostgreSQL)
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Configure audit settings
ALTER SYSTEM SET pgaudit.log = 'all';
ALTER SYSTEM SET pgaudit.log_catalog = on;
ALTER SYSTEM SET pgaudit.log_parameter = on;
ALTER SYSTEM SET pgaudit.log_statement_once = on;

-- Reload configuration
SELECT pg_reload_conf();
```

---

## 📊 **Database Reporting**

### **Usage Statistics**
```python
# scripts/db_reports.py
from flask_app.database import db
from flask_app.models import Binary, Function, SecurityFinding, AIAnalysis

def generate_usage_report():
    """Generate database usage statistics"""
    report = {
        'total_binaries': Binary.query.count(),
        'total_functions': Function.query.count(),
        'total_findings': SecurityFinding.query.count(),
        'total_ai_analyses': AIAnalysis.query.count(),
        'binaries_by_type': {},
        'findings_by_severity': {},
        'analyses_by_provider': {}
    }
    
    # Binaries by type
    binary_types = db.session.query(
        Binary.file_type,
        db.func.count(Binary.id)
    ).group_by(Binary.file_type).all()
    
    for file_type, count in binary_types:
        report['binaries_by_type'][file_type] = count
    
    # Findings by severity
    finding_severities = db.session.query(
        SecurityFinding.severity,
        db.func.count(SecurityFinding.id)
    ).group_by(SecurityFinding.severity).all()
    
    for severity, count in finding_severities:
        report['findings_by_severity'][severity] = count
    
    # Analyses by provider
    analysis_providers = db.session.query(
        AIAnalysis.provider,
        db.func.count(AIAnalysis.id)
    ).group_by(AIAnalysis.provider).all()
    
    for provider, count in analysis_providers:
        report['analyses_by_provider'][provider] = count
    
    return report
```

### **Performance Reports**
```sql
-- Daily performance report
SELECT 
    DATE(created_at) as date,
    COUNT(*) as total_analyses,
    AVG(
        CASE 
            WHEN completed_at IS NOT NULL AND started_at IS NOT NULL
            THEN EXTRACT(EPOCH FROM (completed_at - started_at))
            ELSE NULL
        END
    ) as avg_analysis_time
FROM task
WHERE task_type = 'binary_analysis'
AND created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE(created_at)
ORDER BY date DESC;

-- Top findings report
SELECT 
    finding_type,
    COUNT(*) as count,
    AVG(confidence) as avg_confidence,
    COUNT(CASE WHEN severity = 'CRITICAL' THEN 1 END) as critical_count,
    COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_count
FROM security_finding
WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY finding_type
ORDER BY count DESC
LIMIT 20;
```

---

## 🚨 **Troubleshooting**

### **Common Database Issues**
1. **Connection Pool Exhaustion**
   ```python
   # Monitor connection pool
   from flask_app.database import db
   print(f"Pool size: {db.engine.pool.size()}")
   print(f"Checked out: {db.engine.pool.checkedout()}")
   print(f"Overflow: {db.engine.pool.overflow()}")
   ```

2. **Long Running Queries**
   ```sql
   -- Find long running queries
   SELECT 
       pid,
       now() - pg_stat_activity.query_start AS duration,
       query
   FROM pg_stat_activity
   WHERE (now() - pg_stat_activity.query_start) > interval '5 minutes'
   AND state = 'active';
   ```

3. **Lock Issues**
   ```sql
   -- Check for locks
   SELECT 
       t.relname,
       l.locktype,
       l.page,
       l.virtualtransaction,
       l.pid,
       l.mode,
       l.granted
   FROM pg_locks l, pg_stat_all_tables t
   WHERE l.relation = t.relid
   ORDER BY t.relname;
   ```

### **Database Recovery**
```bash
# Check database corruption
python manage.py db-check --corruption

# Repair database (SQLite)
sqlite3 shadowseek.db ".recover" | sqlite3 shadowseek_recovered.db

# Rebuild indexes
python manage.py db-maintenance --rebuild-indexes
```

---

## 📈 **Scaling Considerations**

### **Read Replicas**
```python
# Configure read replicas
DATABASE_CONFIG = {
    'master': 'postgresql://user:pass@master:5432/shadowseek',
    'replicas': [
        'postgresql://user:pass@replica1:5432/shadowseek',
        'postgresql://user:pass@replica2:5432/shadowseek'
    ]
}

# Route read queries to replicas
class ReadWriteRouter:
    def db_for_read(self, model):
        return 'replica'
    
    def db_for_write(self, model):
        return 'master'
```

### **Partitioning Strategy**
```sql
-- Partition large tables by date
CREATE TABLE binary_partitioned (
    id INTEGER NOT NULL,
    created_at TIMESTAMP NOT NULL,
    -- other columns
) PARTITION BY RANGE (created_at);

-- Create monthly partitions
CREATE TABLE binary_2024_01 PARTITION OF binary_partitioned
FOR VALUES FROM ('2024-01-01') TO ('2024-02-01');

CREATE TABLE binary_2024_02 PARTITION OF binary_partitioned
FOR VALUES FROM ('2024-02-01') TO ('2024-03-01');
```

### **Archiving Strategy**
```bash
# Archive old data
python manage.py archive-data --table binary --older-than 1y --destination archive_db
python manage.py archive-data --table task --older-than 6m --destination archive_db
```

Remember to regularly monitor database performance and adjust configurations based on your specific workload patterns and requirements. 