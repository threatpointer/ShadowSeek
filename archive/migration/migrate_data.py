#!/usr/bin/env python3
"""
Data Migration Script for ShadowSeek
Migrates data from ghidra_analyzer.db to shadowseek.db
"""

import os
import sqlite3
import shutil
from datetime import datetime

def backup_database(db_path):
    """Create a backup of the database before migration"""
    backup_path = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.copy2(db_path, backup_path)
    print(f"✅ Created backup: {backup_path}")
    return backup_path

def get_table_names(cursor):
    """Get all table names from the database"""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    return [row[0] for row in cursor.fetchall()]

def migrate_table_data(source_cursor, dest_cursor, table_name):
    """Migrate data from one table to another"""
    try:
        # Get all data from source table
        source_cursor.execute(f"SELECT * FROM {table_name}")
        rows = source_cursor.fetchall()
        
        if not rows:
            print(f"  📋 Table '{table_name}': No data to migrate")
            return 0
        
        # Get column info
        source_cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in source_cursor.fetchall()]
        
        # Prepare insert statement
        placeholders = ','.join(['?' for _ in columns])
        insert_sql = f"INSERT OR REPLACE INTO {table_name} ({','.join(columns)}) VALUES ({placeholders})"
        
        # Insert data into destination
        dest_cursor.executemany(insert_sql, rows)
        
        migrated_count = len(rows)
        print(f"  📋 Table '{table_name}': Migrated {migrated_count} records")
        return migrated_count
        
    except sqlite3.Error as e:
        print(f"  ❌ Error migrating table '{table_name}': {e}")
        return 0

def main():
    source_db = "instance/ghidra_analyzer.db"
    dest_db = "instance/shadowseek.db"
    
    print("🔄 ShadowSeek Database Migration")
    print("=" * 50)
    
    # Check if source database exists
    if not os.path.exists(source_db):
        print(f"❌ Source database not found: {source_db}")
        return
    
    # Check if destination database exists
    if not os.path.exists(dest_db):
        print(f"❌ Destination database not found: {dest_db}")
        return
    
    # Create backups
    print("📦 Creating backups...")
    source_backup = backup_database(source_db)
    dest_backup = backup_database(dest_db)
    
    try:
        # Connect to both databases
        print("\n🔗 Connecting to databases...")
        source_conn = sqlite3.connect(source_db)
        dest_conn = sqlite3.connect(dest_db)
        
        source_cursor = source_conn.cursor()
        dest_cursor = dest_conn.cursor()
        
        # Get tables from source database
        source_tables = get_table_names(source_cursor)
        dest_tables = get_table_names(dest_cursor)
        
        print(f"📊 Source database tables: {len(source_tables)}")
        print(f"📊 Destination database tables: {len(dest_tables)}")
        
        # Migrate data for tables that exist in both databases
        print("\n🚚 Starting data migration...")
        total_migrated = 0
        migrated_tables = 0
        
        for table in source_tables:
            if table in dest_tables:
                print(f"\n  🔄 Migrating table: {table}")
                count = migrate_table_data(source_cursor, dest_cursor, table)
                if count > 0:
                    total_migrated += count
                    migrated_tables += 1
            else:
                print(f"  ⚠️  Table '{table}' not found in destination database - skipping")
        
        # Commit changes
        dest_conn.commit()
        
        print("\n" + "=" * 50)
        print("✅ Migration completed successfully!")
        print(f"📊 Tables migrated: {migrated_tables}")
        print(f"📊 Total records migrated: {total_migrated}")
        print(f"📦 Source backup: {source_backup}")
        print(f"📦 Destination backup: {dest_backup}")
        
        # Close connections
        source_conn.close()
        dest_conn.close()
        
        print("\n🎯 Next steps:")
        print("1. Restart your Flask application")
        print("2. Your data should now be available in ShadowSeek!")
        
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        print("🔄 Restoring backups...")
        if os.path.exists(dest_backup):
            shutil.copy2(dest_backup, dest_db)
            print("✅ Destination database restored from backup")

if __name__ == "__main__":
    main() 