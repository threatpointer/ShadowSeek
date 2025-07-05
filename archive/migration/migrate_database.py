#!/usr/bin/env python3
"""
Database Migration Script
Adds new fields for Function decompilation and AI analysis features
"""

import os
import sys
import sqlite3
from pathlib import Path

def get_db_path():
    """Get the path to the SQLite database"""
    # Check for instance directory
    instance_dir = Path('instance')
    if instance_dir.exists():
        db_path = instance_dir / 'ghidra_analyzer.db'
        if db_path.exists():
            return str(db_path)
    
    # Check for app.db in current directory
    db_path = Path('app.db')
    if db_path.exists():
        return str(db_path)
    
    # Check for common database names
    for db_name in ['ghidra.db', 'database.db', 'app.sqlite']:
        db_path = Path(db_name)
        if db_path.exists():
            return str(db_path)
    
    return None

def check_column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns

def migrate_functions_table(cursor):
    """Add new columns to the functions table"""
    migrations = [
        {
            'column': 'decompiled_code',
            'sql': 'ALTER TABLE functions ADD COLUMN decompiled_code TEXT'
        },
        {
            'column': 'ai_summary', 
            'sql': 'ALTER TABLE functions ADD COLUMN ai_summary TEXT'
        },
        {
            'column': 'risk_score',
            'sql': 'ALTER TABLE functions ADD COLUMN risk_score INTEGER'
        },
        {
            'column': 'is_decompiled',
            'sql': 'ALTER TABLE functions ADD COLUMN is_decompiled BOOLEAN DEFAULT 0'
        },
        {
            'column': 'ai_analyzed',
            'sql': 'ALTER TABLE functions ADD COLUMN ai_analyzed BOOLEAN DEFAULT 0'
        }
    ]
    
    applied_migrations = 0
    
    for migration in migrations:
        column_name = migration['column']
        sql = migration['sql']
        
        if not check_column_exists(cursor, 'functions', column_name):
            try:
                cursor.execute(sql)
                print(f"✅ Added column: functions.{column_name}")
                applied_migrations += 1
            except sqlite3.Error as e:
                print(f"❌ Error adding column {column_name}: {e}")
        else:
            print(f"⏭️  Column already exists: functions.{column_name}")
    
    return applied_migrations

def backup_database(db_path):
    """Create a backup of the database before migration"""
    backup_path = db_path + '.backup'
    
    try:
        # Read original database
        with open(db_path, 'rb') as src:
            data = src.read()
        
        # Write backup
        with open(backup_path, 'wb') as dst:
            dst.write(data)
        
        print(f"✅ Database backed up to: {backup_path}")
        return backup_path
    except Exception as e:
        print(f"❌ Failed to create backup: {e}")
        return None

def main():
    """Main migration function"""
    print("🚀 Starting database migration for ShadowSeek...")
    print()
    
    # Find database
    db_path = get_db_path()
    if not db_path:
        print("❌ Database file not found!")
        print("Please ensure the Flask app has been run at least once to create the database.")
        return 1
    
    print(f"📁 Found database: {db_path}")
    
    # Create backup
    backup_path = backup_database(db_path)
    if not backup_path:
        print("⚠️  Continuing without backup (risky!)")
    
    # Connect to database
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if functions table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='functions'")
        if not cursor.fetchone():
            print("❌ Functions table not found! Please run the Flask app first to create tables.")
            conn.close()
            return 1
        
        print("📋 Functions table found. Applying migrations...")
        print()
        
        # Apply migrations
        applied = migrate_functions_table(cursor)
        
        # Commit changes
        conn.commit()
        conn.close()
        
        print()
        print(f"✅ Migration completed! Applied {applied} new columns.")
        print()
        
        if applied > 0:
            print("🎉 Your database is now ready for the new features:")
            print("   - Function decompilation")
            print("   - AI-powered explanations")
            print("   - Risk scoring")
            print()
            print("Next steps:")
            print("1. Add OPENAI_API_KEY to your .env file for AI features")
            print("2. Restart your Flask application")
            print("3. Upload a binary and try the new decompilation features!")
        
        return 0
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code) 