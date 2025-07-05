#!/usr/bin/env python3
"""
Database migration script to add fuzzing harness tables
For ShadowSeek - Fuzzing Feature Implementation
"""

import os
import sys
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.getcwd())

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_app import create_app, db
from flask_app.models import (
    FuzzingHarness, FuzzingTarget, FuzzingSession
)

def create_fuzzing_tables():
    """Create fuzzing-related tables"""
    
    print("🔧 Creating fuzzing harness tables...")
    
    # Create all tables defined in models
    try:
        # This will create any tables that don't exist
        db.create_all()
        print("✅ Successfully created fuzzing tables:")
        print("   - fuzzing_harnesses")
        print("   - fuzzing_targets") 
        print("   - fuzzing_sessions")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False

def verify_tables():
    """Verify that the tables were created successfully"""
    
    print("\n🔍 Verifying table creation...")
    
    try:
        # Test table access
        harness_count = FuzzingHarness.query.count()
        target_count = FuzzingTarget.query.count()
        session_count = FuzzingSession.query.count()
        
        print(f"✅ fuzzing_harnesses table: {harness_count} records")
        print(f"✅ fuzzing_targets table: {target_count} records")
        print(f"✅ fuzzing_sessions table: {session_count} records")
        
        return True
        
    except Exception as e:
        print(f"❌ Error verifying tables: {e}")
        return False

def add_test_data():
    """Add some test configuration data if needed"""
    
    print("\n🧪 Adding initial configuration...")
    
    try:
        # For now, we don't need initial data
        # Future: Could add default fuzzing patterns or configurations
        print("✅ Initial configuration complete")
        return True
        
    except Exception as e:
        print(f"❌ Error adding test data: {e}")
        return False

def main():
    """Main migration function"""
    
    print("🚀 Starting Fuzzing Tables Migration")
    print("=" * 50)
    
    # Create Flask app
    app = create_app()
    
    with app.app_context():
        try:
            # Check current database state
            print(f"📊 Database URI: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not configured')}")
            
            # Create tables
            if not create_fuzzing_tables():
                print("\n❌ Failed to create tables. Exiting.")
                return False
            
            # Verify tables
            if not verify_tables():
                print("\n❌ Table verification failed. Exiting.")
                return False
            
            # Add initial data
            if not add_test_data():
                print("\n❌ Failed to add initial data. Exiting.")
                return False
            
            print("\n" + "=" * 50)
            print("🎉 Fuzzing Tables Migration Completed Successfully!")
            print("\n📋 Next Steps:")
            print("   1. Restart your Flask application")
            print("   2. Navigate to a binary details page")
            print("   3. Look for the new 'Fuzzing' tab")
            print("   4. Generate your first fuzzing harness!")
            print("\n🔗 Available endpoints:")
            print("   - POST /api/binaries/{id}/generate-fuzzing-harness")
            print("   - GET /api/binaries/{id}/fuzzing-harnesses")
            print("   - POST /api/functions/{id}/generate-fuzzing-harness")
            print("   - GET /api/fuzzing-harnesses/{id}/download/package")
            
            return True
            
        except Exception as e:
            print(f"\n❌ Migration failed: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 