#!/usr/bin/env python
"""
Reset database script for ShadowSeek - Advanced Binary Security Analysis Platform
"""

import os
import sqlite3
from flask_app.models import db
from flask_app.app import create_app

def reset_database():
    """Drop all tables and recreate them"""
    print("Initializing database...")
    app = create_app()
    
    # Get database path
    db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
    if db_path.startswith('/'):
        db_path = db_path[1:]  # Remove leading slash for relative paths
    
    print(f"Database path: {db_path}")
    
    # Delete database file if it exists
    if os.path.exists(db_path):
        print(f"Deleting existing database file: {db_path}")
        os.remove(db_path)
    
    # Create new database
    with app.app_context():
        print("Creating new tables...")
        db.create_all()
        print("Database reset successfully!")

if __name__ == "__main__":
    reset_database() 