#!/usr/bin/env python3
"""
Simple database migration script to add comprehensive analysis tables
"""

import os
import sys
import sqlite3
from pathlib import Path

def run_migration():
    """Run the migration to add comprehensive analysis tables"""
    
    # Find the database file
    db_path = Path("instance/ghidra_analyzer.db")
    
    if not db_path.exists():
        print(f"❌ Database not found at {db_path}")
        return False
    
    print(f"📁 Found database at: {db_path}")
    
    try:
        # Connect to the database
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        print("🔧 Adding comprehensive analysis tables...")
        
        # Create instructions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS instructions (
                id VARCHAR(36) PRIMARY KEY,
                binary_id VARCHAR(36) NOT NULL,
                address VARCHAR(20) NOT NULL,
                mnemonic VARCHAR(50) NOT NULL,
                operands TEXT,
                bytes_data TEXT,
                length INTEGER,
                fall_through VARCHAR(20),
                FOREIGN KEY (binary_id) REFERENCES binaries (id)
            )
        """)
        
        # Create cross_references table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cross_references (
                id VARCHAR(36) PRIMARY KEY,
                binary_id VARCHAR(36) NOT NULL,
                from_address VARCHAR(20) NOT NULL,
                to_address VARCHAR(20) NOT NULL,
                reference_type VARCHAR(50) NOT NULL,
                operand_index INTEGER,
                is_primary BOOLEAN DEFAULT 0,
                FOREIGN KEY (binary_id) REFERENCES binaries (id)
            )
        """)
        
        # Create comprehensive_analyses table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS comprehensive_analyses (
                id VARCHAR(36) PRIMARY KEY,
                binary_id VARCHAR(36) NOT NULL UNIQUE,
                analysis_version VARCHAR(20) DEFAULT '1.0',
                created_at DATETIME NOT NULL,
                program_metadata TEXT,
                statistics TEXT,
                functions_extracted BOOLEAN DEFAULT 0,
                instructions_extracted BOOLEAN DEFAULT 0,
                strings_extracted BOOLEAN DEFAULT 0,
                symbols_extracted BOOLEAN DEFAULT 0,
                xrefs_extracted BOOLEAN DEFAULT 0,
                imports_extracted BOOLEAN DEFAULT 0,
                exports_extracted BOOLEAN DEFAULT 0,
                memory_blocks_extracted BOOLEAN DEFAULT 0,
                data_types_extracted BOOLEAN DEFAULT 0,
                is_complete BOOLEAN DEFAULT 0,
                error_message TEXT,
                FOREIGN KEY (binary_id) REFERENCES binaries (id)
            )
        """)
        
        # Create indexes for performance
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_instruction_binary ON instructions (binary_id)",
            "CREATE INDEX IF NOT EXISTS idx_instruction_addr ON instructions (binary_id, address)",
            "CREATE INDEX IF NOT EXISTS idx_xref_binary ON cross_references (binary_id)",
            "CREATE INDEX IF NOT EXISTS idx_xref_from ON cross_references (binary_id, from_address)",
            "CREATE INDEX IF NOT EXISTS idx_xref_to ON cross_references (binary_id, to_address)",
            "CREATE INDEX IF NOT EXISTS idx_comprehensive_binary ON comprehensive_analyses (binary_id)"
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
        
        # Commit changes
        conn.commit()
        
        print("✅ Successfully created comprehensive analysis tables:")
        print("  - instructions")
        print("  - cross_references") 
        print("  - comprehensive_analyses")
        print("  - Performance indexes")
        
        print("\n🎉 Migration completed successfully!")
        
        # Close connection
        conn.close()
        
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1) 