#!/usr/bin/env python3
"""
Database migration script to add unified security analysis tables
"""

import os
import sys
import logging
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask_app import create_app, db
from flask_app.models import (
    Binary, Function, UnifiedSecurityFinding, SecurityEvidence, 
    VulnerabilityPattern
)

try:
    from flask_app.models import Configuration
    HAS_CONFIG = True
except ImportError:
    HAS_CONFIG = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_unified_security_tables():
    """Create unified security analysis tables"""
    try:
        logger.info("Creating unified security analysis tables...")
        
        # Create tables
        db.create_all()
        
        logger.info("✅ Unified security analysis tables created successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error creating unified security tables: {str(e)}")
        return False

def add_default_unified_config():
    """Add default configuration for unified security analysis"""
    if not HAS_CONFIG:
        logger.info("Configuration model not available, skipping configuration setup")
        return True
        
    try:
        logger.info("Adding default unified security configuration...")
        
        configs = [
            {
                'key': 'unified_security_enabled',
                'value': 'true',
                'value_type': 'bool',
                'description': 'Enable unified security analysis system',
                'is_public': True
            },
            {
                'key': 'unified_security_confidence_threshold',
                'value': '70',
                'value_type': 'int',
                'description': 'Minimum confidence threshold for unified security findings',
                'is_public': True
            },
            {
                'key': 'unified_security_correlation_weight',
                'value': '0.6',
                'value_type': 'float',
                'description': 'Weight given to AI-pattern correlation in confidence calculation',
                'is_public': False
            },
            {
                'key': 'unified_security_ai_weight',
                'value': '0.4',
                'value_type': 'float',
                'description': 'Weight given to AI analysis in unified security scoring',
                'is_public': False
            },
            {
                'key': 'unified_security_pattern_weight',
                'value': '0.6',
                'value_type': 'float',
                'description': 'Weight given to pattern matching in unified security scoring',
                'is_public': False
            }
        ]
        
        for config_data in configs:
            existing = Configuration.query.filter_by(key=config_data['key']).first()
            if not existing:
                config = Configuration(
                    key=config_data['key'],
                    value=config_data['value'],
                    value_type=config_data['value_type'],
                    description=config_data['description'],
                    is_public=config_data['is_public']
                )
                db.session.add(config)
                logger.info(f"  Added configuration: {config_data['key']}")
            else:
                logger.info(f"  Configuration already exists: {config_data['key']}")
        
        db.session.commit()
        logger.info("✅ Default unified security configuration added successfully")
        return True
        
    except Exception as e:
        logger.error(f"❌ Error adding unified security configuration: {str(e)}")
        db.session.rollback()
        return False

def verify_migration():
    """Verify that the migration was successful"""
    try:
        logger.info("Verifying unified security migration...")
        
        # Check if tables exist by attempting to query them
        unified_count = UnifiedSecurityFinding.query.count()
        evidence_count = SecurityEvidence.query.count()
        
        logger.info(f"  UnifiedSecurityFinding table: {unified_count} records")
        logger.info(f"  SecurityEvidence table: {evidence_count} records") 
        
        if HAS_CONFIG:
            config_count = Configuration.query.filter_by(key='unified_security_enabled').count()
            logger.info(f"  Unified security config: {config_count} records")
            
            if config_count > 0:
                logger.info("✅ Unified security migration verified successfully")
                return True
            else:
                logger.error("❌ Unified security configuration not found")
                return False
        else:
            logger.info("✅ Unified security migration verified successfully (no config model)")
            return True
            
    except Exception as e:
        logger.error(f"❌ Error verifying migration: {str(e)}")
        return False

def main():
    """Main migration function"""
    logger.info("=" * 60)
    logger.info("UNIFIED SECURITY ANALYSIS MIGRATION")
    logger.info("=" * 60)
    
    # Create Flask app
    app = create_app()
    
    with app.app_context():
        success = True
        
        # Step 1: Create tables
        if not create_unified_security_tables():
            success = False
        
        # Step 2: Add default configuration
        if success and not add_default_unified_config():
            success = False
        
        # Step 3: Verify migration
        if success and not verify_migration():
            success = False
        
        if success:
            logger.info("=" * 60)
            logger.info("🎉 UNIFIED SECURITY MIGRATION COMPLETED SUCCESSFULLY")
            logger.info("=" * 60)
            logger.info("Next steps:")
            logger.info("  1. Restart the Flask application")
            logger.info("  2. Test unified security analysis endpoints")
            logger.info("  3. Verify frontend integration")
            logger.info("=" * 60)
        else:
            logger.error("=" * 60)
            logger.error("❌ UNIFIED SECURITY MIGRATION FAILED")
            logger.error("=" * 60)
            logger.error("Please check the error messages above and try again.")
            logger.error("=" * 60)
            sys.exit(1)

if __name__ == '__main__':
    main() 