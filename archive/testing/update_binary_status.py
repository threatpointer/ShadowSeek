#!/usr/bin/env python3
"""
Update binary status
"""

import sys
from flask_app import create_app
from flask_app.models import db, Binary

def update_binary_status(binary_id, status="processing"):
    """Update binary status"""
    app = create_app()
    
    with app.app_context():
        binary = Binary.query.get(binary_id)
        if not binary:
            print(f"Binary {binary_id} not found")
            return False
        
        print(f"Updating binary {binary_id} status from {binary.analysis_status} to {status}")
        binary.analysis_status = status
        db.session.commit()
        print(f"Binary {binary_id} status updated to {status}")
        return True

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python update_binary_status.py <binary_id> [status]")
        return
    
    binary_id = sys.argv[1]
    status = sys.argv[2] if len(sys.argv) > 2 else "processing"
    
    update_binary_status(binary_id, status)

if __name__ == "__main__":
    main() 