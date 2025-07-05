#!/usr/bin/env python3
"""
Check tasks in the database
"""

from flask_app import create_app
from flask_app.models import AnalysisTask

def main():
    """Main function"""
    app = create_app()
    
    with app.app_context():
        tasks = AnalysisTask.query.all()
        print(f"Found {len(tasks)} tasks")
        
        for task in tasks:
            print(f"Task {task.id}: {task.status}")
            print(f"  Binary ID: {task.binary_id}")
            print(f"  Created: {task.created_at}")
            print(f"  Started: {task.started_at}")
            print(f"  Completed: {task.completed_at}")
            print(f"  Error: {task.error_message}")
            print()

if __name__ == "__main__":
    main() 