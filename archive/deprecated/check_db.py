
#!/usr/bin/env python3
"""
Check database status
"""

from flask_app import create_app
from flask_app.models import db, Binary, AnalysisTask, AnalysisResult, Function

app = create_app()

with app.app_context():
    # Check binaries
    binaries = Binary.query.all()
    print(f"Total binaries: {len(binaries)}")
    for binary in binaries:
        print(f"Binary ID: {binary.id}, Name: {binary.original_filename}, Status: {binary.analysis_status}")
    
    # Check tasks
    tasks = AnalysisTask.query.all()
    print(f"\nTotal tasks: {len(tasks)}")
    for task in tasks:
        print(f"Task ID: {task.id}, Type: {task.task_type}, Status: {task.status}, Binary ID: {task.binary_id}")
        if task.error_message:
            print(f"  Error: {task.error_message}")
    
    # Check results
    results = AnalysisResult.query.all()
    print(f"\nTotal results: {len(results)}")
    for result in results:
        print(f"Result ID: {result.id}, Type: {result.analysis_type}, Binary ID: {result.binary_id}")
    
    # Check functions
    functions = Function.query.all()
    print(f"\nTotal functions: {len(functions)}")
    if functions:
        print(f"Sample functions (up to 5):")
        for function in functions[:5]:
            print(f"Function: {function.name} at {function.address}") 