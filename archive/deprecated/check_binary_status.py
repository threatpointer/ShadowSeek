#!/usr/bin/env python3
"""
Check binary status and function completion
"""

import requests
import json

def check_binary_status():
    """Check the status of specific binaries"""
    binary_ids = ['1fe8c353-d30b-443b-957c-05e330d1f9bf', '19aadcc8-6a14-4ca6-83ca-4b9f3c8dcc47']
    
    for binary_id in binary_ids:
        try:
            response = requests.get(f'http://localhost:5000/api/binaries/{binary_id}')
            if response.status_code == 200:
                data = response.json()
                binary = data['binary']
                functions = data['functions']
                
                total_functions = len([f for f in functions if not f.get('is_external', False)])
                decompiled_functions = len([f for f in functions if not f.get('is_external', False) and f.get('is_decompiled', False)])
                ai_analyzed = len([f for f in functions if f.get('ai_analyzed', False)])
                
                decompile_percentage = (decompiled_functions / total_functions * 100) if total_functions > 0 else 0
                
                print(f'Binary {binary_id}:')
                print(f'  Status: {binary["analysis_status"]}')
                print(f'  Functions: {decompiled_functions}/{total_functions} decompiled ({decompile_percentage:.1f}%)')
                print(f'  AI Analyzed: {ai_analyzed}')
                print(f'  Filename: {binary["original_filename"]}')
                print()
                
                # Check if there are any running tasks
                tasks_response = requests.get(f'http://localhost:5000/api/binaries/{binary_id}/tasks')
                if tasks_response.status_code == 200:
                    tasks = tasks_response.json().get('tasks', [])
                    running_tasks = [t for t in tasks if t['status'] in ['running', 'queued']]
                    if running_tasks:
                        print(f'  Running tasks: {len(running_tasks)}')
                        for task in running_tasks[:3]:  # Show first 3
                            print(f'    - {task["task_type"]} ({task["status"]})')
                        print()
                    else:
                        print(f'  No running tasks')
                        print()
            else:
                print(f'Error getting binary {binary_id}: {response.status_code}')
                
        except Exception as e:
            print(f'Exception checking binary {binary_id}: {e}')

if __name__ == "__main__":
    check_binary_status() 