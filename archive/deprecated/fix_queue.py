#!/usr/bin/env python3
"""Fix the task queue and restart analysis"""

import requests
import json

def fix_analysis():
    print("=== FIXING TASK QUEUE ===")
    
    # 1. Cancel all queued/running tasks to clear the backlog
    print("\n1. Canceling all tasks to clear backlog...")
    try:
        r = requests.post('http://localhost:5000/api/tasks/cancel-all', timeout=10)
        if r.status_code == 200:
            result = r.json()
            print(f"   ✅ {result.get('message', 'Tasks cancelled')}")
        else:
            print(f"   ⚠️ Response: {r.status_code} - {r.text}")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # 2. Find dccw.exe binary
    print("\n2. Finding dccw.exe binary...")
    try:
        r = requests.get('http://localhost:5000/api/binaries', timeout=5)
        if r.status_code == 200:
            binaries = r.json().get('binaries', [])
            dccw_binary = None
            for binary in binaries:
                if 'dccw.exe' in binary['original_filename']:
                    dccw_binary = binary
                    break
            
            if dccw_binary:
                binary_id = dccw_binary['id']
                print(f"   ✅ Found dccw.exe: {binary_id}")
                print(f"   Status: {dccw_binary['analysis_status']}")
                
                # 3. Start fresh comprehensive analysis
                print("\n3. Starting fresh comprehensive analysis...")
                r = requests.post(f'http://localhost:5000/api/binaries/{binary_id}/comprehensive-analysis', timeout=10)
                if r.status_code == 200:
                    result = r.json()
                    print(f"   ✅ Analysis started!")
                    print(f"   Task ID: {result.get('task_id')}")
                else:
                    print(f"   ❌ Failed: {r.status_code} - {r.text}")
                    
                # 4. Check new status
                print("\n4. Checking new task status...")
                r = requests.get('http://localhost:5000/api/status', timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    print(f"   Running tasks: {data.get('tasks', {}).get('running', 0)}")
                    print(f"   Queued tasks: {data.get('tasks', {}).get('queued', 0)}")
                    
            else:
                print("   ❌ dccw.exe binary not found")
                
    except Exception as e:
        print(f"   ❌ Error: {e}")

if __name__ == "__main__":
    fix_analysis() 