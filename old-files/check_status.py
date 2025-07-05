#!/usr/bin/env python3
"""Quick status check script"""

import requests
import json

def check_system_status():
    """Check system status"""
    try:
        print("=== SYSTEM STATUS CHECK ===")
        
        # Check API health
        print("\n1. Checking API health...")
        r = requests.get('http://localhost:5000/api/status', timeout=5)
        print(f"   Status Code: {r.status_code}")
        
        if r.status_code == 200:
            data = r.json()
            print(f"   Ghidra Bridge: {data.get('ghidra_bridge', 'unknown')}")
            print(f"   Connected: {data.get('ghidra_bridge_connected', 'unknown')}")
            print(f"   Running Tasks: {data.get('tasks', {}).get('running', 0)}")
            print(f"   Queued Tasks: {data.get('tasks', {}).get('queued', 0)}")
        else:
            print(f"   Error: {r.text}")
            
        # Check tasks
        print("\n2. Checking active tasks...")
        r = requests.get('http://localhost:5000/api/tasks', timeout=5)
        if r.status_code == 200:
            tasks = r.json().get('tasks', [])
            print(f"   Total tasks: {len(tasks)}")
            for task in tasks[-5:]:  # Last 5 tasks
                print(f"   - Task {task['id'][:8]}: {task['task_type']} - {task['status']}")
                if task.get('error_message'):
                    print(f"     Error: {task['error_message']}")
        
        # Check comprehensive analysis for dccw.exe
        print("\n3. Checking comprehensive analysis...")
        # We need to find the binary ID for dccw.exe
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
                print(f"   Found dccw.exe binary: {binary_id}")
                
                # Check comprehensive analysis
                r = requests.get(f'http://localhost:5000/api/binaries/{binary_id}/comprehensive-analysis', timeout=5)
                if r.status_code == 200:
                    analysis = r.json().get('analysis')
                    if analysis:
                        print(f"   Analysis complete: {analysis.get('is_complete', False)}")
                        print(f"   Memory blocks extracted: {analysis.get('memory_blocks_extracted', False)}")
                        print(f"   Functions extracted: {analysis.get('functions_extracted', False)}")
                        print(f"   Error message: {analysis.get('error_message', 'None')}")
                        
                        # Check metadata for progress
                        metadata = analysis.get('program_metadata')
                        if metadata and isinstance(metadata, dict):
                            print(f"   Current progress: {metadata.get('progress', 'unknown')}")
                            print(f"   Current step: {metadata.get('current_step', 'unknown')}")
                    else:
                        print("   No analysis data found")
                else:
                    print(f"   Error getting analysis: {r.status_code} - {r.text}")
            else:
                print("   dccw.exe binary not found")
                
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {e}")
        print("Is the Flask server running on localhost:5000?")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_system_status() 