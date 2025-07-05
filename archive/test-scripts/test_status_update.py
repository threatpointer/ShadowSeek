#!/usr/bin/env python3
"""
Test script to verify the new capitalized binary status system
"""

import requests
import json

def test_status_system():
    """Test the updated status system"""
    print("🧪 Testing Updated Binary Status System")
    print("=" * 50)
    
    try:
        # Test 1: Get all binaries and check their statuses
        print("1. Checking all binary statuses...")
        response = requests.get('http://localhost:5000/api/binaries')
        if response.status_code == 200:
            data = response.json()
            binaries = data.get('binaries', [])
            print(f"   Found {len(binaries)} binaries")
            
            status_counts = {}
            for binary in binaries:
                status = binary['analysis_status']
                status_counts[status] = status_counts.get(status, 0) + 1
                print(f"   📁 {binary['original_filename']}: {status}")
            
            print(f"   Status summary: {status_counts}")
        else:
            print(f"   ❌ Failed to get binaries: {response.status_code}")
        
        print()
        
        # Test 2: Check fuzzing-ready binaries
        print("2. Checking fuzzing-ready binaries...")
        response = requests.get('http://localhost:5000/api/binaries/fuzzing-ready')
        if response.status_code == 200:
            data = response.json()
            ready_binaries = data.get('fuzzing_ready_binaries', [])
            print(f"   Found {len(ready_binaries)} fuzzing-ready binaries")
            
            for binary in ready_binaries:
                print(f"   🎯 {binary['filename']}: {binary['status']} ({binary['decompile_percentage']:.1f}% decompiled)")
        else:
            print(f"   ❌ Failed to get fuzzing-ready binaries: {response.status_code}")
        
        print()
        
        # Test 3: Check binary status info for a specific binary
        if binaries:
            binary_id = binaries[0]['id']
            print(f"3. Checking detailed status info for binary: {binaries[0]['original_filename']}")
            response = requests.get(f'http://localhost:5000/api/binaries/{binary_id}/status-info')
            if response.status_code == 200:
                data = response.json()
                print(f"   Current Status: {data['current_status']}")
                print(f"   Fuzzing Ready: {data['fuzzing_ready']}")
                stats = data.get('statistics', {})
                print(f"   Functions: {stats.get('decompiled_functions', 0)}/{stats.get('total_functions', 0)} decompiled")
                print(f"   AI Analyzed: {stats.get('ai_analyzed_functions', 0)}")
                print(f"   Security Findings: {stats.get('security_findings', 0)}")
                print(f"   Fuzzing Harnesses: {stats.get('fuzzing_harnesses', 0)}")
            else:
                print(f"   ❌ Failed to get status info: {response.status_code}")
        
        print()
        print("✅ Status system test completed!")
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")

if __name__ == "__main__":
    test_status_system() 