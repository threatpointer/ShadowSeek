#!/usr/bin/env python3
"""
Test script for the comprehensive analysis system
"""

import os
import sys
import time
import requests
import json
from pathlib import Path

# Base URL for the Flask API
BASE_URL = "http://localhost:5000/api"

def test_system():
    """Test the comprehensive analysis system end-to-end"""
    
    print("🚀 Testing Comprehensive Analysis System")
    print("=" * 50)
    
    # Step 1: Check if system is running
    print("\n1. Checking system status...")
    try:
        response = requests.get(f"{BASE_URL}/binaries", timeout=5)
        if response.status_code == 200:
            print("✅ System is running")
        else:
            print(f"❌ System error: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to system: {e}")
        print("Make sure Flask app is running on localhost:5000")
        return False
    
    # Step 2: Get list of existing binaries
    print("\n2. Checking for existing binaries...")
    binaries = response.json().get('binaries', [])
    print(f"Found {len(binaries)} existing binaries")
    
    if binaries:
        # Use the first binary for testing
        binary = binaries[0]
        binary_id = binary['id']
        print(f"✅ Using existing binary: {binary['original_filename']} (ID: {binary_id})")
    else:
        print("❌ No binaries found. Please upload a binary first using the web interface.")
        return False
    
    # Step 3: Check if binary has comprehensive analysis
    print(f"\n3. Checking comprehensive analysis status for binary {binary_id}...")
    try:
        response = requests.get(f"{BASE_URL}/binaries/{binary_id}/comprehensive-analysis")
        if response.status_code == 200:
            analysis = response.json()
            if analysis.get('analysis') and analysis['analysis'].get('is_complete'):
                print("✅ Comprehensive analysis already exists")
                print(f"   Analysis version: {analysis['analysis'].get('analysis_version', 'Unknown')}")
                print(f"   Functions extracted: {analysis['analysis'].get('functions_extracted', False)}")
                print(f"   Instructions extracted: {analysis['analysis'].get('instructions_extracted', False)}")
                test_data_retrieval(binary_id)
                return True
            else:
                print("⚠️  Comprehensive analysis incomplete or not started")
        else:
            print("📝 No comprehensive analysis found")
    except Exception as e:
        print(f"⚠️  Error checking analysis: {e}")
    
    # Step 4: Start comprehensive analysis
    print(f"\n4. Starting comprehensive analysis for binary {binary_id}...")
    try:
        response = requests.post(f"{BASE_URL}/binaries/{binary_id}/comprehensive-analysis")
        if response.status_code == 200:
            result = response.json()
            if result.get('cached'):
                print("✅ Analysis loaded from cache")
                test_data_retrieval(binary_id)
                return True
            else:
                print(f"✅ Analysis started. Task ID: {result.get('task_id')}")
                
                # Step 5: Monitor progress
                print("\n5. Monitoring analysis progress...")
                return monitor_analysis_progress(binary_id)
        else:
            error_msg = response.json().get('error', 'Unknown error')
            print(f"❌ Failed to start analysis: {error_msg}")
            return False
    except Exception as e:
        print(f"❌ Error starting analysis: {e}")
        return False

def monitor_analysis_progress(binary_id, max_wait_minutes=30):
    """Monitor the progress of comprehensive analysis"""
    
    start_time = time.time()
    max_wait_seconds = max_wait_minutes * 60
    
    print(f"Monitoring for up to {max_wait_minutes} minutes...")
    
    while True:
        try:
            # Check progress
            response = requests.get(f"{BASE_URL}/binaries/{binary_id}/comprehensive-analysis")
            if response.status_code == 200:
                analysis = response.json()
                
                if analysis.get('analysis'):
                    analysis_data = analysis['analysis']
                    
                    # Show progress
                    completed_steps = sum([
                        analysis_data.get('functions_extracted', False),
                        analysis_data.get('instructions_extracted', False),
                        analysis_data.get('strings_extracted', False),
                        analysis_data.get('symbols_extracted', False),
                        analysis_data.get('xrefs_extracted', False),
                        analysis_data.get('imports_extracted', False),
                        analysis_data.get('exports_extracted', False),
                        analysis_data.get('memory_blocks_extracted', False),
                        analysis_data.get('data_types_extracted', False)
                    ])
                    
                    progress = (completed_steps / 9) * 100
                    print(f"📊 Progress: {progress:.1f}% ({completed_steps}/9 steps)")
                    
                    if analysis_data.get('is_complete'):
                        print("✅ Comprehensive analysis completed!")
                        
                        # Show statistics
                        if analysis_data.get('statistics'):
                            stats = json.loads(analysis_data['statistics'])
                            print("\n📈 Analysis Statistics:")
                            for key, value in stats.items():
                                print(f"   {key}: {value}")
                        
                        # Test data retrieval
                        test_data_retrieval(binary_id)
                        return True
                    
                    if analysis_data.get('error_message'):
                        print(f"❌ Analysis failed: {analysis_data['error_message']}")
                        return False
                
                # Check if we've exceeded the time limit
                elapsed = time.time() - start_time
                if elapsed > max_wait_seconds:
                    print(f"⏰ Timeout: Analysis took longer than {max_wait_minutes} minutes")
                    return False
                
                # Wait before next check
                time.sleep(10)
                
            else:
                print(f"❌ Error checking progress: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Error monitoring progress: {e}")
            return False

def test_data_retrieval(binary_id):
    """Test retrieving different types of comprehensive analysis data"""
    
    print("\n6. Testing data retrieval...")
    
    data_types = [
        ('functions', 'Functions'),
        ('instructions', 'Instructions'),
        ('strings', 'Strings'),
        ('symbols', 'Symbols'),
        ('imports', 'Imports'),
        ('exports', 'Exports'),
        ('memory-regions', 'Memory Regions'),
        ('cross-references', 'Cross References')
    ]
    
    for data_type, label in data_types:
        try:
            print(f"   Fetching {label}...")
            response = requests.get(f"{BASE_URL}/binaries/{binary_id}/comprehensive-data/{data_type}?page=1&per_page=5")
            
            if response.status_code == 200:
                data = response.json()
                count = len(data.get('data', []))
                total = data.get('pagination', {}).get('total', 0)
                print(f"   ✅ {label}: {count} items shown (total: {total})")
            else:
                print(f"   ❌ {label}: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ {label}: Error - {e}")
    
    print("\n🎉 System test completed!")
    return True

if __name__ == '__main__':
    success = test_system()
    print("\n" + "=" * 50)
    if success:
        print("✅ All tests passed! Comprehensive analysis system is working.")
    else:
        print("❌ Some tests failed. Check the output above for details.")
    
    sys.exit(0 if success else 1) 