#!/usr/bin/env python3
"""
Bridge Status Checker - Verify Core System Functionality

This script tests if the core bridge functionality that other 
features depend on is still working after our CFG implementation.
"""

import requests
import time
import sys

def test_bridge_status():
    """Test core bridge functionality"""
    print("🔍 Bridge Status Check - Core System Verification")
    print("=" * 60)
    
    base_url = "http://localhost:5000"
    
    # Test 1: Basic API Health
    print("\n1. Testing API Health...")
    try:
        response = requests.get(f"{base_url}/api/status", timeout=10)
        if response.status_code == 200:
            status_data = response.json()
            print(f"✅ API is responding")
            print(f"   Bridge Status: {status_data.get('ghidra_bridge', 'unknown')}")
            print(f"   Bridge Connected: {status_data.get('ghidra_bridge_connected', False)}")
            
            if status_data.get('ghidra_bridge_connected', False):
                print("✅ Bridge is connected and operational")
                return True
            else:
                print("❌ Bridge is disconnected")
                return False
        else:
            print(f"❌ API health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ API connection failed: {e}")
        return False

def test_binary_operations():
    """Test basic binary operations that depend on bridge"""
    print("\n2. Testing Binary Operations...")
    
    base_url = "http://localhost:5000"
    
    try:
        # Get list of binaries
        response = requests.get(f"{base_url}/api/binaries", timeout=10)
        if response.status_code == 200:
            binaries = response.json()
            print(f"✅ Binary listing works: {len(binaries)} binaries found")
            
            if binaries:
                # Test binary details for first binary
                binary_id = binaries[0]['id']
                detail_response = requests.get(f"{base_url}/api/binaries/{binary_id}", timeout=10)
                if detail_response.status_code == 200:
                    print(f"✅ Binary details accessible for ID {binary_id}")
                    return True
                else:
                    print(f"❌ Binary details failed: {detail_response.status_code}")
                    return False
            else:
                print("⚠️  No binaries available for testing")
                return True
        else:
            print(f"❌ Binary listing failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Binary operations failed: {e}")
        return False

def test_analysis_features():
    """Test non-CFG analysis features"""
    print("\n3. Testing Analysis Features...")
    
    base_url = "http://localhost:5000"
    
    try:
        # Test if we can get task status
        response = requests.get(f"{base_url}/api/tasks", timeout=10)
        if response.status_code == 200:
            tasks = response.json()
            print(f"✅ Task management operational: {len(tasks)} tasks")
            return True
        else:
            print(f"❌ Task management failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Analysis features test failed: {e}")
        return False

def main():
    """Run comprehensive bridge status check"""
    print("🧪 Core System Functionality Check")
    print("Testing if bridge-dependent features still work...")
    print()
    
    tests = [
        ("Bridge Status", test_bridge_status),
        ("Binary Operations", test_binary_operations), 
        ("Analysis Features", test_analysis_features)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 BRIDGE STATUS SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<20} {status}")
        if not result:
            all_passed = False
    
    print()
    if all_passed:
        print("🎉 ALL CORE SYSTEMS OPERATIONAL")
        print("✅ Bridge functionality appears intact")
        print("✅ Safe to proceed with CFG completion")
    else:
        print("⚠️  CORE SYSTEM ISSUES DETECTED")
        print("❌ Bridge functionality may be compromised") 
        print("🔧 Bridge repair needed before CFG completion")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 