#!/usr/bin/env python3
"""
Test runner for ShadowSeek - Advanced Binary Security Analysis Platform
"""

import os
import sys
import importlib
import unittest
from datetime import datetime

def run_test(test_name):
    """Run a specific test"""
    print(f"[{datetime.now()}] Running test: {test_name}")
    
    try:
        # Import the test module
        module_name = os.path.splitext(test_name)[0]
        module = importlib.import_module(module_name)
        
        # If it's a unittest module, run with unittest
        if hasattr(module, 'unittest'):
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            result = unittest.TextTestRunner().run(suite)
            return result.wasSuccessful()
        
        # Otherwise, run the main function if it exists
        elif hasattr(module, 'main'):
            result = module.main()
            return result == 0 if isinstance(result, int) else result
        
        # If no main function, assume success
        else:
            print(f"[{datetime.now()}] Warning: No main function found in {test_name}")
            return True
            
    except Exception as e:
        print(f"[{datetime.now()}] Error running test {test_name}: {e}")
        return False

def main():
    """Run all tests or specified tests"""
    # Get test files
    if len(sys.argv) > 1:
        test_files = [f"{f}.py" if not f.endswith('.py') else f for f in sys.argv[1:]]
    else:
        # Note: Previous test files have been moved to archive/testing
        print(f"[{datetime.now()}] No tests found. Previous tests have been moved to archive/testing.")
        return 0
    
    print(f"[{datetime.now()}] Running {len(test_files)} tests:")
    for test_file in test_files:
        print(f"  - {test_file}")
    print()
    
    # Run tests
    results = {}
    for test_file in test_files:
        results[test_file] = run_test(test_file)
        print()
    
    # Print summary
    print(f"[{datetime.now()}] Test Summary:")
    if not results:
        print("  No tests were run.")
        return 0
        
    passed = sum(1 for r in results.values() if r)
    failed = len(results) - passed
    
    for test_file, result in results.items():
        status = "PASSED" if result else "FAILED"
        print(f"  - {test_file}: {status}")
    
    print(f"\nPassed: {passed}/{len(results)} ({passed/len(results)*100:.1f}%)")
    print(f"Failed: {failed}/{len(results)} ({failed/len(results)*100:.1f}%)")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    # Change to the tests directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main()) 