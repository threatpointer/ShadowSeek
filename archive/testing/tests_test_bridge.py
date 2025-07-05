#!/usr/bin/env python3
"""
Test script for Ghidra Bridge connection
"""

import os
import sys
import time
from datetime import datetime

def test_bridge_connection():
    """Test connection to Ghidra Bridge"""
    print(f"[{datetime.now()}] Testing Ghidra Bridge connection...")
    
    try:
        from ghidra_bridge import GhidraBridge
        
        # Create bridge with default settings
        bridge = GhidraBridge(connect_to_host="localhost", connect_to_port=4768, namespace=globals())
        
        # Try to execute a simple command
        # Just test if we can get the state object, which should always exist
        result = bridge.remote_eval("str(state) if 'state' in globals() else 'Connected to Ghidra'")
        print(f"[{datetime.now()}] Successfully connected to Ghidra Bridge!")
        print(f"[{datetime.now()}] Result: {result}")
        
        # Check if a program is loaded
        program_name = bridge.remote_eval("currentProgram.getName() if currentProgram else 'No program loaded'")
        print(f"[{datetime.now()}] Current program: {program_name}")
        
        return True
    except Exception as e:
        print(f"[{datetime.now()}] Failed to connect to Ghidra Bridge: {e}")
        return False

if __name__ == "__main__":
    # Try to connect multiple times
    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        print(f"[{datetime.now()}] Connection attempt {attempt}/{max_attempts}...")
        if test_bridge_connection():
            sys.exit(0)
        
        if attempt < max_attempts:
            print(f"[{datetime.now()}] Waiting 5 seconds before retrying...")
            time.sleep(5)
    
    print(f"[{datetime.now()}] Failed to connect to Ghidra Bridge after {max_attempts} attempts")
    sys.exit(1) 