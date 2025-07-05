#!/usr/bin/env python3
"""
Test script for Ghidra Bridge
"""

from ghidra_bridge import GhidraBridge

def test_bridge():
    """Test Ghidra Bridge connection and script execution"""
    print("Connecting to Ghidra Bridge...")
    bridge = GhidraBridge(connect_to_host="localhost", connect_to_port=4768)
    print("Connected to Ghidra Bridge")
    
    # Test simple evaluation
    try:
        state_str = bridge.remote_eval("str(state)")
        print(f"Ghidra state: {state_str}")
    except Exception as e:
        print(f"Error accessing state: {e}")
    
    # Test simple script execution - Python 2.7 compatible
    script = """
# Simple test script
result = {
    "status": "success",
    "message": "Script executed successfully"
}
"""
    try:
        result = bridge.remote_eval(script)
        print(f"Script result: {result}")
    except Exception as e:
        print(f"Error executing script: {e}")
    
    # Test if we can access Ghidra objects - Python 2.7 compatible
    test_script = """
# Import Ghidra classes
from ghidra.program.model.listing import CodeUnit

# Return result
result = {
    "status": "success",
    "message": "Successfully imported Ghidra classes",
    "code_unit_class": str(CodeUnit)
}
"""
    try:
        result = bridge.remote_eval(test_script)
        print(f"Ghidra classes access: {result}")
    except Exception as e:
        print(f"Error accessing Ghidra classes: {e}")
    
    # Test if we can access Ghidra environment - Python 2.7 compatible
    env_script = """
# Check Ghidra environment
import sys
import os

# Get Python version and environment info
result = {
    "python_version": sys.version,
    "sys_path": sys.path,
    "has_current_program": "currentProgram" in globals(),
    "has_state": "state" in globals(),
    "os_name": os.name
}

# Add state info if available
if "state" in globals():
    result["state_class"] = state.__class__.__name__

# Add current program info if available
if "currentProgram" in globals() and currentProgram:
    result["program_name"] = currentProgram.getName()
    result["program_language"] = str(currentProgram.getLanguage())

result
"""
    try:
        result = bridge.remote_eval(env_script)
        print(f"Ghidra environment: {result}")
    except Exception as e:
        print(f"Error checking Ghidra environment: {e}")
    
    return True

if __name__ == "__main__":
    test_bridge() 