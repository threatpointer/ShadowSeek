#!/usr/bin/env python
"""
Test script for Ghidra Bridge setup
"""

import os
import sys
import time
import argparse
from pathlib import Path

def test_ghidra_bridge(ghidra_path=None):
    """
    Test Ghidra Bridge setup
    
    Args:
        ghidra_path: Path to Ghidra installation
    """
    if not ghidra_path:
        # Try to get from environment variable
        ghidra_path = os.environ.get('GHIDRA_PATH')
        
        if not ghidra_path:
            print("Error: Ghidra path not provided. Please specify the path to your Ghidra installation.")
            print("Usage: python test_ghidra_bridge.py [path/to/ghidra]")
            return False
    
    # Verify Ghidra path
    ghidra_run = os.path.join(ghidra_path, "ghidraRun.bat" if os.name == 'nt' else "ghidraRun")
    if not os.path.exists(ghidra_run):
        print(f"Error: Could not find Ghidra at {ghidra_path}")
        return False
    
    print(f"Using Ghidra installation at: {ghidra_path}")
    
    # Check if ghidra-bridge is installed
    try:
        import ghidra_bridge
        print("ghidra-bridge package is installed.")
    except ImportError:
        print("Error: ghidra-bridge package is not installed.")
        print("Please run: pip install ghidra-bridge")
        return False
    
    # Check if bridge server script exists
    bridge_script_dir = os.path.join(ghidra_path, "Ghidra", "Features", "Base", "ghidra_scripts", "jfx_bridge")
    bridge_server_script = os.path.join(bridge_script_dir, "ghidra_bridge_server.py")
    
    if not os.path.exists(bridge_server_script):
        print(f"Error: Bridge server script not found at {bridge_server_script}")
        print("Please run setup_ghidra_bridge.py first.")
        return False
    
    print(f"Bridge server script found at {bridge_server_script}")
    
    # Test connecting to Ghidra Bridge
    print("\nTesting connection to Ghidra Bridge...")
    print("Starting Ghidra in headless mode with bridge server...")
    
    # Create a test project directory
    test_dir = os.path.join(os.getcwd(), "test_ghidra_bridge")
    os.makedirs(test_dir, exist_ok=True)
    
    # Import required modules
    import subprocess
    import threading
    
    # Start Ghidra Bridge in a separate thread
    def start_bridge():
        cmd = [
            ghidra_run,
            "analyzeHeadless",
            test_dir,
            "TestProject",
            "-scriptPath", bridge_script_dir,
            "-postScript", "ghidra_bridge_server.py", "13337"
        ]
        
        print(f"Running command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Wait for process to exit
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            print(f"Bridge process exited with code {process.returncode}")
            print(f"STDOUT: {stdout.decode('utf-8', errors='replace')}")
            print(f"STDERR: {stderr.decode('utf-8', errors='replace')}")
    
    # Start bridge thread
    bridge_thread = threading.Thread(target=start_bridge)
    bridge_thread.daemon = True
    bridge_thread.start()
    
    # Wait for bridge to start
    print("Waiting for bridge to start (10 seconds)...")
    time.sleep(10)
    
    # Try to connect to the bridge
    try:
        from ghidra_bridge import GhidraBridge
        
        print("Connecting to bridge...")
        bridge = GhidraBridge(host="localhost", port=13337)
        
        # Test basic functionality
        version = bridge.remote_eval("getVersionInfo()")
        print(f"Connected to Ghidra version: {version}")
        
        # Test calling a function
        print("\nTesting remote function call...")
        result = bridge.remote_eval("1 + 1")
        print(f"1 + 1 = {result}")
        
        print("\nGhidra Bridge test successful!")
        return True
        
    except Exception as e:
        print(f"Error connecting to Ghidra Bridge: {e}")
        return False
    finally:
        # Clean up
        print("\nCleaning up...")
        if os.name == 'nt':
            os.system("taskkill /f /im java.exe /fi \"WINDOWTITLE eq Ghidra*\" >nul 2>&1")
        else:
            os.system("pkill -f 'Ghidra'")

if __name__ == "__main__":
    # Parse arguments
    parser = argparse.ArgumentParser(description="Test Ghidra Bridge setup")
    parser.add_argument("ghidra_path", nargs="?", help="Path to Ghidra installation")
    args = parser.parse_args()
    
    # Run test
    success = test_ghidra_bridge(args.ghidra_path)
    sys.exit(0 if success else 1) 