#!/usr/bin/env python3
"""
Test script for Ghidra Bridge connection from Flask app
"""

import os
import sys
import logging
from datetime import datetime
from flask_app.ghidra_bridge_manager import GhidraBridgeManager

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def main():
    """Test Ghidra Bridge connection from Flask app"""
    print(f"[{datetime.now()}] Testing Ghidra Bridge connection from Flask app...")
    
    # Create a GhidraBridgeManager instance
    ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR', 'D:\\1132-Ghidra\\ghidra_11.3.2_PUBLIC')
    print(f"[{datetime.now()}] Using Ghidra path: {ghidra_path}")
    
    bridge_manager = GhidraBridgeManager(
        ghidra_path=ghidra_path,
        project_dir='ghidra_projects',
        max_connections=3,
        port_start=4768
    )
    
    # Try direct connection
    print(f"[{datetime.now()}] Testing direct connection to Ghidra Bridge...")
    try:
        from ghidra_bridge import GhidraBridge
        bridge = GhidraBridge(connect_to_host="localhost", connect_to_port=4768)
        result = bridge.remote_eval("str(state) if 'state' in globals() else 'Connected to Ghidra'")
        print(f"[{datetime.now()}] Direct connection successful: {result}")
        direct_connected = True
    except Exception as e:
        print(f"[{datetime.now()}] Direct connection failed: {e}")
        direct_connected = False
    
    # Check if connected through bridge manager
    connected = bridge_manager.is_connected()
    print(f"[{datetime.now()}] Bridge manager connected: {connected}")
    
    if connected or direct_connected:
        print(f"[{datetime.now()}] Successfully connected to Ghidra Bridge!")
        return 0
    else:
        print(f"[{datetime.now()}] Failed to connect to Ghidra Bridge")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 