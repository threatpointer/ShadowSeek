#!/usr/bin/env python3
"""
Install Ghidra Bridge Server Script
This script copies the ghidra_bridge_server.py script to the Ghidra scripts directory
"""

import os
import sys
import shutil
from pathlib import Path
import platform

def find_ghidra_path():
    """Find Ghidra installation path from environment or default locations"""
    # Check environment variable
    ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
    if ghidra_path and os.path.exists(ghidra_path):
        return ghidra_path
    
    # Check .env file if it exists
    env_path = Path('.env')
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                if line.startswith('GHIDRA_INSTALL_DIR='):
                    path = line.split('=', 1)[1].strip().strip('"\'')
                    if os.path.exists(path):
                        return path
    
    # Default paths by platform
    default_paths = {
        'Windows': r'D:\1132-Ghidra\ghidra_11.3.2_PUBLIC',
        'Linux': '/opt/ghidra',
        'Darwin': '/Applications/ghidra'
    }
    
    system = platform.system()
    default_path = default_paths.get(system)
    if default_path and os.path.exists(default_path):
        return default_path
    
    return None

def find_bridge_script():
    """Find the ghidra_bridge_server.py script"""
    try:
        import ghidra_bridge
        bridge_dir = Path(ghidra_bridge.__file__).parent
        server_script = bridge_dir / 'server' / 'ghidra_bridge_server.py'
        
        if server_script.exists():
            return server_script
    except ImportError:
        print("Error: ghidra-bridge package not installed")
        return None
    
    return None

def install_bridge_script(ghidra_path):
    """Install the bridge script to Ghidra scripts directory"""
    # Find the bridge script
    bridge_script = find_bridge_script()
    if not bridge_script:
        print("Error: Could not find ghidra_bridge_server.py")
        return False
    
    print(f"Found bridge script at: {bridge_script}")
    
    # Create Ghidra scripts directory
    ghidra_scripts_dir = os.path.join(ghidra_path, "Ghidra", "Features", "Python", "ghidra_scripts")
    
    if not os.path.exists(ghidra_scripts_dir):
        print(f"Creating Ghidra scripts directory: {ghidra_scripts_dir}")
        os.makedirs(ghidra_scripts_dir, exist_ok=True)
    
    # Copy the script
    dest_path = os.path.join(ghidra_scripts_dir, "ghidra_bridge_server.py")
    shutil.copy2(bridge_script, dest_path)
    print(f"Copied bridge script to: {dest_path}")
    
    return True

def main():
    """Main function"""
    print("Installing Ghidra Bridge Server Script")
    
    # Find Ghidra path
    ghidra_path = find_ghidra_path()
    if not ghidra_path:
        print("Error: Could not find Ghidra installation")
        sys.exit(1)
    
    print(f"Using Ghidra at: {ghidra_path}")
    
    # Install the script
    if install_bridge_script(ghidra_path):
        print("✓ Successfully installed ghidra_bridge_server.py")
    else:
        print("Error: Failed to install ghidra_bridge_server.py")
        sys.exit(1)

if __name__ == "__main__":
    main() 