#!/usr/bin/env python3
"""
Setup script for Ghidra Bridge
Installs and configures ghidra-bridge for the project
"""

import os
import sys
import shutil
import subprocess
import argparse
from pathlib import Path
import platform
import time

# Default Ghidra installation paths by platform
DEFAULT_GHIDRA_PATH = {
    'Windows': r'D:\1132-Ghidra\ghidra_11.3.2_PUBLIC',
    'Linux': '/opt/ghidra',
    'Darwin': '/Applications/ghidra'
}

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Setup and manage ghidra-bridge')
    parser.add_argument('--ghidra-path', '-g', 
                        help='Path to Ghidra installation')
    parser.add_argument('--start-server', '-s', action='store_true',
                        help='Start the Ghidra Bridge server')
    parser.add_argument('--port', '-p', type=int, default=4768,
                        help='Port for the Ghidra Bridge server (default: 4768)')
    return parser.parse_args()

def find_ghidra_path():
    """Find Ghidra installation path from environment or default locations"""
    # Check environment variable
    ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
    if ghidra_path and os.path.exists(ghidra_path):
        return ghidra_path
    
    # Check default path for platform
    system = platform.system()
    default_path = DEFAULT_GHIDRA_PATH.get(system)
    if default_path and os.path.exists(default_path):
        return default_path
    
    # Check .env file if it exists
    env_path = Path('.env')
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                if line.startswith('GHIDRA_INSTALL_DIR='):
                    path = line.split('=', 1)[1].strip().strip('"\'')
                    if os.path.exists(path):
                        return path
    
    return None

def install_ghidra_bridge(ghidra_path):
    """Install ghidra-bridge package and configure it"""
    print(f"Installing ghidra-bridge for Ghidra at: {ghidra_path}")
    
    # Install ghidra-bridge package
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'ghidra-bridge'])
        print("✓ ghidra-bridge package installed")
    except subprocess.CalledProcessError as e:
        print(f"Error installing ghidra-bridge: {e}")
        return False
    
    # Find ghidra_bridge_server.py
    try:
        import ghidra_bridge
        bridge_dir = Path(ghidra_bridge.__file__).parent
        server_script = bridge_dir / 'server' / 'ghidra_bridge_server.py'
        
        if not server_script.exists():
            print(f"Error: ghidra_bridge_server.py not found at {server_script}")
            return False
        
        print(f"✓ Found ghidra_bridge_server.py at {server_script}")
    except ImportError:
        print("Error: Failed to import ghidra_bridge")
        return False
    
    # Create Ghidra scripts directory if it doesn't exist
    ghidra_version = os.path.basename(ghidra_path)
    if not ghidra_version.startswith('ghidra_'):
        # Try to find the actual Ghidra version directory
        for item in os.listdir(ghidra_path):
            if item.startswith('ghidra_'):
                ghidra_version = item
                break
    
    user_home = os.path.expanduser('~')
    ghidra_user_dir = os.path.join(user_home, '.ghidra')
    ghidra_scripts_dir = os.path.join(ghidra_user_dir, f'.{ghidra_version}', 'Extensions', 'ghidra_bridge')
    
    os.makedirs(ghidra_scripts_dir, exist_ok=True)
    print(f"✓ Created Ghidra scripts directory at {ghidra_scripts_dir}")
    
    # Copy ghidra_bridge_server.py to Ghidra scripts directory
    shutil.copy2(server_script, os.path.join(ghidra_scripts_dir, 'ghidra_bridge_server.py'))
    print(f"✓ Copied ghidra_bridge_server.py to {ghidra_scripts_dir}")
    
    return True

def start_bridge_server(port=4768):
    """Start the Ghidra Bridge server"""
    print(f"Starting Ghidra Bridge server on port {port}...")
    
    # Look for the bridge script in Ghidra installation
    ghidra_path = find_ghidra_path()
    if not ghidra_path:
        print("Error: Ghidra installation not found")
        return False
        
    # Check in Ghidra scripts directory
    bridge_script_path = os.path.join(ghidra_path, "Ghidra", "Features", "Base", "ghidra_scripts", "jfx_bridge", "ghidra_bridge_server.py")
    
    if not os.path.exists(bridge_script_path):
        print(f"Error: ghidra_bridge_server.py not found at {bridge_script_path}")
        
        # Try to find it in the Python package
        try:
            import ghidra_bridge
            bridge_dir = Path(ghidra_bridge.__file__).parent
            server_script = bridge_dir / 'server' / 'ghidra_bridge_server.py'
            
            if not server_script.exists():
                print(f"Error: ghidra_bridge_server.py not found at {server_script}")
                return False
                
            bridge_script_path = str(server_script)
        except ImportError:
            print("Error: Failed to import ghidra_bridge")
            return False
    
    print(f"Found bridge script at: {bridge_script_path}")
    
    # Start the server
    try:
        # Use subprocess.Popen to start the server in the background
        process = subprocess.Popen(
            [sys.executable, bridge_script_path, str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait a bit to see if it starts successfully
        time.sleep(2)
        
        # Check if process is still running
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            print(f"Error starting Ghidra Bridge server: {stderr}")
            return False
        
        print(f"✓ Ghidra Bridge server started on port {port}")
        print("  Press Ctrl+C to stop the server")
        
        # Keep the server running until interrupted
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping Ghidra Bridge server...")
            process.terminate()
            process.wait(timeout=5)
            print("Ghidra Bridge server stopped")
    
    except Exception as e:
        print(f"Error starting Ghidra Bridge server: {e}")
        return False
    
    return True

def main():
    """Main function"""
    args = parse_args()
    
    # If starting the server directly, do that and exit
    if args.start_server:
        start_bridge_server(args.port)
        return
    
    # Find Ghidra path
    ghidra_path = args.ghidra_path or find_ghidra_path()
    
    if not ghidra_path:
        print("Error: Ghidra installation not found")
        print("Please specify the path to Ghidra with --ghidra-path or set GHIDRA_INSTALL_DIR environment variable")
        sys.exit(1)
    
    if not os.path.exists(ghidra_path):
        print(f"Error: Ghidra installation not found at {ghidra_path}")
        sys.exit(1)
    
    # Install ghidra-bridge
    if not install_ghidra_bridge(ghidra_path):
        print("Error: Failed to install ghidra-bridge")
        sys.exit(1)
    
    print("\n✓ ghidra-bridge setup completed successfully")
    print("\nYou can now use ghidra-bridge in your Python scripts:")
    print("  from ghidra_bridge import GhidraBridge")
    print("  bridge = GhidraBridge()")
    print("  program_name = bridge.remote_eval('currentProgram.getName()')")

if __name__ == "__main__":
    main() 