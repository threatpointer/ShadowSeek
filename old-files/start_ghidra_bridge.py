#!/usr/bin/env python3
"""
Start Ghidra Bridge server
"""

import os
import sys
import time
import logging
import subprocess
from pathlib import Path
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def find_ghidra_path():
    """Find Ghidra installation path"""
    # Check environment variable
    ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
    if ghidra_path and os.path.exists(ghidra_path):
        return ghidra_path
    
    # Check .env file
    load_dotenv()
    ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
    if ghidra_path and os.path.exists(ghidra_path):
        return ghidra_path
    
    # Check common installation paths
    common_paths = [
        r'D:\1132-Ghidra\ghidra_11.3.2_PUBLIC',
        r'C:\Program Files\Ghidra',
        r'C:\ghidra',
        r'/opt/ghidra',
        r'/usr/local/ghidra',
        os.path.expanduser('~/ghidra')
    ]
    
    for path in common_paths:
        if os.path.exists(path):
            return path
    
    return None

def start_bridge(port=4768):
    """Start Ghidra Bridge server"""
    # Find Ghidra path
    ghidra_path = find_ghidra_path()
    if not ghidra_path:
        logger.error("Ghidra installation not found")
        return False
    
    # Create projects directory if it doesn't exist
    projects_dir = os.path.join(os.getcwd(), "ghidra_projects")
    os.makedirs(projects_dir, exist_ok=True)
    
    # Determine the bridge script path
    if os.name == 'nt':
        bridge_script = os.path.join(ghidra_path, "support", "ghidra_bridge_server.bat")
        if not os.path.exists(bridge_script):
            # Try to find the script in the Ghidra scripts directory (correct path)
            bridge_script = os.path.join(ghidra_path, "Ghidra", "Features", "Base", "ghidra_scripts", "jfx_bridge", "ghidra_bridge_server.py")
    else:
        bridge_script = os.path.join(ghidra_path, "support", "ghidra_bridge_server.sh")
        if not os.path.exists(bridge_script):
            bridge_script = os.path.join(ghidra_path, "Ghidra", "Features", "Base", "ghidra_scripts", "jfx_bridge", "ghidra_bridge_server.py")
    
    if not os.path.exists(bridge_script):
        logger.error(f"Ghidra Bridge script not found at {bridge_script}")
        return False
    
    # Start Ghidra Bridge process
    logger.info(f"Starting Ghidra Bridge on port {port}...")
    
    if os.name == 'nt':
        headless_cmd = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
    else:
        headless_cmd = os.path.join(ghidra_path, "support", "analyzeHeadless")
    
    cmd = [
        headless_cmd,
        projects_dir,
        "BridgeProject",
        "-scriptPath", os.path.dirname(bridge_script),
        "-postScript", os.path.basename(bridge_script),
        str(port)
    ]
    
    logger.info(f"Running command: {' '.join(cmd)}")
    
    # Start the process
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Wait for bridge to start
        time.sleep(5)
        
        # Check if process is still running
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            logger.error(f"Ghidra Bridge process exited with code {process.returncode}")
            logger.error(f"STDOUT: {stdout}")
            logger.error(f"STDERR: {stderr}")
            return False
        
        logger.info("Ghidra Bridge started successfully")
        
        # Keep the process running
        while process.poll() is None:
            time.sleep(1)
        
        # Process exited
        stdout, stderr = process.communicate()
        logger.error(f"Ghidra Bridge process exited with code {process.returncode}")
        logger.error(f"STDOUT: {stdout}")
        logger.error(f"STDERR: {stderr}")
        
    except Exception as e:
        logger.error(f"Error starting Ghidra Bridge: {e}")
        return False
    
    return True

def main():
    """Main function"""
    port = 4768
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            logger.error(f"Invalid port number: {sys.argv[1]}")
            sys.exit(1)
    
    success = start_bridge(port)
    if not success:
        logger.error("Failed to start Ghidra Bridge")
        sys.exit(1)

if __name__ == "__main__":
    main() 