"""
Ghidra Bridge Manager
Manages connections to Ghidra via ghidra-bridge
"""

import os
import sys
import uuid
import time
import json
import logging
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from flask import current_app
from ghidra_bridge import GhidraBridge

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GhidraBridgeManager:
    """Manages Ghidra Bridge connection and operations"""
    
    def __init__(self, app=None):
        """Initialize the Ghidra Bridge Manager"""
        self.app = app
        self.bridge = None
        self.bridge_process = None
        self.bridge_thread = None
        self.bridge_lock = threading.Lock()
        self.is_running = False
        self.ghidra_path = None
        self.bridge_port = 4768  # Default bridge port
        self.last_connection_check = 0
        self.connection_check_interval = 10  # Check connection every 10 seconds max (increased from 5)
        self.cached_connection_status = False
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app
        self.ghidra_path = app.config.get('GHIDRA_INSTALL_DIR')
        self.bridge_port = app.config.get('GHIDRA_BRIDGE_PORT', 4768)
        
        # Find Ghidra path if not configured
        if not self.ghidra_path:
            self.ghidra_path = self._find_ghidra_path()
            if self.ghidra_path:
                logger.info(f"Found Ghidra installation at: {self.ghidra_path}")
            else:
                logger.warning("Ghidra installation not found. Please configure GHIDRA_INSTALL_DIR.")
    
    def _find_ghidra_path(self):
        """Find Ghidra installation path"""
        # Check environment variable
        ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
        if ghidra_path and os.path.exists(ghidra_path):
            return ghidra_path
        
        # Check .env file
        env_path = Path('.env')
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    if line.startswith('GHIDRA_INSTALL_DIR='):
                        path = line.split('=', 1)[1].strip().strip('"\'')
                        if os.path.exists(path):
                            return path
        
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
    
    def start_bridge(self):
        """Start Ghidra Bridge in a separate process"""
        with self.bridge_lock:
            if self.is_running:
                logger.info("Ghidra Bridge is already running")
                return True
            
            if not self.ghidra_path:
                logger.error("Ghidra installation path not found")
                return False
            
            try:
                # Determine the bridge script path
                if os.name == 'nt':
                    bridge_script = os.path.join(self.ghidra_path, "support", "ghidra_bridge_server.bat")
                    if not os.path.exists(bridge_script):
                        # Try to find the script in the Ghidra scripts directory (correct path)
                        bridge_script = os.path.join(self.ghidra_path, "Ghidra", "Features", "Base", "ghidra_scripts", "jfx_bridge", "ghidra_bridge_server.py")
                else:
                    bridge_script = os.path.join(self.ghidra_path, "support", "ghidra_bridge_server.sh")
                    if not os.path.exists(bridge_script):
                        bridge_script = os.path.join(self.ghidra_path, "Ghidra", "Features", "Base", "ghidra_scripts", "jfx_bridge", "ghidra_bridge_server.py")
                
                if not os.path.exists(bridge_script):
                    logger.error(f"Ghidra Bridge script not found at {bridge_script}")
                    return False
                
                # Start Ghidra Bridge process
                logger.info(f"Starting Ghidra Bridge on port {self.bridge_port}...")
                
                if os.path.splitext(bridge_script)[1] in ['.py']:
                    # Run Python script directly with Ghidra
                    if os.name == 'nt':
                        headless_cmd = os.path.join(self.ghidra_path, "support", "analyzeHeadless.bat")
                    else:
                        headless_cmd = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
                    
                    cmd = [
                        headless_cmd,
                        os.path.join(os.getcwd(), "ghidra_projects"),
                        "BridgeProject",
                        "-scriptPath", os.path.dirname(bridge_script),
                        "-postScript", os.path.basename(bridge_script),
                        str(self.bridge_port)
                    ]
                else:
                    # Run batch/shell script
                    cmd = [bridge_script, str(self.bridge_port)]
                
                logger.info(f"Running command: {' '.join(cmd)}")
                
                # Start the process
                self.bridge_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Wait for bridge to start (increased timeout)
                logger.info("Waiting for Ghidra Bridge to initialize...")
                time.sleep(20)  # Increased from 15 to 20 seconds
                
                # Check if process is still running
                if self.bridge_process.poll() is not None:
                    stdout, stderr = self.bridge_process.communicate()
                    logger.error(f"Ghidra Bridge process exited with code {self.bridge_process.returncode}")
                    logger.error(f"STDOUT: {stdout}")
                    logger.error(f"STDERR: {stderr}")
                    return False
                
                # Mark as running
                self.is_running = True
                logger.info("Ghidra Bridge started successfully")
                
                # Reset connection cache
                self.cached_connection_status = False
                self.last_connection_check = 0
                if hasattr(self, '_connection_logged'):
                    delattr(self, '_connection_logged')
                
                # Start monitor thread
                self.bridge_thread = threading.Thread(target=self._monitor_bridge)
                self.bridge_thread.daemon = True
                self.bridge_thread.start()
                
                return True
                
            except Exception as e:
                logger.error(f"Error starting Ghidra Bridge: {e}")
                return False
    
    def _monitor_bridge(self):
        """Monitor Ghidra Bridge process"""
        while self.is_running and self.bridge_process:
            # Check if process is still running
            if self.bridge_process.poll() is not None:
                stdout, stderr = self.bridge_process.communicate()
                logger.error(f"Ghidra Bridge process exited with code {self.bridge_process.returncode}")
                logger.error(f"STDOUT: {stdout}")
                logger.error(f"STDERR: {stderr}")
                with self.bridge_lock:
                    self.is_running = False
                    self.bridge = None
                break
            
            time.sleep(5)
    
    def stop_bridge(self):
        """Stop Ghidra Bridge process"""
        with self.bridge_lock:
            if not self.is_running:
                logger.info("Ghidra Bridge is not running")
                return True
            
            try:
                # Terminate the process
                if self.bridge_process:
                    logger.info("Stopping Ghidra Bridge...")
                    self.bridge_process.terminate()
                    self.bridge_process.wait(timeout=10)
                    self.bridge_process = None
                
                # Reset state
                self.is_running = False
                self.bridge = None
                self.cached_connection_status = False
                self.last_connection_check = 0
                
                logger.info("Ghidra Bridge stopped successfully")
                return True
                
            except Exception as e:
                logger.error(f"Error stopping Ghidra Bridge: {e}")
                return False
    
    def restart_bridge(self):
        """Restart Ghidra Bridge"""
        self.stop_bridge()
        time.sleep(2)
        # Reset connection cache before starting
        self.cached_connection_status = False
        self.last_connection_check = 0
        return self.start_bridge()
    
    def force_connection_check(self):
        """Force a fresh connection check, bypassing cache"""
        self.last_connection_check = 0
        self.cached_connection_status = False
        return self.is_connected()
    
    def is_connected(self):
        """Check if Ghidra Bridge is connected"""
        try:
            current_time = time.time()
            
            # Use cached status if we checked recently
            if (current_time - self.last_connection_check) < self.connection_check_interval:
                return self.cached_connection_status
            
            if not self.is_running:
                self.cached_connection_status = False
                self.last_connection_check = current_time
                return False
            
            # Try to connect to bridge with retry logic
            if not self.bridge:
                try:
                    self.bridge = GhidraBridge(connect_to_host="localhost", connect_to_port=self.bridge_port)
                except Exception as connect_error:
                    # If connection fails, don't log as error immediately (might be starting up)
                    logger.debug(f"Bridge connection attempt failed: {connect_error}")
                    self.cached_connection_status = False
                    self.last_connection_check = current_time
                    return False
            
            # Test connection with a simple command
            try:
                result = self.bridge.remote_eval("str(state)")
                connection_ok = result is not None
                self.cached_connection_status = connection_ok
                self.last_connection_check = current_time
                if connection_ok and not hasattr(self, '_connection_logged'):
                    logger.info("Successfully connected to Ghidra Bridge")
                    self._connection_logged = True
                return connection_ok
            except Exception as test_error:
                # Connection lost or not ready
                logger.debug(f"Bridge test command failed: {test_error}")
                self.bridge = None
                self.cached_connection_status = False
                self.last_connection_check = current_time
                return False
            
        except Exception as e:
            logger.debug(f"Error checking Ghidra Bridge connection: {e}")
            self.bridge = None
            self.cached_connection_status = False
            self.last_connection_check = time.time()
            return False
    
    def get_bridge_status(self):
        """Get Ghidra Bridge status"""
        try:
            if self.is_connected():
                state_str = self.bridge.remote_eval("str(state)")
                return {
                    "status": "connected",
                    "message": f"Successfully connected to Ghidra Bridge: {state_str}",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f")
                }
            else:
                return {
                    "status": "disconnected",
                    "message": "Not connected to Ghidra Bridge",
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f")
                }
        except Exception as e:
            logger.debug(f"Error checking Ghidra Bridge connection: {e}")
            return {
                "status": "error",
                "message": f"Error checking Ghidra Bridge connection: {e}",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f")
            }
    
    def execute_script(self, project_name, script_path, args=None, binary_path=None):
        """
        Execute a Ghidra script via bridge connection
        
        Args:
            project_name: Name of the Ghidra project
            script_path: Path to the script to execute
            args: List of arguments to pass to the script
            binary_path: Path to binary file (if needed)
        
        Returns:
            Script execution results
        """
        if not self.is_connected():
            logger.error("Ghidra Bridge is not connected")
            return {
                "success": False,
                "error": "Ghidra Bridge is not connected"
            }
        
        try:
            logger.info(f"Executing script: {script_path} with args: {args}")
            
            # Since bridge execution is complex with Jython, let's use a simpler fallback approach
            # The headless mode is working well, so let's just return a "not supported" error
            # to trigger the headless fallback immediately
            
            logger.warning("Bridge execution temporarily disabled due to Jython compatibility issues")
            return {
                "success": False,
                "error": "Bridge execution not available, using headless mode"
            }
            
        except Exception as e:
            logger.error(f"Error executing script {script_path}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {
                "success": False,
                "error": str(e)
            }
    
    def run_headless_analysis(self, binary_path, output_dir=None, project_name=None):
        """
        Run Ghidra analysis on a binary file using headless analyzer
        
        Args:
            binary_path: Path to binary file
            output_dir: Directory to save output
            project_name: Ghidra project name
        
        Returns:
            Analysis results
        """
        if not self.ghidra_path:
            logger.error("Ghidra installation path not found")
            return None
        
        # Use default project name if not specified
        if not project_name:
            project_name = f"GhidraProject_{int(time.time())}"
        
        # Use temp directory if not specified
        if not output_dir:
            output_dir = os.path.join(os.getcwd(), "temp")
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Create projects directory if it doesn't exist
        projects_dir = os.path.join(os.getcwd(), "ghidra_projects")
        os.makedirs(projects_dir, exist_ok=True)
        
        # Get path to headless analyzer
        if os.name == 'nt':
            headless_path = os.path.join(self.ghidra_path, "support", "analyzeHeadless.bat")
        else:
            headless_path = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
        
        # Get path to analysis script
        script_path = os.path.join(os.getcwd(), "analysis_scripts", "simple_analysis.py")
        
        # Run headless analyzer
        cmd = [
            headless_path,
            projects_dir,
            project_name,
            "-import", binary_path,
            "-scriptPath", os.path.dirname(script_path),
            "-postScript", os.path.basename(script_path)
        ]
        
        logger.info(f"Running Ghidra headless analyzer: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Error running Ghidra headless analyzer: {stderr}")
                return None
            
            # Check if output file was created
            output_file = os.path.join(os.path.expanduser("~"), "ghidra_temp", "ghidra_analysis.json")
            if os.path.exists(output_file):
                # Read output file
                with open(output_file, 'r') as f:
                    result = json.load(f)
                
                # Copy output file to specified directory
                output_path = os.path.join(output_dir, os.path.basename(binary_path) + "_analysis.json")
                with open(output_path, 'w') as f:
                    json.dump(result, f, indent=2)
                
                logger.info(f"Analysis results saved to {output_path}")
                return result
            else:
                logger.error(f"Output file not found: {output_file}")
                return None
        except Exception as e:
            logger.error(f"Error running Ghidra headless analyzer: {e}")
            return None
    
    def close_all_connections(self):
        """Close all bridge connections and cleanup"""
        try:
            if self.bridge:
                self.bridge.remote_shutdown()
                self.bridge = None
            self.stop_bridge()
            logger.info("All Ghidra Bridge connections closed")
        except Exception as e:
            logger.error(f"Error closing bridge connections: {e}") 