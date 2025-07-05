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
        self.connection_check_interval = 30  # Reduced frequency to avoid blocking
        self.cached_connection_status = False
        
        # Default to headless mode for reliability
        self._bridge_mode = "headless"
        
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
                
                if os.name == 'nt':
                    headless_cmd = os.path.join(self.ghidra_path, "support", "analyzeHeadless.bat")
                else:
                    headless_cmd = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
                
                # Use the proper ghidra-bridge server script
                cmd = [
                    headless_cmd,
                    os.path.join(os.getcwd(), "ghidra_projects"),
                    "BridgeProject",
                    "-scriptPath", "C:\\Users\\moham\\ghidra_scripts",
                    "-postScript", "ghidra_bridge_server.py",
                    str(self.bridge_port)
                ]
                
                logger.info(f"Running command: {' '.join(cmd)}")
                
                # Create log file for bridge output
                log_dir = os.path.join(os.getcwd(), "logs")
                os.makedirs(log_dir, exist_ok=True)
                
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                self.bridge_log_file = os.path.join(log_dir, f"bridge_manager_{timestamp}.log")
                
                logger.info(f"Starting bridge process with detailed logging to: {self.bridge_log_file}")
                
                # Write initial log info
                with open(self.bridge_log_file, 'w') as log_f:
                    log_f.write(f"[{datetime.now()}] Starting Ghidra Bridge Process\n")
                    log_f.write(f"Command: {' '.join(cmd)}\n")
                    log_f.write(f"Working Directory: {os.getcwd()}\n")
                    log_f.write("-" * 50 + "\n")
                
                # Start the process with pipes so we can capture and log output
                self.bridge_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=os.getcwd()
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
        """Monitor Ghidra Bridge process and capture detailed logs"""
        while self.is_running and self.bridge_process:
            # Check if process is still running
            if self.bridge_process.poll() is not None:
                stdout, stderr = self.bridge_process.communicate()
                return_code = self.bridge_process.returncode
                
                # Log the complete output to file
                if hasattr(self, 'bridge_log_file'):
                    try:
                        with open(self.bridge_log_file, 'a') as log_f:
                            log_f.write(f"\n[{datetime.now()}] Process exited with code: {return_code}\n")
                            log_f.write("=" * 50 + " STDOUT " + "=" * 50 + "\n")
                            log_f.write(stdout if stdout else "(no stdout)")
                            log_f.write("\n" + "=" * 50 + " STDERR " + "=" * 50 + "\n")
                            log_f.write(stderr if stderr else "(no stderr)")
                            log_f.write("\n" + "=" * 107 + "\n")
                    except Exception as e:
                        logger.error(f"Failed to write to bridge log file: {e}")
                
                # Analyze the error more comprehensively
                full_output = (stdout or "") + (stderr or "")
                
                # Check for specific error patterns
                if "cannot create 'jep.PyJClass' instances" in full_output:
                    logger.error("❌ CRITICAL: Jython/Python compatibility issue detected")
                    logger.error("   This is likely due to incompatible Jep version or Python/Java integration issues")
                    with self.bridge_lock:
                        self.is_running = False
                        self.bridge = None
                        self._bridge_mode = "jep_error"
                elif "ghidra_bridge_server.py" in full_output and ("not found" in full_output or "No such file" in full_output):
                    logger.error("❌ CRITICAL: ghidra_bridge_server.py script not found")
                    logger.error("   Bridge server script is missing from Ghidra installation")
                    with self.bridge_lock:
                        self.is_running = False
                        self.bridge = None
                        self._bridge_mode = "script_missing"
                elif return_code != 0:
                    logger.error(f"❌ CRITICAL: Ghidra Bridge process failed with exit code {return_code}")
                    logger.error(f"   STDOUT: {stdout[:500] if stdout else 'None'}")
                    logger.error(f"   STDERR: {stderr[:500] if stderr else 'None'}")
                    logger.error(f"   Full logs available in: {getattr(self, 'bridge_log_file', 'unknown')}")
                    with self.bridge_lock:
                        self.is_running = False
                        self.bridge = None
                        self._bridge_mode = "failed"
                else:
                    logger.info("✅ Ghidra Bridge process exited normally")
                    with self.bridge_lock:
                        self.is_running = False
                        self.bridge = None
                        self._bridge_mode = "stopped"
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
        """Check if Ghidra Bridge is connected - simplified non-blocking version"""
        try:
            current_time = time.time()
            
            # Use cached status if we checked recently
            if (current_time - self.last_connection_check) < self.connection_check_interval:
                return self.cached_connection_status
            
            # For now, always return False to use headless mode
            # This avoids blocking operations that hang the Flask app
            self.cached_connection_status = False
            self.last_connection_check = current_time
            
            # If bridge mode is headless, consider it "operationally connected"
            # This allows the rest of the application to function normally
            return False
            
        except Exception as e:
            logger.debug(f"Error checking Ghidra Bridge connection: {e}")
            self.cached_connection_status = False
            self.last_connection_check = time.time()
            return False
    
    def get_bridge_status(self):
        """Get Ghidra Bridge status - simplified non-blocking version"""
        try:
            # Always return headless mode for reliability
            return {
                "status": "headless_mode",
                "message": "Using headless mode for analysis. Bridge functionality available via Ghidra scripts.",
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.debug(f"Error checking Ghidra Bridge status: {e}")
            return {
                "status": "headless_mode",
                "message": "Using headless mode for analysis (default fallback)",
                "timestamp": datetime.utcnow().isoformat()
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
    
    def load_program(self, binary_path):
        """
        Load a program in Ghidra via bridge
        
        Args:
            binary_path: Path to binary file
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_connected():
            logger.error("Ghidra Bridge is not connected")
            return False
        
        try:
            # Import necessary Ghidra classes through bridge
            logger.info(f"Loading program: {binary_path}")
            
            # Load the program through bridge
            result = self.bridge.remote_eval(f"""
try:
    from ghidra.app.util import HeadlessAnalyzer
    from ghidra.app.util.opinion import ProgramMappingService 
    from ghidra.framework.model import DomainFolder
    from java.io import File
    
    # Get current program if exists
    current_program = currentProgram
    if current_program:
        current_name = current_program.getName()
    else:
        current_name = None
    
    binary_file = File(r'{binary_path}')
    expected_name = binary_file.getName()
    
    # Check if we already have the right program loaded
    if current_program and current_name == expected_name:
        'already_loaded'
    else:
        # Import the binary
        HeadlessAnalyzer.createProgram(binary_file, None, None)
        'loaded'
except Exception as e:
    str(e)
""")
            
            if result == "already_loaded":
                logger.info(f"Program {os.path.basename(binary_path)} already loaded")
                return True
            elif result == "loaded":
                logger.info(f"Successfully loaded program {os.path.basename(binary_path)}")
                return True
            else:
                logger.error(f"Failed to load program: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Error loading program {binary_path}: {e}")
            return False
    
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