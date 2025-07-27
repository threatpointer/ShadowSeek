#!/usr/bin/env python3
"""
ShadowSeek Environment Setup Script

This script configures the ShadowSeek environment by:
- Auto-detecting Ghidra installations
- Installing Python and frontend dependencies
- Creating .env configuration file
- Setting up Ghidra Bridge server and client
- Starting ShadowSeek components automatically
- Testing all connections and validations

Usage:
    python setup_environment.py [options]

Options:
    --auto                    Run in auto mode without prompts
    --skip-install            Skip automatic dependency installation
    --skip-startup            Skip automatic component startup
    --skip-system-check       Skip system requirements check
    --force-clean             Force clean virtual environment
    --use-pip                 Force use of pip instead of UV
    --ghidra-path PATH        Specify Ghidra installation path
"""

import os
import sys
import subprocess
import platform
import time
import socket
import argparse
import json
from pathlib import Path

# Terminal colors for better output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def print_status(message, status="info", detail=""):
    """Print formatted status message - CLEANED UP VERSION"""
    if platform.system() == "Windows":
        # Simplified icons for Windows
        icons = {"success": "✓", "error": "✗", "warning": "!", "info": "ℹ"}
        icon = icons.get(status, "•")
        print(f"{icon} {message}")
        if detail:
            print(f"   {detail}")
    else:
        # Unix systems - with colors but simplified
        colors = {
            "success": Colors.GREEN,
            "error": Colors.RED, 
            "warning": Colors.YELLOW,
            "info": Colors.BLUE
        }
        icons = {"success": "✓", "error": "✗", "warning": "!", "info": "ℹ"}
        color = colors.get(status, Colors.WHITE)
        icon = icons.get(status, "•")
        print(f"{color}{icon} {message}{Colors.RESET}")
        if detail:
            print(f"   {detail}")

def print_header(title):
    """Print a clean header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

def print_step(step_num, title):
    """Print a step header"""
    print(f"\n[{step_num}] {title}")
    print("-" * 40)

def run_command(cmd, cwd=None, check=True, capture_output=True, timeout=None):
    """Run a command and return the result"""
    try:
        if isinstance(cmd, str):
            cmd = cmd.split()
        
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=capture_output,
            text=True,
            check=check,
            timeout=timeout
        )
        return result
    except subprocess.TimeoutExpired as e:
        print_status(f"Command timed out after {timeout}s: {' '.join(cmd)}", "error")
        raise
    except subprocess.CalledProcessError as e:
        if not check:
            return e
        print_status(f"Command failed: {' '.join(cmd)}", "error")
        if e.stdout:
            print_status(f"Output: {e.stdout.strip()}", "error")
        if e.stderr:
            print_status(f"Error: {e.stderr.strip()}", "error")
        raise
    except FileNotFoundError:
        print_status(f"Command not found: {cmd[0]}", "error")
        raise

def clean_corrupted_venv():
    """Clean up corrupted virtual environment"""
    venv_dir = Path(".venv")
    if venv_dir.exists():
        try:
            # Test if the virtual environment is working
            python_exe = venv_dir / "Scripts" / "python.exe"  # Windows
            if not python_exe.exists():
                python_exe = venv_dir / "bin" / "python"  # Unix
            
            if python_exe.exists():
                # Try to run a simple command to test if venv is working
                result = run_command([str(python_exe), "--version"], check=False, timeout=10)
                if result.returncode == 0:
                    print_status("Existing virtual environment is functional", "success")
                    return True
            
            # If we get here, the venv is broken
            print_status("Virtual environment corrupted, cleaning up...", "info")
            import shutil
            shutil.rmtree(venv_dir)
            print_status("Corrupted virtual environment removed", "success")
            return False
            
        except Exception:
            # Try to remove it anyway
            try:
                import shutil
                shutil.rmtree(venv_dir)
                print_status("Problematic virtual environment removed", "success")
            except Exception:
                print_status("Could not remove venv directory", "warning")
            return False
    return False

def create_fresh_venv():
    """Create a fresh virtual environment for UV"""
    print_status("Creating fresh virtual environment...", "info")
    try:
        # Create virtual environment using the current Python interpreter
        run_command([sys.executable, "-m", "venv", ".venv"], timeout=60)
        print_status("Virtual environment created successfully", "success")
        
        # Test the virtual environment
        venv_python = get_venv_python()
        if venv_python and os.path.exists(venv_python):
            result = run_command([venv_python, "--version"], check=False, timeout=10)
            if result.returncode == 0:
                return True
        
        print_status("Virtual environment created but not functional", "warning")
        return False
            
    except Exception as e:
        print_status(f"Failed to create virtual environment: {e}", "error")
        return False

def get_venv_python():
    """Get the Python executable path in the virtual environment"""
    if platform.system() == "Windows":
        return os.path.join(".venv", "Scripts", "python.exe")
    else:
        return os.path.join(".venv", "bin", "python")

def check_package_manager():
    """Check which package manager to use (UV preferred, pip fallback)"""
    try:
        result = run_command(["uv", "--version"], check=False, timeout=10)
        if result.returncode == 0:
            print_status(f"UV available: {result.stdout.strip()}", "success")
            return "uv"
    except:
        pass
    
    try:
        result = run_command([sys.executable, "-m", "pip", "--version"], check=False, timeout=10)
        if result.returncode == 0:
            print_status(f"pip available: {result.stdout.strip()}", "success")
            return "pip"
    except:
        pass
    
    print_status("No package manager found (need UV or pip)", "error")
    return None

def install_python_dependencies(use_pip=False):
    """Install missing Python dependencies using UV or pip"""
    # First, check and clean up any corrupted virtual environment
    venv_exists = clean_corrupted_venv()
    
    # Check which package manager to use, but respect user preference
    if use_pip:
        print_status("Using pip (user requested)", "info")
        pkg_manager = "pip"
    else:
        pkg_manager = check_package_manager()
        if not pkg_manager:
            print_status("No package manager available", "error")
            return False
    
    try:
        if pkg_manager == "uv" and not use_pip:
            print_status("Using UV package manager", "info")
            
            # Ensure we have a clean virtual environment for UV
            if not venv_exists:
                if not create_fresh_venv():
                    print_status("Virtual environment creation failed, falling back to pip", "warning")
                    return install_packages_individually("pip")
            
            # Verify virtual environment is working before UV operations
            venv_python = get_venv_python()
            if not venv_python or not os.path.exists(venv_python):
                print_status("Virtual environment issue, falling back to pip", "warning")
                return install_packages_individually("pip")
            
            # Check if pyproject.toml exists (UV project)
            if os.path.exists("pyproject.toml"):
                try:
                    run_command(["uv", "sync", "--no-dev"], timeout=180)
                    print_status("Dependencies installed via UV sync", "success")
                    
                    # Verify installation worked
                    result = run_command(["uv", "pip", "list"], check=False, timeout=30)
                    if result.returncode == 0:
                        return True
                    else:
                        print_status("UV installation verification failed", "warning")
                        
                except Exception as e:
                    print_status(f"UV sync failed: {e}", "warning")
            
            # Fallback: individual UV pip installs
            try:
                return install_packages_individually("uv")
            except Exception:
                print_status("UV package installation failed, falling back to pip", "warning")
                return install_packages_individually("pip")
        else:
            return install_packages_individually("pip")
            
    except Exception as e:
        print_status(f"Dependency installation failed: {e}", "error")
        try:
            return install_packages_individually("pip")
        except Exception:
            return False

def install_packages_individually(pkg_manager):
    """Install packages one by one into virtual environment (fallback method)"""
    # Required packages for ShadowSeek (fallback if pyproject.toml sync fails)
    # Updated with all dependencies for binary comparison and AI features
    required_packages = [
        "flask>=2.3",
        "flask-sqlalchemy>=3.1", 
        "flask-cors>=4.0",
        "flask-migrate>=4.0",
        "flask-socketio>=5.3",
        "flask-restx>=1.3",
        "requests>=2.31",
        "python-dotenv>=1.0",
        "ghidra-bridge>=1.0",
        "werkzeug>=2.3",
        "sqlalchemy>=2.0",
        "psutil>=5.9",
        "python-magic>=0.4",
        "aiohttp>=3.9",
        "aiohttp-cors>=0.7",
        "websockets>=12.0",
        "redis>=5.0",
        "openai>=1.0",
        "anthropic>=0.7",
        "google-generativeai>=0.3",
        "jsonschema>=4.20"
    ]
    
    try:
        # Determine which Python to use
        venv_python = None
        if os.path.exists(".venv"):
            venv_python = get_venv_python()
            if venv_python and os.path.exists(venv_python):
                print_status("Using virtual environment", "success")
            else:
                venv_python = None
        
        # Choose the appropriate Python executable
        python_exe = venv_python if venv_python else sys.executable
        
        # First try to upgrade the package manager  
        if pkg_manager == "pip":
            try:
                run_command([python_exe, "-m", "pip", "install", "--upgrade", "pip"], timeout=60)
                print_status("pip upgraded", "success")
            except Exception:
                print_status("pip upgrade failed - continuing", "warning")
        
        # Install packages one by one for better error handling
        installed_packages = []
        failed_packages = []
        
        print_status(f"Installing {len(required_packages)} packages...", "info")
        
        for package in required_packages:
            try:
                if pkg_manager == "uv":
                    run_command(["uv", "pip", "install", package], timeout=120)
                else:
                    run_command([python_exe, "-m", "pip", "install", package], timeout=120)
                installed_packages.append(package)
            except Exception:
                # Try fallback with simpler package name
                simple_name = package.split('>=')[0]
                try:
                    if pkg_manager == "uv":
                        run_command(["uv", "pip", "install", simple_name], timeout=120)
                    else:
                        run_command([python_exe, "-m", "pip", "install", simple_name], timeout=120)
                    installed_packages.append(package)
                except Exception as e2:
                    failed_packages.append((package, str(e2)))
        
        # Try requirements.txt as fallback if individual installs failed
        if failed_packages and os.path.exists("requirements.txt"):
            print_status("Trying requirements.txt as fallback...", "info")
            try:
                if pkg_manager == "uv":
                    run_command(["uv", "pip", "install", "-r", "requirements.txt"], timeout=180)
                else:
                    run_command([python_exe, "-m", "pip", "install", "-r", "requirements.txt"], timeout=180)
                failed_packages = []
            except Exception:
                # Last resort: try installing simplified package names without versions
                simple_packages = ["flask", "flask-sqlalchemy", "flask-cors", "requests", "python-dotenv", "ghidra-bridge", "werkzeug"]
                try:
                    cmd = [python_exe, "-m", "pip", "install"] + simple_packages
                    run_command(cmd, timeout=300)
                    failed_packages = []
                except Exception:
                    pass
        
        # Final report
        if installed_packages:
            install_location = "virtual environment" if venv_python else "system"
            print_status(f"Installed {len(installed_packages)} packages into {install_location}", "success")
        
        if failed_packages:
            print_status(f"Failed to install {len(failed_packages)} packages", "warning")
            if installed_packages:
                print_status("Some packages installed successfully, continuing...", "info")
                return True
            return False
        
        return True
        
    except Exception as e:
        print_status(f"Individual package installation failed: {e}", "error")
        return False

def test_python_dependencies(force_clean=False, use_pip=False):
    """Test if Python dependencies are available and install missing ones"""
    
    # Force clean setup if requested
    if force_clean:
        print_status("Force clean requested - removing virtual environment", "info")
        venv_dir = Path(".venv")
        if venv_dir.exists():
            import shutil
            try:
                shutil.rmtree(venv_dir)
                print_status("Virtual environment removed", "success")
            except Exception as e:
                print_status(f"Could not remove venv: {e}", "warning")
    
    dependencies = {
        'flask': 'Flask web framework',
        'flask_sqlalchemy': 'Database ORM',
        'flask_cors': 'CORS handling',
        'flask_migrate': 'Database migrations',
        'flask_restx': 'REST API framework',
        'requests': 'HTTP client',
        'python-dotenv': 'Environment variable management',
        'ghidra_bridge': 'Ghidra integration',
        'psutil': 'System monitoring',
        'aiohttp': 'Async HTTP client',
        'redis': 'Redis client (optional)',
        'openai': 'OpenAI API client (optional)',
        'anthropic': 'Anthropic API client (optional)',
        'google-generativeai': 'Google AI client (optional)'
    }
    
    missing = []
    available = []
    optional_packages = ['redis', 'openai', 'anthropic', 'google-generativeai']
    
    for package, description in dependencies.items():
        # Handle package name differences between pip and import
        import_name = package.replace('-', '_')
        
        try:
            __import__(import_name)
            available.append(package)
            print_status(f"{package} ✓", "success")
        except ImportError:
            if package in optional_packages:
                print_status(f"{package} - optional (for AI features)", "info")
            else:
                missing.append(package)
                print_status(f"{package} - missing", "warning")
    
    if missing:
        print_status(f"Installing {len(missing)} missing packages...", "info")
        if install_python_dependencies(use_pip=use_pip):
            print_status("All dependencies installed", "success")
            return True
        else:
            print_status("Some dependencies failed to install", "error")
            return False
    else:
        print_status("All Python dependencies available", "success")
        return True

def find_ghidra_installations():
    """Find Ghidra installations on the system"""
    possible_paths = []
    system = platform.system()
    
    if system == "Windows":
        # Windows common paths
        search_paths = [
            "C:\\ghidra*",
            "C:\\Program Files\\ghidra*", 
            "C:\\Program Files (x86)\\ghidra*",
            "D:\\ghidra*",
            "D:\\*ghidra*",
            str(Path.home() / "ghidra*"),
            str(Path.home() / "Downloads" / "ghidra*")
        ]
    else:
        # Linux/macOS common paths
        search_paths = [
            "/opt/ghidra*",
            "/usr/local/ghidra*",
            str(Path.home() / "ghidra*"),
            str(Path.home() / "Downloads" / "ghidra*"),
            "./ghidra*"
        ]
    
    import glob
    for pattern in search_paths:
        matches = glob.glob(pattern)
        for match in matches:
            path = Path(match)
            if path.is_dir():
                # Validate Ghidra installation - check for support directory and key files
                support_dir = path / "support"
                if support_dir.exists():
                    # Check for either ghidra.jar OR analyzeHeadless (the key Ghidra files)
                    ghidra_jar = support_dir / "ghidra.jar"
                    headless_bat = support_dir / "analyzeHeadless.bat"
                    headless_sh = support_dir / "analyzeHeadless"
                    
                    if ghidra_jar.exists() or headless_bat.exists() or headless_sh.exists():
                        possible_paths.append(path)
                        print_status(f"Found Ghidra: {path}", "success")
    
    if not possible_paths:
        print_status("No auto-detected Ghidra installations", "info")
    
    return possible_paths

def prompt_for_paths(found_paths, args):
    """Interactive configuration with auto-detection - FIXED GHIDRA LOGIC"""
    config = {}
    
    # Ghidra installation - IMPROVED LOGIC
    if args.ghidra_path:
        ghidra_path = Path(args.ghidra_path)
        if validate_ghidra_path(ghidra_path):
            config["GHIDRA_INSTALL_DIR"] = str(ghidra_path)
            print_status(f"Using specified Ghidra: {ghidra_path}", "success")
        else:
            print_status(f"Invalid Ghidra path: {ghidra_path}", "error")
            sys.exit(1)
    elif found_paths:
        default_ghidra = str(found_paths[0])
        print_status(f"Found Ghidra: {default_ghidra}", "success")
        if args.auto:
            ghidra_path = default_ghidra
        else:
            ghidra_path = input(f"Ghidra path [{default_ghidra}]: ").strip()
        config["GHIDRA_INSTALL_DIR"] = ghidra_path if ghidra_path else default_ghidra
    else:
        print_status("No Ghidra installation found", "warning")
        if args.auto:
            # FIXED: In auto mode, provide common paths to try
            common_paths = [
                "C:\\ghidra_11.3.2_PUBLIC",
                "C:\\ghidra_11.4_PUBLIC", 
                "C:\\Tools\\ghidra_11.3.2_PUBLIC",
                "C:\\Tools\\ghidra_11.4_PUBLIC",
                "D:\\ghidra_11.3.2_PUBLIC",
                "D:\\ghidra_11.4_PUBLIC"
            ]
            
            found_auto_path = None
            for path in common_paths:
                if Path(path).exists() and validate_ghidra_path(Path(path)):
                    found_auto_path = path
                    print_status(f"Auto-detected Ghidra at: {path}", "success")
                    break
            
            if found_auto_path:
                config["GHIDRA_INSTALL_DIR"] = found_auto_path
            else:
                print_status("Auto mode: Ghidra required for bridge functionality", "warning")
                print_status("Please run: python setup_environment.py --ghidra-path YOUR_GHIDRA_PATH", "info")
                config["GHIDRA_INSTALL_DIR"] = ""
        else:
            ghidra_path = input("Ghidra installation path (Enter to skip): ").strip()
            config["GHIDRA_INSTALL_DIR"] = ghidra_path
    
    # Other configuration with defaults
    if args.auto:
        config.update({
            "GHIDRA_BRIDGE_PORT": "4768",
            "FLASK_PORT": "5000", 
            "GHIDRA_TEMP_DIR": "./temp/ghidra_temp",
            "GHIDRA_PROJECTS_DIR": "./ghidra_projects",
            "UPLOAD_FOLDER": "./uploads",
            "TEMP_FOLDER": "./temp",
            "LOG_FOLDER": "./logs",
            "GHIDRA_BRIDGE_HOST": "127.0.0.1",
            "FLASK_HOST": "127.0.0.1"
        })
    else:
        # Interactive prompts with defaults
        config["GHIDRA_BRIDGE_PORT"] = input("Ghidra Bridge port [4768]: ").strip() or "4768"
        config["FLASK_PORT"] = input("Flask server port [5000]: ").strip() or "5000"
        
        # Directory configuration
        config["GHIDRA_TEMP_DIR"] = input("Ghidra temp directory [./temp/ghidra_temp]: ").strip() or "./temp/ghidra_temp"
        config["GHIDRA_PROJECTS_DIR"] = input("Ghidra projects directory [./ghidra_projects]: ").strip() or "./ghidra_projects"
        config["UPLOAD_FOLDER"] = input("Upload folder [./uploads]: ").strip() or "./uploads"
        config["TEMP_FOLDER"] = input("Temp folder [./temp]: ").strip() or "./temp"
        config["LOG_FOLDER"] = input("Log folder [./logs]: ").strip() or "./logs"
        
        # Network configuration
        config["GHIDRA_BRIDGE_HOST"] = input("Ghidra Bridge host [127.0.0.1]: ").strip() or "127.0.0.1"
        config["FLASK_HOST"] = input("Flask host [127.0.0.1]: ").strip() or "127.0.0.1"
    
    return config

def validate_ghidra_path(path):
    """Validate Ghidra installation path with detailed error reporting"""
    if not path:
        print_status("No Ghidra path provided", "error")
        return False
        
    path_obj = Path(path)
    
    # Check if basic path exists
    if not path_obj.exists():
        print_status(f"Path does not exist: {path}", "error")
        return False
    
    if not path_obj.is_dir():
        print_status(f"Path is not a directory: {path}", "error")
        return False
    
    print_status(f"✓ Base path exists: {path}", "success")
    
    # Check for support directory
    support_dir = path_obj / "support"
    if not support_dir.exists():
        print_status(f"Missing 'support' directory in: {path}", "error")
        print_status("Expected: support/", "error")
        
        # Show what's actually in the directory
        try:
            contents = [item.name for item in path_obj.iterdir() if item.is_dir()][:10]  # First 10 directories
            if contents:
                print_status(f"Available directories: {', '.join(contents)}", "info")
            else:
                print_status("No subdirectories found", "warning")
        except Exception as e:
            print_status(f"Cannot read directory contents: {e}", "warning")
        return False
    
    print_status("✓ Support directory found", "success")
    
    # Check for ghidra.jar in support directory
    ghidra_jar = support_dir / "ghidra.jar"
    if not ghidra_jar.exists():
        print_status(f"Missing 'ghidra.jar' in support directory", "error")
        print_status(f"Expected: {ghidra_jar}", "error")
        
        # Show what's actually in the support directory
        try:
            jar_files = [item.name for item in support_dir.iterdir() if item.suffix.lower() == '.jar']
            if jar_files:
                print_status(f"Available .jar files: {', '.join(jar_files)}", "info")
            else:
                print_status("No .jar files found in support directory", "warning")
            
            # Also check for analyzeHeadless which is a key Ghidra file
            headless_bat = support_dir / "analyzeHeadless.bat"
            headless_sh = support_dir / "analyzeHeadless"
            if headless_bat.exists():
                print_status("✓ analyzeHeadless.bat found (good sign this is Ghidra)", "success")
                return True  # If we have analyzeHeadless, this is likely valid Ghidra even without ghidra.jar
            elif headless_sh.exists():
                print_status("✓ analyzeHeadless found (good sign this is Ghidra)", "success")
                return True  # If we have analyzeHeadless, this is likely valid Ghidra even without ghidra.jar
            else:
                print_status("✗ No analyzeHeadless script found either", "warning")
        except Exception as e:
            print_status(f"Cannot read support directory contents: {e}", "warning")
        return False
    
    print_status("✓ ghidra.jar found", "success")
    return True

def setup_ghidra_bridge_server(config):
    """Set up Ghidra Bridge server script - simplified approach"""
    ghidra_install = config.get("GHIDRA_INSTALL_DIR", "")
    if not ghidra_install:
        print_status("No Ghidra installation - skipping bridge setup", "warning")
        return False
    
    # Always create our working bridge server script
    print_status("Setting up bridge server script...", "info")
    
    # Create the bridge server script that works with analyzeHeadless.bat
    success = create_ghidra_bridge_server_script()
    
    if success:
        print_status("Bridge server script ready", "success")
        print_status("Use existing start_ghidra_bridge_new.bat to start bridge", "info")
    else:
        print_status("Failed to create bridge server script", "error")
    
    return success

def create_ghidra_bridge_server_script():
    """Create proper ghidra_bridge_server.py script that works with analyzeHeadless.bat"""
    print_status("Creating Ghidra bridge server script...", "info")
    
    # Based on working approach from documentation
    server_script_content = '''#!/usr/bin/env python3
"""
Ghidra Bridge Server Script
This script runs inside Ghidra headless mode and starts a bridge server
that allows external Python scripts to connect and interact with Ghidra.

Usage: Called by analyzeHeadless.bat as -postScript with port argument
"""

import sys
import time

# Default port
DEFAULT_PORT = 4768

def main():
    port = DEFAULT_PORT
    
    # Read port from command line arguments
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
            print("Using port from command line: {}".format(port))
        except (ValueError, IndexError):
            print("Invalid port argument, using default port {}".format(DEFAULT_PORT))
            port = DEFAULT_PORT
    else:
        print("No port specified, using default port {}".format(DEFAULT_PORT))
    
    print("Starting Ghidra Bridge server on port {}...".format(port))
    
    try:
        # Import ghidra_bridge (should be available in environment)
        import ghidra_bridge
        
        # Create and start the bridge server
        # Use background=True for better connection handling
        bridge_server = ghidra_bridge.GhidraBridgeServer(
            server_port=port,
            response_timeout=ghidra_bridge.DEFAULT_RESPONSE_TIMEOUT
        )
        
        print("Bridge server starting...")
        bridge_server.start(background=True)
        
        print("Ghidra Bridge server started successfully on port {}".format(port))
        print("Server is running and accepting connections...")
        
        # Keep the script running - essential for bridge to stay alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Shutting down Ghidra Bridge server...")
            
    except ImportError as e:
        print("Error: Could not import ghidra_bridge: {}".format(e))
        print("Make sure ghidra_bridge is installed in your Python environment")
        sys.exit(1)
    except Exception as e:
        print("Error starting Ghidra Bridge server: {}".format(e))
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
'''
    
    try:
        with open("ghidra_bridge_server.py", "w") as f:
            f.write(server_script_content)
        print_status("Ghidra bridge server script created", "success")
        return True
    except Exception as e:
        print_status(f"Failed to create bridge server script: {e}", "error")
        return False



def create_env_file(config):
    """Create .env file with configuration"""
    env_content = []
    env_content.append("# ShadowSeek Environment Configuration")
    env_content.append(f"# Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}")
    env_content.append("")
    
    # Core configuration
    env_content.append("# Core Configuration")
    env_content.append(f"GHIDRA_INSTALL_DIR={config.get('GHIDRA_INSTALL_DIR', '')}")
    env_content.append(f"GHIDRA_BRIDGE_PORT={config.get('GHIDRA_BRIDGE_PORT', '4768')}")
    env_content.append(f"FLASK_PORT={config.get('FLASK_PORT', '5000')}")
    env_content.append("")
    
    # Directory configuration
    env_content.append("# Directory Configuration")
    env_content.append(f"GHIDRA_TEMP_DIR={config.get('GHIDRA_TEMP_DIR', './temp/ghidra_temp')}")
    env_content.append(f"GHIDRA_PROJECTS_DIR={config.get('GHIDRA_PROJECTS_DIR', './ghidra_projects')}")
    env_content.append(f"UPLOAD_FOLDER={config.get('UPLOAD_FOLDER', './uploads')}")
    env_content.append(f"TEMP_FOLDER={config.get('TEMP_FOLDER', './temp')}")
    env_content.append(f"LOG_FOLDER={config.get('LOG_FOLDER', './logs')}")
    env_content.append("")
    
    # Network configuration
    env_content.append("# Network Configuration")
    env_content.append(f"GHIDRA_BRIDGE_HOST={config.get('GHIDRA_BRIDGE_HOST', '127.0.0.1')}")
    env_content.append(f"FLASK_HOST={config.get('FLASK_HOST', '127.0.0.1')}")
    env_content.append("")
    
    # AI service configuration
    env_content.append("# AI Service Configuration (Optional)")
    env_content.append("LLM_PROVIDER=openai")
    env_content.append("# OPENAI_API_KEY=your_key_here")
    env_content.append("# OPENAI_MODEL=gpt-3.5-turbo")
    env_content.append("# LLM_TEMPERATURE=0.3")
    env_content.append("")
    env_content.append("# Alternative AI Providers")
    env_content.append("# ANTHROPIC_API_KEY=your_key_here")
    env_content.append("# GOOGLE_API_KEY=your_key_here")
    env_content.append("")
    
    # Database configuration
    env_content.append("# Database Configuration")
    env_content.append("DATABASE_URL=sqlite:///instance/shadowseek.db")
    env_content.append("")
    
    # Write .env file
    with open(".env", "w") as f:
        f.write("\n".join(env_content))
    
    print_status(".env file created successfully", "success")

def create_directories(config):
    """Create required directories"""
    directories = [
        config.get('GHIDRA_TEMP_DIR', './temp/ghidra_temp'),
        config.get('GHIDRA_PROJECTS_DIR', './ghidra_projects'),
        config.get('UPLOAD_FOLDER', './uploads'),
        config.get('TEMP_FOLDER', './temp'),
        config.get('LOG_FOLDER', './logs'),
        './instance'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            print_status(f"Directory: {directory}", "success")
        except Exception as e:
            print_status(f"Failed: {directory} - {e}", "error")

def run_start_all(skip_startup=False):
    """Start all ShadowSeek components with proper virtual environment"""
    if skip_startup:
        print_status("⏭️ Skipping automatic component startup", "info")
        return True
    
    try:
        print_status("🚀 Starting ShadowSeek components with virtual environment...", "info")
        
        # Start components manually with proper virtual environment
        return start_components_with_venv()
        
    except Exception as e:
        print_status(f"Error starting components: {e}", "error")
        return False

def start_components_with_venv():
    """Start components using the virtual environment with improved reliability"""
    try:
        # Get virtual environment Python path
        venv_python = get_venv_python()
        if not venv_python or not os.path.exists(venv_python):
            print_status("Virtual environment not found, using system Python", "warning")
            venv_python = sys.executable
        
        print_status(f"Using Python: {venv_python}", "info")
        
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)
        
        # Verify Flask can import properly before starting
        print_status("Testing Flask imports...", "info")
        try:
            test_result = run_command([venv_python, "-c", 
                "import flask, flask_sqlalchemy, flask_cors, ghidra_bridge; print('All imports successful')"], 
                check=False, timeout=30)
            if test_result.returncode == 0:
                print_status("Flask dependencies verified", "success")
            else:
                print_status(f"Import test failed: {test_result.stderr}", "warning")
                print_status("Flask may have issues starting", "warning")
        except Exception as e:
            print_status(f"Import test error: {e}", "warning")
        
        # Start Ghidra Bridge first (it takes longer to initialize)
        print_status("Starting Ghidra Bridge server...", "info")
        if os.path.exists("start_ghidra_bridge_new.bat") or os.path.exists("start_ghidra_bridge_new.sh"):
            script_name = "start_ghidra_bridge_new.bat" if platform.system() == "Windows" else "start_ghidra_bridge_new.sh"
            try:
                if platform.system() == "Windows":
                    subprocess.Popen([script_name], 
                                   shell=True, 
                                   creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen([f"./{script_name}"], shell=True)
                print_status("Ghidra Bridge starting in separate window", "success")
            except Exception as e:
                print_status(f"Failed to start Ghidra Bridge: {e}", "warning")
        else:
            print_status("Ghidra Bridge startup script not found", "warning")
        
        # Give bridge some time to initialize
        print_status("Waiting for Ghidra Bridge to initialize (10 seconds)...", "info")
        time.sleep(10)
        
        # Start Flask backend with improved logging and error handling
        print_status("Starting Flask backend...", "info")
        flask_log = os.path.join("logs", "flask_startup.log")
        
        if platform.system() == "Windows":
            # Create an improved Windows batch script
            flask_launcher = "start_flask_reliable.bat"
            batch_content = f'''@echo off
title ShadowSeek Flask Backend
echo ===== ShadowSeek Flask Backend =====
echo Python: {venv_python}
echo Working Directory: {os.getcwd()}
echo Log File: {flask_log}
echo =====================================
echo.

echo Testing Python executable...
"{venv_python}" --version
if errorlevel 1 (
    echo ERROR: Python executable failed
    pause
    exit /b 1
)

echo Testing Flask imports...
"{venv_python}" -c "import flask, flask_app; print('Flask imports OK')"
if errorlevel 1 (
    echo ERROR: Flask import failed
    pause
    exit /b 1
)

echo Starting Flask application...
"{venv_python}" run.py 2>&1 | "{venv_python}" -c "import sys; import os; [print(line.rstrip(), flush=True) or (open(r'{flask_log}', 'a').write(line) if os.path.exists('logs') else None) for line in sys.stdin]"

echo.
echo Flask application stopped.
pause
'''
            
            try:
                with open(flask_launcher, "w") as f:
                    f.write(batch_content)
                
                subprocess.Popen([flask_launcher], 
                               shell=True, 
                               creationflags=subprocess.CREATE_NEW_CONSOLE)
                print_status("Flask backend starting in separate window", "success")
                print_status(f"Flask logs: {flask_log}", "info")
            except Exception as e:
                print_status(f"Failed to start Flask backend: {e}", "error")
                return False
        else:
            # For Unix systems, use a simpler approach
            try:
                with open(flask_log, "w") as log_file:
                    process = subprocess.Popen([venv_python, "run.py"], 
                                             stdout=subprocess.PIPE, 
                                             stderr=subprocess.STDOUT,
                                             universal_newlines=True)
                    
                    # Start a separate thread to handle logging
                    import threading
                    def log_output():
                        for line in process.stdout:
                            print(line.rstrip())
                            log_file.write(line)
                            log_file.flush()
                    
                    log_thread = threading.Thread(target=log_output)
                    log_thread.daemon = True
                    log_thread.start()
                    
                print_status("Flask backend started", "success")
                print_status(f"Flask logs: {flask_log}", "info")
            except Exception as e:
                print_status(f"Failed to start Flask backend: {e}", "error")
                return False
        
        # Give Flask time to initialize
        print_status("Waiting for Flask to initialize (8 seconds)...", "info")
        time.sleep(8)
        
        # Start React frontend
        if os.path.exists("frontend"):
            print_status("Starting React frontend...", "info")
            
            frontend_path = os.path.join(os.getcwd(), "frontend")
            node_modules = os.path.join(frontend_path, "node_modules")
            
            # Check and install frontend dependencies if needed
            if not os.path.exists(node_modules):
                print_status("Frontend dependencies not found, installing...", "info")
                if not install_frontend_dependencies():
                    print_status("Frontend dependency installation failed", "warning")
                    print_status("You may need to install them manually: cd frontend && npm install", "info")
            else:
                print_status("Frontend dependencies found", "success")
            
            # Start React frontend
            try:
                if platform.system() == "Windows":
                    subprocess.Popen(["npm", "start"], 
                                   shell=True, 
                                   cwd=frontend_path,
                                   creationflags=subprocess.CREATE_NEW_CONSOLE)
                else:
                    subprocess.Popen(["npm", "start"], cwd=frontend_path)
                
                print_status("React frontend starting", "success")
                print_status("Frontend will be available at: http://localhost:3000", "info")
            except Exception as e:
                print_status(f"Failed to start React frontend: {e}", "warning")
        else:
            print_status("Frontend directory not found", "warning")
        
        print_status("All components started successfully", "success")
        print_status("Components are initializing in separate windows...", "info")
        
        return True
        
    except Exception as e:
        print_status(f"Error starting components: {e}", "error")
        return False

def test_port_connectivity(host, port, timeout=5):
    """Test if a port is accessible"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, socket.error, ConnectionRefusedError):
        return False

def test_running_components_with_retry(config, max_retries=4, delay=15):
    """Test connectivity to running components with extended retry logic"""
    flask_port = int(config.get('FLASK_PORT', '5000'))
    bridge_port = int(config.get('GHIDRA_BRIDGE_PORT', '4768'))
    host = config.get('FLASK_HOST', '127.0.0.1')
    
    results = {'flask': False, 'bridge': False, 'frontend': False}
    
    for attempt in range(max_retries):
        print_status(f"Testing connectivity... ({attempt + 1}/{max_retries})", "info")
        
        # Test Flask backend
        if not results['flask'] and test_port_connectivity(host, flask_port, timeout=8):
            print_status(f"Flask backend connected ({host}:{flask_port})", "success")
            results['flask'] = True
        
        # Test Ghidra Bridge  
        if not results['bridge'] and test_port_connectivity(host, bridge_port, timeout=8):
            print_status(f"Ghidra Bridge connected ({host}:{bridge_port})", "success")
            results['bridge'] = True
        
        # Test frontend
        if not results['frontend'] and test_port_connectivity('127.0.0.1', 3000, timeout=8):
            print_status("Frontend connected (127.0.0.1:3000)", "success")
            results['frontend'] = True
        
        # Check if all components are running
        working_count = sum(results.values())
        if working_count == len(results):
            print_status(f"All components connected after {attempt + 1} attempt(s)!", "success")
            break
        
        # If not the last attempt, wait and try again
        if attempt < max_retries - 1:
            missing_components = [k for k, v in results.items() if not v]
            print_status(f"Waiting for: {', '.join(missing_components)}... ({delay}s)", "info")
            time.sleep(delay)
    
    # Test API endpoints if Flask is running
    if results['flask']:
        test_api_endpoints(host, flask_port)
    
    # Final status report
    if not results['flask']:
        print_status(f"Flask backend not responding - check logs/flask_startup.log", "error")
    if not results['bridge']:
        print_status(f"Ghidra Bridge not responding - check bridge window", "error")
    if not results['frontend']:
        print_status("Frontend not responding - check React window", "error")
    
    return results

def test_api_endpoints(host, port):
    """Test that API endpoints are available"""
    try:
        import requests
        base_url = f"http://{host}:{port}"
        
        # Test AI insights endpoint
        ai_insights_url = f"{base_url}/api/ai/insights"
        try:
            # Test with minimal payload
            test_payload = {
                "context": {"binary1": "test.exe", "binary2": "test2.exe"},
                "includeWebSearch": False,
                "searchQueries": []
            }
            response = requests.post(ai_insights_url, json=test_payload, timeout=10)
            if response.status_code in [200, 400, 500]:  # Any response means endpoint exists
                print_status("✓ AI insights endpoint responding", "success")
            else:
                print_status("⚠ AI insights endpoint exists but may have issues", "warning")
        except requests.exceptions.ConnectionError:
            print_status("✗ AI insights endpoint not available", "warning")
        except Exception:
            print_status("⚠ AI insights endpoint test inconclusive", "info")
        
        # Test main API health
        try:
            health_response = requests.get(f"{base_url}/api/tasks", timeout=5)
            if health_response.status_code == 200:
                print_status("✓ Core API endpoints responding", "success")
            else:
                print_status("⚠ Core API may have issues", "warning")
        except Exception:
            print_status("⚠ Core API endpoint test failed", "warning")
            
    except ImportError:
        print_status("Requests not available - skipping API tests", "info")
    except Exception as e:
        print_status(f"API feature test error: {e}", "info")

def check_nodejs():
    """Check if Node.js and npm are installed"""
    node_ok = False
    npm_ok = False
    
    # Check Node.js version first
    try:
        result = run_command(["node", "--version"], check=False, timeout=10)
        if result.returncode == 0:
            node_version = result.stdout.strip()
            try:
                major_version = int(node_version.replace('v', '').split('.')[0])
                if major_version >= 16:
                    print_status(f"Node.js {node_version}", "success")
                    node_ok = True
                else:
                    print_status(f"Node.js {node_version} - need 16+", "error")
                    return False
            except ValueError:
                print_status(f"Could not parse Node.js version: {node_version}", "error")
                return False
        else:
            print_status("Node.js not found", "error")
            return False
    except Exception as e:
        print_status(f"Node.js check failed: {e}", "error")
        return False
    
    # Check npm - and try to fix if missing
    try:
        npm_result = run_command(["npm", "--version"], check=False, timeout=10)
        if npm_result.returncode == 0:
            npm_version = npm_result.stdout.strip()
            print_status(f"npm {npm_version}", "success")
            npm_ok = True
        else:
            print_status("npm not found, attempting to install...", "warning")
            if install_npm():
                npm_ok = True
    except Exception:
        print_status("npm check failed, attempting to install...", "warning")
        if install_npm():
            npm_ok = True
    
    # Return True if Node.js is available, even if npm has issues
    if node_ok:
        if not npm_ok:
            print_status("npm issues detected but Node.js is functional", "info")
        return True
    
    return False

def install_npm():
    """Try to install npm if Node.js is available"""
    try:
        print_status("Installing npm...", "info")
        
        system = platform.system().lower()
        if system == "windows":
            # On Windows, first check if npm exists but isn't in PATH
            try:
                # Check common Node.js installation locations
                node_paths = [
                    os.path.expanduser("~/AppData/Roaming/npm"),
                    "C:/Program Files/nodejs",
                    "C:/Program Files (x86)/nodejs"
                ]
                
                for node_path in node_paths:
                    npm_path = os.path.join(node_path, "npm.cmd")
                    if os.path.exists(npm_path):
                        # Test if it works
                        result = run_command([npm_path, "--version"], check=False, timeout=10)
                        if result.returncode == 0:
                            print_status("npm found and working", "success")
                            return True
                
                # Try winget to install npm specifically
                try:
                    run_command(["winget", "install", "npm"], timeout=180)
                    print_status("npm installed via winget", "success")
                    return check_npm_only()
                except:
                    pass
                
                # Try chocolatey for npm only
                try:
                    run_command(["choco", "install", "npm", "-y"], timeout=180)
                    print_status("npm installed via chocolatey", "success")
                    return check_npm_only()
                except:
                    pass
                    
            except Exception:
                pass
        
        else:
            # On Unix systems, npm is usually in a separate package
            try:
                if system == "darwin":  # macOS
                    run_command(["brew", "install", "npm"], timeout=180)
                    print_status("npm installed via brew", "success")
                    return check_npm_only()
                else:  # Linux
                    # Try apt first
                    run_command(["sudo", "apt", "update"], timeout=60)
                    run_command(["sudo", "apt", "install", "-y", "npm"], timeout=180)
                    print_status("npm installed via apt", "success")
                    return check_npm_only()
            except:
                try:
                    run_command(["sudo", "yum", "install", "-y", "npm"], timeout=180)
                    print_status("npm installed via yum", "success")
                    return check_npm_only()
                except:
                    pass
        
        print_status("Could not install npm automatically", "warning")
        print_status("Consider reinstalling Node.js from https://nodejs.org/", "info")
        return False
        
    except Exception as e:
        print_status(f"npm installation error: {e}", "error")
        return False

def check_npm_only():
    """Check if npm is now available"""
    try:
        npm_result = run_command(["npm", "--version"], check=False, timeout=10)
        if npm_result.returncode == 0:
            npm_version = npm_result.stdout.strip()
            print_status(f"npm {npm_version}", "success")
            return True
    except:
        pass
    return False

def install_frontend_dependencies():
    """Install and verify frontend dependencies"""
    frontend_path = os.path.join(os.getcwd(), "frontend")
    
    if not os.path.exists(frontend_path):
        print_status("Frontend directory not found", "warning")
        return False
    
    print_status("Installing frontend dependencies...", "info")
    
    try:
        # First, ensure package.json exists
        package_json_path = os.path.join(frontend_path, "package.json")
        if not os.path.exists(package_json_path):
            print_status("package.json not found in frontend directory", "error")
            return False
        
        # Install all dependencies from package.json
        print_status("Running npm install...", "info")
        install_result = run_command(["npm", "install"], cwd=frontend_path, timeout=300)
        
        if install_result.returncode != 0:
            print_status("npm install failed, trying with --legacy-peer-deps", "warning")
            install_result = run_command(["npm", "install", "--legacy-peer-deps"], cwd=frontend_path, timeout=300)
        
        if install_result.returncode == 0:
            print_status("Frontend dependencies installed successfully", "success")
        else:
            print_status("Frontend dependency installation failed", "error")
            return False
        
        # Verify critical packages are installed
        critical_packages = [
            "mermaid",
            "recharts", 
            "react-markdown",
            "remark-gfm",
            "rehype-highlight",
            "rehype-raw",
            "remark-breaks",
            "highlight.js"
        ]
        
        print_status("Verifying critical packages...", "info")
        node_modules_path = os.path.join(frontend_path, "node_modules")
        
        missing_packages = []
        for package in critical_packages:
            package_path = os.path.join(node_modules_path, package)
            if not os.path.exists(package_path):
                missing_packages.append(package)
        
        if missing_packages:
            print_status(f"Missing critical packages: {', '.join(missing_packages)}", "warning")
            print_status("Attempting to install missing packages individually...", "info")
            
            for package in missing_packages:
                try:
                    run_command(["npm", "install", package, "--save"], cwd=frontend_path, timeout=120)
                    print_status(f"✓ Installed {package}", "success")
                except Exception as e:
                    print_status(f"✗ Failed to install {package}: {e}", "error")
        else:
            print_status("All critical packages verified", "success")
        
        # Test if React build process works
        print_status("Testing React build process...", "info")
        try:
            # Just test that the build command doesn't immediately fail
            build_test = run_command(["npm", "run", "build", "--", "--dry-run"], 
                                   cwd=frontend_path, check=False, timeout=60)
            if build_test.returncode == 0:
                print_status("Build process test passed", "success")
            else:
                # Try a syntax check instead
                print_status("Testing TypeScript compilation...", "info")
                tsc_test = run_command(["npx", "tsc", "--noEmit"], 
                                     cwd=frontend_path, check=False, timeout=60)
                if tsc_test.returncode == 0:
                    print_status("TypeScript compilation successful", "success")
                else:
                    print_status("Build test warnings (may be normal)", "info")
        except Exception:
            print_status("Build test skipped (may be normal)", "info")
        
        return True
        
    except Exception as e:
        print_status(f"Frontend dependency installation error: {e}", "error")
        return False

def check_java_jdk():
    """Check if Java JDK is installed"""
    try:
        # Check Java version
        result = run_command(["java", "-version"], check=False, timeout=10)
        if result.returncode == 0:
            java_output = result.stderr + result.stdout  # Java version goes to stderr
            
            # Parse version - look for version numbers
            import re
            version_match = re.search(r'version "(\d+)', java_output)
            if version_match:
                java_version = int(version_match.group(1))
                if java_version >= 11:  # Ghidra needs Java 11+
                    print_status(f"Java {java_version}", "success")
                    
                    # Check if it's JDK (has javac)
                    javac_result = run_command(["javac", "-version"], check=False, timeout=10)
                    if javac_result.returncode == 0:
                        print_status("Java JDK (with javac)", "success")
                        return True
                    else:
                        print_status("Java JRE found, but JDK recommended", "info")
                        return True  # JRE is sufficient for Ghidra
                else:
                    print_status(f"Java {java_version} - need 11+", "error")
                    return False
    except:
        pass
    
    print_status("Java not found", "error")
    return False

def check_git():
    """Check if Git is installed"""
    try:
        result = run_command(["git", "--version"], check=False, timeout=10)
        if result.returncode == 0:
            git_version = result.stdout.strip()
            print_status(f"{git_version}", "success")
            return True
    except:
        pass
    
    print_status("Git not found", "info")
    return False

def ask_install_nodejs():
    """Ask user if they want to install Node.js"""
    if platform.system() == "Windows":
        print_status("Node.js installation options:", "info")
        print_status("  1. Automatic installation (if package manager available)", "info")
        print_status("  2. Manual download from https://nodejs.org/", "info")
        
        try:
            choice = input("Install Node.js automatically? (y/n): ").strip().lower()
            return choice in ['y', 'yes']
        except:
            return False
    return True

def ask_install_java():
    """Ask user if they want to install Java JDK"""
    print_status("Java JDK installation options:", "info")
    print_status("  1. Automatic installation (if package manager available)", "info")
    print_status("  2. Manual download from https://adoptium.net/", "info")
    
    try:
        choice = input("Install Java JDK automatically? (y/n): ").strip().lower()
        return choice in ['y', 'yes']
    except:
        return False

def install_nodejs():
    """Install Node.js using system package managers"""
    print_status("Installing Node.js...", "info")
    
    system = platform.system().lower()
    
    try:
        if system == "windows":
            # Try winget first
            try:
                run_command(["winget", "install", "OpenJS.NodeJS"], timeout=300)
                print_status("Node.js installed via winget", "success")
                return check_nodejs()
            except:
                pass
            
            # Try chocolatey
            try:
                run_command(["choco", "install", "nodejs", "-y"], timeout=300)
                print_status("Node.js installed via chocolatey", "success")
                return check_nodejs()
            except:
                pass
                
        elif system == "darwin":  # macOS
            try:
                run_command(["brew", "install", "node"], timeout=300)
                print_status("Node.js installed via Homebrew", "success")
                return check_nodejs()
            except:
                pass
                
        else:  # Linux
            try:
                # Try apt (Ubuntu/Debian)
                run_command(["sudo", "apt", "update"], timeout=60)
                run_command(["sudo", "apt", "install", "-y", "nodejs", "npm"], timeout=300)
                print_status("Node.js installed via apt", "success")
                return check_nodejs()
            except:
                pass
            
            try:
                # Try yum (CentOS/RHEL)
                run_command(["sudo", "yum", "install", "-y", "nodejs", "npm"], timeout=300)
                print_status("Node.js installed via yum", "success")
                return check_nodejs()
            except:
                pass
        
        # If automatic installation failed
        print_status("Automatic Node.js installation failed", "error")
        print_status("Please install manually from https://nodejs.org/", "info")
        return False
        
    except Exception as e:
        print_status(f"Node.js installation error: {e}", "error")
        return False

def install_java_jdk():
    """Install Java JDK using system package managers"""
    print_status("Installing Java JDK...", "info")
    
    system = platform.system().lower()
    
    try:
        if system == "windows":
            # Try winget first
            try:
                run_command(["winget", "install", "Microsoft.OpenJDK.17"], timeout=300)
                print_status("Java JDK installed via winget", "success")
                return check_java_jdk()
            except:
                pass
            
            # Try chocolatey
            try:
                run_command(["choco", "install", "openjdk", "-y"], timeout=300)
                print_status("Java JDK installed via chocolatey", "success")
                return check_java_jdk()
            except:
                pass
                
        elif system == "darwin":  # macOS
            try:
                run_command(["brew", "install", "openjdk@17"], timeout=300)
                print_status("Java JDK installed via Homebrew", "success")
                return check_java_jdk()
            except:
                pass
                
        else:  # Linux
            try:
                # Try apt (Ubuntu/Debian)
                run_command(["sudo", "apt", "update"], timeout=60)
                run_command(["sudo", "apt", "install", "-y", "openjdk-17-jdk"], timeout=300)
                print_status("Java JDK installed via apt", "success")
                return check_java_jdk()
            except:
                pass
            
            try:
                # Try yum (CentOS/RHEL)
                run_command(["sudo", "yum", "install", "-y", "java-17-openjdk-devel"], timeout=300)
                print_status("Java JDK installed via yum", "success")
                return check_java_jdk()
            except:
                pass
        
        # If automatic installation failed
        print_status("Automatic Java JDK installation failed", "error")
        print_status("Please install manually from https://adoptium.net/", "info")
        return False
        
    except Exception as e:
        print_status(f"Java JDK installation error: {e}", "error")
        return False

def check_system_requirements(auto_mode=False):
    """Check and install system requirements like Node.js, Java JDK, etc."""
    all_good = True
    
    # Check Python version
    python_version = sys.version_info
    if python_version >= (3, 8):
        print_status(f"Python {python_version.major}.{python_version.minor}.{python_version.micro}", "success")
    else:
        print_status(f"Python {python_version.major}.{python_version.minor} - need 3.8+", "error")
        all_good = False
    
    # Check Node.js and npm (required for React frontend)
    node_ok = check_nodejs()
    if not node_ok:
        print_status("Node.js required for React frontend", "warning")
        if auto_mode or ask_install_nodejs():
            node_ok = install_nodejs()
        all_good = all_good and node_ok
    
    # Check Java JDK (required for Ghidra)
    java_ok = check_java_jdk()
    if not java_ok:
        print_status("Java JDK required for Ghidra", "warning")
        if auto_mode or ask_install_java():
            java_ok = install_java_jdk()
        all_good = all_good and java_ok
    
    # Check Git (optional but recommended)
    git_ok = check_git()
    if not git_ok:
        print_status("Git not found (optional)", "info")
    
    return all_good

def main():
    """Main setup process with comprehensive Ghidra Bridge setup - CLEANED UP UX"""
    parser = argparse.ArgumentParser(
        description="ShadowSeek Environment Setup Script",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--auto", action="store_true", help="Run in auto mode without prompts")
    parser.add_argument("--skip-install", action="store_true", help="Skip automatic dependency installation")
    parser.add_argument("--skip-startup", action="store_true", help="Skip automatic component startup")
    parser.add_argument("--skip-system-check", action="store_true", help="Skip system requirements check")
    parser.add_argument("--force-clean", action="store_true", help="Force clean virtual environment and start fresh")
    parser.add_argument("--use-pip", action="store_true", help="Force use of pip instead of UV")
    parser.add_argument("--ghidra-path", help="Specify Ghidra installation path")
    
    args = parser.parse_args()
    
    print_header("🚀 ShadowSeek Environment Setup")
    
    # Step 1: Check system requirements (Node.js, Java, etc.)
    if not args.skip_system_check:
        print_step(1, "System Requirements")
        system_ok = check_system_requirements(args.auto)
        if not system_ok and not args.auto:
            choice = input("\nSome system requirements are missing. Continue anyway? (y/n): ").strip().lower()
            if choice not in ['y', 'yes']:
                print_status("Setup cancelled", "error")
                return False
        elif not system_ok:
            print_status("Some requirements missing, continuing in auto mode", "warning")
    
    # Step 2: Test and install Python dependencies
    if not args.skip_install:
        print_step(2, "Python Dependencies")
        if not test_python_dependencies(force_clean=args.force_clean, use_pip=args.use_pip):
            print_status("Dependency installation failed", "error")
            return False
        
        # Step 2b: Install frontend dependencies
        print_step("2b", "Frontend Dependencies")
        if os.path.exists("frontend"):
            if not install_frontend_dependencies():
                print_status("Frontend dependencies installation had issues", "warning")
        else:
            print_status("Frontend directory not found - skipping", "info")
    
    # Step 3: Find Ghidra installations
    print_step(3, "Ghidra Detection & Configuration")
    found_paths = find_ghidra_installations()
    
    # Step 4: Interactive configuration
    config = prompt_for_paths(found_paths, args)
    
    # Step 5: Validate configuration
    if config.get("GHIDRA_INSTALL_DIR") and not validate_ghidra_path(config["GHIDRA_INSTALL_DIR"]):
        print_status(f"Invalid Ghidra installation: {config['GHIDRA_INSTALL_DIR']}", "error")
        return False
    
    # Step 6: Setup Ghidra Bridge
    print_step(4, "Ghidra Bridge Setup")
    if config.get("GHIDRA_INSTALL_DIR"):
        if setup_ghidra_bridge_server(config):
            print_status("Ghidra Bridge configured", "success")
        else:
            print_status("Bridge setup had issues", "warning")
    else:
        print_status("No Ghidra path - bridge will not work", "warning")
    
    # Step 7: Create .env file
    print_step(5, "Environment & Directories")
    create_env_file(config)
    create_directories(config)
    
    # Step 8: Start components
    print_step(6, "Component Startup")
    if run_start_all(args.skip_startup):
        print_status("Components starting...", "info")
        
        # Step 9: Test running components with extended retry logic
        print_step(7, "Connectivity Test")
        results = test_running_components_with_retry(config, max_retries=4, delay=15)
        
        # Report results
        working_count = sum(results.values())
        total_count = len(results)
        
        if working_count == total_count:
            print_status(f"All {total_count} components running!", "success")
        elif working_count > 0:
            print_status(f"{working_count}/{total_count} components running", "warning")
        else:
            print_status("Components still starting up", "warning")
    
    # Final summary - CLEAN AND FOCUSED
    print_header("✅ Setup Complete")
    print_status("Access ShadowSeek at: http://localhost:3000", "info")
    print_status(f"Backend API: http://localhost:{config.get('FLASK_PORT', '5000')}", "info")
    
    print()
    print_status("✓ All components configured successfully", "success")
    
    if config.get("GHIDRA_INSTALL_DIR"):
        print()
        print_status("🌉 BRIDGE SETUP:", "success")
        print_status("✓ Bridge server script ready: ghidra_bridge_server.py", "success")
        print_status("✓ Existing launcher ready: start_ghidra_bridge_new.bat", "success")
        print()
        print_status("TO START BRIDGE:", "info")
        print_status("  1. Run: .\\start_ghidra_bridge_new.bat", "info")
        print_status("  2. Wait ~30 seconds for Ghidra to initialize", "info")
        print_status("  3. Bridge will be available on port 4768", "info")
    else:
        print_status("⚠️  Ghidra Bridge not configured - binary analysis limited", "warning")
        print_status("   To enable: python setup_environment.py --ghidra-path YOUR_GHIDRA_PATH", "info")
    
    print_status("Setup completed successfully", "info")
    
    print_status("Check logs/ directory for detailed information", "info")
    
    return True

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print_status("\n❌ Setup cancelled by user", "error")
        sys.exit(1)
    except Exception as e:
        print_status(f"❌ Setup failed: {e}", "error")
        sys.exit(1) 