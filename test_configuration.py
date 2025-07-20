#!/usr/bin/env python3
"""
ShadowSeek Configuration Test Script

Quick validation script to test if your environment configuration is working properly.
Run this after setting up your environment variables.
"""

import os
import sys
import socket
import platform
from pathlib import Path
from dotenv import load_dotenv

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_header():
    """Print test header"""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}")
    print("🧪 ShadowSeek Configuration Test")
    print(f"{'='*60}{Colors.RESET}\n")

def print_result(test_name, passed, message="", warning=False):
    """Print test result"""
    if passed:
        status = f"{Colors.GREEN}✅ PASS{Colors.RESET}"
    elif warning:
        status = f"{Colors.YELLOW}⚠️ WARN{Colors.RESET}"
    else:
        status = f"{Colors.RED}❌ FAIL{Colors.RESET}"
    
    print(f"{status} {test_name}")
    if message:
        print(f"     {message}")

def test_environment_variables():
    """Test environment variables"""
    print(f"{Colors.BOLD}📋 Environment Variables{Colors.RESET}")
    
    # Load environment variables
    load_dotenv()
    
    # Required variables
    required_vars = {
        'GHIDRA_INSTALL_DIR': 'Ghidra installation directory',
        'GHIDRA_BRIDGE_PORT': 'Ghidra Bridge port',
        'FLASK_PORT': 'Flask server port'
    }
    
    all_passed = True
    
    for var, description in required_vars.items():
        value = os.getenv(var)
        if value:
            print_result(f"{description}", True, f"{var}={value}")
        else:
            print_result(f"{description}", False, f"{var} not set")
            all_passed = False
    
    # Optional variables
    optional_vars = {
        'GHIDRA_TEMP_DIR': './temp/ghidra_temp',
        'GHIDRA_PROJECTS_DIR': './ghidra_projects',
        'VS_INSTALL_PATH': 'Not set (optional)'
    }
    
    for var, default in optional_vars.items():
        value = os.getenv(var, default)
        print_result(f"{var}", True, f"{value}", warning=(value == default and "Not set" in default))
    
    return all_passed

def test_ghidra_installation():
    """Test Ghidra installation"""
    print(f"\n{Colors.BOLD}🔧 Ghidra Installation{Colors.RESET}")
    
    ghidra_path = os.getenv('GHIDRA_INSTALL_DIR')
    if not ghidra_path:
        print_result("Ghidra path configured", False, "GHIDRA_INSTALL_DIR not set")
        return False
    
    # Test if directory exists
    if not os.path.exists(ghidra_path):
        print_result("Ghidra directory exists", False, f"Directory not found: {ghidra_path}")
        return False
    print_result("Ghidra directory exists", True, ghidra_path)
    
    # Test support directory
    support_dir = os.path.join(ghidra_path, "support")
    if os.path.exists(support_dir):
        print_result("Ghidra support directory", True)
    else:
        print_result("Ghidra support directory", False, f"Not found: {support_dir}")
        return False
    
    # Test headless analyzer
    if platform.system() == "Windows":
        headless = os.path.join(support_dir, "analyzeHeadless.bat")
    else:
        headless = os.path.join(support_dir, "analyzeHeadless")
    
    if os.path.exists(headless):
        print_result("Headless analyzer", True, os.path.basename(headless))
    else:
        print_result("Headless analyzer", False, f"Not found: {headless}")
        return False
    
    # Test Ghidra scripts directory
    scripts_dir = os.path.join(ghidra_path, "Ghidra", "Features", "Base", "ghidra_scripts")
    if os.path.exists(scripts_dir):
        print_result("Ghidra scripts directory", True)
    else:
        print_result("Ghidra scripts directory", False, f"Not found: {scripts_dir}", warning=True)
    
    return True

def test_python_environment():
    """Test Python environment"""
    print(f"\n{Colors.BOLD}🐍 Python Environment{Colors.RESET}")
    
    # Python version
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 8):
        print_result("Python version", True, f"Python {python_version}")
    else:
        print_result("Python version", False, f"Python {python_version} (requires >= 3.8)")
        return False
    
    # Required packages
    required_packages = {
        'flask': 'Flask',
        'flask_sqlalchemy': 'Flask-SQLAlchemy', 
        'flask_cors': 'Flask-CORS',
        'requests': 'Requests',
        'dotenv': 'python-dotenv'
    }
    
    all_packages = True
    for module, name in required_packages.items():
        try:
            __import__(module)
            print_result(f"{name} package", True)
        except ImportError:
            print_result(f"{name} package", False, f"Run: pip install {module}")
            all_packages = False
    
    return all_packages

def test_directory_structure():
    """Test directory structure"""
    print(f"\n{Colors.BOLD}📁 Directory Structure{Colors.RESET}")
    
    required_dirs = [
        'uploads', 'temp', 'logs', 'instance', 
        'ghidra_projects', 'analysis_scripts'
    ]
    
    all_dirs = True
    for directory in required_dirs:
        if os.path.exists(directory):
            print_result(f"{directory}/", True)
        else:
            print_result(f"{directory}/", False, "Directory missing - will be created automatically")
            all_dirs = False
    
    return all_dirs

def test_flask_config():
    """Test Flask configuration loading"""
    print(f"\n{Colors.BOLD}⚙️ Flask Configuration{Colors.RESET}")
    
    try:
        # Add current directory to path
        sys.path.insert(0, os.getcwd())
        
        from flask_app.config import Config
        config = Config()
        
        print_result("Flask config loading", True)
        
        # Test database URI
        if hasattr(config, 'SQLALCHEMY_DATABASE_URI'):
            print_result("Database configuration", True, "SQLite configured")
        else:
            print_result("Database configuration", False)
            return False
        
        # Test Ghidra path in config
        if config.GHIDRA_INSTALL_DIR:
            print_result("Ghidra path in config", True, config.GHIDRA_INSTALL_DIR)
        else:
            print_result("Ghidra path in config", False, "Not configured")
            return False
        
        return True
        
    except ImportError as e:
        print_result("Flask config loading", False, f"Import error: {e}")
        return False
    except Exception as e:
        print_result("Flask config loading", False, f"Error: {e}")
        return False

def test_network_configuration():
    """Test network configuration"""
    print(f"\n{Colors.BOLD}🌐 Network Configuration{Colors.RESET}")
    
    # Test Flask port
    flask_port = int(os.getenv('FLASK_PORT', '5000'))
    bridge_port = int(os.getenv('GHIDRA_BRIDGE_PORT', '4768'))
    
    if flask_port != bridge_port:
        print_result("Port configuration", True, f"Flask: {flask_port}, Bridge: {bridge_port}")
    else:
        print_result("Port configuration", False, "Flask and Bridge ports cannot be the same")
        return False
    
    # Test if ports are available
    def test_port(port, name):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('localhost', port))
            sock.close()
            print_result(f"{name} port {port} available", True)
            return True
        except OSError:
            print_result(f"{name} port {port} available", False, "Port in use or restricted", warning=True)
            return True  # Not critical
    
    test_port(flask_port, "Flask")
    test_port(bridge_port, "Bridge")
    
    return True

def test_optional_components():
    """Test optional components"""
    print(f"\n{Colors.BOLD}🔧 Optional Components{Colors.RESET}")
    
    # Visual Studio (Windows only)
    if platform.system() == "Windows":
        vs_path = os.getenv('VS_INSTALL_PATH')
        if vs_path and os.path.exists(vs_path):
            print_result("Visual Studio", True, vs_path)
        else:
            print_result("Visual Studio", False, "Not configured (optional for test binaries)", warning=True)
    
    # Node.js for frontend
    try:
        import subprocess
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print_result("Node.js", True, result.stdout.strip())
        else:
            print_result("Node.js", False, "Required for frontend", warning=True)
    except FileNotFoundError:
        print_result("Node.js", False, "Required for frontend", warning=True)
    
    return True

def print_summary(results):
    """Print test summary"""
    print(f"\n{Colors.BOLD}📊 Test Summary{Colors.RESET}")
    
    passed = sum(results.values())
    total = len(results)
    
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print(f"{Colors.GREEN}🎉 All tests passed! Your ShadowSeek environment is ready.{Colors.RESET}")
        return True
    else:
        print(f"{Colors.YELLOW}⚠️ Some tests failed. Please review and fix the issues above.{Colors.RESET}")
        return False

def main():
    """Main test function"""
    print_header()
    
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    
    # Run all tests
    results = {
        'Environment Variables': test_environment_variables(),
        'Ghidra Installation': test_ghidra_installation(),
        'Python Environment': test_python_environment(),
        'Directory Structure': test_directory_structure(),
        'Flask Configuration': test_flask_config(),
        'Network Configuration': test_network_configuration(),
        'Optional Components': test_optional_components()
    }
    
    # Print summary
    success = print_summary(results)
    
    if success:
        print(f"\n{Colors.CYAN}Ready to start ShadowSeek!{Colors.RESET}")
        print("Next steps:")
        print("1. Start Ghidra Bridge: start_ghidra_bridge_new.bat")
        print("2. Start backend: python run.py")
        print("3. Start frontend: cd frontend && npm start")
    else:
        print(f"\n{Colors.YELLOW}Fix the issues above and run the test again.{Colors.RESET}")
        print(f"See {Colors.CYAN}ENVIRONMENT_VARIABLES.md{Colors.RESET} for detailed setup instructions.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Test cancelled by user.{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Test error: {e}{Colors.RESET}") 