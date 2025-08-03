#!/usr/bin/env python3
"""
ShadowSeek Installation Verification Script

This script verifies that ShadowSeek is properly installed and configured.
Run this after installation to ensure everything is working correctly.

Usage: python verify_installation.py
"""

import os
import sys
import subprocess
import socket
import time
import json
from pathlib import Path

def print_status(message, status="info"):
    """Print status with emoji indicators"""
    icons = {
        "success": "✅",
        "error": "❌", 
        "warning": "⚠️",
        "info": "ℹ️",
        "test": "🧪"
    }
    icon = icons.get(status, "•")
    print(f"{icon} {message}")

def print_header(title):
    """Print section header"""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

def run_command(cmd, timeout=30):
    """Run a command and return success status"""
    try:
        if isinstance(cmd, str):
            cmd = cmd.split()
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError:
        return False, "", f"Command not found: {cmd[0] if cmd else 'Unknown'}"
    except Exception as e:
        return False, "", str(e)

def check_port(port, timeout=5):
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    except:
        return False

def test_prerequisites():
    """Test system prerequisites"""
    print_header("🔍 System Prerequisites")
    
    results = {}
    
    # Test Python
    success, stdout, stderr = run_command([sys.executable, "--version"])
    if success:
        version = stdout.strip()
        print_status(f"Python: {version}", "success")
        results["python"] = True
    else:
        print_status("Python: Not working", "error")
        results["python"] = False
    
    # Test Node.js
    success, stdout, stderr = run_command(["node", "--version"])
    if success:
        version = stdout.strip()
        print_status(f"Node.js: {version}", "success")
        results["nodejs"] = True
    else:
        print_status("Node.js: Not installed or not in PATH", "error")
        results["nodejs"] = False
    
    # Test npm
    success, stdout, stderr = run_command(["npm", "--version"])
    if success:
        version = stdout.strip()
        print_status(f"npm: {version}", "success")
        results["npm"] = True
    else:
        print_status("npm: Not installed or not in PATH", "error")
        results["npm"] = False
    
    # Test Java
    success, stdout, stderr = run_command(["java", "-version"])
    if success:
        # Java version goes to stderr
        version_line = stderr.split('\n')[0] if stderr else stdout.split('\n')[0]
        print_status(f"Java: {version_line}", "success")
        results["java"] = True
    else:
        print_status("Java: Not installed or not in PATH", "error")
        results["java"] = False
    
    # Test Git (optional)
    success, stdout, stderr = run_command(["git", "--version"])
    if success:
        version = stdout.strip()
        print_status(f"Git: {version}", "success")
        results["git"] = True
    else:
        print_status("Git: Not installed (optional)", "warning")
        results["git"] = False
    
    return results

def test_python_dependencies():
    """Test Python package imports"""
    print_header("🐍 Python Dependencies")
    
    required_packages = [
        "flask",
        "flask_sqlalchemy",
        "flask_cors", 
        "flask_migrate",
        "requests",
        "python_dotenv",
        "ghidra_bridge",
        "psutil"
    ]
    
    optional_packages = [
        "openai",
        "anthropic", 
        "redis"
    ]
    
    results = {"required": 0, "optional": 0, "total_required": len(required_packages)}
    
    print_status("Testing required packages:", "test")
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print_status(f"  {package}: Available", "success")
            results["required"] += 1
        except ImportError:
            print_status(f"  {package}: Missing", "error")
    
    print_status("Testing optional packages:", "test")
    for package in optional_packages:
        try:
            __import__(package.replace('-', '_'))
            print_status(f"  {package}: Available", "success")
            results["optional"] += 1
        except ImportError:
            print_status(f"  {package}: Not installed (optional)", "warning")
    
    return results

def test_configuration():
    """Test ShadowSeek configuration"""
    print_header("⚙️ Configuration")
    
    results = {}
    
    # Check .env file
    if Path(".env").exists():
        print_status(".env file: Found", "success")
        results["env_file"] = True
        
        # Load and validate .env
        try:
            with open(".env", "r") as f:
                env_content = f.read()
            
            # Check for key configuration
            if "GHIDRA_INSTALL_DIR" in env_content:
                ghidra_line = [line for line in env_content.split('\n') if line.startswith('GHIDRA_INSTALL_DIR')]
                if ghidra_line:
                    ghidra_path = ghidra_line[0].split('=', 1)[1].strip()
                    if ghidra_path and Path(ghidra_path).exists():
                        print_status(f"Ghidra path: Valid ({ghidra_path})", "success")
                        results["ghidra_path"] = True
                    else:
                        print_status(f"Ghidra path: Invalid or empty ({ghidra_path})", "warning")
                        results["ghidra_path"] = False
            
        except Exception as e:
            print_status(f".env file: Error reading - {e}", "error")
            results["env_file"] = False
    else:
        print_status(".env file: Missing", "error")
        results["env_file"] = False
    
    # Check required directories
    required_dirs = [
        "temp/ghidra_temp",
        "ghidra_projects", 
        "uploads",
        "logs",
        "instance"
    ]
    
    dirs_ok = 0
    for directory in required_dirs:
        if Path(directory).exists():
            print_status(f"Directory {directory}: Exists", "success")
            dirs_ok += 1
        else:
            print_status(f"Directory {directory}: Missing", "error")
    
    results["directories"] = dirs_ok == len(required_dirs)
    
    return results

def test_frontend():
    """Test frontend setup"""
    print_header("⚛️ Frontend")
    
    results = {}
    
    # Check frontend directory
    if Path("frontend").exists():
        print_status("Frontend directory: Found", "success")
        results["frontend_dir"] = True
        
        # Check package.json
        package_json = Path("frontend/package.json")
        if package_json.exists():
            print_status("package.json: Found", "success")
            results["package_json"] = True
        else:
            print_status("package.json: Missing", "error")
            results["package_json"] = False
        
        # Check node_modules
        node_modules = Path("frontend/node_modules")
        if node_modules.exists():
            print_status("node_modules: Found", "success")
            results["node_modules"] = True
        else:
            print_status("node_modules: Missing (run 'cd frontend && npm install')", "warning")
            results["node_modules"] = False
            
    else:
        print_status("Frontend directory: Missing", "error")
        results["frontend_dir"] = False
        results["package_json"] = False
        results["node_modules"] = False
    
    return results

def test_flask_app():
    """Test Flask application"""
    print_header("🌶️ Flask Application")
    
    results = {}
    
    # Test Flask import
    try:
        sys.path.insert(0, os.getcwd())
        from flask_app import create_app
        app = create_app()
        print_status("Flask app creation: Success", "success")
        results["flask_import"] = True
    except Exception as e:
        print_status(f"Flask app creation: Failed - {e}", "error")
        results["flask_import"] = False
        return results
    
    # Test app configuration
    try:
        with app.app_context():
            # Test database initialization
            from flask_app import db
            print_status("Database initialization: Success", "success")
            results["database"] = True
    except Exception as e:
        print_status(f"Database initialization: Failed - {e}", "error")
        results["database"] = False
    
    return results

def test_services():
    """Test running services"""
    print_header("🚀 Running Services")
    
    results = {}
    
    # Test Ghidra Bridge
    if check_port(4768):
        print_status("Ghidra Bridge (port 4768): Running", "success")
        results["ghidra_bridge"] = True
    else:
        print_status("Ghidra Bridge (port 4768): Not running", "warning")
        results["ghidra_bridge"] = False
    
    # Test Flask Backend
    if check_port(5000):
        print_status("Flask Backend (port 5000): Running", "success")
        results["flask_backend"] = True
        
        # Test API endpoint
        try:
            import urllib.request
            import urllib.error
            response = urllib.request.urlopen("http://localhost:5000/api/system/status", timeout=10)
            if response.getcode() == 200:
                data = json.loads(response.read().decode())
                print_status("API Status endpoint: Working", "success")
                results["api_status"] = True
            else:
                print_status("API Status endpoint: Error", "error")
                results["api_status"] = False
        except Exception as e:
            print_status(f"API Status endpoint: Failed - {e}", "error")
            results["api_status"] = False
    else:
        print_status("Flask Backend (port 5000): Not running", "warning")
        results["flask_backend"] = False
        results["api_status"] = False
    
    # Test React Frontend
    if check_port(3000):
        print_status("React Frontend (port 3000): Running", "success")
        results["react_frontend"] = True
    else:
        print_status("React Frontend (port 3000): Not running", "warning")
        results["react_frontend"] = False
    
    return results

def generate_report(all_results):
    """Generate comprehensive report"""
    print_header("📊 Verification Report")
    
    # Calculate scores
    prereq_score = sum(all_results["prerequisites"].values())
    prereq_total = len(all_results["prerequisites"])
    
    deps_score = all_results["dependencies"]["required"]
    deps_total = all_results["dependencies"]["total_required"]
    
    config_score = sum(all_results["configuration"].values())
    config_total = len(all_results["configuration"])
    
    frontend_score = sum(all_results["frontend"].values())
    frontend_total = len(all_results["frontend"])
    
    flask_score = sum(all_results["flask"].values())
    flask_total = len(all_results["flask"])
    
    services_score = sum(all_results["services"].values())
    services_total = len(all_results["services"])
    
    # Print scores
    print_status(f"Prerequisites: {prereq_score}/{prereq_total}", 
                "success" if prereq_score == prereq_total else "warning")
    print_status(f"Python Dependencies: {deps_score}/{deps_total}",
                "success" if deps_score == deps_total else "error")
    print_status(f"Configuration: {config_score}/{config_total}",
                "success" if config_score == config_total else "warning")
    print_status(f"Frontend: {frontend_score}/{frontend_total}",
                "success" if frontend_score == frontend_total else "warning")
    print_status(f"Flask Application: {flask_score}/{flask_total}",
                "success" if flask_score == flask_total else "error")
    print_status(f"Running Services: {services_score}/{services_total}",
                "success" if services_score > 0 else "warning")
    
    # Overall assessment
    total_score = prereq_score + deps_score + config_score + flask_score + services_score
    total_possible = prereq_total + deps_total + config_total + flask_total + services_total
    
    print(f"\n📈 Overall Score: {total_score}/{total_possible} ({total_score/total_possible*100:.1f}%)")
    
    # Recommendations
    print_header("💡 Recommendations")
    
    if prereq_score < prereq_total:
        print_status("Install missing prerequisites (Python, Node.js, Java)", "info")
    
    if deps_score < deps_total:
        print_status("Install missing Python dependencies: pip install -r requirements.txt", "info")
    
    if not all_results["configuration"]["env_file"]:
        print_status("Create .env configuration file", "info")
    
    if not all_results["frontend"]["node_modules"]:
        print_status("Install frontend dependencies: cd frontend && npm install", "info")
    
    if flask_score < flask_total:
        print_status("Fix Flask application issues", "info")
    
    if services_score == 0:
        print_status("Start ShadowSeek services: start_all_enhanced.bat", "info")
    elif services_score < services_total:
        print_status("Some services not running - check individual components", "info")
    
    # Success message
    if total_score == total_possible:
        print_status("🎉 Perfect! ShadowSeek is fully configured and ready to use!", "success")
        print_status("Access the interface at: http://localhost:3000", "info")
    elif total_score >= total_possible * 0.8:
        print_status("✅ Good! ShadowSeek is mostly ready with minor issues to address", "success")
    elif total_score >= total_possible * 0.5:
        print_status("⚠️ Partial setup - several issues need to be resolved", "warning")
    else:
        print_status("❌ Major issues detected - follow INSTALLATION_GUIDE.md", "error")

def main():
    """Main verification process"""
    print_header("🧪 ShadowSeek Installation Verification")
    print_status("This script will verify your ShadowSeek installation", "info")
    print_status("Please wait while we check all components...", "info")
    
    all_results = {}
    
    try:
        # Run all tests
        all_results["prerequisites"] = test_prerequisites()
        all_results["dependencies"] = test_python_dependencies()
        all_results["configuration"] = test_configuration()
        all_results["frontend"] = test_frontend()
        all_results["flask"] = test_flask_app()
        all_results["services"] = test_services()
        
        # Generate report
        generate_report(all_results)
        
        return True
        
    except KeyboardInterrupt:
        print_status("Verification cancelled by user", "warning")
        return False
    except Exception as e:
        print_status(f"Verification failed: {e}", "error")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    
    print("\n" + "="*60)
    if success:
        print("✅ Verification completed. Check the report above for details.")
    else:
        print("❌ Verification failed. Please check the errors above.")
    
    print("📚 For help, check:")
    print("   • INSTALLATION_GUIDE.md - Complete installation instructions")
    print("   • TROUBLESHOOTING.md - Common issues and solutions")
    print("   • GitHub Issues - https://github.com/threatpointer/ShadowSeek/issues")
    
    input("\nPress Enter to exit...")
    sys.exit(0 if success else 1)