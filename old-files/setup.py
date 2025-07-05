#!/usr/bin/env python3
"""
Setup script for Ghidra Web Analyzer
Handles UV installation and project setup
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

# Configuration
PROJECT_ROOT = Path(__file__).parent
GHIDRA_DEFAULT_PATH = {
    'Windows': r'D:\1132-Ghidra\ghidra_11.3.2_PUBLIC',
    'Linux': '/opt/ghidra',
    'Darwin': '/Applications/ghidra'
}

def run_command(command, check=True, shell=True):
    """Run a command and return the result"""
    print(f"Running: {command}")
    try:
        result = subprocess.run(
            command, 
            shell=shell, 
            check=check, 
            capture_output=True, 
            text=True
        )
        if result.stdout:
            print(result.stdout)
        return result
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        if check:
            sys.exit(1)
        return e

def check_uv_installed():
    """Check if UV is installed"""
    try:
        result = run_command("uv --version", check=False)
        if result.returncode == 0:
            print(f"UV is installed: {result.stdout.strip()}")
            return True
        else:
            return False
    except FileNotFoundError:
        return False

def install_uv():
    """Install UV package manager"""
    print("Installing UV package manager...")
    
    system = platform.system()
    if system in ['Linux', 'Darwin']:  # Linux or macOS
        command = 'curl -LsSf https://astral.sh/uv/install.sh | sh'
    elif system == 'Windows':
        command = 'powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"'
    else:
        print(f"Unsupported system: {system}")
        print("Please install UV manually: https://github.com/astral-sh/uv")
        sys.exit(1)
    
    result = run_command(command, check=False)
    if result.returncode != 0:
        print("Failed to install UV via installer. Trying pip...")
        run_command("pip install uv")

def setup_python_environment():
    """Set up Python environment with UV"""
    print("Setting up Python environment...")
    
    # Create virtual environment
    run_command("uv venv")
    
    # Install dependencies
    run_command("uv pip install -e .")
    
    print("Python environment setup complete!")

def setup_frontend():
    """Set up React frontend"""
    print("Setting up React frontend...")
    
    frontend_dir = PROJECT_ROOT / "frontend"
    if not frontend_dir.exists():
        print("Frontend directory not found, skipping frontend setup")
        return
    
    os.chdir(frontend_dir)
    
    # Check if npm is installed
    try:
        run_command("npm --version", check=False)
    except FileNotFoundError:
        print("npm not found. Please install Node.js and npm first.")
        return
    
    # Install dependencies
    run_command("npm install")
    
    print("Frontend setup complete!")
    os.chdir(PROJECT_ROOT)

def create_env_file():
    """Create .env file from template"""
    env_file = PROJECT_ROOT / ".env"
    env_template = PROJECT_ROOT / "env_template.txt"
    
    if env_file.exists():
        print(".env file already exists, skipping creation")
        return
    
    if not env_template.exists():
        print("env_template.txt not found, cannot create .env file")
        return
    
    # Read template
    with open(env_template, 'r') as f:
        content = f.read()
    
    # Get Ghidra path
    system = platform.system()
    default_ghidra = GHIDRA_DEFAULT_PATH.get(system, '/opt/ghidra')
    
    print(f"\nGhidra installation path:")
    print(f"Default for {system}: {default_ghidra}")
    ghidra_path = input(f"Enter Ghidra path (press Enter for default): ").strip()
    
    if not ghidra_path:
        ghidra_path = default_ghidra
    
    # Replace placeholder
    content = content.replace('D:\\1132-Ghidra\\ghidra_11.3.2_PUBLIC', ghidra_path)
    
    # Write .env file
    with open(env_file, 'w') as f:
        f.write(content)
    
    print(f".env file created with Ghidra path: {ghidra_path}")

def setup_directories():
    """Create necessary directories"""
    directories = [
        'uploads',
        'logs',
        'temp',
        'instance'
    ]
    
    for directory in directories:
        dir_path = PROJECT_ROOT / directory
        dir_path.mkdir(exist_ok=True)
        print(f"Created directory: {directory}")

def test_installation():
    """Test the installation"""
    print("\nTesting installation...")
    
    # Test Python imports
    try:
        import flask
        import sqlalchemy
        print("✓ Python dependencies imported successfully")
    except ImportError as e:
        print(f"✗ Python import error: {e}")
        return False
    
    # Check if Ghidra path exists
    env_file = PROJECT_ROOT / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv()
            ghidra_path = os.getenv('GHIDRA_INSTALL_PATH')
            if ghidra_path and Path(ghidra_path).exists():
                print(f"✓ Ghidra path exists: {ghidra_path}")
            else:
                print(f"⚠ Ghidra path not found: {ghidra_path}")
        except Exception as e:
            print(f"⚠ Could not check Ghidra path: {e}")
    
    print("\nInstallation test complete!")
    return True

def print_usage():
    """Print usage information"""
    print("\n" + "="*60)
    print("GHIDRA WEB ANALYZER - SETUP COMPLETE")
    print("="*60)
    print("\n🚀 To start the application:")
    print("\n1. Start the application:")
    print("   start.bat (Windows) or ./start.sh (Linux/Mac)")
    print("\n📝 Configuration:")
    print("   - Edit .env file to configure paths and settings")
    print("   - Ghidra path can be changed in web interface")
    print("\n🌐 Access the application:")
    print("   - Web UI: http://localhost:3000")
    print("   - API: http://localhost:5000")
    print("\n" + "="*60)

def main():
    """Main setup function"""
    print("Ghidra Web Analyzer Setup Script")
    print("=================================")
    
    # Check if UV is installed
    if not check_uv_installed():
        print("UV not found, installing...")
        install_uv()
    
    # Setup Python environment
    setup_python_environment()
    
    # Create directories
    setup_directories()
    
    # Create .env file
    create_env_file()
    
    # Setup frontend
    setup_frontend()
    
    # Test installation
    if test_installation():
        print_usage()
    else:
        print("⚠ Installation test failed. Please check the errors above.")

if __name__ == "__main__":
    main() 