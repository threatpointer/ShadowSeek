#!/usr/bin/env python3
"""
Enhanced ShadowSeek Environment Setup Script
Addresses common installation issues and provides better user guidance

Key Improvements:
- Better prerequisite detection with fallback options
- Enhanced error messages with specific next steps
- Improved Ghidra validation logic
- Robust service startup verification
- Comprehensive manual installation guidance
"""

import os
import sys
import subprocess
import platform
import time
import socket
import argparse
import json
import urllib.request
import urllib.parse
import ssl
import zipfile
import tarfile
import tempfile
import shutil
from pathlib import Path

# Windows-specific imports
try:
    import winreg
    WINREG_AVAILABLE = True
except ImportError:
    WINREG_AVAILABLE = False

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
    """Print formatted status message with enhanced visuals"""
    if platform.system() == "Windows":
        icons = {"success": "✅", "error": "❌", "warning": "⚠️", "info": "ℹ️", "step": "🔧", "download": "📥"}
        icon = icons.get(status, "•")
        print(f"{icon} {message}")
        if detail:
            print(f"   {detail}")
    else:
        colors = {
            "success": Colors.GREEN,
            "error": Colors.RED, 
            "warning": Colors.YELLOW,
            "info": Colors.BLUE,
            "step": Colors.PURPLE,
            "download": Colors.CYAN
        }
        icons = {"success": "✅", "error": "❌", "warning": "⚠️", "info": "ℹ️", "step": "🔧", "download": "📥"}
        color = colors.get(status, Colors.WHITE)
        icon = icons.get(status, "•")
        print(f"{color}{icon} {message}{Colors.RESET}")
        if detail:
            print(f"   {detail}")

def print_header(title):
    """Print a prominent header"""
    print(f"\n{'='*80}")
    print(f"  🚀 {title}")
    print('='*80)

def print_step(step_num, title):
    """Print a step header with enhanced formatting"""
    print(f"\n[{step_num}] 🔧 {title}")
    print("-" * 60)

def print_manual_instructions(component, instructions):
    """Print manual installation instructions in a clear format"""
    print_status(f"Manual Installation Required: {component}", "warning")
    print("📋 Please follow these steps:")
    for i, instruction in enumerate(instructions, 1):
        print(f"   {i}. {instruction}")
    print()

def run_command(cmd, cwd=None, check=True, capture_output=True, timeout=None):
    """Enhanced command runner with better error handling"""
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
        return None
    except FileNotFoundError:
        print_status(f"Command not found: {cmd[0] if cmd else 'Unknown'}", "error")
        return None
    except Exception as e:
        print_status(f"Command failed: {e}", "error")
        return None

def check_system_requirements_enhanced():
    """Enhanced system requirements check with better guidance"""
    print_step(1, "System Requirements Check")
    
    requirements = {
        "python": {"version": sys.version_info, "required": (3, 8), "status": False},
        "node": {"version": None, "required": "16+", "status": False},
        "java": {"version": None, "required": "11+", "status": False},
        "git": {"version": None, "required": "any", "status": False, "optional": True},
        "uv": {"version": None, "required": "any", "status": False, "optional": True}
    }
    
    # Check Python
    if requirements["python"]["version"] >= requirements["python"]["required"]:
        print_status(f"Python {'.'.join(map(str, requirements['python']['version'][:3]))}", "success")
        requirements["python"]["status"] = True
    else:
        print_status(f"Python {'.'.join(map(str, requirements['python']['version'][:3]))} - need 3.8+", "error")
    
    # Check Node.js with enhanced detection
    requirements["node"]["status"], requirements["node"]["version"] = check_nodejs_enhanced()
    
    # Check Java with enhanced detection
    requirements["java"]["status"], requirements["java"]["version"] = check_java_enhanced()
    
    # Check Git (optional)
    requirements["git"]["status"], requirements["git"]["version"] = check_git_enhanced()
    
    # Check uv (optional but recommended)
    requirements["uv"]["status"], requirements["uv"]["version"] = check_uv_enhanced()
    
    return requirements

def check_uv_enhanced():
    """Enhanced uv detection"""
    try:
        result = run_command(["uv", "--version"], check=False, timeout=10)
        if result and result.returncode == 0:
            version = result.stdout.strip()
            print_status(f"uv {version} ✓ (recommended for faster installs)", "success")
            return True, version
    except Exception as e:
        pass
    
    print_status("uv not found (optional - faster Python package installs)", "info")
    print_status("Install with: pip install uv", "info")
    return False, None

def check_nodejs_enhanced():
    """Enhanced Node.js detection with better error reporting"""
    try:
        result = run_command(["node", "--version"], check=False, timeout=10)
        if result and result.returncode == 0:
            version = result.stdout.strip()
            major_version = int(version.replace('v', '').split('.')[0])
            if major_version >= 16:
                print_status(f"Node.js {version} ✓", "success")
                
                # Check npm
                npm_result = run_command(["npm", "--version"], check=False, timeout=10)
                if npm_result and npm_result.returncode == 0:
                    print_status(f"npm {npm_result.stdout.strip()} ✓", "success")
                    return True, version
                else:
                    print_status("npm not found - will try to install during frontend setup", "warning")
                    # Node.js is installed but npm is missing - this is a partial success
                    return True, version
            else:
                print_status(f"Node.js {version} - need v16+", "error")
                return False, version
    except Exception as e:
        pass
    
    print_status("Node.js not found", "error")
    return False, None

def fix_npm_installation():
    """Try to fix npm installation issues"""
    print_status("Attempting to fix npm installation...", "info")
    
    # Common npm fix approaches
    fixes = [
        # Try to install npm globally 
        (["npm", "install", "-g", "npm@latest"], "Updating npm to latest version"),
        # Try to reinstall npm using Node.js installer approach
        (["node", "-e", "console.log('Node.js is working')"], "Verifying Node.js functionality"),
    ]
    
    for cmd, description in fixes:
        try:
            print_status(description, "info")
            result = run_command(cmd, timeout=60)
            if result and result.returncode == 0:
                # Test if npm works now
                npm_test = run_command(["npm", "--version"], check=False, timeout=10)
                if npm_test and npm_test.returncode == 0:
                    print_status("npm fixed successfully", "success")
                    return True
        except Exception as e:
            continue
    
    print_status("Could not automatically fix npm", "warning")
    print_status("npm should have been installed with Node.js", "info")
    print_status("Try restarting your command prompt or reinstalling Node.js", "info")
    return False

def check_java_enhanced():
    """Enhanced Java detection with better version parsing"""
    try:
        result = run_command(["java", "-version"], check=False, timeout=10)
        if result and result.returncode == 0:
            java_output = result.stderr + result.stdout
            
            # Parse version - handle both old and new version formats
            import re
            version_patterns = [
                r'version "(\d+)\.(\d+)',  # Old format: 1.8.0
                r'version "(\d+)',         # New format: 11, 17, etc.
            ]
            
            for pattern in version_patterns:
                version_match = re.search(pattern, java_output)
                if version_match:
                    if len(version_match.groups()) == 2:
                        major, minor = version_match.groups()
                        java_version = int(major) if int(major) >= 9 else int(minor)
                    else:
                        java_version = int(version_match.group(1))
                    
                    if java_version >= 11:
                        print_status(f"Java {java_version} ✓", "success")
                        
                        # Check if JDK is available
                        javac_result = run_command(["javac", "-version"], check=False, timeout=10)
                        if javac_result and javac_result.returncode == 0:
                            print_status("JDK available (with javac) ✓", "success")
                        else:
                            print_status("JRE only (sufficient for Ghidra)", "info")
                        
                        return True, str(java_version)
                    else:
                        print_status(f"Java {java_version} - need 11+", "error")
                        return False, str(java_version)
    except Exception as e:
        pass
    
    print_status("Java not found", "error")
    return False, None

def check_git_enhanced():
    """Enhanced Git detection"""
    try:
        result = run_command(["git", "--version"], check=False, timeout=10)
        if result and result.returncode == 0:
            version = result.stdout.strip()
            print_status(f"{version} ✓", "success")
            return True, version
    except Exception as e:
        pass
    
    print_status("Git not found (optional)", "info")
    return False, None

def create_ssl_context(verify_ssl=True):
    """Create SSL context with optional certificate verification bypass"""
    if verify_ssl:
        return ssl.create_default_context()
    else:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        print_status("⚠️ SSL certificate verification disabled", "warning")
        return context

def download_file_with_ssl_fallback(url, filename, description="file"):
    """Download a file with SSL fallback for corporate environments"""
    print_status(f"Downloading {description}...", "download")
    
    # Try with SSL verification first
    if _attempt_download(url, filename, description, verify_ssl=True):
        return True
    
    # If that fails, try without SSL verification (common in corporate environments)
    print_status("SSL verification failed, trying without SSL verification...", "warning")
    print_status("This is common in corporate environments with proxy/firewall", "info")
    
    if _attempt_download(url, filename, description, verify_ssl=False):
        return True
    
    # If both fail, provide manual download guidance
    print_status(f"Automatic download failed for {description}", "error")
    print_status("This may be due to network restrictions or corporate policies", "info")
    print_status(f"Please manually download from: {url}", "info")
    print_status(f"Save to: {filename}", "info")
    
    return False

def _attempt_download(url, filename, description, verify_ssl=True):
    """Attempt to download a file with the specified SSL settings"""
    try:
        context = create_ssl_context(verify_ssl)
        
        # Create request with custom SSL context
        request = urllib.request.Request(url)
        request.add_header('User-Agent', 'ShadowSeek-Setup/1.0')
        
        with urllib.request.urlopen(request, context=context, timeout=60) as response:
            total_size = int(response.headers.get('content-length', 0))
            
            with open(filename, 'wb') as f:
                block_size = 8192
                downloaded = 0
                last_percent = 0
                
                while True:
                    block = response.read(block_size)
                    if not block:
                        break
                    f.write(block)
                    downloaded += len(block)
                    
                    # Show progress (avoid duplicates)
                    if total_size > 0:
                        percent = min(100, (downloaded * 100) // total_size)
                        if percent >= last_percent + 20 and percent > 0:  # Show every 20% increment
                            print(f"   Progress: {percent}%")
                            last_percent = percent
        
        print_status(f"Downloaded {description} successfully", "success")
        return True
        
    except ssl.SSLError as e:
        print_status(f"SSL Error: {e}", "error")
        return False
    except urllib.error.URLError as e:
        print_status(f"Network Error: {e}", "error")
        return False
    except Exception as e:
        print_status(f"Download Error: {e}", "error")
        return False

# Keep the old function name for compatibility
download_file = download_file_with_ssl_fallback

def install_nodejs_automatically():
    """Automatically install Node.js from official nodejs.org"""
    system = platform.system()
    
    print_status("🚀 Automatic Node.js Installation", "step")
    print_status("Using official nodejs.org installer", "info")
    
    try:
        if system == "Windows":
            # Use Node.js official Windows installer
            print_status("Detecting system architecture...", "info")
            arch = "x64" if platform.machine().endswith('64') else "x86"
            
            # Get latest LTS version info from Node.js API
            print_status("Getting latest Node.js LTS version...", "info")
            try:
                context = create_ssl_context(verify_ssl=True)
                try:
                    with urllib.request.urlopen("https://nodejs.org/dist/index.json", context=context, timeout=30) as response:
                        releases = json.loads(response.read().decode())
                        lts_release = next((r for r in releases if r.get('lts')), releases[0])
                        version = lts_release['version']
                        print_status(f"Latest LTS version: {version}", "success")
                except ssl.SSLError:
                    # Try without SSL verification
                    context = create_ssl_context(verify_ssl=False)
                    with urllib.request.urlopen("https://nodejs.org/dist/index.json", context=context, timeout=30) as response:
                        releases = json.loads(response.read().decode())
                        lts_release = next((r for r in releases if r.get('lts')), releases[0])
                        version = lts_release['version']
                        print_status(f"Latest LTS version: {version}", "success")
            except Exception as e:
                version = "v20.10.0"  # Fallback to known good version
                print_status(f"API lookup failed, using fallback: {version}", "warning")
            
            # Download installer
            installer_url = f"https://nodejs.org/dist/{version}/node-{version}-{arch}.msi"
            installer_path = Path(tempfile.gettempdir()) / f"nodejs-{version}-installer.msi"
            
            if download_file(installer_url, installer_path, f"Node.js {version} installer"):
                print_status("Running Node.js installer...", "info")
                print_status("Please follow the installer prompts (accept defaults)", "info")
                
                # Run the installer
                result = subprocess.run([
                    "msiexec", "/i", str(installer_path), "/passive", "/norestart"
                ], capture_output=False)
                
                if result.returncode == 0:
                    print_status("Node.js installer completed", "success")
                    
                    # Clean up
                    try:
                        installer_path.unlink()
                    except:
                        pass
                    
                    print_status("Please restart your command prompt and run the setup again", "info")
                    print_status("This is required for PATH changes to take effect", "warning")
                    return True
                else:
                    print_status("Node.js installation may have failed", "warning")
                    return False
            
        elif system == "Darwin":  # macOS
            # Use Node.js official macOS installer
            print_status("Getting latest Node.js LTS version...", "info")
            try:
                with urllib.request.urlopen("https://nodejs.org/dist/index.json", timeout=30) as response:
                    releases = json.loads(response.read().decode())
                    lts_release = next((r for r in releases if r.get('lts')), releases[0])
                    version = lts_release['version']
                    print_status(f"Latest LTS version: {version}", "success")
            except:
                version = "v20.10.0"
                print_status(f"Using fallback version: {version}", "warning")
            
            installer_url = f"https://nodejs.org/dist/{version}/node-{version}.pkg"
            installer_path = Path(tempfile.gettempdir()) / f"nodejs-{version}-installer.pkg"
            
            if download_file(installer_url, installer_path, f"Node.js {version} installer"):
                print_status("Running Node.js installer...", "info")
                result = subprocess.run(["open", str(installer_path)], capture_output=False)
                
                if result.returncode == 0:
                    print_status("Node.js installer opened", "success")
                    print_status("Please follow the installer prompts", "info")
                    return True
        
        else:  # Linux
            print_status("Linux detected - using NodeSource repository", "info")
            print_status("This will install Node.js LTS using the official NodeSource setup", "info")
            
            # Use NodeSource setup script (official method)
            try:
                # Download and run NodeSource setup
                setup_script = "https://deb.nodesource.com/setup_lts.x"
                result = subprocess.run([
                    "curl", "-fsSL", setup_script, "|", "sudo", "-E", "bash", "-"
                ], shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    print_status("NodeSource repository configured", "success")
                    
                    # Install Node.js
                    result2 = subprocess.run([
                        "sudo", "apt-get", "install", "-y", "nodejs"
                    ], capture_output=True, text=True)
                    
                    if result2.returncode == 0:
                        print_status("Node.js installed successfully", "success")
                        return True
                    else:
                        print_status("Node.js installation failed", "error")
                        return False
                else:
                    print_status("Failed to configure NodeSource repository", "error")
                    return False
            except Exception as e:
                print_status(f"Linux installation failed: {e}", "error")
                return False
                
    except Exception as e:
        print_status(f"Automatic installation failed: {e}", "error")
        print_status("Please install manually using the provided instructions", "info")
        return False
    
    return False

def install_java_automatically():
    """Automatically install Java JDK from Eclipse Adoptium (official Temurin)"""
    system = platform.system()
    
    print_status("🚀 Automatic Java JDK Installation", "step")
    print_status("Using official Eclipse Adoptium (Temurin) installer", "info")
    
    try:
        if system == "Windows":
            # Use Eclipse Adoptium official installer
            print_status("Detecting system architecture...", "info")
            arch = "x64" if platform.machine().endswith('64') else "x32"
            
            # Get latest JDK 17 (LTS) from Adoptium API
            print_status("Getting latest JDK 17 LTS release...", "info")
            try:
                api_url = f"https://api.adoptium.net/v3/assets/latest/17/hotspot?architecture={arch}&image_type=jdk&os=windows&vendor=eclipse"
                context = create_ssl_context(verify_ssl=True)
                try:
                    with urllib.request.urlopen(api_url, context=context, timeout=30) as response:
                        releases = json.loads(response.read().decode())
                        if releases:
                            download_url = releases[0]['binary']['package']['link']
                            version_data = releases[0]['version_data']
                            version = f"{version_data['major']}.{version_data['minor']}.{version_data['security']}"
                            print_status(f"Latest JDK 17 version: {version}", "success")
                        else:
                            raise Exception("No releases found")
                except ssl.SSLError:
                    # Try without SSL verification
                    context = create_ssl_context(verify_ssl=False)
                    with urllib.request.urlopen(api_url, context=context, timeout=30) as response:
                        releases = json.loads(response.read().decode())
                        if releases:
                            download_url = releases[0]['binary']['package']['link']
                            version_data = releases[0]['version_data']
                            version = f"{version_data['major']}.{version_data['minor']}.{version_data['security']}"
                            print_status(f"Latest JDK 17 version: {version}", "success")
                        else:
                            raise Exception("No releases found")
            except Exception as e:
                # API lookup failed - provide manual installation guidance instead
                print_status(f"API lookup failed: {e}", "warning")
                print_status("Unable to determine latest JDK version automatically", "error")
                print_status("Please install Java JDK manually:", "info")
                print_status("1. Visit https://adoptium.net/temurin/releases/", "info")
                print_status("2. Select JDK 17 (LTS) → Windows → x64", "info")
                print_status("3. Download and run the .msi installer", "info")
                return False
            
            # Download installer
            installer_path = Path(tempfile.gettempdir()) / f"adoptium-jdk17-{version}-installer.msi"
            
            if download_file(download_url, installer_path, f"Java JDK {version} installer"):
                print_status("Running Java JDK installer...", "info")
                print_status("The installer will add Java to PATH automatically", "info")
                
                # Run the installer
                result = subprocess.run([
                    "msiexec", "/i", str(installer_path), "/passive", "/norestart",
                    "ADDLOCAL=FeatureMain,FeatureEnvironment,FeatureJarFileRunWith,FeatureJavaHome"
                ], capture_output=False)
                
                if result.returncode == 0:
                    print_status("Java JDK installer completed", "success")
                    
                    # Clean up
                    try:
                        installer_path.unlink()
                    except:
                        pass
                    
                    print_status("Please restart your command prompt and run the setup again", "info")
                    print_status("This is required for PATH changes to take effect", "warning")
                    return True
                else:
                    print_status("Java JDK installation may have failed", "warning")
                    return False
        
        elif system == "Darwin":  # macOS
            print_status("Getting latest JDK 17 LTS release...", "info")
            try:
                api_url = "https://api.adoptium.net/v3/assets/latest/17/hotspot?architecture=x64&image_type=jdk&os=mac&vendor=eclipse"
                with urllib.request.urlopen(api_url, timeout=30) as response:
                    releases = json.loads(response.read().decode())
                    if releases:
                        download_url = releases[0]['binary']['package']['link']
                        version_data = releases[0]['version_data']
                        version = f"{version_data['major']}.{version_data['minor']}.{version_data['security']}"
                        print_status(f"Latest JDK 17 version: {version}", "success")
                    else:
                        raise Exception("No releases found")
            except:
                download_url = "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.9%2B9/OpenJDK17U-jdk_x64_mac_hotspot_17.0.9_9.pkg"
                version = "17.0.9"
            
            installer_path = Path(tempfile.gettempdir()) / f"adoptium-jdk17-{version}-installer.pkg"
            
            if download_file(download_url, installer_path, f"Java JDK {version} installer"):
                print_status("Running Java JDK installer...", "info")
                result = subprocess.run(["open", str(installer_path)], capture_output=False)
                
                if result.returncode == 0:
                    print_status("Java JDK installer opened", "success")
                    print_status("Please follow the installer prompts", "info")
                    return True
        
        else:  # Linux
            print_status("Linux detected - installing via package manager", "info")
            
            # Try apt first (Ubuntu/Debian)
            try:
                print_status("Updating package lists...", "info")
                result1 = subprocess.run(["sudo", "apt", "update"], capture_output=True, text=True)
                
                if result1.returncode == 0:
                    print_status("Installing OpenJDK 17...", "info")
                    result2 = subprocess.run([
                        "sudo", "apt", "install", "-y", "openjdk-17-jdk"
                    ], capture_output=True, text=True)
                    
                    if result2.returncode == 0:
                        print_status("Java JDK 17 installed successfully", "success")
                        return True
                    else:
                        print_status("apt installation failed, trying yum...", "warning")
                        
                        # Try yum (CentOS/RHEL)
                        result3 = subprocess.run([
                            "sudo", "yum", "install", "-y", "java-17-openjdk-devel"
                        ], capture_output=True, text=True)
                        
                        if result3.returncode == 0:
                            print_status("Java JDK 17 installed successfully via yum", "success")
                            return True
                        else:
                            print_status("Package manager installation failed", "error")
                            return False
                else:
                    print_status("Failed to update package lists", "error")
                    return False
                    
            except Exception as e:
                print_status(f"Linux installation failed: {e}", "error")
                return False
                
    except Exception as e:
        print_status(f"Automatic installation failed: {e}", "error")
        print_status("Please install manually using the provided instructions", "info")
        return False
    
    return False

def install_git_automatically():
    """Automatically install Git from official git-scm.com"""
    system = platform.system()
    
    print_status("🚀 Automatic Git Installation", "step")
    print_status("Using official git-scm.com installer", "info")
    
    try:
        if system == "Windows":
            # Use Git for Windows official installer
            print_status("Detecting system architecture...", "info")
            arch = "64" if platform.machine().endswith('64') else "32"
            
            # Get latest Git version
            print_status("Getting latest Git version...", "info")
            try:
                # Use GitHub API to get latest release
                api_url = "https://api.github.com/repos/git-for-windows/git/releases/latest"
                context = create_ssl_context(verify_ssl=True)
                try:
                    with urllib.request.urlopen(api_url, context=context, timeout=30) as response:
                        release_data = json.loads(response.read().decode())
                        version = release_data['tag_name'].replace('v', '').replace('.windows.1', '')
                        
                        # Find the right installer
                        installer_asset = None
                        for asset in release_data['assets']:
                            if f"Git-{version}-{arch}-bit.exe" in asset['name']:
                                installer_asset = asset
                                break
                        
                        if installer_asset:
                            download_url = installer_asset['browser_download_url']
                            print_status(f"Latest Git version: {version}", "success")
                        else:
                            raise Exception("Installer not found")
                except ssl.SSLError:
                    # Try without SSL verification
                    context = create_ssl_context(verify_ssl=False)
                    with urllib.request.urlopen(api_url, context=context, timeout=30) as response:
                        release_data = json.loads(response.read().decode())
                        version = release_data['tag_name'].replace('v', '').replace('.windows.1', '')
                        
                        # Find the right installer
                        installer_asset = None
                        for asset in release_data['assets']:
                            if f"Git-{version}-{arch}-bit.exe" in asset['name']:
                                installer_asset = asset
                                break
                        
                        if installer_asset:
                            download_url = installer_asset['browser_download_url']
                            print_status(f"Latest Git version: {version}", "success")
                        else:
                            raise Exception("Installer not found")
                        
            except Exception as e:
                # Fallback
                print_status(f"API lookup failed, using fallback: {e}", "warning")
                version = "2.42.0"
                download_url = f"https://github.com/git-for-windows/git/releases/download/v{version}.windows.1/Git-{version}-{arch}-bit.exe"
            
            # Download installer
            installer_path = Path(tempfile.gettempdir()) / f"Git-{version}-installer.exe"
            
            if download_file(download_url, installer_path, f"Git {version} installer"):
                print_status("Running Git installer...", "info")
                print_status("Using silent installation with recommended settings", "info")
                
                # Run installer with silent options
                result = subprocess.run([
                    str(installer_path), "/VERYSILENT", "/NORESTART", "/NOCANCEL",
                    "/SP-", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS",
                    "/COMPONENETS='icons,ext\\reg\\shellhere,assoc,assoc_sh'"
                ], capture_output=False)
                
                if result.returncode == 0:
                    print_status("Git installer completed", "success")
                    
                    # Clean up
                    try:
                        installer_path.unlink()
                    except:
                        pass
                    
                    print_status("Please restart your command prompt and run the setup again", "info")
                    return True
                else:
                    print_status("Git installation may have failed", "warning")
                    return False
        
        elif system == "Darwin":  # macOS
            print_status("macOS detected - Git is usually pre-installed or available via Xcode", "info")
            print_status("Trying to install Xcode command line tools...", "info")
            
            result = subprocess.run(["xcode-select", "--install"], capture_output=True, text=True)
            if result.returncode == 0:
                print_status("Xcode command line tools installation started", "success")
                print_status("Please follow the prompts to complete installation", "info")
                return True
            else:
                print_status("Please install Git manually from https://git-scm.com/", "info")
                return False
                
        else:  # Linux
            print_status("Linux detected - installing via package manager", "info")
            
            try:
                # Try apt first
                result1 = subprocess.run(["sudo", "apt", "update"], capture_output=True, text=True)
                if result1.returncode == 0:
                    result2 = subprocess.run(["sudo", "apt", "install", "-y", "git"], capture_output=True, text=True)
                    if result2.returncode == 0:
                        print_status("Git installed successfully via apt", "success")
                        return True
                
                # Try yum
                result3 = subprocess.run(["sudo", "yum", "install", "-y", "git"], capture_output=True, text=True)
                if result3.returncode == 0:
                    print_status("Git installed successfully via yum", "success")
                    return True
                    
                print_status("Package manager installation failed", "error")
                return False
                
            except Exception as e:
                print_status(f"Linux installation failed: {e}", "error")
                return False
                
    except Exception as e:
        print_status(f"Automatic installation failed: {e}", "error")
        return False
    
    return False

def provide_installation_guidance(requirements, attempted_auto_install=False):
    """Provide installation options including automatic installation from official sources"""
    system = platform.system()
    missing_required = []
    
    for name, req in requirements.items():
        if not req["status"] and not req.get("optional", False):
            missing_required.append(name)
    
    if not missing_required:
        print_status("All required components found!", "success")
        return True
    
    print_status(f"Missing required components: {', '.join(missing_required)}", "warning")
    
    # If we haven't attempted automatic installation yet, offer it
    if not attempted_auto_install:
        # Detect if we're in a corporate/restricted environment
        corporate_environment = detect_corporate_environment()
        if corporate_environment:
            print_status("🏢 Corporate Environment Detected", "info")
            print_status("Automatic downloads may be restricted by proxy/firewall", "warning")
            print_status("You may need to download installers manually", "info")
            print()
        
        print_status("🤖 Automatic Installation Available!", "step")
        print_status("I can automatically install missing components using official sources:", "info")
        
        for component in missing_required:
            if component == "node":
                print_status("  • Node.js: Official installer from nodejs.org", "info")
            elif component == "java":
                print_status("  • Java JDK: Official Eclipse Adoptium (Temurin) installer", "info")
            elif component == "git":
                print_status("  • Git: Official installer from git-scm.com", "info")
        
        try:
            choice = input("\n🤖 Would you like to automatically install missing components? (y/n): ").strip().lower()
            
            if choice in ['y', 'yes']:
                return attempt_automatic_installation(missing_required, requirements, system)
            else:
                print_status("Proceeding with manual installation instructions", "info")
        
        except (KeyboardInterrupt, EOFError):
            print_status("Installation cancelled", "warning")
            return False
    
    # Provide manual instructions
    print_manual_installation_instructions(missing_required, system)
    return False

def detect_corporate_environment():
    """Detect if we're likely in a corporate environment with network restrictions"""
    indicators = []
    
    # Check for common corporate proxy environment variables
    proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
    for var in proxy_vars:
        if os.environ.get(var):
            indicators.append(f"Proxy detected: {var}")
    
    # Check for common corporate domains in environment
    domain_vars = ['USERDNSDOMAIN', 'LOGONSERVER']
    for var in domain_vars:
        if os.environ.get(var):
            indicators.append(f"Domain environment: {var}")
    
    return len(indicators) > 0

def check_admin_privileges():
    """Check if script is running with administrator privileges (Windows)"""
    if platform.system() != "Windows":
        return True  # Assume sufficient privileges on non-Windows
    
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def warn_about_privileges():
    """Warn user about potential privilege issues"""
    if platform.system() == "Windows" and not check_admin_privileges():
        print_status("⚠️ Running without Administrator privileges", "warning")
        print_status("Some automatic installations may fail", "info")
        print_status("Consider running as Administrator if installations fail", "info")
        print()

def install_bridge_server_scripts():
    """
    Install official ghidra_bridge server scripts to enable bridge functionality
    """
    print_status("Installing Ghidra Bridge server scripts...", "info")
    
    try:
        # Create ghidra_scripts directory if it doesn't exist
        scripts_dir = Path("ghidra_scripts")
        scripts_dir.mkdir(exist_ok=True)
        
        # Use the same Python executable that's running this script
        python_exe = get_python_executable()
        
        # Install ghidra_bridge server scripts
        print_status("Running: python -m ghidra_bridge.install_server", "info")
        
        result = subprocess.run([
            python_exe, "-m", "ghidra_bridge.install_server", "ghidra_scripts"
        ], capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0:
            print_status("Ghidra Bridge server scripts installed successfully", "success")
            
            # Verify key files were installed
            key_files = [
                "ghidra_scripts/jfx_bridge/bridge.py",
                "ghidra_scripts/ghidra_bridge_server.py"
            ]
            
            all_found = True
            for file_path in key_files:
                if Path(file_path).exists():
                    print_status(f"✅ {file_path}", "success")
                else:
                    print_status(f"❌ {file_path}", "error")
                    all_found = False
            
            if all_found:
                print_status("All bridge server components installed correctly", "success")
                return True
            else:
                print_status("Some bridge server components are missing", "warning")
                return False
                
        else:
            print_status("Failed to install Ghidra Bridge server scripts", "error")
            if result.stderr:
                print_status(f"Error: {result.stderr.strip()}", "error")
            return False
            
    except subprocess.TimeoutExpired:
        print_status("Bridge server installation timed out", "error")
        return False
    except Exception as e:
        print_status(f"Error installing bridge server scripts: {e}", "error")
        return False

def refresh_environment_variables():
    """Refresh environment variables to detect newly installed software"""
    if platform.system() != "Windows" or not WINREG_AVAILABLE:
        print_status("Environment refresh not needed on this platform", "info")
        return True
    
    try:
        print_status("🔄 Refreshing environment variables...", "step")
        
        # Read the current PATH from the registry (system and user)
        system_path = ""
        user_path = ""
        
        # Get system PATH
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                              r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as key:
                system_path, _ = winreg.QueryValueEx(key, "PATH")
                print_status("Retrieved system PATH from registry", "info")
        except Exception as e:
            print_status(f"Could not read system PATH: {e}", "warning")
        
        # Get user PATH
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
                user_path, _ = winreg.QueryValueEx(key, "PATH")
                print_status("Retrieved user PATH from registry", "info")
        except Exception as e:
            print_status("No user PATH found (this is normal)", "info")
        
        # Combine paths
        if system_path and user_path:
            new_path = f"{system_path};{user_path}"
        elif system_path:
            new_path = system_path
        elif user_path:
            new_path = user_path
        else:
            print_status("No PATH found in registry", "warning")
            return False
        
        # Update the current process environment
        old_path = os.environ.get("PATH", "")
        os.environ["PATH"] = new_path
        
        print_status("Environment variables refreshed successfully", "success")
        
        # Check if any new paths were added
        old_paths = set(old_path.split(";"))
        new_paths = set(new_path.split(";"))
        added_paths = new_paths - old_paths
        
        if added_paths:
            print_status(f"Added {len(added_paths)} new PATH entries", "info")
            for path in sorted(added_paths):
                if path.strip():  # Skip empty paths
                    print_status(f"  + {path}", "info")
        else:
            print_status("No new PATH entries detected", "info")
        
        return True
        
    except Exception as e:
        print_status(f"Failed to refresh environment variables: {e}", "error")
        print_status("You may need to restart your command prompt", "warning")
        return False

def verify_commands_after_refresh():
    """Verify that newly installed commands can now be found"""
    print_status("🔍 Verifying command availability after refresh...", "step")
    
    commands_to_check = [
        ("node", "Node.js"),
        ("npm", "npm"),
        ("java", "Java"),
        ("git", "Git"),
        ("uv", "uv")
    ]
    
    found_commands = []
    still_missing = []
    
    for cmd, name in commands_to_check:
        try:
            result = run_command([cmd, "--version"], check=False, timeout=5)
            if result and result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]  # Get first line
                print_status(f"{name}: {version} ✓", "success")
                found_commands.append(name)
            else:
                print_status(f"{name}: Still not found", "warning")
                still_missing.append(name)
        except Exception:
            print_status(f"{name}: Still not found", "warning")
            still_missing.append(name)
    
    if found_commands:
        print_status(f"✅ Found after refresh: {', '.join(found_commands)}", "success")
    
    if still_missing:
        print_status(f"⚠️ Still missing: {', '.join(still_missing)}", "warning")
        print_status("These may require a command prompt restart", "info")
    
    return len(found_commands) > 0

def attempt_automatic_installation(missing_required, requirements, system):
    """Attempt automatic installation of missing components"""
    print_status("🚀 Starting automatic installation...", "step")
    
    # Check privileges and warn if needed
    warn_about_privileges()
    
    installation_results = {}
    
    if "node" in missing_required:
        print_status("Installing Node.js...", "info")
        installation_results["node"] = install_nodejs_automatically()
        if not installation_results["node"]:
            print_status("Node.js automatic installation failed", "error")
    
    if "java" in missing_required:
        print_status("Installing Java JDK...", "info")
        installation_results["java"] = install_java_automatically()
        if not installation_results["java"]:
            print_status("Java automatic installation failed", "error")
    
    if "git" in missing_required and not requirements["git"].get("optional", True):
        print_status("Installing Git...", "info")
        installation_results["git"] = install_git_automatically()
        if not installation_results["git"]:
            print_status("Git automatic installation failed (continuing anyway)", "warning")
    
    # Check results
    successful_installs = [comp for comp, success in installation_results.items() if success]
    failed_installs = [comp for comp, success in installation_results.items() if not success]
    
    if successful_installs:
        print_status(f"✅ Successfully installed: {', '.join(successful_installs)}", "success")
        
        # Refresh environment variables to detect newly installed software
        print_status("🔄 Refreshing environment to detect new installations...", "info")
        env_refreshed = refresh_environment_variables()
        
        if env_refreshed:
            # Verify what can now be found
            newly_available = verify_commands_after_refresh()
            
            if newly_available:
                print_status("🎉 New components are now available in this session!", "success")
                print_status("No need to restart your command prompt", "success")
            else:
                print_status("Environment refreshed, but some components may still require restart", "warning")
        else:
            print_status("Could not refresh environment automatically", "warning")
            print_status("Please restart your command prompt for changes to take effect", "info")
        
        if not failed_installs:
            print_status("✅ All components installed successfully!", "success")
            return True
    
    if failed_installs:
        print_status(f"⚠️ Failed to install: {', '.join(failed_installs)}", "warning")
        print_status("This is often due to network restrictions or corporate policies", "info")
        print_status("Please install these components manually using the instructions below", "info")
        print_manual_installation_instructions(failed_installs, platform.system())
    
    return len(failed_installs) == 0

def print_manual_installation_instructions(missing_required, system):
    """Print manual installation instructions for missing components"""
    print("\n📋 Manual Installation Instructions:")
    print_status("For immediate download links, visit these official sources:", "info")
    
    if "node" in missing_required:
        print_node_installation_guide(system)
    
    if "java" in missing_required:
        print_java_installation_guide(system)
    
    if "git" in missing_required:
        print_git_installation_guide(system)
    
    # Add additional guidance for corporate environments
    print_status("💡 Corporate Environment Tips:", "info")
    print("   • Contact IT support if downloads are blocked")
    print("   • Use internal software repositories if available")
    print("   • Consider portable versions if allowed by policy")
    print("   • VPN may be required for external downloads")
    print()
    print_status("📥 Direct Download Links (if needed):", "info")
    if "node" in missing_required:
        print("   Node.js: https://nodejs.org/en/download/")
    if "java" in missing_required:
        print("   Java JDK: https://adoptium.net/temurin/releases/")
    if "git" in missing_required:
        print("   Git: https://git-scm.com/download/win")
    print()
    print_status("After manual installation:", "info")
    print("   1. Restart your command prompt")
    print("   2. Run: python setup_environment_enhanced.py")
    print("   3. The script will detect the newly installed components")

def print_node_installation_guide(system):
    """Print Node.js installation guide"""
    print("\n🟨 Node.js Installation:")
    
    if system == "Windows":
        instructions = [
            "Visit https://nodejs.org/",
            "Download the Windows Installer (.msi)",
            "Run the installer with default settings",
            "Restart your command prompt after installation",
            "Verify with: node --version && npm --version"
        ]
    elif system == "Darwin":  # macOS
        instructions = [
            "Option 1 - Official installer:",
            "  • Visit https://nodejs.org/",
            "  • Download macOS Installer (.pkg)",
            "Option 2 - Homebrew (if available):",
            "  • Run: brew install node",
            "Verify with: node --version && npm --version"
        ]
    else:  # Linux
        instructions = [
            "Option 1 - Package manager:",
            "  • Ubuntu/Debian: sudo apt update && sudo apt install nodejs npm",
            "  • CentOS/RHEL: sudo yum install nodejs npm",
            "Option 2 - NodeSource repository:",
            "  • curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -",
            "  • sudo apt-get install -y nodejs",
            "Verify with: node --version && npm --version"
        ]
    
    print_manual_instructions("Node.js", instructions)

def print_java_installation_guide(system):
    """Print Java installation guide"""
    print("\n🟨 Java JDK Installation:")
    
    if system == "Windows":
        instructions = [
            "Visit https://adoptium.net/ (recommended)",
            "Select 'Latest LTS' → Windows → x64",
            "Download and run the .msi installer",
            "Choose 'Add to PATH' during installation",
            "Restart command prompt after installation",
            "Verify with: java -version"
        ]
    elif system == "Darwin":  # macOS
        instructions = [
            "Option 1 - Adoptium (recommended):",
            "  • Visit https://adoptium.net/",
            "  • Download macOS installer",
            "Option 2 - Homebrew:",
            "  • Run: brew install openjdk@17",
            "Verify with: java -version"
        ]
    else:  # Linux
        instructions = [
            "Option 1 - Package manager:",
            "  • Ubuntu/Debian: sudo apt install openjdk-17-jdk",
            "  • CentOS/RHEL: sudo yum install java-17-openjdk-devel",
            "Option 2 - SDKMAN:",
            "  • curl -s 'https://get.sdkman.io' | bash",
            "  • sdk install java 17.0.9-tem",
            "Verify with: java -version"
        ]
    
    print_manual_instructions("Java JDK", instructions)

def print_python_installation_guide(system):
    """Print Python installation guide"""
    print("\n🟨 Python 3.8+ Installation:")
    
    if system == "Windows":
        instructions = [
            "Visit https://python.org/downloads/",
            "Download Python 3.11 or newer",
            "Run installer and check 'Add Python to PATH'",
            "Verify with: python --version"
        ]
    elif system == "Darwin":  # macOS
        instructions = [
            "Visit https://python.org/downloads/",
            "Download macOS installer",
            "Or use Homebrew: brew install python@3.11"
        ]
    else:  # Linux
        instructions = [
            "Ubuntu/Debian: sudo apt install python3.11 python3.11-pip",
            "CentOS/RHEL: sudo yum install python3.11"
        ]
    
    print_manual_instructions("Python", instructions)

def print_git_installation_guide(system):
    """Print Git installation guide"""
    print("\n🟨 Git Installation:")
    
    if system == "Windows":
        instructions = [
            "Visit https://git-scm.com/download/win",
            "Download Git for Windows",
            "Run installer with default settings",
            "Verify with: git --version"
        ]
    elif system == "Darwin":  # macOS
        instructions = [
            "Option 1 - Xcode Command Line Tools:",
            "  • Run: xcode-select --install",
            "Option 2 - Official installer:",
            "  • Visit https://git-scm.com/download/mac",
            "Option 3 - Homebrew:",
            "  • Run: brew install git",
            "Verify with: git --version"
        ]
    else:  # Linux
        instructions = [
            "Ubuntu/Debian: sudo apt update && sudo apt install git",
            "CentOS/RHEL: sudo yum install git",
            "Arch Linux: sudo pacman -S git",
            "Verify with: git --version"
        ]
    
    print_manual_instructions("Git", instructions)

def validate_ghidra_path_enhanced(path):
    """Enhanced Ghidra validation with better error reporting"""
    if not path:
        print_status("No Ghidra path provided", "error")
        return False
        
    path_obj = Path(path)
    
    # Check if basic path exists
    if not path_obj.exists():
        print_status(f"Path does not exist: {path}", "error")
        print_status("Please verify the Ghidra installation path", "info")
        return False
    
    if not path_obj.is_dir():
        print_status(f"Path is not a directory: {path}", "error")
        return False
    
    print_status(f"Base path exists: {path}", "success")
    
    # Check for support directory
    support_dir = path_obj / "support"
    if not support_dir.exists():
        print_status("Missing 'support' directory", "error")
        print_status(f"Expected to find: {support_dir}", "info")
        
        # Show what's actually in the directory
        try:
            contents = [item.name for item in path_obj.iterdir() if item.is_dir()][:10]
            if contents:
                print_status(f"Available directories: {', '.join(contents)}", "info")
        except Exception:
            pass
        return False
    
    print_status("Support directory found", "success")
    
    # Enhanced validation - check for key Ghidra files
    validation_files = [
        ("ghidra.jar", "Core Ghidra JAR file"),
        ("analyzeHeadless.bat", "Headless analysis script (Windows)"),
        ("analyzeHeadless", "Headless analysis script (Unix)"),
        ("LaunchSupport.jar", "Launch support JAR")
    ]
    
    found_files = []
    for filename, description in validation_files:
        file_path = support_dir / filename
        if file_path.exists():
            found_files.append((filename, description))
            print_status(f"Found: {filename}", "success")
    
    # Determine if this is a valid Ghidra installation
    critical_files = ["ghidra.jar", "analyzeHeadless.bat", "analyzeHeadless"]
    has_critical = any(support_dir / f for f in critical_files if (support_dir / f).exists())
    
    if has_critical:
        print_status("Valid Ghidra installation detected", "success")
        return True
    else:
        print_status("No critical Ghidra files found", "error")
        print_status("This may not be a valid Ghidra installation", "warning")
        
        # Show what jar files are available
        jar_files = [f.name for f in support_dir.iterdir() if f.suffix.lower() == '.jar']
        if jar_files:
            print_status(f"Available JAR files: {', '.join(jar_files)}", "info")
        
        return False

def install_python_dependencies_enhanced():
    """Enhanced Python dependency installation with uv support"""
    print_step(2, "Python Dependencies Installation")
    
    # Check if we're in a virtual environment
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    venv_path = Path(".venv")
    
    if not in_venv and not venv_path.exists():
        print_status("Recommended: Create a virtual environment first", "warning")
        try:
            create_venv = input("Create virtual environment? (y/n): ").strip().lower()
            if create_venv in ['y', 'yes']:
                if create_virtual_environment():
                    print_status("Virtual environment created successfully", "success")
                    # Continue with installation in the virtual environment
                    print_status("Installing dependencies in the virtual environment...", "info")
                else:
                    print_status("Failed to create virtual environment, continuing with system Python", "warning")
        except (KeyboardInterrupt, EOFError):
            print_status("Skipping virtual environment creation", "info")
    
    # Check if uv is available for faster installations
    use_uv, _ = check_uv_enhanced()
    
    # Determine the Python executable to use
    python_exe = sys.executable
    if venv_path.exists() and not in_venv:
        # Use the virtual environment Python
        if platform.system() == "Windows":
            venv_python = venv_path / "Scripts" / "python.exe"
        else:
            venv_python = venv_path / "bin" / "python"
        
        if venv_python.exists():
            python_exe = str(venv_python)
            print_status(f"Using virtual environment Python: {venv_python}", "info")
    
    # Install dependencies
    required_packages = [
        "flask>=2.3.0",
        "flask-sqlalchemy>=3.1.0", 
        "flask-cors>=4.0.0",
        "flask-migrate>=4.0.0",
        "flask-socketio>=5.3.0",
        "flask-restx>=1.3.0",
        "requests>=2.31.0",
        "python-dotenv>=1.0.0",
        "ghidra-bridge>=1.0.0",
        "ghidriff>=0.4.0",
        "werkzeug>=2.3.0",
        "sqlalchemy>=2.0.0",
        "psutil>=5.9.0",
        "aiohttp>=3.9.0",
        "websockets>=12.0"
    ]
    
    optional_packages = [
        "openai>=1.0.0",
        "anthropic>=0.7.0", 
        "google-generativeai>=0.3.0",
        "redis>=5.0.0"
    ]
    
    print_status(f"Installing {len(required_packages)} required packages...", "info")
    
    # Choose installation method
    if use_uv and venv_path.exists():
        install_cmd = ["uv", "pip", "install"]
        print_status("Using uv for faster package installation", "info")
    else:
        install_cmd = [python_exe, "-m", "pip", "install"]
        print_status("Using pip for package installation", "info")
    
    failed_packages = []
    for package in required_packages:
        try:
            cmd = install_cmd + [package]
            result = run_command(cmd, timeout=120)
            if result and result.returncode == 0:
                print_status(f"Installed: {package.split('>=')[0]}", "success")
            else:
                failed_packages.append(package)
                print_status(f"Failed: {package.split('>=')[0]}", "error")
        except Exception as e:
            failed_packages.append(package)
            print_status(f"Error installing {package}: {e}", "error")
    
    # Install optional packages
    print_status(f"Installing {len(optional_packages)} optional packages...", "info")
    for package in optional_packages:
        try:
            cmd = install_cmd + [package]
            result = run_command(cmd, timeout=120)
            if result and result.returncode == 0:
                print_status(f"Installed: {package.split('>=')[0]} (optional)", "success")
            else:
                print_status(f"Skipped: {package.split('>=')[0]} (optional)", "info")
        except:
            print_status(f"Skipped: {package.split('>=')[0]} (optional)", "info")
    
    if failed_packages:
        print_status(f"Failed to install {len(failed_packages)} packages", "error")
        print_status("Failed packages:", "error")
        for pkg in failed_packages:
            print_status(f"  - {pkg}", "error")
        return False
    
    print_status("All required Python dependencies installed successfully", "success")
    
    # If using virtual environment, provide activation instructions
    if venv_path.exists() and not in_venv:
        print_status("Virtual environment ready!", "success")
        print_status("To activate it in future sessions:", "info")
        if platform.system() == "Windows":
            print_status("  .venv\\Scripts\\activate", "info")
        else:
            print_status("  source .venv/bin/activate", "info")
    
    return True

def install_frontend_dependencies_enhanced():
    """Enhanced frontend dependency installation"""
    print_step(3, "Frontend Dependencies Installation")
    
    if not Path("frontend").exists():
        print_status("Frontend directory not found", "error")
        return False
    
    # Check if Node.js is available
    node_result = run_command(["node", "--version"], check=False, timeout=10)
    if not node_result or node_result.returncode != 0:
        print_status("Node.js is required for frontend dependencies", "error")
        print_node_installation_guide(platform.system())
        return False
    
    # Check if npm is available
    npm_result = run_command(["npm", "--version"], check=False, timeout=10)
    if not npm_result or npm_result.returncode != 0:
        print_status("npm is required but not found", "error")
        print_status("This usually means Node.js was not installed properly", "warning")
        
        # Try to fix npm installation
        if fix_npm_installation():
            print_status("npm installation fixed, continuing...", "success")
        else:
            print_status("Could not fix npm installation", "error")
            print_status("Please restart your command prompt and try again", "info")
            print_status("If the problem persists, reinstall Node.js", "info")
            return False
    
    print_status("Installing frontend dependencies (this may take a few minutes)...", "info")
    
    try:
        result = run_command(["npm", "install"], cwd="frontend", timeout=300)
        if result and result.returncode == 0:
            print_status("Frontend dependencies installed successfully", "success")
            return True
        else:
            print_status("Frontend dependency installation failed", "error")
            print_status("Try running manually: cd frontend && npm install", "info")
            return False
    except Exception as e:
        print_status(f"Frontend installation error: {e}", "error")
        return False

def create_virtual_environment():
    """Create a virtual environment using uv (preferred) or fallback to venv"""
    try:
        print_status("Creating virtual environment with uv...", "info")
        
        # Try uv first (preferred method for this project)
        result = run_command(["uv", "venv", ".venv"], timeout=60)
        if result and result.returncode == 0:
            print_status("Virtual environment created with uv successfully", "success")
            return True
        else:
            print_status("uv not found, falling back to standard venv", "warning")
            
        # Fallback to standard venv
        print_status("Creating virtual environment with standard venv...", "info")
        result = run_command([sys.executable, "-m", "venv", ".venv"], timeout=60)
        if result and result.returncode == 0:
            print_status("Virtual environment created with venv successfully", "success")
            return True
            
    except Exception as e:
        print_status(f"Virtual environment creation failed: {e}", "error")
    
    return False



def setup_configuration_enhanced():
    """Enhanced configuration setup with better validation"""
    print_step(4, "Configuration Setup")
    
    config = {}
    
    # Ghidra configuration
    print_status("Ghidra Configuration:", "info")
    ghidra_path = input("Ghidra installation path (or press Enter to skip): ").strip()
    
    if ghidra_path:
        if validate_ghidra_path_enhanced(ghidra_path):
            config["GHIDRA_INSTALL_DIR"] = ghidra_path
            print_status("Ghidra path validated successfully", "success")
        else:
            print_status("Invalid Ghidra path - bridge functionality will be limited", "warning")
            config["GHIDRA_INSTALL_DIR"] = ""
    else:
        config["GHIDRA_INSTALL_DIR"] = ""
        print_status("Skipping Ghidra configuration - bridge functionality will be disabled", "info")
    
    # Other configuration with sensible defaults
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
    
    # Create .env file
    create_env_file_enhanced(config)
    create_directories_enhanced(config)
    
    return config

def create_env_file_enhanced(config):
    """Create enhanced .env file with better documentation"""
    env_content = [
        "# ShadowSeek Environment Configuration",
        f"# Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "#",
        "# This file contains environment variables for ShadowSeek.",
        "# Modify these values as needed for your installation.",
        "",
        "# Core Configuration",
        f"GHIDRA_INSTALL_DIR={config.get('GHIDRA_INSTALL_DIR', '')}",
        f"GHIDRA_BRIDGE_PORT={config.get('GHIDRA_BRIDGE_PORT', '4768')}",
        f"FLASK_PORT={config.get('FLASK_PORT', '5000')}",
        "",
        "# Directory Configuration",
        f"GHIDRA_TEMP_DIR={config.get('GHIDRA_TEMP_DIR', './temp/ghidra_temp')}",
        f"GHIDRA_PROJECTS_DIR={config.get('GHIDRA_PROJECTS_DIR', './ghidra_projects')}",
        f"UPLOAD_FOLDER={config.get('UPLOAD_FOLDER', './uploads')}",
        f"TEMP_FOLDER={config.get('TEMP_FOLDER', './temp')}",
        f"LOG_FOLDER={config.get('LOG_FOLDER', './logs')}",
        "",
        "# Network Configuration",
        f"GHIDRA_BRIDGE_HOST={config.get('GHIDRA_BRIDGE_HOST', '127.0.0.1')}",
        f"FLASK_HOST={config.get('FLASK_HOST', '127.0.0.1')}",
        "",
        "# AI Service Configuration (Optional)",
        "# Uncomment and configure your preferred AI provider:",
        "LLM_PROVIDER=openai",
        "# OPENAI_API_KEY=your_openai_key_here",
        "# OPENAI_MODEL=gpt-4o-mini",
        "# ",
        "# Alternative providers:",
        "# ANTHROPIC_API_KEY=your_anthropic_key_here",
        "# GOOGLE_API_KEY=your_google_key_here",
        "",
        "# Database Configuration", 
        "DATABASE_URL=sqlite:///instance/shadowseek.db",
        "",
        "# Security Configuration",
        "FLASK_SECRET_KEY=your-secret-key-change-in-production",
        "",
        "# Performance Configuration",
        "MAX_FILE_SIZE=1073741824",
        "ANALYSIS_TIMEOUT=3600"
    ]
    
    try:
        with open(".env", "w") as f:
            f.write("\n".join(env_content))
        print_status(".env file created successfully", "success")
    except Exception as e:
        print_status(f"Failed to create .env file: {e}", "error")

def create_directories_enhanced(config):
    """Create required directories with better error handling"""
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
            Path(directory).mkdir(parents=True, exist_ok=True)
            print_status(f"Directory ready: {directory}", "success")
        except Exception as e:
            print_status(f"Failed to create directory {directory}: {e}", "error")

def test_installation():
    """Test the installation to ensure everything works"""
    print_step(5, "Installation Verification")
    
    tests = [
        ("Python imports", test_python_imports),
        ("Flask application", test_flask_app),
        ("Frontend build", test_frontend_build)
    ]
    
    results = {}
    for test_name, test_func in tests:
        print_status(f"Testing {test_name}...", "info")
        try:
            result = test_func()
            # Ensure result is always boolean
            results[test_name] = bool(result) if result is not None else False
            if results[test_name]:
                print_status(f"{test_name}: OK", "success")
            else:
                print_status(f"{test_name}: Failed", "error")
        except Exception as e:
            print_status(f"{test_name}: Error - {e}", "error")
            results[test_name] = False
    
    return results

def test_python_imports():
    """Test if critical Python packages can be imported"""
    critical_imports = [
        "flask",
        "flask_sqlalchemy", 
        "flask_cors",
        "requests",
        "ghidra_bridge"
    ]
    
    for module in critical_imports:
        try:
            __import__(module)
        except ImportError as e:
            print_status(f"Import failed: {module} - {e}", "error")
            return False
    
    return True

def test_flask_app():
    """Test if Flask app can be created"""
    try:
        # Try to import the Flask app
        sys.path.insert(0, os.getcwd())
        from flask_app import create_app
        app = create_app()
        return True
    except Exception as e:
        print_status(f"Flask app test failed: {e}", "error")
        return False

def test_frontend_build():
    """Test if frontend can be built"""
    if not Path("frontend").exists():
        print_status("Frontend directory not found", "warning")
        return False
    
    try:
        result = run_command(["npm", "run", "build"], cwd="frontend", timeout=180)
        return result and result.returncode == 0
    except:
        print_status("Frontend build test failed", "warning")
        return False

def print_completion_summary(config, test_results, requirements=None):
    """Print a comprehensive completion summary"""
    print_header("Installation Complete")
    
    print_status("Configuration Summary:", "info")
    print(f"   • Ghidra Path: {config.get('GHIDRA_INSTALL_DIR', 'Not configured')}")
    print(f"   • Flask Port: {config.get('FLASK_PORT', '5000')}")
    print(f"   • Bridge Port: {config.get('GHIDRA_BRIDGE_PORT', '4768')}")
    
    # Check if virtual environment exists
    venv_path = Path(".venv")
    venv_exists = venv_path.exists()
    in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    
    if venv_exists or in_venv:
        print(f"   • Virtual Environment: {'Active' if in_venv else 'Created (.venv)'}")
        if requirements and requirements.get("uv", {}).get("status", False):
            print(f"   • Package Manager: uv (faster installs)")
        else:
            print(f"   • Package Manager: pip")
    
    # Check if bridge server scripts are installed
    bridge_server_path = Path("ghidra_scripts/ghidra_bridge_server.py")
    jfx_bridge_path = Path("ghidra_scripts/jfx_bridge/bridge.py")
    if bridge_server_path.exists() and jfx_bridge_path.exists():
        print(f"   • Ghidra Bridge: Server scripts installed")
    else:
        print(f"   • Ghidra Bridge: ⚠️ Server scripts missing")
    
    print_status("Test Results:", "info")
    # Filter out None values and convert to boolean
    valid_results = {k: bool(v) for k, v in test_results.items() if v is not None}
    passed_tests = sum(valid_results.values())
    total_tests = len(valid_results)
    
    for test_name, result in valid_results.items():
        status = "success" if result else "error"
        print_status(f"{test_name}: {'PASS' if result else 'FAIL'}", status)
    
    if total_tests > 0:
        print_status(f"Tests passed: {passed_tests}/{total_tests}", "success" if passed_tests == total_tests else "warning")
    else:
        print_status("No tests were run", "info")
    
    # Next steps
    print_status("Next Steps:", "info")
    print("   1. Start the components:")
    
    if config.get('GHIDRA_INSTALL_DIR'):
        print("      • Ghidra Bridge: start_ghidra_bridge_new.bat")
    else:
        print("      • ⚠️ Ghidra Bridge: Not configured (limited functionality)")
    
    # Provide context-aware Flask startup instructions
    if venv_exists and not in_venv:
        if platform.system() == "Windows":
            print("      • Activate venv: .venv\\Scripts\\activate")
            print("      • Flask Backend: python run.py")
        else:
            print("      • Activate venv: source .venv/bin/activate")  
            print("      • Flask Backend: python run.py")
        print("      • OR directly: .venv/Scripts/python run.py" if platform.system() == "Windows" else "      • OR directly: .venv/bin/python run.py")
    else:
        print("      • Flask Backend: python run.py")
    
    print("      • React Frontend: cd frontend && npm start")
    print()
    print("   2. Access the application:")
    print("      • Main Interface: http://localhost:3000")
    print("      • API Docs: http://localhost:5000/api/docs")
    print()
    print("   3. Configure AI services (optional):")
    print("      • Edit .env file with your API keys")
    print("      • Supported: OpenAI, Anthropic, Google Gemini")
    print()
    
    # Virtual environment guidance
    if venv_exists and not in_venv:
        print_status("💡 Virtual Environment Tips:", "info")
        print("   • Always activate the virtual environment before running ShadowSeek")
        print("   • All Python packages are installed in the virtual environment")
        print("   • Flask will automatically use the correct Python version and packages")
        print()
    
    # Environment refresh guidance
    print_status("🔄 Environment Management:", "info")
    print("   • If commands are not found after installation:")
    if platform.system() == "Windows":
        print("     python setup_environment_enhanced.py --refresh-env")
        print("   • This refreshes PATH without restarting command prompt")
    else:
        print("     source ~/.bashrc  # or restart terminal")
    print()
    
    # Check if uv is not installed and recommend it
    if requirements and not requirements.get("uv", {}).get("status", False):
        print("   💡 Tip: Install uv for faster Python package management:")
        print("      • pip install uv")
        print("      • Faster than pip for package installations")

def main():
    """Enhanced main setup process"""
    parser = argparse.ArgumentParser(
        description="Enhanced ShadowSeek Environment Setup",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("--skip-system-check", action="store_true", 
                       help="Skip system requirements check")
    parser.add_argument("--skip-deps", action="store_true",
                       help="Skip dependency installation")
    parser.add_argument("--skip-frontend", action="store_true",
                       help="Skip frontend dependency installation")
    parser.add_argument("--skip-test", action="store_true",
                       help="Skip installation verification tests")
    parser.add_argument("--force-continue", action="store_true",
                       help="Continue setup even with missing dependencies")
    parser.add_argument("--refresh-env", action="store_true",
                       help="Refresh environment variables and exit")
    
    args = parser.parse_args()
    
    print_header("ShadowSeek Enhanced Setup")
    print_status("This enhanced setup script provides better error handling and guidance", "info")
    print_status("Report issues at: https://github.com/threatpointer/ShadowSeek/issues", "info")
    
    # Handle refresh environment option
    if args.refresh_env:
        print_status("🔄 Manual Environment Variable Refresh", "step")
        env_refreshed = refresh_environment_variables()
        if env_refreshed:
            verify_commands_after_refresh()
            print_status("Environment refresh completed", "success")
        else:
            print_status("Environment refresh failed", "error")
        return env_refreshed
    
    try:
        # Step 1: System requirements with automatic installation
        requirements = {}
        if not args.skip_system_check:
            requirements = check_system_requirements_enhanced()
            
            # Offer automatic installation for missing components
            installation_attempted = provide_installation_guidance(requirements, attempted_auto_install=False)
            
            if not installation_attempted and not args.force_continue:
                print_status("Components still missing after installation attempt", "warning")
                
                # Ask if user wants to continue anyway
                try:
                    choice = input("Continue setup with missing dependencies? (y/n): ").strip().lower()
                    if choice not in ['y', 'yes']:
                        print_status("Setup cancelled. Please install missing dependencies first.", "info")
                        print_status("After installing dependencies, restart your command prompt and run:", "info")
                        print_status("  python setup_environment_enhanced.py", "info")
                        print_status("Or use --force-continue to skip this check:", "info")
                        print_status("  python setup_environment_enhanced.py --force-continue", "info")
                        return False
                except (KeyboardInterrupt, EOFError):
                    print_status("Setup cancelled by user", "warning")
                    return False
            elif args.force_continue:
                print_status("Forcing continuation with missing dependencies (--force-continue)", "warning")
        
        # Step 2: Python dependencies
        if not args.skip_deps:
            if not install_python_dependencies_enhanced():
                print_status("Python dependency installation failed", "error")
                return False
        
        # Step 2.5: Install Ghidra Bridge server scripts
        if not args.skip_deps:
            if not install_bridge_server_scripts():
                print_status("Bridge server installation failed", "warning")
                print_status("Bridge functionality may not work properly", "warning")
        
        # Step 3: Frontend dependencies  
        if not args.skip_frontend:
            install_frontend_dependencies_enhanced()  # Don't fail on frontend issues
        
        # Step 4: Configuration
        config = setup_configuration_enhanced()
        
        # Step 5: Test installation
        test_results = {}
        if not args.skip_test:
            test_results = test_installation()
        
        # Step 6: Completion summary
        print_completion_summary(config, test_results, requirements)
        
        print_status("Setup completed successfully!", "success")
        print_status("You can now start using ShadowSeek", "success")
        
        return True
        
    except KeyboardInterrupt:
        print_status("Setup cancelled by user", "warning")
        return False
    except Exception as e:
        print_status(f"Setup failed with error: {e}", "error")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)