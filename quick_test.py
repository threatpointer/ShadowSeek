#!/usr/bin/env python3
"""
Quick ShadowSeek Configuration Test

A simplified test script to quickly verify your ShadowSeek setup is working.
Run this anytime to check if your configuration is still valid.
"""

import os
import socket
import platform
from dotenv import load_dotenv

def test_basic_config():
    """Test basic configuration"""
    print("🔍 Testing ShadowSeek Configuration...\n")
    
    # Load environment variables
    load_dotenv()
    
    # Test Ghidra path
    ghidra_path = os.getenv('GHIDRA_INSTALL_DIR')
    if not ghidra_path or not os.path.exists(ghidra_path):
        print("❌ GHIDRA_INSTALL_DIR not configured or path doesn't exist")
        return False
    else:
        print(f"✅ Ghidra installation found: {ghidra_path}")
    
    # Test headless analyzer
    if platform.system() == "Windows":
        headless = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
    else:
        headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
    
    if os.path.exists(headless):
        print("✅ Headless analyzer available")
    else:
        print("❌ Headless analyzer not found")
        return False
    
    # Test required directories
    dirs = ["uploads", "temp", "logs", "instance", "ghidra_projects"]
    for directory in dirs:
        if os.path.exists(directory):
            print(f"✅ Directory exists: {directory}")
        else:
            print(f"⚠️  Directory missing: {directory} (will be created automatically)")
    
    return True

def test_network():
    """Test network connectivity"""
    print("\n🌐 Testing Network Configuration...")
    
    flask_port = int(os.getenv('FLASK_PORT', '5000'))
    bridge_port = int(os.getenv('GHIDRA_BRIDGE_PORT', '4768'))
    
    # Test Flask backend
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', flask_port))
        sock.close()
        if result == 0:
            print(f"✅ Flask backend running on port {flask_port}")
        else:
            print(f"⚠️  Flask backend not running on port {flask_port}")
    except Exception:
        print(f"⚠️  Could not test Flask port {flask_port}")
    
    # Test Ghidra Bridge
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('localhost', bridge_port))
        sock.close()
        if result == 0:
            print(f"✅ Ghidra Bridge running on port {bridge_port}")
        else:
            print(f"⚠️  Ghidra Bridge not running on port {bridge_port}")
    except Exception:
        print(f"⚠️  Could not test Bridge port {bridge_port}")

def test_python_deps():
    """Test Python dependencies"""
    print("\n🐍 Testing Python Dependencies...")
    
    required = ['flask', 'flask_sqlalchemy', 'flask_cors', 'requests', 'dotenv']
    missing = []
    
    for package in required:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package}")
        except ImportError:
            missing.append(package)
            print(f"❌ {package}")
    
    if missing:
        print(f"\n⚠️  Missing packages: {', '.join(missing)}")
        print("   Run: pip install -r requirements.txt")
        return False
    
    return True

def main():
    """Main test function"""
    print("=" * 50)
    print("   ShadowSeek Quick Configuration Test")
    print("=" * 50)
    
    config_ok = test_basic_config()
    deps_ok = test_python_deps()
    test_network()
    
    print("\n" + "=" * 50)
    if config_ok and deps_ok:
        print("🎉 Configuration looks good!")
        print("   Ready to use ShadowSeek!")
    else:
        print("⚠️  Some issues found - check above for details")
        print("   Run setup_environment.py to fix configuration")
    
    print("\n💡 Components running?")
    print("   • Frontend: http://localhost:3000")
    print("   • Backend:  http://localhost:5000") 
    print("   • Stop all: run stop.bat")
    print("=" * 50)

if __name__ == "__main__":
    main() 