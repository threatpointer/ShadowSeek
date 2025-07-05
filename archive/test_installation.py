#!/usr/bin/env python3
"""
Quick test script to verify installation and basic functionality
Run with: uv run python test_installation.py
"""

import sys
import os
import asyncio
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test that all required modules can be imported"""
    print("🧪 Testing imports...")
    
    try:
        import flask
        print(f"✓ Flask {flask.__version__}")
    except ImportError as e:
        print(f"✗ Flask import failed: {e}")
        return False
    
    try:
        import celery
        print(f"✓ Celery {celery.__version__}")
    except ImportError as e:
        print(f"✗ Celery import failed: {e}")
        return False
    
    try:
        import kombu
        print(f"✓ Kombu {kombu.__version__}")
    except ImportError as e:
        print(f"✗ Kombu import failed: {e}")
        return False
    
    try:
        import sqlalchemy
        print(f"✓ SQLAlchemy {sqlalchemy.__version__}")
    except ImportError as e:
        print(f"✗ SQLAlchemy import failed: {e}")
        return False
    
    try:
        import httpx
        print(f"✓ HTTPX {httpx.__version__}")
    except ImportError as e:
        print(f"✗ HTTPX import failed: {e}")
        return False
    
    try:
        import websockets
        print(f"✓ WebSockets {websockets.__version__}")
    except ImportError as e:
        print(f"✗ WebSockets import failed: {e}")
        return False
    
    print("✓ All imports successful!")
    return True

def test_project_structure():
    """Test that required project files exist"""
    print("\n📁 Testing project structure...")
    
    required_files = [
        'pyproject.toml',
        'env_template.txt',
        'flask_app/__init__.py',
        'flask_app/config.py',
        'flask_app/models.py',
        'flask_app/mcp_client.py',
        'flask_app/tasks.py',
        'flask_app/app.py',
        'mcp_server/__init__.py',
        'mcp_server/protocol.py',
        'mcp_server/ghidra_manager.py',
        'mcp_server/ghidra_mcp_server.py',
        'mcp_server/ghidra_scripts/get_cfg.py',
        'mcp_server/ghidra_scripts/decompile_function.py',
        'mcp_server/ghidra_scripts/get_xrefs.py',
        'frontend/package.json',
        'frontend/src/components/CFGVisualization.tsx'
    ]
    
    missing_files = []
    for file_path in required_files:
        if not (project_root / file_path).exists():
            missing_files.append(file_path)
            print(f"✗ Missing: {file_path}")
        else:
            print(f"✓ Found: {file_path}")
    
    if missing_files:
        print(f"\n⚠ {len(missing_files)} files missing")
        return False
    else:
        print("\n✓ All required files present!")
        return True

def test_configuration():
    """Test configuration loading"""
    print("\n⚙️ Testing configuration...")
    
    try:
        from flask_app.config import DevelopmentConfig
        config = DevelopmentConfig()
        print("✓ Configuration class loaded")
        
        # Test required config values
        required_configs = [
            'GHIDRA_INSTALL_PATH',
            'CELERY_BROKER_URL',
            'CELERY_RESULT_BACKEND',
            'UPLOAD_FOLDER',
            'MAX_CONTENT_LENGTH'
        ]
        
        for config_name in required_configs:
            if hasattr(config, config_name):
                value = getattr(config, config_name)
                print(f"✓ {config_name}: {value}")
            else:
                print(f"✗ Missing config: {config_name}")
        
        return True
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False

def test_database():
    """Test database connection and models"""
    print("\n🗄️ Testing database...")
    
    try:
        from flask_app.models import db, Binary, AnalysisTask, AnalysisResult
        print("✓ Database models imported")
        
        # Test model creation (without actual database)
        binary = Binary(
            filename="test.exe",
            original_filename="test.exe",
            file_path="/tmp/test.exe",
            file_size=1024
        )
        print("✓ Binary model created")
        
        task = AnalysisTask(
            binary_id="test-id",
            task_type="test",
            status="queued"
        )
        print("✓ AnalysisTask model created")
        
        return True
        
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        return False

async def test_mcp_client():
    """Test MCP client creation (without actual server)"""
    print("\n🔗 Testing MCP client...")
    
    try:
        from flask_app.mcp_client import MCPClient
        
        # Test client creation
        client = MCPClient("127.0.0.1", 8080)
        print("✓ MCP client created")
        
        # Test request creation
        request = client._create_request("test_method", {"param": "value"})
        print("✓ JSON-RPC request created")
        
        if request.get("jsonrpc") == "2.0":
            print("✓ JSON-RPC 2.0 format correct")
        
        return True
        
    except Exception as e:
        print(f"✗ MCP client test failed: {e}")
        return False

def test_flask_app():
    """Test Flask app creation"""
    print("\n🌐 Testing Flask app...")
    
    try:
        from flask_app.app import create_app
        
        # Test app creation
        app, socketio, celery = create_app()
        print("✓ Flask app created")
        
        # Test basic app configuration
        if app.config.get('TESTING') is not None:
            print("✓ App configuration loaded")
        
        # Test routes (basic check)
        with app.test_client() as client:
            response = client.get('/api/health')
            if response.status_code == 200:
                print("✓ Health endpoint accessible")
            else:
                print(f"⚠ Health endpoint returned: {response.status_code}")
        
        return True
        
    except Exception as e:
        print(f"✗ Flask app test failed: {e}")
        return False

def test_directories():
    """Test that required directories exist or can be created"""
    print("\n📂 Testing directories...")
    
    required_dirs = [
        'uploads',
        'logs', 
        'temp',
        'instance'
    ]
    
    for dir_name in required_dirs:
        dir_path = project_root / dir_name
        if not dir_path.exists():
            try:
                dir_path.mkdir(exist_ok=True)
                print(f"✓ Created directory: {dir_name}")
            except Exception as e:
                print(f"✗ Failed to create directory {dir_name}: {e}")
                return False
        else:
            print(f"✓ Directory exists: {dir_name}")
    
    return True

def test_rabbitmq_connection():
    """Test RabbitMQ connection"""
    print("\n🐰 Testing RabbitMQ connection...")
    
    try:
        from kombu import Connection
        from flask_app.config import DevelopmentConfig
        
        config = DevelopmentConfig()
        connection_url = config.CELERY_BROKER_URL
        print(f"✓ Broker URL: {connection_url}")
        
        # Test connection (basic check)
        try:
            conn = Connection(connection_url)
            conn.ensure_connection(max_retries=3)
            print("✓ RabbitMQ connection successful")
            conn.close()
            return True
        except Exception as conn_error:
            print(f"⚠ RabbitMQ connection failed: {conn_error}")
            print("  Make sure RabbitMQ is running (rabbitmq-server)")
            return False
            
    except Exception as e:
        print(f"✗ RabbitMQ test failed: {e}")
        return False

def test_ghidra_path():
    """Test Ghidra installation path"""
    print("\n🔍 Testing Ghidra path...")
    
    try:
        from dotenv import load_dotenv
        
        # Try to load .env file
        env_file = project_root / ".env"
        if env_file.exists():
            load_dotenv(env_file)
            ghidra_path = os.getenv('GHIDRA_INSTALL_PATH')
            
            if ghidra_path:
                ghidra_path_obj = Path(ghidra_path)
                if ghidra_path_obj.exists():
                    print(f"✓ Ghidra path exists: {ghidra_path}")
                    
                    # Check for key Ghidra components
                    ghidra_headless = ghidra_path_obj / "support" / "analyzeHeadless"
                    if ghidra_headless.exists() or (ghidra_headless.with_suffix('.bat')).exists():
                        print("✓ analyzeHeadless found")
                    else:
                        print("⚠ analyzeHeadless not found")
                    
                    return True
                else:
                    print(f"⚠ Ghidra path does not exist: {ghidra_path}")
                    return False
            else:
                print("⚠ GHIDRA_INSTALL_PATH not set in .env")
                return False
        else:
            print("⚠ .env file not found")
            return False
            
    except Exception as e:
        print(f"✗ Ghidra path test failed: {e}")
        return False

async def main():
    """Run all tests"""
    print("🚀 Ghidra Web Analyzer - Installation Test")
    print("=" * 50)
    
    tests = [
        ("Imports", test_imports),
        ("Project Structure", test_project_structure),
        ("Configuration", test_configuration),
        ("Database Models", test_database),
        ("MCP Client", test_mcp_client),
        ("Flask App", test_flask_app),
        ("Directories", test_directories),
        ("RabbitMQ Connection", test_rabbitmq_connection),
        ("Ghidra Path", test_ghidra_path)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            
            if result:
                passed += 1
                print(f"\n✓ {test_name} - PASSED")
            else:
                print(f"\n✗ {test_name} - FAILED")
                
        except Exception as e:
            print(f"\n✗ {test_name} - ERROR: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Installation looks good.")
        print("\n🚀 Next steps:")
        print("1. Start RabbitMQ: rabbitmq-server")
        print("2. Start services as described in README.md")
        print("3. Access the application at http://localhost:3000")
    else:
        print(f"⚠ {total - passed} tests failed. Check the errors above.")
        print("Run 'python setup.py' to fix common issues.")
    
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main()) 