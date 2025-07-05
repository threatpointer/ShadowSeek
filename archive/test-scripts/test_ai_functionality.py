#!/usr/bin/env python3
"""
Test script to verify OpenAI API functionality in ShadowSeek
"""

import os
import sys
from datetime import datetime

# Add the current directory to Python path
sys.path.insert(0, os.getcwd())

from flask_app.ai_service import AIService
from flask_app import create_app

def test_environment_loading():
    """Test if environment variables are loaded correctly"""
    print("🔧 Testing Environment Variable Loading...")
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    api_key = os.getenv('OPENAI_API_KEY')
    
    if api_key:
        print(f"✅ OpenAI API Key found: {api_key[:20]}...{api_key[-10:] if len(api_key) > 30 else ''}")
        print(f"   Full key length: {len(api_key)} characters")
        
        # Check if it looks like a valid OpenAI key format
        if api_key.startswith('sk-') and len(api_key) > 40:
            print("✅ API key format appears valid (starts with 'sk-' and has proper length)")
            return True
        else:
            print("⚠️  API key format may be invalid (should start with 'sk-' and be ~51+ chars)")
            return False
    else:
        print("❌ OpenAI API Key not found in environment variables")
        return False

def test_ai_service_initialization():
    """Test AI service initialization"""
    print("\n🤖 Testing AI Service Initialization...")
    
    try:
        ai_service = AIService()
        
        if ai_service.client:
            print("✅ AI Service initialized successfully")
            print(f"   Model: {ai_service.model}")
            print(f"   API Key configured: {bool(ai_service.api_key)}")
            return ai_service
        else:
            print("❌ AI Service failed to initialize (no client)")
            return None
            
    except Exception as e:
        print(f"❌ AI Service initialization failed: {e}")
        return None

def test_simple_api_call(ai_service):
    """Test a simple API call to verify connectivity"""
    print("\n📡 Testing Simple OpenAI API Call...")
    
    if not ai_service or not ai_service.client:
        print("❌ Cannot test API call - AI service not initialized")
        return False
    
    try:
        # Simple test function context
        test_context = {
            "function_name": "test_function",
            "function_address": "0x401000",
            "decompiled_code": """
int test_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Potential buffer overflow
    return strlen(buffer);
}
""",
            "signature": "int test_function(char *input)",
            "size": 128
        }
        
        print("   Making API call to OpenAI...")
        print(f"   Using model: {ai_service.model}")
        
        result = ai_service.explain_function(test_context)
        
        if result.get("success"):
            print("✅ API call successful!")
            print(f"   Response length: {len(result.get('explanation', ''))}")
            print(f"   Risk score: {result.get('risk_score', 'N/A')}")
            print(f"   Model used: {result.get('model_used', 'N/A')}")
            print(f"   Vulnerabilities found: {len(result.get('vulnerabilities', []))}")
            
            # Show a snippet of the explanation
            explanation = result.get('explanation', '')
            if explanation:
                snippet = explanation[:200] + "..." if len(explanation) > 200 else explanation
                print(f"   Explanation snippet: {snippet}")
            
            return True
        else:
            print(f"❌ API call failed: {result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ API call test failed: {e}")
        return False

def test_binary_analysis(ai_service):
    """Test binary analysis functionality"""
    print("\n🔍 Testing Binary Analysis...")
    
    if not ai_service or not ai_service.client:
        print("❌ Cannot test binary analysis - AI service not initialized")
        return False
    
    try:
        # Test binary context
        binary_context = {
            "binary_name": "test_binary.exe",
            "file_size": 524288,
            "architecture": "x86_64",
            "total_functions": 42,
            "analyzed_functions": 35,
            "decompiled_functions": 28,
            "external_functions": 15,
            "function_list": [
                {"name": "main", "is_external": False},
                {"name": "process_input", "is_external": False},
                {"name": "validate_user", "is_external": False},
                {"name": "malloc", "is_external": True},
                {"name": "strcpy", "is_external": True}
            ]
        }
        
        print("   Making binary analysis API call...")
        
        result = ai_service.analyze_binary(binary_context)
        
        if result.get("success"):
            print("✅ Binary analysis successful!")
            print(f"   Summary length: {len(result.get('summary', ''))}")
            print(f"   Analysis length: {len(result.get('analysis', ''))}")
            print(f"   Risk assessment length: {len(result.get('risk_assessment', ''))}")
            print(f"   Model used: {result.get('model_used', 'N/A')}")
            
            # Show summary snippet
            summary = result.get('summary', '')
            if summary:
                snippet = summary[:150] + "..." if len(summary) > 150 else summary
                print(f"   Summary snippet: {snippet}")
            
            return True
        else:
            print(f"❌ Binary analysis failed: {result.get('error', 'Unknown error')}")
            return False
            
    except Exception as e:
        print(f"❌ Binary analysis test failed: {e}")
        return False

def test_with_flask_context():
    """Test within Flask application context"""
    print("\n🌐 Testing within Flask Application Context...")
    
    try:
        app = create_app()
        with app.app_context():
            print("   Flask app context created successfully")
            
            # Test AI service within Flask context
            ai_service = AIService()
            
            if ai_service.client:
                print("✅ AI Service works within Flask context")
                return True
            else:
                print("❌ AI Service failed within Flask context")
                return False
                
    except Exception as e:
        print(f"❌ Flask context test failed: {e}")
        return False

def main():
    """Main test function"""
    print("🧪 ShadowSeek AI Functionality Test")
    print("=" * 50)
    print(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests_passed = 0
    total_tests = 5
    
    # Test 1: Environment loading
    if test_environment_loading():
        tests_passed += 1
    
    # Test 2: AI service initialization
    ai_service = test_ai_service_initialization()
    if ai_service:
        tests_passed += 1
    
    # Test 3: Simple API call
    if test_simple_api_call(ai_service):
        tests_passed += 1
    
    # Test 4: Binary analysis
    if test_binary_analysis(ai_service):
        tests_passed += 1
    
    # Test 5: Flask context
    if test_with_flask_context():
        tests_passed += 1
    
    # Results
    print("\n" + "=" * 50)
    print("🏁 Test Results Summary")
    print(f"Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        print("✅ ALL TESTS PASSED - AI functionality is working properly!")
        print("🎉 OpenAI API integration is fully functional.")
    elif tests_passed >= 3:
        print("⚠️  MOST TESTS PASSED - AI functionality mostly working with some issues")
    else:
        print("❌ MULTIPLE TESTS FAILED - AI functionality has significant issues")
        print("🔧 Check API key configuration and network connectivity")
    
    print(f"\nTest completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return tests_passed == total_tests

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 