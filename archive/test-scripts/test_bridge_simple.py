#!/usr/bin/env python3
"""
Simple Bridge Connection Test
Tests if bridge is running without using problematic Jep/PyJClass
"""

import socket
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_simple_connection(host="localhost", port=4768, timeout=5):
    """
    Test if anything is listening on the bridge port
    """
    try:
        logger.info(f"Testing simple socket connection to {host}:{port}")
        
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            logger.info("✅ Something is listening on bridge port")
            return True
        else:
            logger.info(f"❌ Nothing listening on port {port}")
            return False
            
    except Exception as e:
        logger.error(f"Socket test failed: {e}")
        return False

def test_flask_bridge_manager():
    """Test if Flask bridge manager thinks it's connected"""
    try:
        import requests
        response = requests.get("http://localhost:5000/api/bridge/test", timeout=10)
        if response.status_code == 200:
            status = response.json()
            logger.info(f"Flask bridge status: {status}")
            return status.get('status') == 'connected'
        else:
            logger.error(f"Flask bridge test failed: {response.status_code}")
            return False
    except Exception as e:
        logger.error(f"Flask bridge test error: {e}")
        return False

def main():
    """Main test function"""
    logger.info("=" * 50)
    logger.info("SIMPLE BRIDGE CONNECTION TEST")
    logger.info("=" * 50)
    
    # Test 1: Socket connection
    logger.info("\n1. Testing socket connection...")
    socket_ok = test_simple_connection()
    
    # Test 2: Flask API
    logger.info("\n2. Testing Flask bridge manager...")
    flask_ok = test_flask_bridge_manager()
    
    # Summary
    logger.info("\n" + "=" * 50)
    logger.info("TEST RESULTS:")
    logger.info(f"Socket Connection: {'✅ PASS' if socket_ok else '❌ FAIL'}")
    logger.info(f"Flask Bridge API: {'✅ PASS' if flask_ok else '❌ FAIL'}")
    
    if socket_ok or flask_ok:
        logger.info("🎉 Some bridge functionality is working!")
        return True
    else:
        logger.info("💥 Bridge functionality appears to be broken")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1) 