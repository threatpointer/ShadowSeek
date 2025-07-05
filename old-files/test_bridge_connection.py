#!/usr/bin/env python3
"""
Test Ghidra Bridge connection
"""

import time
import logging
import sys
from ghidra_bridge import GhidraBridge

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_bridge_connection(host="localhost", port=4768, max_attempts=30, delay=2):
    """
    Test if Ghidra Bridge is ready to accept connections
    
    Args:
        host: Bridge host
        port: Bridge port
        max_attempts: Maximum connection attempts
        delay: Delay between attempts in seconds
    
    Returns:
        True if connection successful, False otherwise
    """
    logger.info(f"Testing Ghidra Bridge connection to {host}:{port}")
    
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"Connection attempt {attempt}/{max_attempts}")
            bridge = GhidraBridge(connect_to_host=host, connect_to_port=port)
            
            # Test with a simple command
            result = bridge.remote_eval("str(state)")
            if result is not None:
                logger.info(f"Successfully connected to Ghidra Bridge: {result}")
                return True
                
        except Exception as e:
            logger.debug(f"Connection attempt {attempt} failed: {e}")
            if attempt < max_attempts:
                logger.info(f"Waiting {delay} seconds before next attempt...")
                time.sleep(delay)
            else:
                logger.error(f"Failed to connect after {max_attempts} attempts")
                return False
    
    return False

def main():
    """Main function"""
    port = 4768
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            logger.error(f"Invalid port number: {sys.argv[1]}")
            sys.exit(1)
    
    success = test_bridge_connection(port=port)
    if success:
        logger.info("Ghidra Bridge is ready!")
        sys.exit(0)
    else:
        logger.error("Ghidra Bridge is not ready")
        sys.exit(1)

if __name__ == "__main__":
    main() 