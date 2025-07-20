# -*- coding: utf-8 -*-
"""
Ghidra Bridge Server Script - Using Built-in Bridge
This script runs inside Ghidra and starts the built-in JFX bridge server
that allows external Python scripts to connect and interact with Ghidra.

This works with Ghidra's internal Jython environment without requiring
external package imports.
"""

# Python 2.7 compatible script for Jython
import sys

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
        # Use Ghidra's built-in JFX bridge (available in Jython environment)
        from jfx_bridge import bridge
        
        print("Using Ghidra's built-in JFX Bridge")
        
        # Create the bridge server with Ghidra's built-in capabilities
        # This works because we're running inside Ghidra's Jython environment
        bridge_server = bridge.BridgeServer(
            server_port=port,
            loglevel="INFO"
        )
        
        print("Bridge server created, starting...")
        bridge_server.start()
        
        print("Ghidra Bridge server started successfully on port {}".format(port))
        print("Server is running and accepting connections...")
        print("Available namespace includes: currentProgram, state, monitor")
        
        # Keep the script running - essential for bridge to stay alive
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Shutting down Ghidra Bridge server...")
            
    except ImportError as e:
        print("Error: Could not import jfx_bridge: {}".format(e))
        
        # Fallback: Try alternative bridge approach
        try:
            print("Trying alternative bridge setup...")
            
            # This might be available in newer Ghidra versions
            from ghidra.util.task import TaskMonitor
            
            # Create a simple bridge using Ghidra's built-in networking
            import socket
            import threading
            
            def handle_client(client_socket):
                try:
                    while True:
                        data = client_socket.recv(1024)
                        if not data:
                            break
                        # Simple echo for now - can be enhanced
                        response = "Ghidra Bridge Response: {}".format(data)
                        client_socket.send(response.encode())
                except Exception as e:
                    print("Client handler error: {}".format(e))
                finally:
                    client_socket.close()
            
            # Start simple bridge server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('127.0.0.1', port))
            server_socket.listen(5)
            
            print("Simple bridge server listening on port {}".format(port))
            
            while True:
                client_socket, addr = server_socket.accept()
                print("Client connected from: {}".format(addr))
                client_thread = threading.Thread(target=handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            print("Alternative bridge setup failed: {}".format(e))
            print("Please check Ghidra installation and try again")
            sys.exit(1)
            
    except Exception as e:
        print("Error starting bridge server: {}".format(e))
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 