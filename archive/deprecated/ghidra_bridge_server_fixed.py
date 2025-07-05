# Run a ghidra_bridge server for external python environments to interact with
# @author justfoxing
# @category Bridge

# NOTE: any imports here may need to be excluded in ghidra_bridge
import logging
import subprocess
import sys
from jfx_bridge import bridge
from ghidra_bridge_port import DEFAULT_SERVER_PORT

# NOTE: we definitely DON'T want to exclude ghidra from ghidra_bridge :P
import ghidra


class GhidraBridgeServer(object):
    """ Class mostly used to collect together functions and variables that we don't want contaminating the global namespace
        variables set in remote clients

        NOTE: this class needs to be excluded from ghidra_bridge - it doesn't need to be in the globals, if people want it and
        know what they're doing, they can get it from the BridgedObject for the main module
    """

    class PrintAccumulator(object):
        """ Class to handle capturing print output so we can send it across the bridge, by hooking sys.stdout.write().
            Not multithreading aware, it'll just capture whatever is printed from the moment it hooks to the moment
            it stops.
        """

        output = None
        old_stdout = None

        def __init__(self):
            self.output = ""

        def write(self, output):
            self.output += output

        def get_output(self):
            return self.output

        def hook(self):
            self.old_stdout = sys.stdout
            sys.stdout = self

        def unhook(self):
            if self.old_stdout is not None:
                sys.stdout = self.old_stdout

        def __enter__(self):
            self.hook()
            return self

        def __exit__(self, type, value, traceback):
            self.unhook()

    @staticmethod
    def ghidra_help(param=None):
        """ call the ghidra help method, capturing the print output with PrintAccumulator, and return it as a string """
        with GhidraBridgeServer.PrintAccumulator() as help_output:
            help(param)

            return help_output.get_output()

    @staticmethod
    def run_server(
        server_host=bridge.DEFAULT_HOST,
        server_port=DEFAULT_SERVER_PORT,
        response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT,
        background=True,
    ):
        """ Run a ghidra_bridge_server (forever)
            server_host - what address the server should listen on
            server_port - what port the server should listen on
            response_timeout - default timeout in seconds before a response is treated as "failed"
            background - false to run the server in this thread (script popup will stay), true for a new thread (script popup disappears)
        """
        server = bridge.BridgeServer(
            server_host=server_host,
            server_port=server_port,
            loglevel=logging.INFO,
            response_timeout=response_timeout,
        )

        if background:
            server.start()
            server.logger.info(
                "Server launching in background - will continue to run after launch script finishes..."
            )
        else:
            server.run()


if __name__ == "__main__":
    # Parse command line arguments for port
    server_port = DEFAULT_SERVER_PORT
    
    # Check if port was provided as command line argument
    if len(sys.argv) > 1:
        try:
            server_port = int(sys.argv[1])
            print("Using port from command line: {}".format(server_port))
        except ValueError:
            print("Invalid port argument '{}', using default port {}".format(sys.argv[1], DEFAULT_SERVER_PORT))
            server_port = DEFAULT_SERVER_PORT
    else:
        print("No port specified, using default port {}".format(DEFAULT_SERVER_PORT))
    
    print("Starting Ghidra Bridge Server on port {}".format(server_port))
    
    # Run the server with the specified port and in background mode for better connection handling
    GhidraBridgeServer.run_server(
        server_port=server_port,
        response_timeout=bridge.DEFAULT_RESPONSE_TIMEOUT, 
        background=True  # Changed to True for better connection handling
    )
    
    # Keep the script running to maintain the bridge connection
    print("Bridge server started successfully on port {}".format(server_port))
    print("Bridge will continue running in background...")
    
    # Keep main thread alive
    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Bridge server shutting down...") 