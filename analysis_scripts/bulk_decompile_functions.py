# Bulk Decompile Functions Script for Ghidra Bridge
# @category Analysis

import sys
import json

def decompile_functions_batch(function_addresses):
    """
    Decompile multiple functions efficiently in a single session
    
    Args:
        function_addresses (list): List of function addresses to decompile
        
    Returns:
        dict: Results for each function
    """
    results = {}
    
    try:
        # Get the decompiler interface
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        
        decompiler = DecompInterface()
        decompiler.openProgram(currentProgram)
        monitor = ConsoleTaskMonitor()
        
        function_manager = currentProgram.getFunctionManager()
        
        for function_address in function_addresses:
            try:
                print(f"Decompiling function at {function_address}")
                
                # Parse the address
                addr = toAddr(function_address)
                
                # Get the function at this address
                function = function_manager.getFunctionAt(addr)
                
                if function is None:
                    results[function_address] = {
                        "success": False,
                        "error": f"No function found at address {function_address}",
                        "address": function_address
                    }
                    continue
                
                # Decompile the function
                decomp_results = decompiler.decompileFunction(function, 30, monitor)
                
                if decomp_results is None or not decomp_results.decompileCompleted():
                    error_msg = "Decompilation failed"
                    if decomp_results is not None:
                        error_msg = decomp_results.getErrorMessage()
                    
                    results[function_address] = {
                        "success": False,
                        "error": error_msg,
                        "address": function_address,
                        "function_name": function.getName()
                    }
                    continue
                
                # Get the decompiled C code
                decomp_source = decomp_results.getDecompiledFunction()
                c_code = decomp_source.getC()
                
                # Get function metadata
                signature = function.getSignature()
                calling_convention = function.getCallingConventionName()
                body_size = function.getBody().getNumAddresses()
                
                # Get parameters
                parameters = []
                for param in function.getParameters():
                    parameters.append({
                        "name": param.getName(),
                        "datatype": str(param.getDataType()),
                        "size": param.getLength()
                    })
                
                # Get local variables
                local_vars = []
                for var in function.getLocalVariables():
                    local_vars.append({
                        "name": var.getName(),
                        "datatype": str(var.getDataType()),
                        "size": var.getLength(),
                        "storage": str(var.getVariableStorage())
                    })
                
                # Store successful result
                results[function_address] = {
                    "success": True,
                    "address": function_address,
                    "function_name": function.getName(),
                    "signature": str(signature),
                    "calling_convention": calling_convention,
                    "body_size": body_size,
                    "decompiled_code": c_code,
                    "parameters": parameters,
                    "local_variables": local_vars,
                    "metadata": {
                        "is_thunk": function.isThunk(),
                        "is_external": function.isExternal(),
                        "has_no_return": function.hasNoReturn(),
                        "has_var_args": function.hasVarArgs(),
                        "stack_frame_size": function.getStackFrame().getFrameSize() if function.getStackFrame() else 0
                    }
                }
                
            except Exception as e:
                results[function_address] = {
                    "success": False,
                    "error": str(e),
                    "address": function_address
                }
        
        # Close decompiler
        decompiler.closeProgram()
        
        return {
            "success": True,
            "total_functions": len(function_addresses),
            "results": results
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "total_functions": len(function_addresses),
            "results": results
        }

# Main execution
if __name__ == "__main__":
    # Get function addresses from command line arguments
    if len(sys.argv) > 1:
        # Expect addresses as comma-separated string
        addresses_str = sys.argv[1]
        function_addresses = [addr.strip() for addr in addresses_str.split(',')]
        
        print(f"Bulk decompiling {len(function_addresses)} functions")
        
        # Perform bulk decompilation
        result = decompile_functions_batch(function_addresses)
        
        print("Bulk decompilation complete!")
        print(f"Processed {result['total_functions']} functions")
        
        if result["success"]:
            successful = sum(1 for r in result["results"].values() if r["success"])
            print(f"Successfully decompiled: {successful}")
        else:
            print(f"Error: {result['error']}")
    else:
        print("No function addresses provided")
        print("Usage: script.py 'addr1,addr2,addr3'") 