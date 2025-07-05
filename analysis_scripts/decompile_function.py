# Decompile Function Script for Ghidra
# @category Analysis

import os
import sys
import json

def decompile_function(function_address):
    """
    Decompile a specific function and return the C code
    
    Args:
        function_address (str): Hexadecimal address of the function
    
    Returns:
        dict: Decompilation results
    """
    try:
        # Parse the address
        addr = toAddr(function_address)
        
        # Get the function at this address
        function_manager = currentProgram.getFunctionManager()
        function = function_manager.getFunctionAt(addr)
        
        if function is None:
            return {
                "success": False,
                "error": "No function found at address " + str(function_address),
                "address": function_address
            }
        
        # Get the decompiler
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import ConsoleTaskMonitor
        
        decompiler = DecompInterface()
        decompiler.openProgram(currentProgram)
        
        # Decompile the function
        monitor = ConsoleTaskMonitor()
        decomp_results = decompiler.decompileFunction(function, 30, monitor)
        
        if decomp_results is None or not decomp_results.decompileCompleted():
            error_msg = "Decompilation failed"
            if decomp_results is not None:
                error_msg = decomp_results.getErrorMessage()
            
            return {
                "success": False,
                "error": error_msg,
                "address": function_address,
                "function_name": function.getName()
            }
        
        # Get the decompiled C code
        decomp_source = decomp_results.getDecompiledFunction()
        c_code = decomp_source.getC()
        
        # Get function signature and other metadata
        signature = function.getSignature()
        entry_point = function.getEntryPoint()
        body_size = function.getBody().getNumAddresses()
        calling_convention = function.getCallingConventionName()
        
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
        
        # Get called functions (basic call analysis)
        called_functions = []
        instructions = currentProgram.getListing().getInstructions(function.getBody(), True)
        for instr in instructions:
            if instr.getFlowType().isCall():
                for ref in instr.getReferencesFrom():
                    if ref.getReferenceType().isCall():
                        called_addr = ref.getToAddress()
                        called_func = function_manager.getFunctionAt(called_addr)
                        if called_func:
                            called_functions.append({
                                "name": called_func.getName(),
                                "address": str(called_addr),
                                "call_address": str(instr.getAddress())
                            })
        
        result = {
            "success": True,
            "address": function_address,
            "function_name": function.getName(),
            "signature": str(signature),
            "calling_convention": calling_convention,
            "entry_point": str(entry_point),
            "body_size": body_size,
            "decompiled_code": c_code,
            "parameters": parameters,
            "local_variables": local_vars,
            "called_functions": called_functions,
            "metadata": {
                "is_thunk": function.isThunk(),
                "is_external": function.isExternal(),
                "has_no_return": function.hasNoReturn(),
                "has_var_args": function.hasVarArgs(),
                "stack_frame_size": function.getStackFrame().getFrameSize() if function.getStackFrame() else 0
            }
        }
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "address": function_address
        }

# Main execution
if __name__ == "__main__":
    # Get function address from command line arguments or script args
    function_address = None
    
    # Try to get from script arguments first
    if len(sys.argv) > 1:
        function_address = sys.argv[1]
    else:
        # Get from askString if running interactively
        try:
            function_address = askString("Function Address", "Enter function address to decompile:")
        except:
            function_address = "0x401000"  # Default fallback
    
    if function_address:
        print("Decompiling function at address: " + function_address)
        
        # Perform decompilation
        result = decompile_function(function_address)
        
        # Output result in parseable format to stdout
        print("RESULT_START")
        print(json.dumps(result, indent=2))
        print("RESULT_END")
        
        print("Decompilation complete!")
        
        if result["success"]:
            print("Function: " + result["function_name"])
            print("Code length: " + str(len(result["decompiled_code"])) + " characters")
        else:
            print("Error: " + result["error"])
    else:
        print("No function address provided")
        result = {
            "success": False,
            "error": "No function address provided"
        }
        print("RESULT_START")
        print(json.dumps(result, indent=2))
        print("RESULT_END") 