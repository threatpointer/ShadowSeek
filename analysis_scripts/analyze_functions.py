"""
Analyze Functions Script for Ghidra Bridge

This script extracts function information and decompiles functions in a binary.
It is designed to be run through the Ghidra Bridge.
"""

# Import Ghidra modules (these will be available in the Ghidra Python environment)
# The script will be executed in Ghidra's Jython environment through the bridge
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol import SourceType

def analyze_functions(program=None, filter_params=None):
    """
    Analyze all functions in the program
    
    Args:
        program: The Ghidra Program object (defaults to currentProgram)
        filter_params: Optional dictionary with filter parameters
            - name_filter: Filter functions by name (substring match)
            - min_size: Minimum function size in bytes
            - max_size: Maximum function size in bytes
            - limit: Maximum number of functions to return
    
    Returns:
        Dictionary with function information
    """
    # Use current program if not specified
    if program is None:
        program = currentProgram
    
    if filter_params is None:
        filter_params = {}
    
    # Initialize result
    result = {
        "program_name": program.getName(),
        "program_path": program.getExecutablePath(),
        "architecture": program.getLanguage().getProcessor().toString(),
        "compiler": program.getCompiler(),
        "creation_date": str(program.getCreationDate()),
        "functions": []
    }
    
    # Get function manager
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True = forward order
    
    # Apply filters
    name_filter = filter_params.get("name_filter", "")
    min_size = filter_params.get("min_size", 0)
    max_size = filter_params.get("max_size", float('inf'))
    limit = filter_params.get("limit", 1000)  # Default limit to prevent huge results
    
    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    
    # Process functions
    count = 0
    for function in functions:
        # Check if we've reached the limit
        if count >= limit:
            break
        
        # Apply filters
        function_name = function.getName()
        function_size = function.getBody().getNumAddresses()
        
        if name_filter and name_filter.lower() not in function_name.lower():
            continue
        
        if function_size < min_size or function_size > max_size:
            continue
        
        # Get function details
        entry_point = function.getEntryPoint()
        function_address = "0x" + entry_point.toString()
        
        # Get function signature
        return_type = function.getReturnType().getDisplayName()
        params = []
        for param in function.getParameters():
            params.append({
                "name": param.getName(),
                "type": param.getDataType().getDisplayName()
            })
        
        # Get function body
        function_body = function.getBody()
        function_ranges = []
        for range in function_body.toList():
            function_ranges.append({
                "min_address": "0x" + range.getMinAddress().toString(),
                "max_address": "0x" + range.getMaxAddress().toString()
            })
        
        # Get references to this function
        references = []
        refs = program.getReferenceManager().getReferencesTo(entry_point)
        for ref in refs:
            if not ref.getReferenceType().isCall():
                continue
            
            from_addr = ref.getFromAddress()
            from_func = function_manager.getFunctionContaining(from_addr)
            
            if from_func:
                references.append({
                    "address": "0x" + from_addr.toString(),
                    "function": from_func.getName()
                })
        
        # Decompile function
        decompiled = None
        try:
            results = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY)
            if results.decompileCompleted():
                decompiled = results.getDecompiledFunction().getC()
        except Exception as e:
            decompiled = f"// Error decompiling: {str(e)}"
        
        # Build function info
        function_info = {
            "name": function_name,
            "address": function_address,
            "size": function_size,
            "signature": {
                "return_type": return_type,
                "parameters": params
            },
            "is_library": function.isLibrary(),
            "is_thunk": function.isThunk(),
            "has_vars": function.hasVars(),
            "has_custom_storage": function.hasCustomStorage(),
            "calling_convention": function.getCallingConventionName(),
            "body_ranges": function_ranges,
            "references": references,
            "decompiled": decompiled
        }
        
        result["functions"].append(function_info)
        count += 1
    
    # Close decompiler
    decompiler.dispose()
    
    return result

# When executed directly through the bridge, run the analysis
result = analyze_functions(currentProgram) 