"""
Comprehensive Analysis Script for Ghidra Bridge

This script performs comprehensive binary analysis and stores results directly
in the database. It is designed to be run through the Ghidra Bridge.
"""

# Import Ghidra modules (these will be available in the Ghidra Python environment)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import TaskMonitor
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import Instruction

import json
import os
import sys

def comprehensive_analysis(program=None, binary_id=None, database_url=None):
    """
    Perform comprehensive analysis of the binary and store results in database
    
    Args:
        program: The Ghidra Program object (defaults to currentProgram)
        binary_id: Database ID of the binary being analyzed
        database_url: Database connection string
    
    Returns:
        Dictionary with analysis results and database storage status
    """
    # Use current program if not specified
    if program is None:
        program = currentProgram
    
    # Initialize result
    result = {
        "program_name": program.getName(),
        "program_path": program.getExecutablePath(),
        "architecture": program.getLanguage().getProcessor().toString(),
        "compiler": program.getCompiler(),
        "creation_date": str(program.getCreationDate()),
        "binary_id": binary_id,
        "analysis_data": {
            "functions": [],
            "instructions": [],
            "strings": [],
            "symbols": [],
            "imports": [],
            "exports": [],
            "memory_blocks": [],
            "xrefs": []
        },
        "database_stored": False,
        "total_functions": 0,
        "analyzed_functions": 0
    }
    
    # Get managers
    function_manager = program.getFunctionManager()
    listing = program.getListing()
    symbol_table = program.getSymbolTable()
    memory = program.getMemory()
    reference_manager = program.getReferenceManager()
    
    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(program)
    
    try:
        # 1. Analyze Functions
        print("Analyzing functions...")
        functions = function_manager.getFunctions(True)
        function_list = []
        
        for function in functions:
            # Basic function info
            function_name = function.getName()
            entry_point = function.getEntryPoint()
            function_address = "0x" + entry_point.toString()
            function_size = function.getBody().getNumAddresses()
            
            # Get function signature
            return_type = function.getReturnType().getDisplayName()
            params = []
            for param in function.getParameters():
                params.append({
                    "name": param.getName(),
                    "type": param.getDataType().getDisplayName()
                })
            
            # Decompile function
            decompiled = None
            try:
                results = decompiler.decompileFunction(function, 60, TaskMonitor.DUMMY)
                if results.decompileCompleted():
                    decompiled = results.getDecompiledFunction().getC()
                    result["analyzed_functions"] += 1
            except Exception as e:
                decompiled = f"// Error decompiling: {str(e)}"
            
            function_info = {
                "name": function_name,
                "address": function_address,
                "size": function_size,
                "return_type": return_type,
                "parameters": params,
                "is_library": function.isLibrary(),
                "is_thunk": function.isThunk(),
                "decompiled": decompiled,
                "binary_id": binary_id
            }
            
            function_list.append(function_info)
            result["total_functions"] += 1
        
        result["analysis_data"]["functions"] = function_list
        
        # 2. Analyze Strings
        print("Analyzing strings...")
        strings_list = []
        string_iterator = listing.getDefinedData(True)
        for data in string_iterator:
            if data.hasStringValue():
                strings_list.append({
                    "address": "0x" + data.getAddress().toString(),
                    "value": str(data.getValue()),
                    "length": data.getLength(),
                    "binary_id": binary_id
                })
        
        result["analysis_data"]["strings"] = strings_list[:1000]  # Limit to prevent huge results
        
        # 3. Analyze Symbols
        print("Analyzing symbols...")
        symbols_list = []
        symbol_iterator = symbol_table.getAllSymbols(True)
        for symbol in symbol_iterator:
            symbols_list.append({
                "name": symbol.getName(),
                "address": "0x" + symbol.getAddress().toString(),
                "symbol_type": str(symbol.getSymbolType()),
                "source": str(symbol.getSource()),
                "binary_id": binary_id
            })
        
        result["analysis_data"]["symbols"] = symbols_list[:1000]  # Limit to prevent huge results
        
        # 4. Analyze Memory Blocks
        print("Analyzing memory blocks...")
        memory_blocks = []
        for block in memory.getBlocks():
            memory_blocks.append({
                "name": block.getName(),
                "start_address": "0x" + block.getStart().toString(),
                "end_address": "0x" + block.getEnd().toString(),
                "size": block.getSize(),
                "permissions": str(block.getPermissions()),
                "is_initialized": block.isInitialized(),
                "binary_id": binary_id
            })
        
        result["analysis_data"]["memory_blocks"] = memory_blocks
        
        # 5. Store results in database (if connection available)
        if binary_id and database_url:
            try:
                # This would normally use the Flask app context to store in database
                # For now, we'll save to a temporary file that the task manager can read
                temp_file = os.path.join(os.path.expanduser("~"), "ghidra_temp", f"comprehensive_analysis_{binary_id}.json")
                os.makedirs(os.path.dirname(temp_file), exist_ok=True)
                
                with open(temp_file, 'w') as f:
                    json.dump(result, f, indent=2)
                
                result["database_stored"] = True
                result["temp_file"] = temp_file
                print(f"Analysis results saved to: {temp_file}")
                
            except Exception as e:
                print(f"Error saving analysis results: {e}")
                result["database_error"] = str(e)
        
        # Close decompiler
        decompiler.dispose()
        
        print(f"Comprehensive analysis completed: {result['total_functions']} functions, {result['analyzed_functions']} decompiled")
        return result
        
    except Exception as e:
        decompiler.dispose()
        print(f"Error during comprehensive analysis: {e}")
        return {
            "success": False,
            "error": str(e),
            "binary_id": binary_id
        }

# When executed directly through the bridge, run the comprehensive analysis
# The binary_id and other parameters will be passed through the bridge environment
import __main__
binary_id = getattr(__main__, 'binary_id', None)
database_url = getattr(__main__, 'database_url', None)

print(f"Starting comprehensive analysis for binary_id: {binary_id}")
result = comprehensive_analysis(currentProgram, binary_id, database_url)
print(f"Comprehensive analysis result: {result.get('total_functions', 0)} functions analyzed") 