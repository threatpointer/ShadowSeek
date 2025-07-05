"""
Quick Analysis Script for Ghidra Bridge

This script extracts key binary information and saves it as JSON.
Optimized for speed and completeness.
"""

import json
import os
import time
from ghidra.program.model.symbol import SymbolType

def quick_analysis(program=None, output_dir=None):
    """
    Perform quick analysis of a program and save results as JSON
    
    Args:
        program: The Ghidra Program object (defaults to currentProgram)
        output_dir: Directory to save output JSON (defaults to temp directory)
    
    Returns:
        Dictionary with analysis results
    """
    start_time = time.time()
    
    # Use current program if not specified
    if program is None:
        program = currentProgram
    
    # Use temp directory if not specified
    if output_dir is None:
        output_dir = "/tmp"
    
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Get program info
    program_name = program.getName()
    program_path = program.getExecutablePath()
    
    # Initialize result
    result = {
        "program_info": {
            "name": program_name,
            "path": program_path,
            "architecture": str(program.getLanguage().getProcessor()),
            "compiler": str(program.getCompiler()),
            "creation_date": str(program.getCreationDate()),
            "language_id": str(program.getLanguageID())
        },
        "functions": [],
        "imports": [],
        "exports": [],
        "strings": [],
        "symbols": [],
        "memory_map": []
    }
    
    # Get functions
    print("Extracting functions...")
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True = forward order
    
    for func in functions:
        entry_point = func.getEntryPoint()
        function_info = {
            "name": func.getName(),
            "address": "0x" + entry_point.toString(),
            "size": func.getBody().getNumAddresses(),
            "is_library": func.isLibrary(),
            "is_thunk": func.isThunk(),
            "has_vars": func.hasVars(),
            "calling_convention": func.getCallingConventionName(),
            "parameter_count": len(func.getParameters()) if func.getParameters() else 0,
            "return_type": str(func.getReturnType())
        }
        result["functions"].append(function_info)
    
    # Get imports
    print("Extracting imports...")
    symbol_table = program.getSymbolTable()
    external_symbols = symbol_table.getExternalSymbols()
    
    for symbol in external_symbols:
        import_info = {
            "name": symbol.getName(),
            "address": "0x" + symbol.getAddress().toString(),
            "library": symbol.getParentNamespace().getName() if symbol.getParentNamespace() else "unknown",
            "namespace": str(symbol.getParentNamespace())
        }
        result["imports"].append(import_info)
    
    # Get exports
    print("Extracting exports...")
    export_symbols = [s for s in symbol_table.getExternalEntryPointSymbols()]
    
    for symbol in export_symbols:
        export_info = {
            "name": symbol.getName(),
            "address": "0x" + symbol.getAddress().toString(),
            "namespace": str(symbol.getParentNamespace())
        }
        result["exports"].append(export_info)
    
    # Get strings (optimized approach)
    print("Extracting strings...")
    from ghidra.program.model.util import CodeUnitIterator
    from ghidra.program.model.listing import CodeUnit
    
    # Use the built-in string references
    string_refs = []
    for ref in program.getReferenceManager().getReferencesTo(program.getMemory().getAllInitializedAddressSet()):
        if ref.getReferenceType().isData() and ref.getToAddress() is not None:
            data = program.getListing().getDataAt(ref.getToAddress())
            if data is not None and data.hasStringValue():
                string_refs.append({
                    "address": "0x" + ref.getToAddress().toString(),
                    "value": data.getValue().toString(),
                    "length": len(data.getValue().toString()),
                    "type": str(data.getDataType())
                })
    
    # Limit to 1000 strings to avoid overwhelming output
    result["strings"] = string_refs[:1000]
    
    # Get symbols (excluding functions, imports, exports)
    print("Extracting symbols...")
    all_symbols = []
    for symbol in symbol_table.getAllSymbols(True):
        if symbol.getSymbolType() not in [SymbolType.FUNCTION, SymbolType.EXTERNAL]:
            symbol_info = {
                "name": symbol.getName(),
                "address": "0x" + symbol.getAddress().toString(),
                "type": str(symbol.getSymbolType()),
                "namespace": str(symbol.getParentNamespace())
            }
            all_symbols.append(symbol_info)
    
    # Limit to 1000 symbols to avoid overwhelming output
    result["symbols"] = all_symbols[:1000]
    
    # Get memory map
    print("Extracting memory map...")
    memory = program.getMemory()
    for block in memory.getBlocks():
        block_info = {
            "name": block.getName(),
            "start": "0x" + block.getStart().toString(),
            "end": "0x" + block.getEnd().toString(),
            "size": block.getSize(),
            "permissions": {
                "read": block.isRead(),
                "write": block.isWrite(),
                "execute": block.isExecute(),
                "volatile": block.isVolatile()
            }
        }
        result["memory_map"].append(block_info)
    
    # Calculate stats
    result["stats"] = {
        "function_count": len(result["functions"]),
        "import_count": len(result["imports"]),
        "export_count": len(result["exports"]),
        "string_count": len(result["strings"]),
        "symbol_count": len(result["symbols"]),
        "memory_block_count": len(result["memory_map"]),
        "analysis_time_seconds": time.time() - start_time
    }
    
    # Save to file
    output_file = os.path.join(output_dir, program_name + "_analysis.json")
    try:
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)
        print(f"Analysis saved to {output_file}")
    except Exception as e:
        print(f"Error saving analysis to file: {e}")
    
    return result

# When executed directly through the bridge, run the analysis
result = quick_analysis(currentProgram, "/tmp") 