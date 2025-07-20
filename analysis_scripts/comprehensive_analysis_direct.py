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

import os
import sys
import json
import time

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
    analysis_start_time = time.time()
    result = {
        "success": True,
        "analysis_type": "comprehensive",
        "binary_id": binary_id,
        "data": {
            "metadata": {
                "program_name": program.getName(),
                "language": str(program.getLanguage().getLanguageDescription()),
                "processor": str(program.getLanguage().getProcessor()),
                "endianness": str(program.getLanguage().isBigEndian()),
                "address_size": program.getAddressFactory().getDefaultAddressSpace().getSize(),
                "executable_path": str(program.getExecutablePath()) if program.getExecutablePath() else "",
                "executable_format": str(program.getExecutableFormat()),
                "executable_md5": str(program.getExecutableMD5()) if program.getExecutableMD5() else "",
                "creation_date": str(program.getCreationDate()) if program.getCreationDate() else "",
                "image_base": str(program.getImageBase()),
                "min_address": str(program.getMinAddress()),
                "max_address": str(program.getMaxAddress())
            },
            "statistics": {
                "total_functions": 0,
                "total_instructions": 0,
                "total_strings": 0,
                "total_symbols": 0,
                "total_imports": 0,
                "total_exports": 0,
                "memory_blocks": 0,
                "analysis_time": 0,
                "analysis_version": "1.0"
            },
            "functions": [],
            "memoryBlocks": [],
            "strings": [],
            "symbols": [],
            "imports": [],
            "exports": []
        }
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
        function_manager = program.getFunctionManager()
        functions = function_manager.getFunctions(True)
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        
        functions_data = []
        instruction_count = 0
        
        for function in functions:
            function_info = {
                "name": function.getName(),
                "entry": str(function.getEntryPoint()),
                "address": str(function.getEntryPoint()),
                "bodySize": function.getBody().getNumAddresses(),
                "signature": function.getSignature().getPrototypeString(),
                "callingConvention": str(function.getCallingConventionName()),
                "returnType": str(function.getReturnType()),
                "stackFrame": function.getStackFrame().getFrameSize(),
                "flags": {
                    "isThunk": function.isThunk(),
                    "isExternal": function.isExternal(),
                    "hasNoReturn": function.hasNoReturn(),
                    "hasVarArgs": function.hasVarArgs(),
                    "isInline": function.isInline()
                }
            }
            
            # Get decompiled code
            try:
                results = decompiler.decompileFunction(function, 30, None)
                if results and results.decompileCompleted():
                    function_info["decompiled"] = results.getDecompiledFunction().getC()
                else:
                    error_msg = results.getErrorMessage() if results else 'Unknown error'
                    function_info["decompiled"] = "// Error decompiling: " + str(error_msg)
            except Exception as e:
                function_info["decompiled"] = "// Error decompiling: " + str(e)
            
            # Count instructions
            instruction_count += function.getBody().getNumAddresses()
            functions_data.append(function_info)
        
        result["data"]["functions"] = functions_data
        
        # 2. Analyze Strings
        print("Analyzing strings...")
        strings_data = []
        listing = program.getListing()
        memory = program.getMemory()
        
        def safe_str(value):
            """Safely convert to string, handling Unicode in Jython"""
            try:
                if value is None:
                    return ""
                # Convert to string and encode/decode to handle Unicode safely
                str_val = str(value)
                
                # Check if we're dealing with Unicode in Jython/Python 2
                try:
                    if isinstance(str_val, unicode):  # Jython/Python 2 check
                        return str_val.encode('utf-8', 'replace').decode('utf-8', 'replace')
                except NameError:
                    # unicode type not available (Python 3 or other environments)
                    pass
                    
                return str_val
            except (UnicodeEncodeError, UnicodeDecodeError):
                # If all else fails, return a safe representation
                try:
                    return repr(value)
                except:
                    return "[ENCODING_ERROR]"
            except Exception:
                return str(type(value))
        
        for block in memory.getBlocks():
            if block.isInitialized():
                search_set = program.getAddressFactory().getAddressSet(block.getStart(), block.getEnd())
                found_strings = currentProgram.getListing().getDefinedData(search_set, True)
                
                for data in found_strings:
                    if data.hasStringValue():
                        try:
                            string_value = safe_str(data.getValue())
                            strings_data.append({
                                "address": str(data.getAddress()),
                                "value": string_value[:200],  # Limit string length safely
                                "length": len(string_value),
                                "dataType": safe_str(data.getDataType())
                            })
                        except Exception as str_error:
                            # Skip problematic strings but continue processing
                            print("Warning: Skipped string at " + str(data.getAddress()) + " due to encoding error")
        
        result["data"]["strings"] = strings_data[:1000]  # Limit to prevent huge results
        
        # 3. Analyze Symbols
        print("Analyzing symbols...")
        symbols_data = []
        symbol_table = program.getSymbolTable()
        all_symbols = symbol_table.getAllSymbols(True)
        
        for symbol in all_symbols:
            symbols_data.append({
                "name": symbol.getName(),
                "address": str(symbol.getAddress()),
                "type": str(symbol.getSymbolType()),
                "source": str(symbol.getSource()),
                "namespace": symbol.getParentNamespace().getName()
            })
        
        result["data"]["symbols"] = symbols_data[:1000]  # Limit to prevent huge results
        
        # 4. Analyze Memory Blocks
        print("Analyzing memory blocks...")
        memory_blocks = []
        for block in memory.getBlocks():
            memory_blocks.append({
                "name": block.getName(),
                "start": str(block.getStart()),
                "end": str(block.getEnd()),
                "size": block.getSize(),
                "permissions": {
                    "read": block.isRead(),
                    "write": block.isWrite(),
                    "execute": block.isExecute(),
                    "initialized": block.isInitialized()
                }
            })
        
        result["data"]["memoryBlocks"] = memory_blocks
        
        # 5. Analyze Imports/Exports
        print("Analyzing imports...")
        imports_data = []
        symbol_table = program.getSymbolTable()
        external_symbols = symbol_table.getExternalSymbols()
        
        for symbol in external_symbols:
            import_info = {
                "name": safe_str(symbol.getName()),
                "address": str(symbol.getAddress()),
                "library": safe_str(symbol.getParentNamespace().getName() if symbol.getParentNamespace() else "unknown"),
                "module": safe_str(symbol.getParentNamespace().getName() if symbol.getParentNamespace() else "unknown"),
                "function_name": safe_str(symbol.getName()),
                "namespace": safe_str(str(symbol.getParentNamespace()))
            }
            imports_data.append(import_info)
        
        print("Analyzing exports...")
        exports_data = []
        
        # Method 1: Get symbols that are likely exports (global, non-external functions and data)
        all_symbols = symbol_table.getAllSymbols(True)
        for symbol in all_symbols:
            # Check if symbol is likely an export:
            # - Not external (not imported)
            # - Global or primary symbol
            # - Has a real address (not just a placeholder)
            if (not symbol.isExternal() and 
                (symbol.isGlobal() or symbol.isPrimary()) and
                symbol.getAddress() is not None):
                
                symbol_type = str(symbol.getSymbolType())
                # Include functions and data symbols that could be exports
                if symbol_type in ["Function", "Label", "Global"]:
                    export_info = {
                        "name": safe_str(symbol.getName()),
                        "address": str(symbol.getAddress()),
                        "function_name": safe_str(symbol.getName()),
                        "type": symbol_type,
                        "namespace": safe_str(str(symbol.getParentNamespace()))
                    }
                    exports_data.append(export_info)
        
        # Method 2: For PE files, try to get exports from the export table
        try:
            # Get entry point symbols which are often exports
            entry_points = symbol_table.getExternalEntryPointSymbols()
            for symbol in entry_points:
                if not symbol.isExternal():  # Make sure it's not an import
                    export_info = {
                        "name": safe_str(symbol.getName()),
                        "address": str(symbol.getAddress()),
                        "function_name": safe_str(symbol.getName()),
                        "type": "EntryPoint",
                        "namespace": safe_str(str(symbol.getParentNamespace()))
                    }
                    # Avoid duplicates
                    if not any(exp["name"] == export_info["name"] for exp in exports_data):
                        exports_data.append(export_info)
                        
        except Exception as export_error:
            print("Note: Could not access entry point symbols: " + str(export_error))
        
        # Method 3: Check functions that might be exports (public functions)
        try:
            functions = function_manager.getFunctions(True)
            for func in functions:
                # If function is not a library function and has a meaningful name
                if (not func.isExternal() and 
                    not func.getName().startswith("FUN_") and
                    not func.getName().startswith("SUB_") and
                    not func.getName().startswith("LAB_")):
                    
                    export_info = {
                        "name": safe_str(func.getName()),
                        "address": str(func.getEntryPoint()),
                        "function_name": safe_str(func.getName()),
                        "type": "Function",
                        "namespace": "Global"
                    }
                    # Avoid duplicates
                    if not any(exp["name"] == export_info["name"] for exp in exports_data):
                        exports_data.append(export_info)
                        
        except Exception as func_export_error:
            print("Note: Could not analyze function exports: " + str(func_export_error))
        
        # Add these to result
        result["data"]["imports"] = imports_data
        result["data"]["exports"] = exports_data
        
        # Update final statistics
        result["data"]["statistics"].update({
            "total_functions": len(functions_data),
            "total_instructions": instruction_count,
            "total_strings": len(strings_data),
            "total_symbols": len(symbols_data),
            "total_imports": len(imports_data),
            "total_exports": len(exports_data),
            "memory_blocks": len(memory_blocks),
            "analysis_time": time.time() - analysis_start_time
        })
        
        # 6. Store results to temp file for task manager to process
        if binary_id:
            # Use configurable temp directory
            temp_base_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
            
            # Create directory if it doesn't exist (Jython compatible)
            try:
                os.makedirs(temp_base_dir)
            except OSError:
                pass  # Directory already exists
                
            temp_file = os.path.join(temp_base_dir, "comprehensive_analysis_" + str(binary_id) + ".json")
            
            with open(temp_file, 'w') as f:
                json.dump(result, f, indent=2)
            
            print("Analysis results saved to: " + temp_file)
        
        # Close decompiler
        decompiler.dispose()
        
        print("Comprehensive analysis completed: " + str(result['data']['statistics']['total_functions']) + " functions, " + 
              str(result['data']['statistics']['total_strings']) + " strings, " + str(result['data']['statistics']['memory_blocks']) + " memory blocks")
        return result
    
    except Exception as e:
        print("Error during comprehensive analysis: " + str(e))
        import traceback
        traceback.print_exc()
        
        # Return error result
        error_result = {
            "success": False,
            "error": str(e),
            "binary_id": binary_id
        }
        
        # Save error result to temp file if possible
        if binary_id:
            try:
                temp_base_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
                
                # Create directory if it doesn't exist (Jython compatible)
                try:
                    os.makedirs(temp_base_dir)
                except OSError:
                    pass  # Directory already exists
                    
                temp_file = os.path.join(temp_base_dir, "comprehensive_analysis_" + str(binary_id) + ".json")
                
                with open(temp_file, 'w') as f:
                    json.dump(error_result, f, indent=2)
                print("Error result saved to: " + temp_file)
            except Exception as save_error:
                print("Could not save error result: " + str(save_error))
        
        return error_result

# When executed directly through Ghidra headless analyzer, parse script arguments
# Parameters are passed as: -postScript script.py binary_id=value skip_functions=value

# Parse script arguments passed by Ghidra headless
binary_id = None
database_url = None
skip_functions = 0

# Get script arguments from the Ghidra script environment
try:
    # In Ghidra headless, script args are available through getScriptArgs() if available
    # Otherwise, parse from argv or environment
    
    # Method 1: Try to get from script arguments
    if 'getScriptArgs' in globals():
        args = getScriptArgs()
        if args:
            for arg in args:
                if '=' in arg:
                    key, value = arg.split('=', 1)
                    if key == 'binary_id':
                        binary_id = value
                    elif key == 'database_url':
                        database_url = value
                    elif key == 'skip_functions':
                        skip_functions = int(value)
    
    # Method 2: Try to get from __main__ (bridge mode)
    if not binary_id:
        import __main__
        binary_id = getattr(__main__, 'binary_id', None)
        database_url = getattr(__main__, 'database_url', None)
        skip_functions = int(getattr(__main__, 'skip_functions', '0'))
    
    # Method 3: Parse from system arguments or environment
    if not binary_id:
        # Check for environment variables set by task manager
        binary_id = os.environ.get('GHIDRA_BINARY_ID')
        database_url = os.environ.get('DATABASE_URL')
        skip_functions = int(os.environ.get('GHIDRA_SKIP_FUNCTIONS', '0'))

except Exception as parse_error:
    print("Warning: Could not parse script arguments: " + str(parse_error))
    binary_id = None

print("Script arguments parsed - binary_id: " + str(binary_id) + ", skip_functions: " + str(skip_functions))
print("Starting comprehensive analysis for binary_id: " + str(binary_id))

if binary_id:
    result = comprehensive_analysis(currentProgram, binary_id, database_url)
    
    # Safely access result statistics for reporting
    try:
        if result and result.get('success') and 'data' in result and 'statistics' in result['data']:
            stats = result['data']['statistics']
            print("Comprehensive analysis completed: " + str(stats.get('total_functions', 0)) + " functions, " + 
                  str(stats.get('total_strings', 0)) + " strings, " + str(stats.get('memory_blocks', 0)) + " memory blocks")
        elif result and not result.get('success'):
            print("Comprehensive analysis failed: " + str(result.get('error', 'Unknown error')))
        else:
            print("Comprehensive analysis completed but result structure is incomplete")
    except Exception as reporting_error:
        print("Analysis completed but could not generate summary: " + str(reporting_error))
else:
    print("ERROR: No binary_id found - script arguments not parsed correctly")
    error_result = {
        "success": False,
        "error": "No binary_id provided to script",
        "binary_id": None
    }
    # Try to save error anyway
    try:
        temp_base_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
        
        # Create directory if it doesn't exist (Jython compatible)
        try:
            os.makedirs(temp_base_dir)
        except OSError:
            pass  # Directory already exists
            
        temp_file = os.path.join(temp_base_dir, "comprehensive_analysis_error.json")
        
        with open(temp_file, 'w') as f:
            json.dump(error_result, f, indent=2)
        print("Error result saved to: " + temp_file)
    except Exception as save_error:
        print("Could not save error result: " + str(save_error)) 