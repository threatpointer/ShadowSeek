#!/usr/bin/env python
# Decompile Exports Script for Ghidra
# @category Analysis

import os
import sys
import json
import time

# Import Ghidra types that will be needed
from ghidra.program.model.symbol import SourceType

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

def decompile_exports(program=None, binary_id=None, max_exports=10):
    """
    Decompile exported functions and return results
    
    Args:
        program: The Ghidra Program object (defaults to currentProgram)
        binary_id: Database ID of the binary
        max_exports: Maximum number of exports to decompile (default 10)
        
    Returns:
        Dictionary with decompilation results
    """
    # Use current program if not specified
    if program is None:
        program = currentProgram
    
    # Initialize result
    result = {
        "success": True,
        "binary_id": binary_id,
        "program_name": safe_str(program.getName()),
        "exports_found": 0,
        "exports_decompiled": 0,
        "failed_exports": 0,
        "decompiled_functions": [],
        "analysis_time": 0
    }
    
    start_time = time.time()
    
    try:
        print("Starting export decompilation analysis...")
        
        # Get symbol table and function manager
        symbol_table = program.getSymbolTable()
        function_manager = program.getFunctionManager()
        listing = program.getListing()
        
        # Get all global symbols that could be exports
        exports = []
        all_symbols = symbol_table.getAllSymbols(True)
        
        for symbol in all_symbols:
            # Look for symbols that are likely exports:
            # - Not external (not imports)
            # - Global or primary symbols
            # - Have real addresses
            if (not symbol.isExternal() and 
                (symbol.isGlobal() or symbol.isPrimary()) and
                symbol.getAddress() is not None):
                
                symbol_type = str(symbol.getSymbolType())
                symbol_name = safe_str(symbol.getName())
                
                # Focus on Function symbols and skip obvious internal/generated symbols
                if (symbol_type == "Function" and
                    not symbol_name.startswith("_") and
                    not symbol_name.startswith(".") and
                    not symbol_name.startswith("$") and
                    not symbol_name.startswith("FUN_") and
                    not symbol_name.startswith("SUB_") and
                    len(symbol_name) > 1):
                    
                    exports.append({
                        'name': symbol_name,
                        'address': str(symbol.getAddress()),
                        'type': symbol_type,
                        'symbol': symbol
                    })
        
        # Also check for DLL exports using different methods
        try:
            # Method: Check for symbols in .text section that might be exports
            text_symbols = []
            for symbol in symbol_table.getDefinedSymbols():
                if (not symbol.isExternal() and 
                    symbol.getAddress() is not None):
                    
                    symbol_name = safe_str(symbol.getName())
                    symbol_type = str(symbol.getSymbolType())
                    
                    # For DLLs, look for any non-external symbols that could be exports
                    if (symbol_name and len(symbol_name) > 1 and
                        not symbol_name.startswith("FUN_") and
                        not symbol_name.startswith("SUB_") and
                        not symbol_name.startswith("LAB_") and
                        not symbol_name.startswith("DAT_") and
                        not symbol_name.startswith("s_") and
                        not symbol_name.startswith("PTR_") and
                        not symbol_name.endswith("_entry") and
                        not any(exp['name'] == symbol_name for exp in exports)):
                        
                        exports.append({
                            'name': symbol_name,
                            'address': str(symbol.getAddress()),
                            'type': 'Symbol_' + symbol_type,
                            'symbol': symbol
                        })
                        
        except Exception as symbol_error:
            print("Note: Could not access symbol list: " + str(symbol_error))
        
        result["exports_found"] = len(exports)
        print("Found " + str(len(exports)) + " potential exports")
        
        # Limit exports to prevent overwhelming analysis
        exports_to_analyze = exports[:max_exports]
        
        # Initialize decompiler
        from ghidra.app.decompiler import DecompInterface
        from ghidra.util.task import TaskMonitor
        
        decompiler = DecompInterface()
        decompiler.openProgram(program)
        
        print("Starting decompilation of " + str(len(exports_to_analyze)) + " exports...")
        
        # Debug: Show first few exports
        for i, export in enumerate(exports[:3]):
            print("Export " + str(i) + ": " + str(export))
        
        for export in exports_to_analyze:
            try:
                export_name = export['name']
                export_address = export['address']
                
                print("Processing export: " + export_name + " at " + export_address)
                
                # Parse address more carefully
                try:
                    if export_address.startswith('0x'):
                        address = program.getAddressFactory().getAddress(export_address)
                    else:
                        # Try to parse as hex without 0x prefix
                        address = program.getAddressFactory().getAddress("0x" + export_address)
                    
                    if address is None:
                        print("Failed to parse address: " + export_address)
                        result["failed_exports"] += 1
                        continue
                        
                    print("Parsed address successfully: " + str(address))
                    
                except Exception as addr_error:
                    print("Address parsing error for " + export_address + ": " + str(addr_error))
                    result["failed_exports"] += 1
                    continue
                
                # Check if there's already a function at this address
                function = function_manager.getFunctionAt(address)
                
                if function is None:
                    # For DLL exports, check if this is a forwarded export or table entry
                    try:
                        # Check if there's code at this address
                        instruction = listing.getInstructionAt(address)
                        if instruction is not None:
                            print("Found instruction at export address: " + str(instruction))
                            # Try to create function
                            function = function_manager.createFunction(export_name, address, None, SourceType.USER_DEFINED)
                            if function:
                                print("Created function: " + export_name)
                            else:
                                print("Failed to create function at: " + export_address)
                                continue
                        else:
                            print("No instruction at export address: " + export_address)
                            
                            # For DLLs, check if this might be a data reference to actual function
                            try:
                                # Try to read the data at this address as a pointer
                                data = listing.getDataAt(address)
                                if data is not None and data.hasStringValue():
                                    print("Export appears to be forwarded: " + str(data.getValue()))
                                    continue
                                elif data is not None:
                                    print("Export points to data: " + str(data))
                                    # Try to see if it's a pointer to code
                                    if data.getDataType().getName().endswith("*"):
                                        try:
                                            # Try to dereference pointer
                                            ref_addr = data.getValue()
                                            if ref_addr is not None:
                                                ref_instruction = listing.getInstructionAt(ref_addr)
                                                if ref_instruction is not None:
                                                    print("Found code via pointer: " + str(ref_addr))
                                                    function = function_manager.createFunction(export_name, ref_addr, None, SourceType.USER_DEFINED)
                                                    if function:
                                                        print("Created function via pointer: " + export_name)
                                                        # Update address for decompilation
                                                        address = ref_addr
                                                    else:
                                                        print("Failed to create function via pointer")
                                                        continue
                                        except Exception as deref_error:
                                            print("Could not dereference pointer: " + str(deref_error))
                                
                                # If still no function, try to find nearby code
                                if function is None:
                                    print("Searching for nearby code...")
                                    # Search in a small range around the export address
                                    for offset in [0, 4, 8, -4, -8, 16, -16]:
                                        try:
                                            nearby_addr = address.add(offset)
                                            nearby_instruction = listing.getInstructionAt(nearby_addr)
                                            if nearby_instruction is not None:
                                                print("Found nearby instruction at offset " + str(offset) + ": " + str(nearby_addr))
                                                function = function_manager.createFunction(export_name, nearby_addr, None, SourceType.USER_DEFINED)
                                                if function:
                                                    print("Created function at nearby address: " + export_name)
                                                    address = nearby_addr  # Update for decompilation
                                                    break
                                        except Exception:
                                            continue
                                
                                if function is None:
                                    print("Could not find executable code for export: " + export_name)
                                    result["failed_exports"] += 1
                                    continue
                                    
                            except Exception as data_error:
                                print("Error analyzing export data: " + str(data_error))
                                result["failed_exports"] += 1
                                continue
                            
                    except Exception as create_error:
                        print("Error creating function " + export_name + ": " + str(create_error))
                        result["failed_exports"] += 1
                        continue
                
                if function is not None:
                    # Decompile the function
                    try:
                        decomp_results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY)
                        
                        if decomp_results and decomp_results.decompileCompleted():
                            c_code = safe_str(decomp_results.getDecompiledFunction().getC())
                            
                            function_info = {
                                "name": export_name,
                                "address": export_address,
                                "signature": safe_str(function.getSignature().getPrototypeString()),
                                "decompiled_code": c_code,
                                "body_size": function.getBody().getNumAddresses(),
                                "parameter_count": len(function.getParameters()) if function.getParameters() else 0,
                                "return_type": safe_str(function.getReturnType()),
                                "calling_convention": safe_str(function.getCallingConventionName()),
                                "is_export": True,
                                "export_type": export['type']
                            }
                            
                            result["decompiled_functions"].append(function_info)
                            result["exports_decompiled"] += 1
                            print("Successfully decompiled: " + export_name)
                            
                        else:
                            error_msg = "Decompilation failed"
                            if decomp_results:
                                error_msg = safe_str(decomp_results.getErrorMessage())
                            print("Failed to decompile " + export_name + ": " + error_msg)
                            result["failed_exports"] += 1
                            
                    except Exception as decomp_error:
                        print("Error decompiling " + export_name + ": " + str(decomp_error))
                        result["failed_exports"] += 1
                else:
                    print("No function available for export: " + export_name)
                    result["failed_exports"] += 1
                    
            except Exception as export_error:
                print("Error processing export " + export.get('name', 'unknown') + ": " + str(export_error))
                result["failed_exports"] += 1
        
        # Close decompiler
        decompiler.dispose()
        
        result["analysis_time"] = time.time() - start_time
        
        print("Export decompilation completed:")
        print("  Found: " + str(result["exports_found"]) + " exports")
        print("  Decompiled: " + str(result["exports_decompiled"]) + " exports")
        print("  Failed: " + str(result["failed_exports"]) + " exports")
        print("  Time: " + str(result["analysis_time"]) + " seconds")
        
        return result
        
    except Exception as e:
        print("Error in export decompilation: " + str(e))
        result["success"] = False
        result["error"] = str(e)
        result["analysis_time"] = time.time() - start_time
        return result

# Main execution when run through Ghidra headless
if __name__ == "__main__":
    try:
        # Parse script arguments passed by Ghidra headless
        binary_id = None
        max_exports = 10
        
        # Get script arguments
        try:
            # Method 1: Try environment variables
            binary_id = os.environ.get('GHIDRA_BINARY_ID')
            max_exports = int(os.environ.get('GHIDRA_MAX_EXPORTS', '10'))
            
            # Method 2: Try to parse from script args if available
            if 'getScriptArgs' in globals():
                args = getScriptArgs()
                if args:
                    for arg in args:
                        if '=' in arg:
                            key, value = arg.split('=', 1)
                            if key == 'binary_id':
                                binary_id = value
                            elif key == 'max_exports':
                                max_exports = int(value)
        except Exception as parse_error:
            print("Warning: Could not parse script arguments: " + str(parse_error))
        
        print("Starting export decompilation with binary_id: " + str(binary_id))
        
        # Run export decompilation
        result = decompile_exports(
            program=currentProgram, 
            binary_id=binary_id,
            max_exports=max_exports
        )
        
        # Save results to temp file for retrieval
        temp_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
        try:
            os.makedirs(temp_dir)
        except:
            pass
        
        output_file = os.path.join(temp_dir, "export_decompilation_results.json")
        
        try:
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2)
            print("Results saved to: " + output_file)
        except Exception as save_error:
            print("Error saving results: " + str(save_error))
            # Try alternative location
            try:
                alt_output = os.path.join(os.getcwd(), "export_decompilation_results.json") 
                with open(alt_output, 'w') as f:
                    json.dump(result, f, indent=2)
                print("Results saved to alternative location: " + alt_output)
            except:
                print("Failed to save results to any location")
        
    except Exception as main_error:
        print("Error in main execution: " + str(main_error))
        # Save error result
        error_result = {
            "success": False,
            "error": str(main_error),
            "exports_found": 0,
            "exports_decompiled": 0,
            "failed_exports": 0
        }
        
        try:
            temp_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
            os.makedirs(temp_dir, exist_ok=True)
            output_file = os.path.join(temp_dir, "export_decompilation_results.json")
            with open(output_file, 'w') as f:
                json.dump(error_result, f, indent=2)
        except:
            pass 