#!/usr/bin/env python
"""Simple analysis script for Ghidra Bridge"""

import os
import sys
import json

# Use configurable temp directory instead of hardcoded user home
temp_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
os.makedirs(temp_dir, exist_ok=True)

def simple_analysis():
    """Simple analysis that returns basic binary information"""
    result = {
        "analysis_type": "simple",
        "success": True,
        "functions": [],
        "strings": [],
        "imports": [],
        "exports": []
    }
    
    try:
        # Access current program (should be available in Ghidra script context)
        if 'currentProgram' in globals():
            program = currentProgram
            
            # Get functions
            function_manager = program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            for func in functions:
                result["functions"].append({
                    "name": func.getName(),
                    "address": str(func.getEntryPoint()),
                    "size": func.getBody().getNumAddresses()
                })
            
            # Get strings
            listing = program.getListing()
            string_table = listing.getDefinedData(True)
            
            for data in string_table:
                if data.hasStringValue():
                    result["strings"].append({
                        "address": str(data.getAddress()),
                        "value": data.getValue()
                    })
            
        # Save results to temp file
        output_file = os.path.join(temp_dir, "ghidra_analysis.json")
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
            
        print(f"Analysis results saved to: {output_file}")
        return result
        
    except Exception as e:
        result["success"] = False
        result["error"] = str(e)
        print(f"Analysis failed: {e}")
        return result

if __name__ == "__main__":
    simple_analysis() 