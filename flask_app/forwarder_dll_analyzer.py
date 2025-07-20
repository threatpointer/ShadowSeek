#!/usr/bin/env python3
"""
Forwarder DLL Analyzer

Handles Windows API Set / Forwarder DLLs that contain no actual code,
only forwarding information to real implementation DLLs.
"""

import os
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class ForwarderDLLAnalyzer:
    """Analyzer for Windows API Set / Forwarder DLLs"""
    
    def __init__(self, ghidra_install_dir: str, projects_dir: str, scripts_dir: str):
        self.ghidra_install_dir = ghidra_install_dir
        self.projects_dir = projects_dir
        self.scripts_dir = scripts_dir
    
    def analyze_forwarder_dll(self, binary_id: str, binary_path: str) -> Dict:
        """
        Analyze a forwarder DLL to extract forwarding information
        
        Args:
            binary_id: Unique identifier for the binary
            binary_path: Path to the binary file
            
        Returns:
            Dictionary containing forwarder analysis results
        """
        logger.info(f"Starting forwarder DLL analysis for binary {binary_id}")
        
        result = {
            "success": False,
            "is_forwarder": False,
            "forwarding_entries": [],
            "target_dlls": set(),
            "analysis_time": 0,
            "error": None
        }
        
        import time
        start_time = time.time()
        
        try:
            # Create forwarder analysis script in temp directory to avoid Flask file watcher
            script_content = self._create_forwarder_analysis_script(binary_id)
            temp_script_dir = Path("temp/scripts")
            temp_script_dir.mkdir(parents=True, exist_ok=True)
            script_path = temp_script_dir / "analyze_forwarder.py"
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            # Run Ghidra analysis
            project_name = f"ForwarderAnalysis_{binary_id}_{int(time.time())}"
            analysis_result = self._run_ghidra_analysis(binary_path, project_name, str(script_path))
            
            if analysis_result:
                # Parse results
                results_file = Path("temp/ghidra_temp/forwarder_analysis_results.json")
                if results_file.exists():
                    with open(results_file) as f:
                        ghidra_results = json.load(f)
                    
                    result.update(ghidra_results)
                    result["target_dlls"] = list(result["target_dlls"])  # Convert set to list for JSON
                    result["success"] = True
                    
                    # Determine if this is a forwarder DLL
                    result["is_forwarder"] = (
                        len(result["forwarding_entries"]) > 0 and
                        len(result["target_dlls"]) > 0 and
                        ghidra_results.get("function_count", 0) == 0
                    )
                    
                    logger.info(f"Forwarder analysis completed: {len(result['forwarding_entries'])} forwarding entries found")
                else:
                    result["error"] = "Results file not found"
            else:
                result["error"] = "Ghidra analysis failed"
        
        except Exception as e:
            logger.error(f"Error in forwarder DLL analysis: {e}")
            result["error"] = str(e)
        
        finally:
            result["analysis_time"] = time.time() - start_time
        
        return result
    
    def _create_forwarder_analysis_script(self, binary_id: str) -> str:
        """Create the Ghidra script for forwarder DLL analysis"""
        
        return f'''#!/usr/bin/env python
# Forwarder DLL Analysis Script for Ghidra
# @category Analysis

import os
import sys
import json
import time

def safe_str(value):
    """Safely convert to string"""
    try:
        return str(value) if value is not None else ""
    except:
        return "[ERROR_CONVERTING]"

def analyze_forwarder_dll():
    """Analyze DLL for API forwarding patterns"""
    
    print("=== FORWARDER DLL ANALYSIS ===")
    
    result = {{
        "binary_id": "{binary_id}",
        "program_name": "",
        "function_count": 0,
        "forwarding_entries": [],
        "target_dlls": set(),
        "export_count": 0,
        "analysis_time": 0,
        "success": True
    }}
    
    start_time = time.time()
    
    try:
        program = currentProgram
        result["program_name"] = program.getName()
        print("Program: " + program.getName())
        
        # Get managers
        symbol_table = program.getSymbolTable()
        function_manager = program.getFunctionManager()
        listing = program.getListing()
        memory = program.getMemory()
        
        # Count actual functions
        all_functions = function_manager.getFunctions(True)
        function_count = 0
        for func in all_functions:
            function_count += 1
        
        result["function_count"] = function_count
        print("Functions found: " + str(function_count))
        
        # Analyze symbols for forwarding patterns
        forwarding_entries = []
        target_dlls = set()
        export_count = 0
        
        print("\\nAnalyzing symbols for forwarding...")
        
        for symbol in symbol_table.getDefinedSymbols():
            if not symbol.isExternal():
                symbol_name = safe_str(symbol.getName())
                symbol_addr = str(symbol.getAddress())
                
                # Skip internal symbols
                if (symbol_name.startswith("FUN_") or 
                    symbol_name.startswith("DAT_") or
                    symbol_name.startswith("LAB_") or
                    symbol_name.startswith("SUB_")):
                    continue
                
                export_count += 1
                
                # Check if this symbol points to forwarded data
                try:
                    address = symbol.getAddress()
                    data = listing.getDataAt(address)
                    
                    if data and data.hasStringValue():
                        string_value = safe_str(data.getValue())
                        
                        # Check if this looks like a forwarded export
                        if "." in string_value and ("-" in string_value or string_value.count(".") >= 2):
                            # Parse forwarding format: "target_dll.function_name"
                            parts = string_value.split(".", 1)
                            if len(parts) == 2:
                                target_dll = parts[0].strip()
                                target_function = parts[1].strip()
                                
                                forwarding_entry = {{
                                    "export_name": symbol_name,
                                    "export_address": symbol_addr,
                                    "target_dll": target_dll,
                                    "target_function": target_function,
                                    "forwarding_string": string_value
                                }}
                                
                                forwarding_entries.append(forwarding_entry)
                                target_dlls.add(target_dll)
                                
                                print("Found forwarding: " + symbol_name + " -> " + string_value)
                    
                except Exception as sym_error:
                    print("Error analyzing symbol " + symbol_name + ": " + str(sym_error))
        
        result["forwarding_entries"] = forwarding_entries
        result["target_dlls"] = list(target_dlls)  # Convert set to list
        result["export_count"] = export_count
        
        print("\\nForwarding analysis complete:")
        print("  Exports found: " + str(export_count))
        print("  Forwarding entries: " + str(len(forwarding_entries)))
        print("  Target DLLs: " + str(len(target_dlls)))
        
        # Determine if this is a forwarder DLL
        is_forwarder = (len(forwarding_entries) > 0 and 
                       len(target_dlls) > 0 and 
                       function_count == 0)
        
        print("  Is forwarder DLL: " + str(is_forwarder))
        
    except Exception as e:
        print("SCRIPT ERROR: " + str(e))
        result["success"] = False
        result["error"] = str(e)
        import traceback
        traceback.print_exc()
    
    finally:
        result["analysis_time"] = time.time() - start_time
    
    # Save results to file
    try:
        import os
        try:
            os.makedirs("temp/ghidra_temp")
        except OSError:
            pass  # Directory already exists
        
        with open("temp/ghidra_temp/forwarder_analysis_results.json", "w") as f:
            # Convert sets to lists for JSON serialization
            json_result = dict(result)
            if isinstance(json_result.get("target_dlls"), set):
                json_result["target_dlls"] = list(json_result["target_dlls"])
            
            json.dump(json_result, f, indent=2)
        
        print("\\nResults saved to temp/ghidra_temp/forwarder_analysis_results.json")
        
    except Exception as save_error:
        print("Error saving results: " + str(save_error))
    
    print("\\n=== FORWARDER ANALYSIS COMPLETE ===")

# Run the analysis
if __name__ == "__main__":
    analyze_forwarder_dll()
'''
    
    def _run_ghidra_analysis(self, binary_path: str, project_name: str, script_path: str) -> bool:
        """Run Ghidra headless analysis"""
        
        headless_path = os.path.join(self.ghidra_install_dir, "support", "analyzeHeadless.bat")
        
        # Handle both script names and full script paths
        if os.path.isabs(script_path) or os.path.sep in script_path:
            # Full path - use the directory and script name
            script_dir = os.path.abspath(os.path.dirname(script_path))
            script_name = os.path.basename(script_path)
        else:
            # Just script name - use default scripts directory
            script_dir = os.path.abspath(self.scripts_dir)
            script_name = script_path
        
        cmd = [
            headless_path,
            os.path.abspath(self.projects_dir),
            project_name,
            "-import", os.path.abspath(binary_path),
            "-overwrite",  # Allow overwriting existing files in project
            "-scriptPath", script_dir,
            "-postScript", script_name
        ]
        
        try:
            # For Windows, create the command as a single string
            cmd_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in cmd)
            logger.info(f"Running Ghidra forwarder analysis: {cmd_str}")
            
            process = subprocess.run(
                cmd_str,
                capture_output=True,
                text=True,
                timeout=60,  # 1 minute timeout for forwarder analysis
                cwd=os.path.dirname(self.projects_dir),
                shell=True  # Required for Windows batch file execution
            )
            
            if process.returncode == 0:
                logger.info("Ghidra forwarder analysis completed successfully")
                return True
            else:
                logger.error(f"Ghidra forwarder analysis failed: {process.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Ghidra forwarder analysis timed out")
            return False
        except Exception as e:
            logger.error(f"Error running Ghidra forwarder analysis: {e}")
            return False
    
    def format_forwarder_summary(self, analysis_result: Dict) -> str:
        """Format forwarder analysis results for display"""
        
        if not analysis_result.get("success"):
            return f"Forwarder analysis failed: {{analysis_result.get('error', 'Unknown error')}}"
        
        if not analysis_result.get("is_forwarder"):
            return "Not a forwarder DLL - contains actual code"
        
        forwarding_count = len(analysis_result.get("forwarding_entries", []))
        target_count = len(analysis_result.get("target_dlls", []))
        
        return f"API Forwarder DLL: {{forwarding_count}} forwards to {{target_count}} target DLLs"
    
    def get_forwarding_details(self, analysis_result: Dict) -> List[Dict]:
        """Get detailed forwarding information for UI display"""
        
        if not analysis_result.get("is_forwarder"):
            return []
        
        forwarding_entries = analysis_result.get("forwarding_entries", [])
        
        # Group by target DLL for better organization
        grouped = {{}}
        for entry in forwarding_entries:
            target_dll = entry["target_dll"]
            if target_dll not in grouped:
                grouped[target_dll] = []
            grouped[target_dll].append(entry)
        
        # Format for UI
        details = []
        for target_dll, entries in grouped.items():
            details.append({{
                "target_dll": target_dll,
                "forward_count": len(entries),
                "forwards": entries
            }})
        
        return details 