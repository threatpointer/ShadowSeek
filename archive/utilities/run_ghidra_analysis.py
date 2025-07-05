#!/usr/bin/env python3
"""
Run Ghidra analysis using the headless analyzer
"""

import os
import sys
import json
import subprocess
import tempfile
import time
from pathlib import Path

def find_ghidra_path():
    """Find Ghidra installation path"""
    # Check environment variable
    ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
    if ghidra_path and os.path.exists(ghidra_path):
        return ghidra_path
    
    # Check .env file
    env_path = Path('.env')
    if env_path.exists():
        with open(env_path, 'r') as f:
            for line in f:
                if line.startswith('GHIDRA_INSTALL_DIR='):
                    path = line.split('=', 1)[1].strip().strip('"\'')
                    if os.path.exists(path):
                        return path
    
    # Default path
    default_path = r'D:\1132-Ghidra\ghidra_11.3.2_PUBLIC'
    if os.path.exists(default_path):
        return default_path
    
    return None

def run_ghidra_analysis(binary_path, output_dir=None, project_name=None):
    """
    Run Ghidra analysis on a binary file
    
    Args:
        binary_path: Path to binary file
        output_dir: Directory to save output
        project_name: Ghidra project name
    
    Returns:
        Analysis results
    """
    # Find Ghidra path
    ghidra_path = find_ghidra_path()
    if not ghidra_path:
        print("Error: Ghidra installation not found")
        return None
    
    # Use default project name if not specified
    if not project_name:
        project_name = f"GhidraProject_{int(time.time())}"
    
    # Use temp directory if not specified
    if not output_dir:
        output_dir = os.path.join(os.getcwd(), "temp")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Create projects directory if it doesn't exist
    projects_dir = os.path.join(os.getcwd(), "ghidra_projects")
    os.makedirs(projects_dir, exist_ok=True)
    
    # Get path to headless analyzer
    if os.name == 'nt':
        headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
    else:
        headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless")
    
    # Get path to analysis script
    script_path = os.path.join(os.getcwd(), "analysis_scripts", "simple_analysis.py")
    
    # Create temp directory for output
    temp_dir = tempfile.mkdtemp(prefix="ghidra_analysis_")
    temp_output = os.path.join(temp_dir, "ghidra_analysis.json")
    
    # Run headless analyzer
    cmd = [
        headless_path,
        projects_dir,
        project_name,
        "-import", binary_path,
        "-scriptPath", os.path.dirname(script_path),
        "-postScript", os.path.basename(script_path)
    ]
    
    print(f"Running Ghidra headless analyzer: {' '.join(cmd)}")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        stdout, stderr = process.communicate()
        
        if process.returncode != 0:
            print(f"Error running Ghidra headless analyzer: {stderr}")
            return None
        
        # Check if output file was created
        output_file = os.path.join(os.path.expanduser("~"), "ghidra_temp", "ghidra_analysis.json")
        if os.path.exists(output_file):
            # Read output file
            with open(output_file, 'r') as f:
                result = json.load(f)
            
            # Copy output file to specified directory
            output_path = os.path.join(output_dir, os.path.basename(binary_path) + "_analysis.json")
            with open(output_path, 'w') as f:
                json.dump(result, f, indent=2)
            
            print(f"Analysis results saved to {output_path}")
            return result
        else:
            print("Error: Output file not found")
            return None
    except Exception as e:
        print(f"Error running Ghidra headless analyzer: {e}")
        return None

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python run_ghidra_analysis.py <binary_path> [output_dir] [project_name]")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    project_name = sys.argv[3] if len(sys.argv) > 3 else None
    
    if not os.path.exists(binary_path):
        print(f"Error: Binary file not found: {binary_path}")
        sys.exit(1)
    
    result = run_ghidra_analysis(binary_path, output_dir, project_name)
    if result:
        print(f"Analysis completed successfully with {result.get('function_count', 0)} functions")
    else:
        print("Analysis failed")
        sys.exit(1)

if __name__ == "__main__":
    main() 