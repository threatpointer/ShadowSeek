#!/usr/bin/env python3
"""
Test basic Ghidra script execution
"""

import os
import subprocess
import time

def test_basic_ghidra():
    """Test basic Ghidra script execution"""
    print("Testing Basic Ghidra Script Execution")
    print("=" * 50)
    
    # Find Ghidra path
    ghidra_path = r"D:\1132-Ghidra\ghidra_11.3.2_PUBLIC"
    if not os.path.exists(ghidra_path):
        print("❌ Ghidra not found")
        return False
    
    print(f"✅ Ghidra found: {ghidra_path}")
    
    # Find a sample binary
    sample_binary = None
    upload_dirs = ["uploads", "temp"]
    
    for upload_dir in upload_dirs:
        if os.path.exists(upload_dir):
            for filename in os.listdir(upload_dir):
                if os.path.isfile(os.path.join(upload_dir, filename)):
                    sample_binary = os.path.join(upload_dir, filename)
                    break
            if sample_binary:
                break
    
    if not sample_binary:
        print("❌ No sample binary found")
        return False
    
    print(f"✅ Sample binary: {sample_binary}")
    
    # Test basic script
    headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
    script_path = os.path.join("analysis_scripts", "test_basic.py")
    projects_dir = "test_projects"
    
    os.makedirs(projects_dir, exist_ok=True)
    
    project_name = f"BasicTest_{int(time.time())}"
    
    cmd = [
        headless_path,
        projects_dir,
        project_name,
        "-import", sample_binary,
        "-scriptPath", os.path.dirname(script_path),
        "-postScript", os.path.basename(script_path)
    ]
    
    print(f"Running command: {' '.join(cmd)}")
    print("Timeout: 2 minutes")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=os.getcwd()
        )
        
        stdout, stderr = process.communicate(timeout=120)  # 2 minute timeout
        
        print(f"\nReturn code: {process.returncode}")
        print(f"STDOUT length: {len(stdout)} chars")
        print(f"STDERR length: {len(stderr)} chars")
        
        # Look for our markers
        if "=== TEST_START ===" in stdout:
            print("✅ Script executed successfully!")
            
            # Extract test output
            start_idx = stdout.find("=== TEST_START ===")
            end_idx = stdout.find("=== TEST_END ===")
            
            if end_idx != -1:
                test_output = stdout[start_idx:end_idx + len("=== TEST_END ===")]
                print("\n" + "="*30)
                print("SCRIPT OUTPUT:")
                print("="*30)
                print(test_output)
                print("="*30)
                return True
            else:
                print("⚠️ Script started but didn't complete properly")
                print(f"Full output: {stdout[:1000]}...")
                return False
        else:
            print("❌ Script did not execute or produce expected output")
            print("\nFirst 1000 chars of STDOUT:")
            print(stdout[:1000])
            print("\nFirst 500 chars of STDERR:")
            print(stderr[:500])
            return False
    
    except subprocess.TimeoutExpired:
        process.kill()
        print("❌ Process timed out after 2 minutes")
        return False
    except Exception as e:
        print(f"❌ Error running test: {e}")
        return False

if __name__ == "__main__":
    success = test_basic_ghidra()
    
    print("\n" + "="*50)
    if success:
        print("🎉 Basic Ghidra script execution works!")
        print("The issue might be with the CFG script itself.")
    else:
        print("❌ Basic Ghidra script execution failed!")
        print("This explains why CFG generation isn't working.")
    
    print("\nNext step: Debug the CFG script execution if basic test passes.") 