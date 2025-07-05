#!/usr/bin/env python3
"""
Basic test for simplified Ghidra analysis
Tests the new persistent project approach directly
"""

import asyncio
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from mcp_server.ghidra_manager import GhidraHeadlessManager


async def test_basic_analysis():
    """Test basic Ghidra analysis with persistent project"""
    print("🧪 Testing Basic Ghidra Analysis")
    print("=" * 50)
    
    # Initialize manager
    manager = GhidraHeadlessManager(
        ghidra_install_dir="D:\\Ghidra\\ghidra_11.3_PUBLIC",
        max_concurrent=1,
        timeout=300  # 5 minutes
    )
    
    await manager.start()
    
    # Test with a small binary (calc.exe)
    test_binary = Path("./uploads/53c22b15-546d-4ff7-a726-469133139937_calc.exe")
    
    if not test_binary.exists():
        print(f"❌ Test binary not found: {test_binary}")
        return False
    
    print(f"📁 Testing with: {test_binary.name}")
    print(f"📦 File size: {test_binary.stat().st_size} bytes")
    
    # Test basic analysis
    try:
        print("\n🔍 Running basic analysis...")
        result = await manager.execute_analysis("getMemoryRegions", {
            "binary_path": str(test_binary)
        })
        
        print(f"✅ Analysis completed!")
        print(f"Status: {result.get('status')}")
        print(f"Duration: {result.get('duration', 0):.2f}s")
        
        # Check results
        analysis_results = result.get('analysis_results', {})
        functions_found = analysis_results.get('functions_found', 0)
        memory_blocks = analysis_results.get('memory_blocks', 0)
        analysis_completed = analysis_results.get('analysis_completed', False)
        
        print(f"\n📊 Analysis Results:")
        print(f"   Functions found: {functions_found}")
        print(f"   Memory blocks: {memory_blocks}")
        print(f"   Analysis completed: {analysis_completed}")
        
        if functions_found > 0:
            print("\n🎉 SUCCESS: Ghidra found functions!")
            return True
        else:
            print("\n⚠️  Warning: No functions found, but analysis ran")
            print("Raw stdout (first 500 chars):")
            print(result.get('stdout', '')[:500] + "...")
            return False
            
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")
        return False
    
    finally:
        await manager.stop()


async def main():
    """Main test function"""
    print("🚀 Starting Ghidra Basic Analysis Test")
    
    success = await test_basic_analysis()
    
    if success:
        print("\n✅ TEST PASSED: Basic Ghidra analysis is working!")
        print("🎯 You can now test through the web interface")
    else:
        print("\n❌ TEST FAILED: Need to debug Ghidra setup")
        
    print("\n" + "=" * 50)


if __name__ == "__main__":
    asyncio.run(main()) 