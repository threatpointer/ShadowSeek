#!/usr/bin/env python3
"""
Enhanced ghidriff wrapper with aggressive timeout handling and automatic database saving
Prevents hanging on problematic binaries like 7za
Automatically saves results to database upon completion
"""

import os
import sys
import subprocess
import json
import time
import signal
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv
import multiprocessing

# Add the flask app to the path for database access
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

def get_flask_app():
    """Get Flask app instance for database operations"""
    try:
        # Try primary import
        from flask_app import create_app
        return create_app()
    except ImportError as e:
        print(f"Warning: Could not import Flask app create_app: {e}")
        try:
            # Try alternative import
            from flask_app.app import app
            return app
        except ImportError as e2:
            print(f"Warning: Alternative import also failed: {e2}")
            return None

def save_results_to_database(task_id, binary_id1, binary_id2, diff_type, results, app=None):
    """Save analysis results to database"""
    if not app:
        app = get_flask_app()
    
    if not app:
        print("Warning: Could not get Flask app - results not saved to database")
        return False
    
    try:
        with app.app_context():
            from flask_app.models import db, AnalysisResult, AnalysisTask, Binary
            
            # Check if result already exists
            existing = AnalysisResult.query.filter_by(task_id=task_id).first()
            if existing:
                print(f"Results for task {task_id} already exist in database - updating")
                existing.results = json.dumps(results, indent=2)
                existing.meta_data = {
                    'binary_id2': binary_id2,
                    'engine_type': results.get('engine', 'SimpleDiff'),
                    'diff_type': diff_type,
                    'auto_saved': True,
                    'auto_save_timestamp': datetime.now().isoformat(),
                    'success': results.get('success', False)
                }
                db.session.commit()
                print(f"✅ Updated existing results for task {task_id}")
                return True
            
            # Get or create task
            task = AnalysisTask.query.filter_by(id=task_id).first()
            if not task:
                # Create a new task entry
                task = AnalysisTask(
                    id=task_id,
                    task_type='binary_comparison',
                    status='completed' if results.get('success') else 'failed',
                    priority=1,
                    progress=100,
                    binary_id=binary_id1,
                    parameters={
                        'binary_id1': binary_id1,
                        'binary_id2': binary_id2,
                        'diff_type': diff_type
                    },
                    created_at=datetime.now(),
                    started_at=datetime.now(),
                    completed_at=datetime.now(),
                    error_message=results.get('error') if not results.get('success') else None
                )
                db.session.add(task)
                db.session.flush()
                print(f"Created new task entry for {task_id}")
            else:
                # Update existing task
                task.status = 'completed' if results.get('success') else 'failed'
                task.progress = 100
                task.completed_at = datetime.now()
                task.error_message = results.get('error') if not results.get('success') else None
                print(f"Updated existing task {task_id}")
            
            # Get binary names for better display
            binary1_name = 'Unknown'
            binary2_name = 'Unknown'
            
            binary1 = Binary.query.filter_by(id=binary_id1).first()
            if binary1:
                binary1_name = binary1.original_filename
                
            binary2 = Binary.query.filter_by(id=binary_id2).first()
            if binary2:
                binary2_name = binary2.original_filename
            
            # Add binary names to results
            results['binary1'] = binary1_name
            results['binary2'] = binary2_name
            
            # Create AnalysisResult
            analysis_result = AnalysisResult(
                binary_id=binary_id1,
                task_id=task_id,
                analysis_type='binary_diff',
                results=json.dumps(results, indent=2),
                meta_data={
                    'binary_id2': binary_id2,
                    'binary1_name': binary1_name,
                    'binary2_name': binary2_name,
                    'engine_type': results.get('engine', 'SimpleDiff'),
                    'diff_type': diff_type,
                    'auto_saved': True,
                    'auto_save_timestamp': datetime.now().isoformat(),
                    'success': results.get('success', False),
                    'execution_time': results.get('execution_time', 0)
                },
                created_at=datetime.now()
            )
            
            db.session.add(analysis_result)
            db.session.commit()
            
            print(f"✅ Successfully saved results to database for task {task_id}")
            print(f"   Binary 1: {binary1_name}")
            print(f"   Binary 2: {binary2_name}")
            print(f"   Success: {results.get('success', False)}")
            return True
            
    except Exception as e:
        print(f"❌ Error saving results to database: {e}")
        return False

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("ghidriff execution timed out")

def get_system_info():
    """Get system information for optimization"""
    try:
        cpu_count = multiprocessing.cpu_count()
        # Get available memory in GB (approximate)
        if os.name == 'nt':  # Windows
            import psutil
            mem_gb = psutil.virtual_memory().total / (1024**3)
        else:  # Unix-like
            with open('/proc/meminfo', 'r') as f:
                meminfo = f.read()
                mem_kb = int([line for line in meminfo.split('\n') if 'MemTotal' in line][0].split()[1])
                mem_gb = mem_kb / (1024**2)
        
        return {
            'cpu_cores': cpu_count,
            'memory_gb': mem_gb,
            'logical_cores': cpu_count  # Fallback, could be refined
        }
    except:
        # Fallback values
        return {
            'cpu_cores': 4,
            'memory_gb': 16,
            'logical_cores': 8
        }

def get_optimized_jvm_args(memory_gb, cpu_cores):
    """Generate simplified, compatible JVM arguments"""
    
    # Calculate optimal heap size (60% of available RAM for safety)
    heap_size_gb = min(int(memory_gb * 0.6), 8)  # Cap at 8GB for stability
    
    # Use only essential, widely-compatible JVM arguments
    jvm_args = [
        # Essential memory settings
        f'-Xmx{heap_size_gb}g',
        f'-Xms{heap_size_gb//2}g',
        
        # Use G1GC (widely supported)
        '-XX:+UseG1GC',
        
        # Essential optimizations
        '-XX:+UseCompressedOops',
        '-Djava.awt.headless=true',
        
        # Threading (conservative)
        f'-XX:ParallelGCThreads={min(cpu_cores, 4)}',
    ]
    
    print(f"🔧 Using simplified JVM args: {' '.join(jvm_args)}")
    return ' '.join(jvm_args)

def run_ghidriff(binary1_path, binary2_path, engine_type, output_dir, timeout_minutes=15, 
                  task_id=None, binary_id1=None, binary_id2=None, diff_type=None, auto_save_db=True,
                  performance_mode='balanced'):
    """
    Run ghidriff with advanced performance optimizations
    
    Args:
        binary1_path: Path to first binary
        binary2_path: Path to second binary 
        engine_type: ghidriff engine (SimpleDiff, StructualGraphDiff, VersionTrackingDiff)
        output_dir: Output directory for results
        timeout_minutes: Maximum runtime in minutes (default 15)
        task_id: Task ID for database saving
        binary_id1: First binary ID for database saving
        binary_id2: Second binary ID for database saving
        diff_type: Diff type for database saving
        auto_save_db: Whether to automatically save results to database (default True)
        performance_mode: 'speed', 'balanced', or 'accuracy' (default 'balanced')
    """
    
    # Load environment variables
    load_dotenv()
    
    # Get system information for optimization
    system_info = get_system_info()
    cpu_cores = system_info['cpu_cores']
    memory_gb = system_info['memory_gb']
    
    print(f"🚀 PERFORMANCE MODE: {performance_mode.upper()}")
    print(f"💻 System: {cpu_cores} cores, {memory_gb:.1f}GB RAM")
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Starting OPTIMIZED ghidriff comparison with {timeout_minutes} minute timeout...")
    print(f"Engine: {engine_type}")
    print(f"Binary 1: {binary1_path}")
    print(f"Binary 2: {binary2_path}")
    print(f"Output: {output_dir}")
    
    # Performance-based configuration (conservative settings for reliability)
    if performance_mode == 'speed':
        ram_percent = 60  # Conservative for stability
        use_bsim = False
        bsim_full = False  
        min_func_len = 20  # More conservative
        max_section_funcs = 50   # Reduced for speed
        use_calling_counts = False
        log_level = 'ERROR'  # Minimal logging
        print("⚡ SPEED MODE: Fast execution with reduced accuracy")
        
    elif performance_mode == 'accuracy':
        ram_percent = 70
        use_bsim = True
        bsim_full = False  # Too slow, disable for now
        min_func_len = 5   # Include more functions
        max_section_funcs = 300  # Reasonable limit
        use_calling_counts = False  # Disable for stability
        log_level = 'INFO'
        print("🎯 ACCURACY MODE: Maximum precision with longer runtime")
        
    else:  # balanced
        ram_percent = 65
        use_bsim = True
        bsim_full = False
        min_func_len = 10  # Default
        max_section_funcs = 100  # Conservative
        use_calling_counts = False
        log_level = 'WARN'  # Moderate logging
        print("⚖️ BALANCED MODE: Good speed/accuracy tradeoff")
    
    # Build optimized command
    cmd = [
        'uv', 'run', 'python', '-m', 'ghidriff',
        '--engine', engine_type,
        '--output-path', output_dir,
        '--force-diff',
        '--threaded',  # Always use threading
        '--log-level', log_level,
        '--max-ram-percent', str(ram_percent),
        '--min-func-len', str(min_func_len),
        '--max-section-funcs', str(max_section_funcs),
        binary1_path,
        binary2_path
    ]
    
    # Add BSIM options
    if use_bsim:
        cmd.append('--bsim')
        if bsim_full:
            cmd.append('--bsim-full')
    else:
        cmd.append('--no-bsim')
        
    # Add calling counts option
    if use_calling_counts:
        cmd.append('--use-calling-counts')
    else:
        cmd.append('--no-use-calling-counts')
        
    # Add JVM arguments only if not in speed mode (for maximum compatibility)
    if performance_mode != 'speed':
        jvm_args = get_optimized_jvm_args(memory_gb, cpu_cores)
        cmd.extend(['--jvm-args', jvm_args])
    else:
        print("⚡ SPEED MODE: Using default JVM settings for maximum compatibility")
    
    print(f"🔧 JVM RAM: {ram_percent}% ({ram_percent * memory_gb / 100:.1f}GB)")
    print(f"🧵 Threading: Enabled with {cpu_cores} cores")
    print(f"🎛️ BSIM: {'ON' if use_bsim else 'OFF'}, Full: {'ON' if bsim_full else 'OFF'}")
    print(f"📊 Min function length: {min_func_len}")
    
    # Setup environment with GHIDRA_INSTALL_DIR
    env = os.environ.copy()
    ghidra_dir = os.getenv('GHIDRA_INSTALL_DIR')
    if ghidra_dir:
        env['GHIDRA_INSTALL_DIR'] = ghidra_dir
        print(f"GHIDRA_INSTALL_DIR: {ghidra_dir}")
    else:
        raise RuntimeError("GHIDRA_INSTALL_DIR environment variable is not set")
    
    # Add Java performance environment variables
    env['JAVA_OPTS'] = jvm_args
    env['_JAVA_OPTIONS'] = jvm_args
    
    start_time = time.time()
    timeout_seconds = timeout_minutes * 60
    
    try:
        print(f"Running command: {' '.join(cmd)}")
        print(f"Timeout: {timeout_seconds} seconds")
        
        # Run with aggressive timeout
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=os.getcwd(),
            env=env
        )
        
        elapsed_time = time.time() - start_time
        print(f"ghidriff completed in {elapsed_time:.1f} seconds")
        
        if result.returncode != 0:
            # More detailed error analysis
            if "Unrecognized VM option" in result.stderr:
                error_msg = "JVM compatibility issue - please try Speed Mode for maximum compatibility"
            elif "java.lang.OutOfMemoryError" in result.stderr:
                error_msg = "Out of memory - try reducing RAM percentage or use Speed Mode"
            elif "No such file or directory" in result.stderr:
                error_msg = "Binary file not found or access denied"
            else:
                error_msg = f"ghidriff failed with return code {result.returncode}"
            
            print(f"❌ ANALYSIS FAILED: {error_msg}")
            print(f"STDERR: {result.stderr}")
            
            failure_result = {
                'success': False,
                'error': error_msg,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'execution_time': elapsed_time,
                'engine': engine_type,
                'user_friendly_error': error_msg
            }
            
            # Auto-save failed results to database if enabled
            if auto_save_db and task_id and binary_id1 and binary_id2 and diff_type:
                print("💾 Saving failed results to database...")
                save_results_to_database(task_id, binary_id1, binary_id2, diff_type, failure_result)
            
            return failure_result
        
        # Parse results
        results = parse_ghidriff_output(output_dir, result.stdout, elapsed_time)
        results['success'] = True
        results['engine'] = engine_type
        
        # Auto-save successful results to database if enabled
        if auto_save_db and task_id and binary_id1 and binary_id2 and diff_type:
            print("💾 Saving successful results to database...")
            save_results_to_database(task_id, binary_id1, binary_id2, diff_type, results)
        
        return results
        
    except subprocess.TimeoutExpired:
        elapsed_time = time.time() - start_time
        error_msg = f"ghidriff timed out after {elapsed_time:.1f} seconds ({timeout_minutes} minutes)"
        print(f"TIMEOUT: {error_msg}")
        
        # Try to get partial results if any files were created
        try:
            partial_results = parse_ghidriff_output(output_dir, "", elapsed_time)
            partial_results['success'] = False
            partial_results['error'] = error_msg
            partial_results['timeout'] = True
            partial_results['engine'] = engine_type
            
            # Auto-save timeout results to database if enabled
            if auto_save_db and task_id and binary_id1 and binary_id2 and diff_type:
                print("💾 Saving timeout results to database...")
                save_results_to_database(task_id, binary_id1, binary_id2, diff_type, partial_results)
            
            return partial_results
        except:
            pass
            
        timeout_result = {
            'success': False,
            'error': error_msg,
            'timeout': True,
            'execution_time': elapsed_time,
            'stdout': 'Process timed out - no output captured',
            'stderr': 'Process killed due to timeout',
            'engine': engine_type
        }
        
        # Auto-save timeout results to database if enabled
        if auto_save_db and task_id and binary_id1 and binary_id2 and diff_type:
            print("💾 Saving timeout results to database...")
            save_results_to_database(task_id, binary_id1, binary_id2, diff_type, timeout_result)
        
        return timeout_result
        
    except Exception as e:
        elapsed_time = time.time() - start_time
        error_msg = f"Unexpected error: {str(e)}"
        print(f"ERROR: {error_msg}")
        
        exception_result = {
            'success': False,
            'error': error_msg,
            'execution_time': elapsed_time,
            'stdout': '',
            'stderr': str(e),
            'engine': engine_type
        }
        
        # Auto-save exception results to database if enabled
        if auto_save_db and task_id and binary_id1 and binary_id2 and diff_type:
            print("💾 Saving exception results to database...")
            save_results_to_database(task_id, binary_id1, binary_id2, diff_type, exception_result)
        
        return exception_result

def parse_ghidriff_output(output_dir, stdout, execution_time):
    """Parse ghidriff output files and return structured results"""
    
    result = {
        'success': True,
        'engine': 'unknown',
        'binary1': '',
        'binary2': '',
        'summary': {},
        'markdown': '',
        'json_data': {},
        'output_files': [],
        'stdout': stdout,
        'execution_time': execution_time
    }
    
    output_path = Path(output_dir)
    
    try:
        # Find all generated files
        output_files = list(output_path.glob('*'))
        result['output_files'] = [str(f.relative_to(output_path)) for f in output_files]
        
        print(f"Found {len(output_files)} output files: {result['output_files']}")
        
        # Look for JSON results file
        json_files = list(output_path.glob('*.json'))
        if json_files:
            json_file = json_files[0]  # Take the first JSON file
            print(f"Reading JSON results from: {json_file}")
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    json_content = f.read()
                    result['json_data'] = json.loads(json_content)
                    
                    # Extract summary info from JSON if available
                    if isinstance(result['json_data'], dict):
                        result['summary'] = extract_summary_from_json(result['json_data'])
                        
            except Exception as e:
                print(f"Error reading JSON file: {e}")
                result['json_data'] = {'error': f'Failed to parse JSON: {e}'}
        
        # Look for markdown report
        md_files = list(output_path.glob('*.md'))
        if md_files:
            md_file = md_files[0]
            print(f"Reading markdown report from: {md_file}")
            
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    result['markdown'] = f.read()
            except Exception as e:
                print(f"Error reading markdown file: {e}")
                result['markdown'] = f'Error reading markdown: {e}'
        
        # If no structured output, create summary from stdout
        if not result['summary'] and stdout:
            result['summary'] = {
                'analysis_completed': True,
                'output_files_generated': len(output_files),
                'execution_time_seconds': execution_time,
                'notes': 'Analysis completed but no structured summary available'
            }
        
        return result
        
    except Exception as e:
        print(f"Error parsing output: {e}")
        result['success'] = False
        result['error'] = f'Error parsing results: {e}'
        return result

def extract_summary_from_json(json_data):
    """Extract key summary information from ghidriff JSON output"""
    
    summary = {
        'analysis_completed': True,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    try:
        # Try to extract common fields that ghidriff might provide
        if 'metadata' in json_data:
            metadata = json_data['metadata']
            summary.update({
                'engine_used': metadata.get('engine', 'unknown'),
                'binary1_name': metadata.get('binary1', ''),
                'binary2_name': metadata.get('binary2', ''),
            })
        
        # Look for function comparison data
        if 'functions' in json_data:
            functions = json_data['functions']
            if isinstance(functions, dict):
                summary['functions_compared'] = len(functions)
                summary['changes_detected'] = sum(1 for f in functions.values() if f.get('changed', False))
        
        # Look for differences
        if 'differences' in json_data:
            diffs = json_data['differences']
            if isinstance(diffs, list):
                summary['total_differences'] = len(diffs)
            elif isinstance(diffs, dict):
                summary['total_differences'] = len(diffs)
        
        # Look for statistics
        if 'stats' in json_data:
            stats = json_data['stats']
            summary.update(stats)
        
    except Exception as e:
        summary['extraction_error'] = str(e)
    
    return summary

if __name__ == "__main__":
    # Test with the problematic 7za binaries
    binary1 = "uploads/009373c2-4439-40e0-8006-a6343be628e1_7za2107.exe"
    binary2 = "uploads/8f3bd8aa-0e56-4500-9c86-26ee55ea7036_7za2201.exe"
    
    if os.path.exists(binary1) and os.path.exists(binary2):
        print("Testing ghidriff with 7za binaries and aggressive timeout...")
        result = run_ghidriff(
            binary1_path=binary1, 
            binary2_path=binary2, 
            engine_type='SimpleDiff', 
            output_dir='test_7za_output', 
            timeout_minutes=5,
            auto_save_db=False,  # Disable database saving for testing
            performance_mode='balanced' # Test with balanced mode
        )
        
        print("\n" + "="*50)
        print("RESULT:")
        print("="*50)
        print(f"Success: {result['success']}")
        print(f"Execution time: {result.get('execution_time', 0):.1f} seconds")
        
        if result['success']:
            print("✅ Analysis completed successfully!")
            print(f"Output files: {result['output_files']}")
        else:
            print(f"❌ Analysis failed: {result['error']}")
            if result.get('timeout'):
                print("💡 Consider using smaller/simpler binaries for comparison")
    else:
        print("❌ Binary files not found")
        print(f"Looking for: {binary1}")
        print(f"Looking for: {binary2}") 