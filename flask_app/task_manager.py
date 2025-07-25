"""
Task Manager for handling background analysis tasks
"""

import os
import uuid
import json
import time
import logging
import threading
import traceback
from datetime import datetime
from pathlib import Path

from flask import current_app
from flask_app.models import db, Binary, AnalysisTask, AnalysisResult, Function
from flask_app.ghidra_bridge_manager import GhidraBridgeManager
from ghidra_bridge import GhidraBridge

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TaskManager:
    """Manage analysis tasks"""
    
    def __init__(self, app=None, bridge_manager=None):
        """Initialize the task manager"""
        self.app = app
        self.bridge_manager = bridge_manager
        self.tasks = {}  # task_id -> {task_info}
        self.task_lock = threading.Lock()
        
        if app:
            self.init_app(app, bridge_manager)
    
    def init_app(self, app, bridge_manager=None):
        """Initialize with Flask app"""
        self.app = app
        self.bridge_manager = bridge_manager
    
    def _get_bridge_manager(self):
        """Get or create Ghidra Bridge manager"""
        if self.bridge_manager:
            return self.bridge_manager
        
        # Create bridge manager if not provided
        from flask import current_app
        from .ghidra_bridge_manager import GhidraBridgeManager
        
        if not hasattr(current_app, 'ghidra_bridge_manager'):
            current_app.ghidra_bridge_manager = GhidraBridgeManager(current_app)
        
        self.bridge_manager = current_app.ghidra_bridge_manager
        return self.bridge_manager
    
    def start_task(self, task_type, binary_id, **kwargs):
        """
        Start a new background task
        
        Args:
            task_type: Type of analysis task
            binary_id: ID of the binary to analyze
            **kwargs: Additional task parameters
            
        Returns:
            task_id: ID of the created task
        """
        task_id = str(uuid.uuid4())
        
        # Create task record
        task = AnalysisTask(
            id=task_id,
            binary_id=binary_id,
            task_type=task_type,
            parameters=json.dumps(kwargs),
            status="queued",
            created_at=datetime.utcnow()
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Start thread for task
        with self.task_lock:
            thread = threading.Thread(
                target=self._run_task,
                args=(task_id, task_type, binary_id),
                kwargs=kwargs
            )
            thread.daemon = True
            thread.start()
            
            self.tasks[task_id] = {
                "thread": thread,
                "started_at": datetime.utcnow()
            }
        
        return task_id
    
    def _run_task(self, task_id, task_type, binary_id, **kwargs):
        """
        Execute the task in background
        
        Args:
            task_id: ID of the task
            task_type: Type of analysis task
            binary_id: ID of the binary to analyze
            **kwargs: Additional task parameters
        """
        try:
            from flask import current_app
            from .models import db, Binary, AnalysisTask, AnalysisResult, Function
            import uuid
            import os
            from datetime import datetime
            
            # Ensure we have Flask application context for the entire task execution
            with self.app.app_context():
                # Update task status
                task = AnalysisTask.query.get(task_id)
                if not task:
                    logger.error(f"Task {task_id} not found")
                    return
                
                task.status = 'running'
                task.started_at = datetime.utcnow()
                db.session.commit()
                
                # Get binary
                binary = Binary.query.get(binary_id)
                if not binary:
                    logger.error(f"Binary {binary_id} not found")
                    task.status = 'failed'
                    task.error_message = f"Binary {binary_id} not found"
                    task.completed_at = datetime.utcnow()
                    db.session.commit()
                    return
                
                # Update binary status
                binary.analysis_status = 'analyzing'
                db.session.commit()
                
                # Execute appropriate analysis based on task_type
                if task_type == 'basic':
                    # Run basic analysis using Ghidra headless analyzer
                    try:
                        logger.info(f"Starting Ghidra headless analysis for binary {binary_id}")
                        
                        # Use the bridge manager to run headless analysis
                        analysis_result = current_app.ghidra_bridge_manager.run_headless_analysis(
                            binary_path=binary.file_path,
                            output_dir=os.path.join(os.getcwd(), 'temp'),
                            project_name=f"GhidraProject_{binary_id}"
                        )
                        
                        if not analysis_result:
                            raise RuntimeError("Headless analysis returned no results")
                        
                        logger.info(f"Analysis completed with {analysis_result.get('function_count', 0)} functions")
                        
                        # Store functions
                        if "functions" in analysis_result and isinstance(analysis_result["functions"], list):
                            for func_data in analysis_result["functions"]:
                                # Check if function already exists
                                existing = Function.query.filter_by(
                                    binary_id=binary_id,
                                    address=func_data["address"]
                                ).first()
                                
                                if not existing:
                                    function = Function(
                                        id=str(uuid.uuid4()),
                                        binary_id=binary_id,
                                        address=func_data.get("address", "0x0"),
                                        name=func_data.get("name", "unknown"),
                                        original_name=func_data.get("name", "unknown"),
                                        size=func_data.get("size", 0),
                                        is_analyzed=True,
                                        is_thunk=str(func_data.get("is_thunk", "false")).lower() == "true",
                                        is_external=str(func_data.get("is_library", "false")).lower() == "true",
                                        calling_convention=func_data.get("calling_convention"),
                                        has_cfg=True,  # Assume CFG is available for all functions
                                        meta_data={}
                                    )
                                    db.session.add(function)
                        
                        # Store analysis result
                        analysis_result_obj = AnalysisResult(
                            id=str(uuid.uuid4()),
                            binary_id=binary_id,
                            task_id=task_id,
                            analysis_type="basic_analysis",
                            created_at=datetime.utcnow(),
                            results=analysis_result
                        )
                        db.session.add(analysis_result_obj)
                        
                        # Update binary status and metadata
                        binary.analysis_status = 'processed'
                        binary.architecture = analysis_result.get("architecture", "unknown")
                        db.session.commit()
                        
                    except Exception as e:
                        logger.error(f"Error in Ghidra analysis: {e}")
                        binary.analysis_status = 'failed'
                        task.status = 'failed'
                        task.error_message = str(e)
                        task.completed_at = datetime.utcnow()
                        db.session.commit()
                        return
                
                elif task_type == "generate_cfg":
                    result = self._generate_cfg(binary.file_path, kwargs.get("function_address"), **kwargs)
                    self._store_cfg(task_id, binary_id, result, kwargs.get("function_address"))
                
                elif task_type == "decompile_function":
                    # Decompile a specific function
                    function_id = kwargs.get("function_id")
                    function_address = kwargs.get("function_address")
                    
                    if not function_id or not function_address:
                        raise ValueError("Function ID and address required for decompilation")
                    
                    # Remove function_address from kwargs to avoid parameter conflict
                    filtered_kwargs = {k: v for k, v in kwargs.items() if k not in ["function_address"]}
                    
                    result = self._decompile_function(binary.file_path, function_address, **filtered_kwargs)
                    self._store_decompilation(task_id, binary_id, function_id, result)
                
                elif task_type == "explain_function":
                    # Generate AI explanation for a function
                    function_id = kwargs.get("function_id")
                    
                    if not function_id:
                        raise ValueError("Function ID required for AI explanation")
                    
                    # Remove function_id from kwargs to avoid parameter conflict
                    filtered_kwargs = {k: v for k, v in kwargs.items() if k not in ["function_id"]}
                    
                    result = self._explain_function_ai(function_id, **filtered_kwargs)
                    self._store_ai_explanation(task_id, binary_id, function_id, result)
                
                elif task_type == "bulk_decompile":
                    # Decompile multiple functions
                    function_ids = kwargs.get("function_ids", [])
                    function_addresses = kwargs.get("function_addresses", [])
                    
                    if not function_ids or not function_addresses:
                        raise ValueError("Function IDs and addresses required for bulk decompilation")
                    
                    # Remove function_ids and function_addresses from kwargs to avoid parameter conflict
                    filtered_kwargs = {k: v for k, v in kwargs.items() if k not in ["function_ids", "function_addresses"]}
                    
                    result = self._bulk_decompile_functions(binary.file_path, function_ids, function_addresses, **filtered_kwargs)
                    self._store_bulk_decompilation(task_id, binary_id, function_ids, result)
                
                elif task_type == "bulk_ai_explain":
                    # AI explain multiple functions
                    function_ids = kwargs.get("function_ids", [])
                    function_addresses = kwargs.get("function_addresses", [])
                    
                    if not function_ids or not function_addresses:
                        raise ValueError("Function IDs and addresses required for bulk AI explanation")
                    
                    # Remove function_ids and function_addresses from kwargs to avoid parameter conflict
                    filtered_kwargs = {k: v for k, v in kwargs.items() if k not in ["function_ids", "function_addresses"]}
                    
                    result = self._bulk_ai_explain_functions(binary.file_path, function_ids, function_addresses, **filtered_kwargs)
                    self._store_bulk_ai_explanation(task_id, binary_id, function_ids, result)
                
                elif task_type == "binary_ai_summary":
                    # Generate AI summary for the entire binary
                    binary_path = kwargs.get("binary_path")
                    
                    if not binary_path:
                        raise ValueError("Binary path required for AI summary")
                    
                    # Remove binary_path from kwargs to avoid parameter conflict
                    filtered_kwargs = {k: v for k, v in kwargs.items() if k != "binary_path"}
                    
                    result = self._generate_binary_ai_summary(binary_id, binary_path, **filtered_kwargs)
                    self._store_binary_ai_summary(task_id, binary_id, result)
                
                elif task_type == "comprehensive_analysis":
                    # Run comprehensive analysis on the binary
                    binary_path = kwargs.get("binary_path")
                    
                    if not binary_path:
                        raise ValueError("Binary path required for comprehensive analysis")
                    
                    # Remove binary_path from kwargs to avoid parameter conflict
                    filtered_kwargs = {k: v for k, v in kwargs.items() if k != "binary_path"}
                    
                    result = self._comprehensive_analysis(binary_id, binary_path, **filtered_kwargs)
                    self._store_comprehensive_analysis(task_id, binary_id, result)
                
                else:
                    raise ValueError(f"Unknown task type: {task_type}")
                
                # Update task status
                task.status = 'completed'
                task.completed_at = datetime.utcnow()
                db.session.commit()
                
        except Exception as e:
            logger.error(f"Error executing task {task_id}: {e}")
            try:
                from flask import current_app
                from .models import db, AnalysisTask, Binary
                
                with self.app.app_context():
                    # Update task status
                    task = AnalysisTask.query.get(task_id)
                    if task:
                        task.status = 'failed'
                        task.error_message = str(e)
                        task.completed_at = datetime.utcnow()
                    
                    # Update binary status
                    binary = Binary.query.get(binary_id)
                    if binary and binary.analysis_status == 'analyzing':
                        binary.analysis_status = 'failed'
                    
                    db.session.commit()
            except Exception as db_error:
                logger.error(f"Error updating database: {db_error}")
        
        finally:
            # Remove task from tasks dict
            with self.task_lock:
                if task_id in self.tasks:
                    del self.tasks[task_id]
    
    def _update_task_status(self, task_id, status, error=None):
        """
        Update task status in database
        
        Args:
            task_id: ID of the task
            status: New status
            error: Optional error message
        """
        task = db.session.query(AnalysisTask).get(task_id)
        if task:
            task.status = status
            task.error = error
            
            if status == "running":
                task.started_at = datetime.utcnow()
            elif status in ["completed", "failed"]:
                task.completed_at = datetime.utcnow()
            
            db.session.commit()
    
    def _store_task_result(self, task_id, binary_id, result):
        """
        Store task result in database
        
        Args:
            task_id: ID of the task
            binary_id: ID of the binary
            result: Analysis result
        """
        task = db.session.query(AnalysisTask).get(task_id)
        if task:
            task.results = json.dumps(result)
            db.session.commit()
    
    def _analyze_functions(self, binary_path, **kwargs):
        """
        Analyze functions in a binary
        
        Args:
            binary_path: Path to binary file
            **kwargs: Additional parameters
            
        Returns:
            Analysis result
        """
        bridge_manager = self._get_bridge_manager()
        project_name = f"analysis_{os.path.basename(binary_path)}"
        script_path = os.path.join(current_app.config['ANALYSIS_SCRIPTS_DIR'], 'analyze_functions.py')
        
        filter_params = {
            "name_filter": kwargs.get("name_filter", ""),
            "min_size": kwargs.get("min_size", 0),
            "max_size": kwargs.get("max_size", float('inf')),
            "limit": kwargs.get("limit", 1000)
        }
        
        result = bridge_manager.execute_script(
            project_name=project_name,
            script_path=script_path,
            args=[filter_params],
            binary_path=binary_path
        )
        
        return result
    
    def _generate_cfg(self, binary_path, function_address, **kwargs):
        """
        Generate CFG for a function
        
        Args:
            binary_path: Path to binary file
            function_address: Address of the function
            **kwargs: Additional parameters
            
        Returns:
            CFG data
        """
        bridge_manager = self._get_bridge_manager()
        project_name = f"analysis_{os.path.basename(binary_path)}"
        script_path = os.path.join(current_app.config['ANALYSIS_SCRIPTS_DIR'], 'extract_cfg.py')
        
        include_instructions = kwargs.get("include_instructions", True)
        
        result = bridge_manager.execute_script(
            project_name=project_name,
            script_path=script_path,
            args=[function_address, include_instructions],
            binary_path=binary_path
        )
        
        return result
    
    def _comprehensive_analysis(self, binary_id, binary_path, **kwargs):
        """
        Run comprehensive analysis on the binary using Ghidra headless with direct database storage
        
        Args:
            binary_id: ID of the binary
            binary_path: Path to binary file
            **kwargs: Additional parameters
            
        Returns:
            Comprehensive analysis result
        """
        try:
            import time  # Move import to top level
            from flask import current_app
            from .models import (db, Binary, AnalysisResult, Function, Import, Export, 
                               BinaryString, MemoryRegion, Symbol, DataType, Instruction, 
                               CrossReference, ComprehensiveAnalysis, FunctionParameter,
                               LocalVariable, FunctionCall)
            import uuid
            from datetime import datetime
            import subprocess
            import threading
            
            bridge_manager = self._get_bridge_manager()
            
            # Create projects directory if it doesn't exist
            projects_dir = os.path.join(os.getcwd(), "ghidra_projects")
            os.makedirs(projects_dir, exist_ok=True)
            
            # Get path to headless analyzer
            ghidra_path = bridge_manager.ghidra_path
            if os.name == 'nt':
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
            else:
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless")
            
            # Use the new direct database storage script
            script_path = os.path.join(current_app.config['ANALYSIS_SCRIPTS_DIR'], 'comprehensive_analysis_direct.py')
            
            # Verify script exists - if not, use fallback
            if not os.path.exists(script_path):
                logger.warning(f"Comprehensive analysis script not found: {script_path}")
                logger.info("Using fallback analysis method with existing scripts")
                
                # Use basic analysis as fallback
                fallback_script = os.path.join(current_app.config['ANALYSIS_SCRIPTS_DIR'], 'analyze_functions.py')
                if os.path.exists(fallback_script):
                    return self._comprehensive_analysis_fallback(binary_id, binary_path, **kwargs)
                else:
                    logger.error(f"No analysis scripts available")
                    return {
                        "success": False,
                        "error": f"No analysis scripts available in {current_app.config['ANALYSIS_SCRIPTS_DIR']}"
                    }
            
            # Verify binary exists
            if not os.path.exists(binary_path):
                logger.error(f"Binary file not found: {binary_path}")
                return {
                    "success": False,
                    "error": f"Binary file not found: {binary_path}"
                }
            
            # Check if we can optimize by skipping function-level analysis
            skip_functions = kwargs.get('skip_existing_functions', True)
            existing_functions_count = 0
            
            if skip_functions:
                existing_functions_count = Function.query.filter_by(binary_id=binary_id).count()
                if existing_functions_count > 0:
                    logger.info(f"Found {existing_functions_count} existing functions, will optimize extraction")
            
            # Create comprehensive analysis progress tracking record immediately
            logger.info(f"Starting comprehensive analysis for binary {binary_id}")
            
            # Create or update comprehensive analysis record with initial progress
            comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
            if comp_analysis:
                # Reset existing record
                comp_analysis.created_at = datetime.utcnow()
                comp_analysis.is_complete = False
                comp_analysis.error_message = None
                # Reset all extraction flags
                comp_analysis.memory_blocks_extracted = False
                comp_analysis.functions_extracted = False
                comp_analysis.instructions_extracted = False
                comp_analysis.strings_extracted = False
                comp_analysis.symbols_extracted = False
                comp_analysis.xrefs_extracted = False
                comp_analysis.imports_extracted = False
                comp_analysis.exports_extracted = False
                comp_analysis.data_types_extracted = False
            else:
                comp_analysis = ComprehensiveAnalysis(
                    id=str(uuid.uuid4()),
                    binary_id=binary_id,
                    analysis_version='1.0',
                    created_at=datetime.utcnow()
                )
                db.session.add(comp_analysis)
            
            # Set initial progress metadata
            comp_analysis.program_metadata = json.dumps({
                "status": "initializing",
                "progress": 0.1,
                "current_step": "Starting analysis"
            })
            db.session.commit()
            logger.info("Created comprehensive analysis progress tracking record")
            
            # Run headless analyzer with direct database script
            project_name = f"ComprehensiveProject_{binary_id}_{int(time.time())}"
            
            # Prepare script arguments for direct database storage
            script_args = [
                f"binary_id={binary_id}",
                f"skip_functions={existing_functions_count}"
            ]
            
            # Set up environment variables for the script
            env = os.environ.copy()
            env['GHIDRA_BINARY_ID'] = binary_id
            env['GHIDRA_SKIP_FUNCTIONS'] = str(existing_functions_count)
            if not env.get('GHIDRA_TEMP_DIR'):
                env['GHIDRA_TEMP_DIR'] = os.path.join(os.getcwd(), "temp", "ghidra_temp")
            
            # Construct the full command
            cmd = [
                headless_path,
                projects_dir,
                project_name,
                "-import", binary_path,
                "-scriptPath", current_app.config['ANALYSIS_SCRIPTS_DIR'],
                "-postScript", "comprehensive_analysis_direct.py"
            ]
            
            # Add script arguments
            cmd.extend(script_args)
            
            logger.info("Running comprehensive analysis command:")
            logger.info(f"  Command: {' '.join(cmd)}")
            logger.info(f"  Script path: {script_path}")
            logger.info(f"  Binary path: {binary_path}")
            logger.info(f"  Existing functions: {existing_functions_count}")
            logger.info(f"  Environment: GHIDRA_BINARY_ID={env.get('GHIDRA_BINARY_ID')}, GHIDRA_TEMP_DIR={env.get('GHIDRA_TEMP_DIR')}")
            
            # Monitor analysis progress with fake progress updates
            stop_progress = threading.Event()
            
            def monitor_progress():
                progress_steps = [
                    ("Initializing analysis", 0.1),
                    ("Analyzing functions", 0.2),
                    ("Decompiling functions", 0.4),
                    ("Extracting strings", 0.6),
                    ("Analyzing memory", 0.7),
                    ("Processing symbols", 0.8),
                    ("Generating results", 0.9),
                    ("Finalizing analysis", 1.0)
                ]
                
                step_duration = 8  # seconds per step
                start_time = time.time()
                
                for step_name, progress in progress_steps:
                    if stop_progress.wait(step_duration):
                        break  # Stop if analysis completed
                    
                    # Update progress in database
                    try:
                        elapsed = time.time() - start_time
                        if elapsed > step_duration * len(progress_steps):
                            break  # Process taking too long, stop fake progress
                        
                        logger.info(f"Progress update: {step_name} ({int(progress*100)}%)")
                        comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
                        if comp_analysis and not comp_analysis.is_complete:
                            comp_analysis.program_metadata = json.dumps({
                                "status": step_name.lower().replace(" ", "_"),
                                "progress": progress,
                                "current_step": step_name
                            })
                            db.session.commit()
                    except Exception as e:
                        logger.error(f"Error updating progress: {e}")
            
            # Start monitoring thread
            progress_thread = threading.Thread(target=monitor_progress)
            progress_thread.daemon = True
            progress_thread.start()
            
            # Execute the headless analysis with timeout
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.getcwd(),
                env=env  # Pass the environment variables
            )
            
            # Wait for completion with timeout (30 minutes)
            try:
                stdout, stderr = process.communicate(timeout=1800)  # 30 minutes
                stop_progress.set()  # Stop progress monitoring
            except subprocess.TimeoutExpired:
                process.kill()
                stop_progress.set()
                logger.error("Comprehensive analysis timed out after 30 minutes")
                comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
                if comp_analysis:
                    comp_analysis.error_message = "Comprehensive analysis timed out after 30 minutes"
                    db.session.commit()
                return {
                    "success": False,
                    "error": "Comprehensive analysis timed out after 30 minutes"
                }
            
            if process.returncode != 0:
                stop_progress.set()
                logger.error(f"Comprehensive analysis process failed (code {process.returncode})")
                logger.error(f"STDERR: {stderr}")
                logger.error(f"STDOUT: {stdout}")
                comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
                if comp_analysis:
                    comp_analysis.error_message = f"Analysis process failed (code {process.returncode}): {stderr[:500]}"
                    db.session.commit()
                return {
                    "success": False,
                    "error": f"Comprehensive analysis process failed (code {process.returncode}): {stderr}",
                    "debug_stdout": stdout,
                    "debug_stderr": stderr
                }
            
            # Check if analysis completed successfully by verifying database records
            logger.info("Comprehensive analysis completed, verifying database results...")
            
            # Always log the process output for debugging
            logger.info(f"Ghidra process completed with return code: {process.returncode}")
            if stdout.strip():
                logger.info(f"Ghidra STDOUT: {stdout}")
            if stderr.strip():
                logger.info(f"Ghidra STDERR: {stderr}")
            
            # Wait a moment for database writes to complete
            time.sleep(2)
            
            # First, check if the script wrote results to the temp JSON file
            # (since the script runs in Ghidra's environment and can't access Flask's database directly)
            temp_base_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
            temp_file = os.path.join(temp_base_dir, f"comprehensive_analysis_{binary_id}.json")
            
            if os.path.exists(temp_file):
                logger.info(f"Found comprehensive analysis results in temp file: {temp_file}")
                try:
                    # Read the JSON results from the temp file
                    with open(temp_file, 'r') as f:
                        temp_results = json.load(f)
                    
                    if temp_results.get("success"):
                        logger.info("Processing comprehensive analysis results from temp file...")
                        
                        # Store the results in database using the existing storage method
                        # Create a task ID for this storage operation
                        storage_task_id = str(uuid.uuid4())
                        
                        # Use existing storage method to save to database
                        self._store_comprehensive_analysis(storage_task_id, binary_id, temp_results)
                        
                        # Clean up temp file after successful storage
                        os.remove(temp_file)
                        logger.info("Successfully processed temp file results and stored in database")
                        
                    else:
                        logger.error(f"Temp file indicates analysis failed: {temp_results.get('error')}")
                        return {
                            "success": False,
                            "error": f"Analysis script failed: {temp_results.get('error')}",
                            "debug_output": temp_results
                        }
                        
                except Exception as e:
                    logger.error(f"Error processing temp file results: {e}")
                    return {
                        "success": False,
                        "error": f"Failed to process analysis results from temp file: {e}",
                        "temp_file": temp_file
                    }
            else:
                logger.warning(f"No temp file found at: {temp_file}")
            
            # Now check comprehensive analysis record in database
            comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
            if not comp_analysis or not comp_analysis.is_complete:
                logger.error("Comprehensive analysis did not complete successfully - no database record found")
                return {
                    "success": False,
                    "error": "Analysis script completed but no results found in database",
                    "debug_output": stdout[:500],
                    "temp_file_checked": temp_file,
                    "temp_file_exists": os.path.exists(temp_file)
                }
            
            # Verify we have data in the database
            function_count = Function.query.filter_by(binary_id=binary_id).count()
            memory_count = MemoryRegion.query.filter_by(binary_id=binary_id).count()
            string_count = BinaryString.query.filter_by(binary_id=binary_id).count()
            symbol_count = Symbol.query.filter_by(binary_id=binary_id).count()
            
            # Create success result based on database contents
            statistics = json.loads(comp_analysis.statistics) if comp_analysis.statistics else {}
            metadata = json.loads(comp_analysis.program_metadata) if comp_analysis.program_metadata else {}
            
            result = {
                "success": True,
                "message": "Comprehensive analysis completed successfully with direct database storage",
                "data": {
                    "metadata": metadata,
                    "statistics": {
                        "totalFunctions": function_count,
                        "memoryBlocks": memory_count,
                        "strings": string_count,
                        "symbols": symbol_count,
                        "optimized": existing_functions_count > 0,
                        "existingFunctions": existing_functions_count,
                        "newFunctions": max(0, function_count - existing_functions_count),
                        **statistics  # Include any additional stats from the script
                    }
                },
                "storage_method": "direct_database",
                "records_created": {
                    "functions": function_count,
                    "memory_regions": memory_count,
                    "strings": string_count,
                    "symbols": symbol_count
                }
            }
            
            logger.info(f"Successfully completed comprehensive analysis for binary {binary_id}")
            logger.info(f"Database records created: {function_count} functions, {memory_count} memory regions, {string_count} strings, {symbol_count} symbols")
            
            return result
            
        except Exception as e:
            logger.error(f"Error in comprehensive analysis: {e}")
            try:
                comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
                if comp_analysis:
                    comp_analysis.error_message = f"Unexpected error: {str(e)}"
                    db.session.commit()
            except:
                pass
            return {
                "success": False,
                "error": str(e)
            }
    
    def _comprehensive_analysis_fallback(self, binary_id, binary_path, **kwargs):
        """
        Fallback comprehensive analysis using existing scripts
        
        Args:
            binary_id: ID of the binary  
            binary_path: Path to binary file
            **kwargs: Additional parameters
            
        Returns:
            Analysis result using basic function analysis
        """
        try:
            logger.info(f"Starting fallback comprehensive analysis for binary {binary_id}")
            
            from flask_app.models import (db, ComprehensiveAnalysis, Function)
            import uuid
            
            # Create or update comprehensive analysis record
            comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
            if comp_analysis:
                comp_analysis.created_at = datetime.utcnow()
                comp_analysis.is_complete = False
                comp_analysis.error_message = None
                comp_analysis.functions_extracted = False
            else:
                comp_analysis = ComprehensiveAnalysis(
                    id=str(uuid.uuid4()),
                    binary_id=binary_id,
                    analysis_version='1.0',
                    created_at=datetime.utcnow()
                )
                db.session.add(comp_analysis)
            
            # Set progress metadata
            comp_analysis.program_metadata = json.dumps({
                "status": "fallback_analysis",
                "progress": 0.3,
                "current_step": "Using fallback analysis method"
            })
            db.session.commit()
            
            # Run basic function analysis
            logger.info("Running basic function analysis as fallback")
            result = self._analyze_functions(binary_path, limit=1000)
            
            if result and "functions" in result:
                # Store functions in database
                self._store_functions(binary_id, result)
                
                # Update comprehensive analysis as complete
                comp_analysis.functions_extracted = True
                comp_analysis.is_complete = True
                comp_analysis.program_metadata = json.dumps({
                    "status": "completed",
                    "progress": 1.0,
                    "current_step": "Fallback analysis completed",
                    "method": "basic_function_analysis"
                })
                comp_analysis.statistics = json.dumps({
                    "totalFunctions": len(result.get("functions", [])),
                    "analysis_method": "fallback",
                    "script_used": "analyze_functions.py"
                })
                db.session.commit()
                
                function_count = Function.query.filter_by(binary_id=binary_id).count()
                
                return {
                    "success": True,
                    "message": "Comprehensive analysis completed using fallback method",
                    "data": {
                        "metadata": {
                            "status": "completed",
                            "method": "fallback_analysis"
                        },
                        "statistics": {
                            "totalFunctions": function_count,
                            "memoryBlocks": 0,
                            "strings": 0,
                            "symbols": 0,
                            "analysis_method": "fallback"
                        }
                    },
                    "storage_method": "fallback_database",
                    "records_created": {
                        "functions": function_count,
                        "memory_regions": 0,
                        "strings": 0,
                        "symbols": 0
                    }
                }
            else:
                # Analysis failed
                comp_analysis.error_message = "Fallback function analysis failed to extract functions"
                db.session.commit()
                
                return {
                    "success": False,
                    "error": "Fallback analysis failed - no functions extracted",
                    "debug_result": result
                }
                
        except Exception as e:
            logger.error(f"Error in fallback comprehensive analysis: {e}")
            try:
                comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
                if comp_analysis:
                    comp_analysis.error_message = f"Fallback analysis error: {str(e)}"
                    db.session.commit()
            except:
                pass
            return {
                "success": False,
                "error": f"Fallback analysis failed: {str(e)}"
            }
    
    def _store_functions(self, binary_id, result):
        """
        Store function information in database
        
        Args:
            binary_id: ID of the binary
            result: Function analysis result
        """
        if "functions" not in result:
            return
        
        # Store functions
        for func_data in result["functions"]:
            function = Function(
                binary_id=binary_id,
                name=func_data.get("name", "unknown"),
                address=func_data.get("address", "0x0"),
                size=func_data.get("size", 0),
                is_library=func_data.get("is_library", False),
                signature=json.dumps(func_data.get("signature", {})),
                metadata=json.dumps(func_data)
            )
            
            db.session.add(function)
        
        db.session.commit()
    
    def _store_cfg(self, task_id, binary_id, result, function_address):
        """
        Store CFG data in database
        
        Args:
            task_id: ID of the task
            binary_id: ID of the binary
            result: CFG result
            function_address: Address of the function
        """
        # Create analysis result
        analysis_result = AnalysisResult(
            task_id=task_id,
            binary_id=binary_id,
            analysis_type="getCFG",
            function_address=function_address,
            results=json.dumps(result),
            created_at=datetime.utcnow()
        )
        
        db.session.add(analysis_result)
        db.session.commit()
    
    def _decompile_function(self, binary_path, function_address, **kwargs):
        """
        Decompile a specific function using optimized headless Ghidra (primary method)
        
        Args:
            binary_path: Path to binary file
            function_address: Address of the function to decompile
            **kwargs: Additional parameters
            
        Returns:
            Decompilation result
        """
        try:
            logger.info(f"Starting headless decompilation for function at {function_address}")
            
            # Use headless as primary method since it's more reliable
            return self._decompile_function_headless(binary_path, function_address, **kwargs)
                
        except Exception as e:
            logger.error(f"Error in decompilation: {e}")
            return {
                "success": False,
                "error": str(e),
                "address": function_address
            }
    
    def _decompile_function_headless(self, binary_path, function_address, **kwargs):
        """
        Fallback decompilation using headless Ghidra
        
        Args:
            binary_path: Path to binary file
            function_address: Address of the function to decompile
            **kwargs: Additional parameters
            
        Returns:
            Decompilation result
        """
        try:
            logger.info(f"Starting headless decompilation for function at {function_address}")
            
            bridge_manager = self._get_bridge_manager()
            
            # Create projects directory if it doesn't exist
            projects_dir = os.path.join(os.getcwd(), "ghidra_projects")
            os.makedirs(projects_dir, exist_ok=True)
            
            # Get path to headless analyzer
            ghidra_path = bridge_manager.ghidra_path
            if os.name == 'nt':
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
            else:
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless")
            
            # Get path to decompilation script
            script_path = os.path.join(current_app.config['ANALYSIS_SCRIPTS_DIR'], 'decompile_function.py')
            
            # Verify script exists
            if not os.path.exists(script_path):
                logger.error(f"Decompilation script not found: {script_path}")
                return {
                    "success": False,
                    "error": f"Decompilation script not found: {script_path}",
                    "address": function_address
                }
            
            # Verify binary exists
            if not os.path.exists(binary_path):
                logger.error(f"Binary file not found: {binary_path}")
                return {
                    "success": False,
                    "error": f"Binary file not found: {binary_path}",
                    "address": function_address
                }
            
            # Run headless analyzer with decompilation script
            project_name = f"DecompProject_{os.path.basename(binary_path)}_{int(time.time())}"
            
            cmd = [
                headless_path,
                projects_dir,
                project_name,
                "-import", binary_path,
                "-scriptPath", os.path.dirname(script_path),
                "-postScript", os.path.basename(script_path), function_address
            ]
            
            logger.info(f"Running headless command for {function_address}:")
            logger.info(f"  Command: {' '.join(cmd)}")
            logger.info(f"  Script path: {script_path}")
            logger.info(f"  Binary path: {binary_path}")
            logger.info(f"  Working directory: {os.getcwd()}")
            
            import subprocess
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=os.getcwd()
            )
            
            # Add timeout to prevent hanging - increased for complex binaries
            try:
                stdout, stderr = process.communicate(timeout=600)  # 10 minute timeout per function
            except subprocess.TimeoutExpired:
                process.kill()
                return {
                    "success": False,
                    "error": "Headless decompilation timed out after 5 minutes",
                    "address": function_address
                }
            
            if process.returncode != 0:
                logger.error(f"Headless decompilation failed for {function_address}")
                logger.error(f"Return code: {process.returncode}")
                logger.error(f"STDERR: {stderr}")
                logger.error(f"STDOUT: {stdout}")
                return {
                    "success": False,
                    "error": f"Headless decompilation process failed (code {process.returncode}): {stderr}",
                    "address": function_address,
                    "debug_stdout": stdout,
                    "debug_stderr": stderr
                }
            
            # Parse result from stdout - improved parsing
            try:
                import json
                import re
                
                logger.info(f"Headless decompilation successful for {function_address}, parsing output...")
                
                # Look for JSON result in stdout
                json_patterns = [
                    r'RESULT_START\s*(.*?)\s*RESULT_END',  # Fixed: Match any content between delimiters
                    r'\{.*?"success".*?"data".*?\}',       # Match complete JSON with nested structures
                    r'\{[^{}]*"success"[^{}]*(?:\{[^{}]*\})*[^{}]*\}'  # Fallback simple pattern
                ]
                
                result = None
                for pattern in json_patterns:
                    json_match = re.search(pattern, stdout, re.DOTALL | re.IGNORECASE)
                    if json_match:
                        try:
                            result_text = json_match.group(1) if json_match.groups() else json_match.group(0)
                            result = json.loads(result_text)
                            logger.info(f"Successfully parsed JSON result from headless output")
                            break
                        except json.JSONDecodeError:
                            continue
                
                if result:
                    logger.info(f"Successfully parsed JSON result for {function_address}")
                    return result
                else:
                    logger.warning(f"No JSON result found for {function_address}, checking for success patterns...")
                    # Look for specific output patterns that indicate success
                    if "Decompilation complete" in stdout and "Error:" not in stdout:
                        # Extract basic information from output
                        function_name_match = re.search(r'Function:\s*(\w+)', stdout)
                        function_name = function_name_match.group(1) if function_name_match else f"func_{function_address}"
                        
                        # Create a basic successful result
                        logger.info(f"Creating basic success result from headless output patterns for {function_address}")
                        return {
                            "success": True,
                            "address": function_address,
                            "function_name": function_name,
                            "decompiled_code": f"// Function {function_name} decompiled successfully\n// Full output: {stdout[:200]}...",
                            "signature": "unknown",
                            "metadata": {
                                "headless_output": stdout[:500]  # Store partial output for debugging
                            }
                        }
                    else:
                        # Return failure with diagnostic info
                        logger.error(f"No success patterns found for {function_address}")
                        logger.error(f"Looking for 'Decompilation complete' in stdout...")
                        logger.error(f"First 500 chars of stdout: {stdout[:500]}")
                        return {
                            "success": False,
                            "error": "Could not parse headless result - no recognizable success pattern",
                            "address": function_address,
                            "debug_output": stdout[:500]
                        }
                    
            except Exception as parse_error:
                logger.error(f"Error parsing headless result: {parse_error}")
                return {
                    "success": False,
                    "error": f"Could not parse headless result: {parse_error}",
                    "address": function_address,
                    "debug_output": stdout[:300] if 'stdout' in locals() else "No output"
                }
                
        except Exception as e:
            logger.error(f"Error in headless decompilation: {e}")
            return {
                "success": False,
                "error": str(e),
                "address": function_address
            }
    
    def _bulk_decompile_functions(self, binary_path, function_ids, function_addresses, **kwargs):
        """
        Decompile multiple functions efficiently using optimized headless processing
        
        Args:
            binary_path: Path to binary file
            function_ids: List of function IDs
            function_addresses: List of function addresses
            **kwargs: Additional parameters
            
        Returns:
            Dictionary with decompilation results for each function
        """
        results = {}
        successful = 0
        failed = 0
        
        logger.info(f"Starting efficient bulk decompilation of {len(function_addresses)} functions using headless mode")
        
        try:
            # Process functions individually using the reliable headless method
            # This is more reliable than batch processing via bridge
            batch_size = kwargs.get('batch_size', 5)  # Smaller batches for headless to avoid overwhelming
            
            for i in range(0, len(function_addresses), batch_size):
                batch_ids = function_ids[i:i+batch_size]
                batch_addresses = function_addresses[i:i+batch_size]
                
                logger.info(f"Processing batch {i//batch_size + 1}/{(len(function_addresses) + batch_size - 1)//batch_size} ({len(batch_addresses)} functions)")
                
                for func_id, func_addr in zip(batch_ids, batch_addresses):
                    try:
                        # Use the reliable headless decompilation method
                        result = self._decompile_function_headless(binary_path, func_addr, **kwargs)
                        results[func_id] = result
                        
                        if result.get("success"):
                            successful += 1
                            # Store result immediately to avoid losing data
                            self._store_single_decompilation(func_id, result)
                        else:
                            failed += 1
                            
                    except Exception as e:
                        logger.error(f"Error decompiling function {func_addr}: {e}")
                        results[func_id] = {
                            "success": False,
                            "error": str(e),
                            "address": func_addr
                        }
                        failed += 1
                
                # Update progress
                progress = (successful + failed) / len(function_addresses) * 100
                logger.info(f"Batch completed. Overall progress: {progress:.1f}% ({successful + failed}/{len(function_addresses)})")
                
                # Small delay between batches to prevent overwhelming the system
                import time
                time.sleep(1)
            
            logger.info(f"Bulk decompilation completed: {successful} successful, {failed} failed")
            
            return {
                "success": True,
                "total_functions": len(function_addresses),
                "successful": successful,
                "failed": failed,
                "results": results
            }
            
        except Exception as e:
            logger.error(f"Error in bulk decompilation: {e}")
            return {
                "success": False,
                "error": str(e),
                "total_functions": len(function_addresses),
                "successful": successful,
                "failed": failed,
                "results": results
            }
    
    def _store_single_decompilation(self, function_id, result):
        """
        Store individual decompilation result directly to function record
        
        Args:
            function_id: ID of the function
            result: Decompilation result
        """
        try:
            function = Function.query.get(function_id)
            if not function:
                logger.error(f"Function {function_id} not found")
                return
            
            if result.get("success"):
                function.decompiled_code = result.get("decompiled_code", "")
                function.is_decompiled = True
                function.signature = result.get("signature", function.signature)
                function.calling_convention = result.get("calling_convention", function.calling_convention)
                function.return_type = result.get("return_type", function.return_type)
                function.stack_frame_size = result.get("stack_frame_size", function.stack_frame_size)
                
                logger.info(f"Updated function {function.name or function.address} with decompilation")
                
                # Update binary status using the new sophisticated status logic
                try:
                    binary = Binary.query.get(function.binary_id)
                    if binary:
                        old_status = binary.analysis_status
                        new_status = binary.update_analysis_status()
                        if new_status != old_status:
                            logger.info(f"Binary {function.binary_id} status updated from {old_status} to {new_status}")
                        
                except Exception as status_update_error:
                    logger.error(f"Error updating binary status: {status_update_error}")
                    # Don't fail the whole operation for status update errors
                
            else:
                logger.error(f"Decompilation failed for function {function_id}: {result.get('error')}")
            
            db.session.commit()
            
        except Exception as e:
            logger.error(f"Error storing decompilation for function {function_id}: {e}")
            # Try to rollback to prevent partial updates
            try:
                db.session.rollback()
            except:
                pass
    
    def _store_bulk_decompilation(self, task_id, binary_id, function_ids, result):
        """
        Store bulk decompilation results in database
        
        Args:
            task_id: ID of the task
            binary_id: ID of the binary
            function_ids: List of function IDs
            result: Bulk decompilation result
        """
        try:
            # Store the overall bulk result
            analysis_result = AnalysisResult(
                id=str(uuid.uuid4()),
                binary_id=binary_id,
                task_id=task_id,
                analysis_type="bulk_decompile",
                created_at=datetime.utcnow(),
                results=result
            )
            db.session.add(analysis_result)
            
            # Check if all functions are now decompiled and update binary status
            try:
                binary = Binary.query.get(binary_id)
                if binary:
                    # Use the new sophisticated status update logic instead of hardcoded 'processed'
                    old_status = binary.analysis_status
                    new_status = binary.update_analysis_status()
                    if new_status != old_status:
                        logger.info(f"Binary {binary_id} status updated from {old_status} to {new_status}")
                    
            except Exception as status_update_error:
                logger.error(f"Error updating binary status: {status_update_error}")
                # Don't fail the whole operation for status update errors
            
            db.session.commit()
            
            logger.info(f"Stored bulk decompilation results for task {task_id}")
            
        except Exception as e:
            logger.error(f"Error storing bulk decompilation results: {e}")
            # Try to rollback to prevent partial updates
            try:
                db.session.rollback()
            except:
                pass
    
    def _bulk_ai_explain_functions(self, binary_path, function_ids, function_addresses, **kwargs):
        """
        AI explain multiple functions efficiently
        
        Args:
            binary_path: Path to binary file
            function_ids: List of function IDs
            function_addresses: List of function addresses
            **kwargs: Additional parameters
            
        Returns:
            Dictionary with AI explanation results for each function
        """
        results = {}
        successful = 0
        failed = 0
        
        logger.info(f"Starting bulk AI explanation of {len(function_addresses)} functions")
        
        try:
            # Process functions individually for better error handling
            batch_size = kwargs.get('batch_size', 3)  # Smaller batches for AI processing
            
            for i in range(0, len(function_addresses), batch_size):
                batch_ids = function_ids[i:i+batch_size]
                batch_addresses = function_addresses[i:i+batch_size]
                
                logger.info(f"Processing AI batch {i//batch_size + 1}/{(len(function_addresses) + batch_size - 1)//batch_size} ({len(batch_addresses)} functions)")
                
                for func_id, func_addr in zip(batch_ids, batch_addresses):
                    try:
                        # Use the existing AI explanation method
                        result = self._explain_function_ai(func_id, **kwargs)
                        results[func_id] = result
                        
                        if result.get("success"):
                            # Update function immediately instead of waiting for bulk storage
                            try:
                                function = Function.query.get(func_id)
                                if function:
                                    function.ai_summary = result.get("explanation") or result.get("ai_summary")
                                    function.risk_score = result.get("risk_score")
                                    function.ai_analyzed = True
                                    db.session.commit()
                                    
                                    logger.info(f"[IMMEDIATE UPDATE] Updated function {function.name or function.address} with AI analysis (risk: {function.risk_score})")
                                else:
                                    logger.warning(f"[IMMEDIATE UPDATE] Function {func_id} not found in database")
                            except Exception as update_error:
                                logger.error(f"[IMMEDIATE UPDATE] Error updating function {func_id}: {update_error}")
                                # Don't fail the whole process for individual update errors
                            
                            successful += 1
                        else:
                            failed += 1
                            
                    except Exception as e:
                        logger.error(f"Error AI explaining function {func_addr}: {e}")
                        results[func_id] = {
                            "success": False,
                            "error": str(e),
                            "address": func_addr
                        }
                        failed += 1
                
                # Update progress
                progress = (successful + failed) / len(function_addresses) * 100
                logger.info(f"AI batch completed. Overall progress: {progress:.1f}% ({successful + failed}/{len(function_addresses)})")
                
                # Delay between batches to prevent overwhelming AI API
                import time
                time.sleep(2)  # 2 second delay between AI batches
            
            logger.info(f"Bulk AI explanation completed: {successful} successful, {failed} failed")
            
            return {
                "success": True,
                "total_functions": len(function_addresses),
                "successful": successful,
                "failed": failed,
                "results": results
            }
            
        except Exception as e:
            logger.error(f"Error in bulk AI explanation: {e}")
            return {
                "success": False,
                "error": str(e),
                "total_functions": len(function_addresses),
                "successful": successful,
                "failed": failed,
                "results": results
            }
    
    def _store_bulk_ai_explanation(self, task_id, binary_id, function_ids, result):
        """
        Store bulk AI explanation results in database
        
        Args:
            task_id: ID of the task
            binary_id: ID of the binary
            function_ids: List of function IDs
            result: Bulk AI explanation result
        """
        try:
            logger.info(f"Starting bulk AI storage for task {task_id}, binary {binary_id}")
            
            # Store individual function results first (this is what was missing!)
            if result.get("success") and "results" in result:
                function_results = result["results"]
                logger.info(f"Processing {len(function_results)} function AI results")
                
                successful_updates = 0
                for function_id, func_result in function_results.items():
                    if func_result.get("success"):
                        function = Function.query.get(function_id)
                        if function:
                            # Update function with AI results (same as individual analysis)
                            function.ai_summary = func_result.get("explanation") or func_result.get("ai_summary")
                            function.risk_score = func_result.get("risk_score")
                            function.ai_analyzed = True
                            successful_updates += 1
                        else:
                            logger.warning(f"Function {function_id} not found in database")
                    else:
                        error_msg = func_result.get('error', 'Unknown error')
                        logger.warning(f"AI analysis failed for function {function_id}: {error_msg}")
                        
                        # If it's a client initialization error, suggest checking configuration
                        if 'client not initialized' in error_msg.lower():
                            logger.info("💡 Hint: Update OpenAI API key in configuration at http://localhost:3000/config")
                
                # Commit individual function updates
                db.session.commit()
                logger.info(f"Successfully updated {successful_updates} functions with AI analysis")
            else:
                logger.warning(f"No results found in bulk AI result. Result keys: {result.keys() if isinstance(result, dict) else 'Not a dict'}")
            
            # Store the overall bulk result
            analysis_result = AnalysisResult(
                id=str(uuid.uuid4()),
                binary_id=binary_id,
                task_id=task_id,
                analysis_type="bulk_ai_explain",
                created_at=datetime.utcnow(),
                results=result
            )
            db.session.add(analysis_result)
            db.session.commit()
            
            logger.info(f"Stored bulk AI explanation results for task {task_id}")
            
        except Exception as e:
            logger.error(f"Error storing bulk AI explanation results: {e}")
    
    def _generate_binary_ai_summary(self, binary_id, binary_path, **kwargs):
        """
        Generate comprehensive AI summary for the entire binary using function analyses
        
        Args:
            binary_id: ID of the binary
            binary_path: Path to binary file
            **kwargs: Additional parameters
            
        Returns:
            AI summary result
        """
        try:
            binary = Binary.query.get(binary_id)
            if not binary:
                return {
                    "success": False,
                    "error": "Binary not found"
                }
            
            # Get functions for context
            all_functions = Function.query.filter_by(binary_id=binary_id).all()
            analyzed_functions = [f for f in all_functions if f.ai_analyzed and f.ai_summary]
            
            # Prepare comprehensive context for AI
            context = {
                "binary_name": binary.original_filename,
                "file_size": binary.file_size,
                "architecture": binary.architecture or "unknown",
                "total_functions": len(all_functions),
                "analyzed_functions": len([f for f in all_functions if f.is_analyzed]),
                "decompiled_functions": len([f for f in all_functions if f.is_decompiled]),
                "ai_analyzed_functions": len(analyzed_functions),
                "external_functions": len([f for f in all_functions if f.is_external]),
                
                # Function analysis summaries for binary-level insights
                "function_analyses": [
                    {
                        "name": f.name or f.original_name,
                        "address": f.address,
                        "size": f.size,
                        "risk_score": f.risk_score or 0,
                        "ai_summary": f.ai_summary,
                        "is_external": f.is_external,
                        "calling_convention": f.calling_convention
                    } for f in analyzed_functions[:20]  # Top 20 analyzed functions
                ],
                
                # High-risk functions summary
                "high_risk_functions": [
                    {
                        "name": f.name or f.original_name,
                        "address": f.address,
                        "risk_score": f.risk_score,
                        "ai_summary": f.ai_summary[:200] + "..." if len(f.ai_summary or "") > 200 else f.ai_summary
                    } for f in all_functions if f.risk_score and f.risk_score >= 70
                ],
                
                # Statistics
                "statistics": {
                    "avg_risk_score": sum(f.risk_score or 0 for f in all_functions) / len(all_functions) if all_functions else 0,
                    "high_risk_count": len([f for f in all_functions if f.risk_score and f.risk_score >= 70]),
                    "medium_risk_count": len([f for f in all_functions if f.risk_score and 40 <= f.risk_score < 70]),
                    "low_risk_count": len([f for f in all_functions if f.risk_score and f.risk_score < 40])
                }
            }
            
            logger.info(f"Generating binary AI summary with {len(analyzed_functions)} function analyses")
            
            # Generate comprehensive AI summary
            ai_service = self._get_ai_service()
            summary_result = ai_service.analyze_binary_comprehensive(context)
            
            return summary_result
            
        except Exception as e:
            logger.error(f"Error in binary AI summary: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _store_binary_ai_summary(self, task_id, binary_id, result):
        """
        Store binary AI summary results in database
        
        Args:
            task_id: ID of the task
            binary_id: ID of the binary
            result: AI summary result
        """
        try:
            if result.get("success"):
                # Store analysis result
                analysis_result = AnalysisResult(
                    id=str(uuid.uuid4()),
                    binary_id=binary_id,
                    task_id=task_id,
                    analysis_type="binary_ai_summary",
                    created_at=datetime.utcnow(),
                    results=result
                )
                db.session.add(analysis_result)
                db.session.commit()
                
                logger.info(f"Stored binary AI summary for binary {binary_id}")
            
        except Exception as e:
            logger.error(f"Error storing binary AI summary: {e}")
    
    def _store_comprehensive_analysis(self, task_id, binary_id, result):
        """
        Store comprehensive analysis results in database
        
        Args:
            task_id: ID of the task
            binary_id: ID of the binary
            result: Comprehensive analysis result
        """
        try:
            from flask import current_app
            from .models import (db, Binary, AnalysisResult, Function, Import, Export, 
                               BinaryString, MemoryRegion, Symbol, DataType, Instruction, 
                               CrossReference, ComprehensiveAnalysis, FunctionParameter,
                               LocalVariable, FunctionCall)
            import uuid
            from datetime import datetime
            
            # We're already in the app context from the caller
            if not result.get("success"):
                logger.error(f"Cannot store failed comprehensive analysis: {result.get('error')}")
                return
            
            data = result.get("data", {})
            
            # Create or update comprehensive analysis record
            comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
            if comp_analysis:
                # Update existing record
                comp_analysis.created_at = datetime.utcnow()
                comp_analysis.is_complete = False
                comp_analysis.error_message = None
            else:
                # Create new record
                comp_analysis = ComprehensiveAnalysis(
                    id=str(uuid.uuid4()),
                    binary_id=binary_id,
                    analysis_version='1.0',
                    created_at=datetime.utcnow()
                )
                db.session.add(comp_analysis)
            
            # Store metadata and statistics as JSON strings (not dicts)
            import json
            comp_analysis.program_metadata = json.dumps(data.get('metadata', {}))
            comp_analysis.statistics = json.dumps(data.get('statistics', {}))
            
            logger.info(f"Storing comprehensive analysis data for binary {binary_id}")
            
            # Store Memory Blocks
            if 'memoryBlocks' in data:
                logger.info(f"Storing {len(data['memoryBlocks'])} memory blocks")
                # Clear existing memory regions
                MemoryRegion.query.filter_by(binary_id=binary_id).delete()
                
                for block_data in data['memoryBlocks']:
                    memory_region = MemoryRegion(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        name=block_data.get('name', ''),
                        start_address=block_data.get('start', ''),
                        end_address=block_data.get('end', ''),
                        size=block_data.get('size', 0),
                        is_read=block_data.get('permissions', {}).get('read', True),
                        is_write=block_data.get('permissions', {}).get('write', False),
                        is_execute=block_data.get('permissions', {}).get('execute', False),
                        is_initialized=block_data.get('permissions', {}).get('initialized', True)
                    )
                    db.session.add(memory_region)
                comp_analysis.memory_blocks_extracted = True
            
            # Store Functions (enhanced)
            if 'functions' in data:
                logger.info(f"Storing {len(data['functions'])} functions")
                # Clear existing functions and related data
                Function.query.filter_by(binary_id=binary_id).delete()
                
                for func_data in data['functions']:
                    function = Function(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        address=func_data.get('entry', ''),
                        name=func_data.get('name', ''),
                        original_name=func_data.get('name', ''),
                        signature=func_data.get('signature', ''),
                        calling_convention=func_data.get('callingConvention', ''),
                        return_type=func_data.get('returnType', ''),
                        stack_frame_size=func_data.get('stackFrame', 0),
                        size=func_data.get('bodySize', 0),
                        is_analyzed=True,
                        is_thunk=func_data.get('flags', {}).get('isThunk', False),
                        is_external=func_data.get('flags', {}).get('isExternal', False),
                        has_no_return=func_data.get('flags', {}).get('hasNoReturn', False),
                        has_var_args=func_data.get('flags', {}).get('hasVarArgs', False),
                        decompiled_code=func_data.get('decompiled', ''),
                        is_decompiled=bool(func_data.get('decompiled', '')),
                        meta_data=func_data.get('flags', {})
                    )
                    db.session.add(function)
                    db.session.flush()  # Get the function ID
                    
                    # Store function parameters
                    for param_data in func_data.get('parameters', []):
                        parameter = FunctionParameter(
                            id=str(uuid.uuid4()),
                            function_id=function.id,
                            name=param_data.get('name', ''),
                            data_type=param_data.get('dataType', ''),
                            size=param_data.get('size', 0),
                            ordinal=param_data.get('ordinal', 0)
                        )
                        db.session.add(parameter)
                    
                    # Store local variables
                    for var_data in func_data.get('localVariables', []):
                        local_var = LocalVariable(
                            id=str(uuid.uuid4()),
                            function_id=function.id,
                            name=var_data.get('name', ''),
                            data_type=var_data.get('dataType', ''),
                            size=var_data.get('size', 0),
                            storage=var_data.get('storage', '')
                        )
                        db.session.add(local_var)
                
                comp_analysis.functions_extracted = True
            
            # Store Instructions
            if 'instructions' in data:
                logger.info(f"Storing {len(data['instructions'])} instructions")
                # Clear existing instructions
                Instruction.query.filter_by(binary_id=binary_id).delete()
                
                for instr_data in data['instructions']:
                    instruction = Instruction(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        address=instr_data.get('address', ''),
                        mnemonic=instr_data.get('mnemonic', ''),
                        operands=instr_data.get('operands', []),
                        bytes_data=instr_data.get('bytes', []),
                        length=instr_data.get('length', 0),
                        fall_through=instr_data.get('fallThrough')
                    )
                    db.session.add(instruction)
                comp_analysis.instructions_extracted = True
            
            # Store Strings
            if 'strings' in data:
                logger.info(f"Storing {len(data['strings'])} strings")
                # Clear existing strings
                BinaryString.query.filter_by(binary_id=binary_id).delete()
                
                for string_data in data['strings']:
                    binary_string = BinaryString(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        address=string_data.get('address', ''),
                        value=string_data.get('value', ''),
                        length=string_data.get('length', 0),
                        string_type=string_data.get('type', '')
                    )
                    db.session.add(binary_string)
                comp_analysis.strings_extracted = True
            
            # Store Symbols
            if 'symbols' in data:
                logger.info(f"Storing {len(data['symbols'])} symbols")
                # Clear existing symbols
                Symbol.query.filter_by(binary_id=binary_id).delete()
                
                for symbol_data in data['symbols']:
                    symbol = Symbol(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        name=symbol_data.get('name', ''),
                        address=symbol_data.get('address', ''),
                        symbol_type=symbol_data.get('symbolType', ''),
                        namespace=symbol_data.get('namespace', ''),
                        is_primary=symbol_data.get('primary', False)
                    )
                    db.session.add(symbol)
                comp_analysis.symbols_extracted = True
            
            # Store Cross References
            if 'xrefs' in data:
                logger.info(f"Storing {len(data['xrefs'])} cross-references")
                # Clear existing cross references
                CrossReference.query.filter_by(binary_id=binary_id).delete()
                
                for xref_data in data['xrefs']:
                    xref = CrossReference(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        from_address=xref_data.get('from', ''),
                        to_address=xref_data.get('to', ''),
                        reference_type=xref_data.get('type', ''),
                        operand_index=xref_data.get('operandIndex'),
                        is_primary=xref_data.get('primary', False)
                    )
                    db.session.add(xref)
                comp_analysis.xrefs_extracted = True
            
            # Store Imports
            if 'imports' in data:
                logger.info(f"Storing {len(data['imports'])} imports")
                # Clear existing imports
                Import.query.filter_by(binary_id=binary_id).delete()
                
                for import_data in data['imports']:
                    import_obj = Import(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        name=import_data.get('symbol', '') or import_data.get('label', ''),
                        library=import_data.get('library', ''),
                        address=import_data.get('address'),
                        namespace=''
                    )
                    db.session.add(import_obj)
                comp_analysis.imports_extracted = True
            
            # Store Exports
            if 'exports' in data:
                logger.info(f"Storing {len(data['exports'])} exports")
                # Clear existing exports
                Export.query.filter_by(binary_id=binary_id).delete()
                
                for export_data in data['exports']:
                    export_obj = Export(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        name=export_data.get('name', ''),
                        address=export_data.get('address', ''),
                        namespace=export_data.get('namespace', '')
                    )
                    db.session.add(export_obj)
                comp_analysis.exports_extracted = True
            
            # Store Data Types
            if 'dataTypes' in data:
                logger.info(f"Storing {len(data['dataTypes'])} data types")
                # Clear existing data types
                DataType.query.filter_by(binary_id=binary_id).delete()
                
                for datatype_data in data['dataTypes']:
                    data_type = DataType(
                        id=str(uuid.uuid4()),
                        binary_id=binary_id,
                        name=datatype_data.get('name', ''),
                        category=datatype_data.get('category', ''),
                        size=datatype_data.get('size', 0),
                        type_class=''
                    )
                    db.session.add(data_type)
                comp_analysis.data_types_extracted = True
            
            # Mark analysis as complete
            comp_analysis.is_complete = True
            
            # Store the overall comprehensive result as well
            analysis_result = AnalysisResult(
                id=str(uuid.uuid4()),
                binary_id=binary_id,
                task_id=task_id,
                analysis_type="comprehensive_analysis",
                created_at=datetime.utcnow(),
                results=result
            )
            db.session.add(analysis_result)
            
            # Update binary metadata
            binary = Binary.query.get(binary_id)
            if binary and 'metadata' in data:
                metadata = data['metadata']
                binary.architecture = metadata.get('language', binary.architecture)
                if metadata.get('executableMD5'):
                    binary.file_hash = metadata.get('executableMD5')
                
                # Update binary metadata
                binary_metadata = binary.meta_data or {}
                binary_metadata.update({
                    'comprehensive_analysis': True,
                    'analysis_timestamp': datetime.utcnow().isoformat(),
                    'ghidra_metadata': metadata
                })
                binary.meta_data = binary_metadata
            
            db.session.commit()
            
            logger.info(f"Successfully stored comprehensive analysis for binary {binary_id}")
        
        except Exception as e:
            logger.error(f"Error storing comprehensive analysis: {e}")
            import traceback
            logger.error(traceback.format_exc())
            db.session.rollback()
    
    def _explain_function_ai(self, function_id, **kwargs):
        """
        Generate AI explanation for a decompiled function
        
        Args:
            function_id: ID of the function to explain
            **kwargs: Additional parameters
            
        Returns:
            AI explanation result
        """
        try:
            function = Function.query.get(function_id)
            if not function:
                return {
                    "success": False,
                    "error": "Function not found"
                }
            
            if not function.decompiled_code:
                return {
                    "success": False,
                    "error": "Function not decompiled"
                }
            
            # Prepare context for AI
            context = {
                "function_name": function.name,
                "function_address": function.address,
                "signature": function.signature,
                "decompiled_code": function.decompiled_code,
                "size": function.size,
                "calling_convention": function.calling_convention
            }
            
            # Generate AI explanation
            ai_service = self._get_ai_service()
            explanation_result = ai_service.explain_function(context)
            
            return explanation_result
            
        except Exception as e:
            logger.error(f"Error in AI explanation: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _get_ai_service(self):
        """Get or create AI service for function explanation"""
        # Import multi-provider AI service
        from .multi_provider_ai_service import MultiProviderAIService
        
        if not hasattr(self, '_ai_service'):
            self._ai_service = MultiProviderAIService()
        
        return self._ai_service
    
    def reload_ai_service(self):
        """Reload AI service with updated configuration"""
        from .multi_provider_ai_service import MultiProviderAIService
        logger.info("Reloading AI service with updated configuration")
        
        # Clear cached AI service
        if hasattr(self, '_ai_service'):
            delattr(self, '_ai_service')
        
        # Create new AI service instance
        self._ai_service = MultiProviderAIService()
        
        # Log the status
        if self._ai_service.client:
            provider_name = getattr(self._ai_service, 'provider_name', 'unknown')
            logger.info(f"AI service successfully reinitialized with {provider_name} provider")
        else:
            logger.warning("AI service reinitialized but no valid provider/API key found")
        
        return self._ai_service.client is not None
    
    def _store_decompilation(self, task_id, binary_id, function_id, result):
        """
        Store decompilation results in database
        
        Args:
            task_id: ID of the task
            binary_id: ID of the binary
            function_id: ID of the function
            result: Decompilation result
        """
        function = Function.query.get(function_id)
        if function and result.get("success"):
            # Update function with decompilation results
            function.decompiled_code = result.get("decompiled_code")
            function.is_decompiled = True
            function.signature = result.get("signature") or function.signature
            function.calling_convention = result.get("calling_convention") or function.calling_convention
            
            # Update metadata
            if result.get("metadata"):
                metadata = function.meta_data or {}
                metadata.update(result["metadata"])
                function.meta_data = metadata
            
            db.session.commit()
            
            # Store analysis result
            analysis_result = AnalysisResult(
                id=str(uuid.uuid4()),
                binary_id=binary_id,
                task_id=task_id,
                analysis_type="decompile_function",
                function_address=function.address,
                created_at=datetime.utcnow(),
                results=result
            )
            db.session.add(analysis_result)
            db.session.commit()
    
    def _store_ai_explanation(self, task_id, binary_id, function_id, result):
        """
        Store AI explanation results in database
        
        Args:
            task_id: ID of the task
            binary_id: ID of the binary
            function_id: ID of the function
            result: AI explanation result
        """
        function = Function.query.get(function_id)
        if function and result.get("success"):
            # Update function with AI results
            function.ai_summary = result.get("explanation")
            function.risk_score = result.get("risk_score")
            function.ai_analyzed = True
            
            db.session.commit()
            
            # Store analysis result  
            analysis_result = AnalysisResult(
                id=str(uuid.uuid4()),
                binary_id=binary_id,
                task_id=task_id,
                analysis_type="explain_function",
                function_address=function.address,
                created_at=datetime.utcnow(),
                results=result
            )
            db.session.add(analysis_result)
            db.session.commit()
    
    def _store_comprehensive_results(self, binary_id, result):
        """
        Store comprehensive analysis results
        
        Args:
            binary_id: ID of the binary
            result: Comprehensive analysis result
        """
        # Store functions
        self._store_functions(binary_id, result)
        
        # Update binary metadata
        binary = db.session.query(Binary).get(binary_id)
        if binary:
            metadata = json.loads(binary.metadata) if binary.metadata else {}
            metadata.update({
                "architecture": result.get("architecture"),
                "compiler": result.get("compiler"),
                "creation_date": result.get("creation_date"),
                "function_count": len(result.get("functions", []))
            })
            binary.metadata = json.dumps(metadata)
            binary.analysis_status = "analyzed"
            db.session.commit()
    
    def cancel_task(self, task_id):
        """
        Cancel a running task
        
        Args:
            task_id: ID of the task to cancel
        
        Returns:
            bool: True if task was canceled, False otherwise
        """
        try:
            from .models import db, AnalysisTask, Binary
            
            # Update task status in database
            task = AnalysisTask.query.get(task_id)
            if not task:
                logger.warning(f"Task {task_id} not found in database")
                return False
            
            # Check if task can be cancelled
            if task.status not in ['queued', 'running']:
                logger.warning(f"Cannot cancel task {task_id} with status {task.status}")
                return False
            
            # Update task in database
            task.status = 'cancelled'
            task.completed_at = datetime.utcnow()
            task.error_message = 'Cancelled by user'
            
            # Update binary status if needed
            binary = Binary.query.get(task.binary_id)
            if binary and binary.analysis_status == 'analyzing':
                # Check if there are other running tasks for this binary
                other_running_tasks = AnalysisTask.query.filter_by(
                    binary_id=task.binary_id
                ).filter(
                    AnalysisTask.status.in_(['queued', 'running'])
                ).filter(
                    AnalysisTask.id != task_id
                ).count()
                
                if other_running_tasks == 0:
                    binary.analysis_status = 'processed'  # Set back to processed instead of cancelled
            
            db.session.commit()
            
            # Remove from active tasks dict if present
            with self.task_lock:
                if task_id in self.tasks:
                    del self.tasks[task_id]
            
            logger.info(f"Successfully cancelled task {task_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error canceling task {task_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False
    
    def cancel_all_tasks(self, binary_id=None):
        """
        Cancel all running tasks
        
        Args:
            binary_id: Optional binary ID to filter tasks
            
        Returns:
            (success, message, cancelled_count): Tuple with success flag, message, and count of cancelled tasks
        """
        try:
            from .models import db, AnalysisTask, Binary
            
            cancelled_count = 0
            
            # Get tasks to cancel from database
            if binary_id:
                # Get all running/queued tasks for specific binary
                tasks_to_cancel = AnalysisTask.query.filter(
                    AnalysisTask.binary_id == binary_id,
                    AnalysisTask.status.in_(['queued', 'running'])
                ).all()
            else:
                # Get all running/queued tasks
                tasks_to_cancel = AnalysisTask.query.filter(
                    AnalysisTask.status.in_(['queued', 'running'])
                ).all()
            
            # Cancel each task
            for task in tasks_to_cancel:
                try:
                    # Update task status
                    task.status = 'cancelled'
                    task.completed_at = datetime.utcnow()
                    task.error_message = 'Cancelled by user'
                    cancelled_count += 1
                    
                    # Remove from active tasks dict if present
                    with self.task_lock:
                        if task.id in self.tasks:
                            del self.tasks[task.id]
                    
                    logger.info(f"Successfully cancelled task {task.id}")
                    
                except Exception as e:
                    logger.error(f"Error cancelling task {task.id}: {e}")
            
            # Update binary statuses if needed
            if binary_id:
                # Update specific binary status
                binary = Binary.query.get(binary_id)
                if binary and binary.analysis_status == 'analyzing':
                    # Check if there are any remaining running tasks for this binary
                    remaining_tasks = AnalysisTask.query.filter(
                        AnalysisTask.binary_id == binary_id,
                        AnalysisTask.status.in_(['queued', 'running'])
                    ).count()
                    
                    if remaining_tasks == 0:
                        binary.analysis_status = 'processed'  # Reset to processed
                        logger.info(f"Updated binary {binary_id} status to 'processed' after cancelling all tasks")
            else:
                # Update all affected binary statuses
                affected_binaries = Binary.query.filter_by(analysis_status='analyzing').all()
                for binary in affected_binaries:
                    remaining_tasks = AnalysisTask.query.filter(
                        AnalysisTask.binary_id == binary.id,
                        AnalysisTask.status.in_(['queued', 'running'])
                    ).count()
                    
                    if remaining_tasks == 0:
                        binary.analysis_status = 'processed'
                        logger.info(f"Updated binary {binary.id} status to 'processed' after cancelling all tasks")
            
            db.session.commit()
            
            if cancelled_count > 0:
                if binary_id:
                    message = f"Cancelled {cancelled_count} tasks for binary {binary_id}"
                else:
                    message = f"Cancelled {cancelled_count} tasks"
                return True, message, cancelled_count
            else:
                if binary_id:
                    message = f"No active tasks found for binary {binary_id}"
                else:
                    message = "No active tasks to cancel"
                return False, message, 0
                
        except Exception as e:
            logger.error(f"Error cancelling tasks: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return False, f"Error cancelling tasks: {str(e)}", 0
    
    def get_task_status(self, task_id):
        """
        Get task status
        
        Args:
            task_id: ID of the task
            
        Returns:
            Task status or None if not found
        """
        task = db.session.query(AnalysisTask).get(task_id)
        return task.to_dict() if task else None
    
    def get_active_tasks(self, binary_id=None):
        """
        Get active tasks
        
        Args:
            binary_id: Optional binary ID to filter tasks
            
        Returns:
            List of active tasks
        """
        query = db.session.query(AnalysisTask).filter(
            AnalysisTask.status.in_(["queued", "running"])
        )
        
        if binary_id:
            query = query.filter_by(binary_id=binary_id)
        
        return [task.to_dict() for task in query.all()]
    
    def shutdown(self):
        """Shutdown task manager and cleanup resources"""
        if self.bridge_manager:
            self.bridge_manager.close_all_connections()
            self.bridge_manager = None
        
        self._instance = None

    def submit_task(self, task_id, task_type, binary_id, parameters=None):
        """
        Submit a task for execution
        
        Args:
            task_id: ID of the task
            task_type: Type of analysis task
            binary_id: ID of the binary to analyze
            parameters: Additional task parameters
        """
        if parameters is None:
            parameters = {}
        
        with self.task_lock:
            # Check if task already exists
            if task_id in self.tasks:
                raise ValueError(f"Task {task_id} already exists")
            
            # Create task thread
            task_thread = threading.Thread(
                target=self._run_task,
                args=(task_id, task_type, binary_id),
                kwargs=parameters,
                daemon=True
            )
            
            # Store task info
            self.tasks[task_id] = {
                'thread': task_thread,
                'status': 'queued',
                'start_time': datetime.utcnow(),
                'type': task_type,
                'binary_id': binary_id,
                'parameters': parameters
            }
            
            # Start task thread
            task_thread.start()
            
            return True


class ThreadingTaskManager(TaskManager):
    """
    Task Manager implementation using Python threading
    """
    
    def submit_task(self, task_id, task_type, binary, parameters, ghidra_bridge_manager=None):
        """
        Submit a task for execution
        
        Args:
            task_id: ID of the task
            task_type: Type of analysis task
            binary: Binary object
            parameters: Task parameters
            ghidra_bridge_manager: Optional Ghidra Bridge Manager instance
            
        Returns:
            task_id: ID of the submitted task
        """
        try:
            # Set bridge manager if provided
            if ghidra_bridge_manager:
                self.bridge_manager = ghidra_bridge_manager
            
            # Check if bridge manager is available
            if not self.bridge_manager:
                raise ValueError("Ghidra Bridge Manager is not available")
                
            # Check if bridge is connected
            if not self.bridge_manager.is_connected():
                raise ConnectionError("Ghidra Bridge is not connected")
            
            # Update task status to running
            self._update_task_status(task_id, "running", None)
            
            # Start thread for task
            with self.task_lock:
                thread = threading.Thread(
                    target=self._run_task,
                    args=(task_id, task_type, binary.id),
                    kwargs=parameters
                )
                thread.daemon = True
                thread.start()
                
                self.tasks[task_id] = {
                    "thread": thread,
                    "started_at": datetime.utcnow()
                }
            
            return task_id
        except Exception as e:
            import traceback
            print(f"Error submitting task: {e}")
            print(traceback.format_exc())
            self._update_task_status(task_id, "failed", str(e))
            raise 