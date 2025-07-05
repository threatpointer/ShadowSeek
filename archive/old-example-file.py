# Flask-Ghidra Integration: Core Implementation Examples

# 1. Ghidra Headless Manager Service
import subprocess
import tempfile
import os
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

class GhidraHeadlessManager:
    """
    Manages Ghidra headless operations for binary analysis
    """
    
    def __init__(self, ghidra_install_path: str, temp_dir: str = "/tmp/ghidra_projects"):
        self.ghidra_path = Path(ghidra_install_path)
        self.temp_dir = Path(temp_dir)
        self.temp_dir.mkdir(exist_ok=True)
        self.analyze_headless = self.ghidra_path / "support" / "analyzeHeadless"
        
        # Verify Ghidra installation
        if not self.analyze_headless.exists():
            raise FileNotFoundError(f"Ghidra installation not found at {ghidra_install_path}")
    
    def create_temp_project(self, project_name: str = None) -> str:
        """Create a temporary Ghidra project directory"""
        if not project_name:
            project_name = f"temp_project_{os.getpid()}"
        
        project_path = self.temp_dir / project_name
        project_path.mkdir(exist_ok=True)
        return str(project_path)
    
    def import_and_analyze_binary(self, binary_path: str, project_name: str = None, 
                                analysis_options: Dict = None) -> Dict[str, Any]:
        """
        Import binary and run comprehensive analysis
        """
        project_path = self.create_temp_project(project_name)
        
        try:
            # Basic analysis command
            cmd = [
                str(self.analyze_headless),
                project_path,
                "TempProject",
                "-import", binary_path,
                "-postScript", "comprehensive_analysis.py",
                "-scriptPath", str(Path(__file__).parent / "ghidra_scripts"),
                "-deleteProject"
            ]
            
            # Add analysis options
            if analysis_options:
                if analysis_options.get('no_analysis', False):
                    cmd.append("-noanalysis")
                if analysis_options.get('timeout'):
                    cmd.extend(["-timeout", str(analysis_options['timeout'])])
            
            # Execute Ghidra headless
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            # Parse results
            if result.returncode == 0:
                return self._parse_analysis_results(result.stdout)
            else:
                raise Exception(f"Ghidra analysis failed: {result.stderr}")
                
        finally:
            # Cleanup temporary files
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def decompile_function(self, binary_path: str, function_address: str) -> Dict[str, str]:
        """
        Decompile a specific function at given address
        """
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "DecompileProject",
                "-import", binary_path,
                "-postScript", "decompile_function.py",
                function_address,
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                return {"decompiled_code": result.stdout, "status": "success"}
            else:
                return {"error": result.stderr, "status": "failed"}
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def get_function_list(self, binary_path: str) -> List[Dict[str, str]]:
        """
        Extract list of all functions from binary
        """
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "FunctionProject",
                "-import", binary_path,
                "-postScript", "list_functions.py",
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"Function listing failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def get_xrefs(self, binary_path: str, address: str, xref_type: str = "both") -> Dict[str, List]:
        """
        Get cross-references to/from a specific address
        xref_type: 'to', 'from', or 'both'
        """
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "XrefProject",
                "-import", binary_path,
                "-postScript", "get_xrefs.py",
                address, xref_type,
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"Xref analysis failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def get_stack_frame(self, binary_path: str, function_address: str) -> Dict[str, Any]:
        """
        Get stack frame information for a function including local variables and parameters
        """
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "StackProject",
                "-import", binary_path,
                "-postScript", "get_stack_frame.py",
                function_address,
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"Stack frame analysis failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def get_memory_regions(self, binary_path: str) -> List[Dict[str, Any]]:
        """
        Get all mapped memory segments/regions
        """
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "MemoryProject",
                "-import", binary_path,
                "-postScript", "get_memory_regions.py",
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"Memory region analysis failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def get_diffs(self, binary_path1: str, binary_path2: str, diff_type: str = "instructions") -> Dict[str, Any]:
        """
        Compare two binaries and identify differences
        diff_type: 'instructions', 'functions', 'data'
        """
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "DiffProject",
                "-import", binary_path1,
                "-import", binary_path2,
                "-postScript", "binary_diff.py",
                diff_type,
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)  # 30 min timeout
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"Binary diff analysis failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def get_cfg(self, binary_path: str, function_address: str) -> Dict[str, Any]:
        """
        Extract control flow graph for a specific function
        """
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "CFGProject",
                "-import", binary_path,
                "-postScript", "extract_cfg.py",
                function_address,
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"CFG extraction failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def execute_symbolically(self, binary_path: str, function_address: str, 
                           engine: str = "angr", max_depth: int = 100) -> Dict[str, Any]:
        """
        Perform symbolic execution on a function
        engine: 'angr' or 'klee'
        """
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "SymbolicProject",
                "-import", binary_path,
                "-postScript", "symbolic_execution.py",
                function_address, engine, str(max_depth),
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)  # 1 hour timeout
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"Symbolic execution failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def search_patterns(self, binary_path: str, pattern_types: List[str] = None) -> Dict[str, List]:
        """
        Search for dangerous patterns, crypto signatures, format strings, etc.
        pattern_types: ['dangerous_calls', 'crypto_signatures', 'format_strings', 'hardcoded_keys', 'user_input']
        """
        if pattern_types is None:
            pattern_types = ['dangerous_calls', 'crypto_signatures', 'format_strings']
        
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "PatternProject",
                "-import", binary_path,
                "-postScript", "pattern_search.py",
                ",".join(pattern_types),
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"Pattern search failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def run_vuln_checks(self, binary_path: str, plugins: List[str] = None) -> Dict[str, Any]:
        """
        Run vulnerability detection plugins
        plugins: ['rizzo', 'fidb', 'vulnchatter', 'pcode_dataflow']
        """
        if plugins is None:
            plugins = ['rizzo', 'fidb', 'vulnchatter']
        
        project_path = self.create_temp_project()
        
        try:
            cmd = [
                str(self.analyze_headless),
                project_path,
                "VulnProject",
                "-import", binary_path,
                "-postScript", "vulnerability_checks.py",
                ",".join(plugins),
                "-deleteProject"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                raise Exception(f"Vulnerability checks failed: {result.stderr}")
                
        finally:
            if os.path.exists(project_path):
                shutil.rmtree(project_path)
    
    def _parse_analysis_results(self, stdout: str) -> Dict[str, Any]:
        """Parse Ghidra analysis output"""
        # Implementation depends on output format from Ghidra scripts
        # This is a placeholder for result parsing logic
        return {"raw_output": stdout, "status": "completed"}


# 2. Flask Application Structure
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:pass@localhost/ghidra_db'
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

db = SQLAlchemy(app)

# Database Models
class Binary(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    analysis_status = db.Column(db.String(50), default='pending')

class AnalysisTask(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(db.String(36), db.ForeignKey('binary.id'), nullable=False)
    task_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), default='queued')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    results = db.Column(db.JSON)
    error_message = db.Column(db.Text)

# 3. API Endpoints
@app.route('/api/binaries/upload', methods=['POST'])
def upload_binary():
    """Upload binary file for analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file:
        filename = secure_filename(file.filename)
        binary_id = str(uuid.uuid4())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{binary_id}_{filename}")
        
        file.save(file_path)
        
        # Create database record
        binary = Binary(
            id=binary_id,
            filename=filename,
            file_path=file_path,
            file_size=os.path.getsize(file_path)
        )
        db.session.add(binary)
        db.session.commit()
        
        return jsonify({
            'binary_id': binary_id,
            'filename': filename,
            'status': 'uploaded'
        }), 201

@app.route('/api/analysis/start', methods=['POST'])
def start_analysis():
    """Start comprehensive binary analysis"""
    data = request.get_json()
    binary_id = data.get('binary_id')
    analysis_type = data.get('analysis_type', 'comprehensive')
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    # Create analysis task
    task = AnalysisTask(
        binary_id=binary_id,
        task_type=analysis_type
    )
    db.session.add(task)
    db.session.commit()
    
    # Queue analysis task (using Celery)
    from tasks.analysis_tasks import analyze_binary_task
    analyze_binary_task.delay(task.id)
    
    return jsonify({
        'task_id': task.id,
        'status': 'queued'
    }), 202

@app.route('/api/analysis/<task_id>/status', methods=['GET'])
def get_analysis_status(task_id):
    """Get analysis task status"""
    task = AnalysisTask.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    return jsonify({
        'task_id': task.id,
        'status': task.status,
        'created_at': task.created_at.isoformat(),
        'completed_at': task.completed_at.isoformat() if task.completed_at else None,
        'error_message': task.error_message
    })

@app.route('/api/analysis/<task_id>/results', methods=['GET'])
def get_analysis_results(task_id):
    """Get analysis results"""
    task = AnalysisTask.query.get(task_id)
    if not task:
        return jsonify({'error': 'Task not found'}), 404
    
    if task.status != 'completed':
        return jsonify({'error': 'Analysis not completed'}), 400
    
    return jsonify({
        'task_id': task.id,
        'results': task.results
    })

@app.route('/api/ghidra/decompile', methods=['POST'])
def decompile_function():
    """Decompile specific function"""
    data = request.get_json()
    binary_id = data.get('binary_id')
    function_address = data.get('function_address')
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    # Initialize Ghidra manager
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        result = ghidra_manager.decompile_function(binary.file_path, function_address)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/functions', methods=['GET'])
def list_functions():
    """List all functions in binary"""
    binary_id = request.args.get('binary_id')
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        functions = ghidra_manager.get_function_list(binary.file_path)
        return jsonify({'functions': functions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/xrefs', methods=['POST'])
def get_cross_references():
    """Get cross-references for an address"""
    data = request.get_json()
    binary_id = data.get('binary_id')
    address = data.get('address')
    xref_type = data.get('xref_type', 'both')
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        xrefs = ghidra_manager.get_xrefs(binary.file_path, address, xref_type)
        return jsonify(xrefs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/stack-frame', methods=['POST'])
def get_function_stack_frame():
    """Get stack frame information for a function"""
    data = request.get_json()
    binary_id = data.get('binary_id')
    function_address = data.get('function_address')
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        stack_frame = ghidra_manager.get_stack_frame(binary.file_path, function_address)
        return jsonify(stack_frame)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/memory-regions', methods=['GET'])
def get_memory_regions():
    """Get memory regions/segments"""
    binary_id = request.args.get('binary_id')
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        regions = ghidra_manager.get_memory_regions(binary.file_path)
        return jsonify({'memory_regions': regions})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/diff', methods=['POST'])
def binary_diff():
    """Compare two binaries"""
    data = request.get_json()
    binary_id1 = data.get('binary_id1')
    binary_id2 = data.get('binary_id2')
    diff_type = data.get('diff_type', 'instructions')
    
    binary1 = Binary.query.get(binary_id1)
    binary2 = Binary.query.get(binary_id2)
    
    if not binary1 or not binary2:
        return jsonify({'error': 'One or both binaries not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        diffs = ghidra_manager.get_diffs(binary1.file_path, binary2.file_path, diff_type)
        return jsonify(diffs)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/cfg', methods=['POST'])
def get_control_flow_graph():
    """Get control flow graph for a function"""
    data = request.get_json()
    binary_id = data.get('binary_id')
    function_address = data.get('function_address')
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        cfg = ghidra_manager.get_cfg(binary.file_path, function_address)
        return jsonify(cfg)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/symbolic-execution', methods=['POST'])
def symbolic_execution():
    """Perform symbolic execution on a function"""
    data = request.get_json()
    binary_id = data.get('binary_id')
    function_address = data.get('function_address')
    engine = data.get('engine', 'angr')
    max_depth = data.get('max_depth', 100)
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        results = ghidra_manager.execute_symbolically(
            binary.file_path, function_address, engine, max_depth
        )
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/pattern-search', methods=['POST'])
def pattern_search():
    """Search for dangerous patterns and signatures"""
    data = request.get_json()
    binary_id = data.get('binary_id')
    pattern_types = data.get('pattern_types', ['dangerous_calls', 'crypto_signatures'])
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        patterns = ghidra_manager.search_patterns(binary.file_path, pattern_types)
        return jsonify(patterns)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ghidra/vulnerability-checks', methods=['POST'])
def vulnerability_checks():
    """Run vulnerability detection plugins"""
    data = request.get_json()
    binary_id = data.get('binary_id')
    plugins = data.get('plugins', ['rizzo', 'fidb', 'vulnchatter'])
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
    
    try:
        vulnerabilities = ghidra_manager.run_vuln_checks(binary.file_path, plugins)
        return jsonify(vulnerabilities)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# 4. Celery Task Implementation
from celery import Celery

celery = Celery('ghidra_tasks')
celery.config_from_object('celeryconfig')

@celery.task(bind=True)
def analyze_binary_task(self, task_id):
    """Celery task for binary analysis"""
    
    # Update task status
    task = AnalysisTask.query.get(task_id)
    task.status = 'running'
    db.session.commit()
    
    try:
        binary = Binary.query.get(task.binary_id)
        ghidra_manager = GhidraHeadlessManager('/path/to/ghidra')
        
        # Run comprehensive analysis
        results = ghidra_manager.import_and_analyze_binary(
            binary.file_path,
            analysis_options={'timeout': 3600}
        )
        
        # Update task with results
        task.status = 'completed'
        task.completed_at = datetime.utcnow()
        task.results = results
        db.session.commit()
        
        return {'status': 'completed', 'results': results}
        
    except Exception as e:
        # Handle errors
        task.status = 'failed'
        task.error_message = str(e)
        task.completed_at = datetime.utcnow()
        db.session.commit()
        
        raise self.retry(exc=e, countdown=60, max_retries=3)


# 5. Ghidra Analysis Scripts
# These would be separate Python files in ghidra_scripts/ directory

# comprehensive_analysis.py (Ghidra script)
"""
Comprehensive binary analysis script for Ghidra headless mode
"""

import json
import sys

# Get current program
currentProgram = getCurrentProgram()
if currentProgram is None:
    print("No program loaded")
    sys.exit(1)

results = {
    "binary_name": currentProgram.getName(),
    "architecture": str(currentProgram.getLanguage().getProcessor()),
    "entry_point": str(currentProgram.getAddressMap().getImageBase()),
    "functions": [],
    "strings": [],
    "imports": [],
    "exports": []
}

# Get function manager
functionManager = currentProgram.getFunctionManager()

# Extract function information
functions = functionManager.getFunctions(True)
for func in functions:
    func_info = {
        "name": func.getName(),
        "address": str(func.getEntryPoint()),
        "size": func.getBody().getNumAddresses(),
        "parameters": len(func.getParameters())
    }
    results["functions"].append(func_info)

# Extract strings
listing = currentProgram.getListing()
stringTable = currentProgram.getListing().getDefinedData(True)
for data in stringTable:
    if data.hasStringValue():
        string_info = {
            "address": str(data.getAddress()),
            "value": data.getValue().toString(),
            "length": data.getLength()
        }
        results["strings"].append(string_info)

# Extract imports
symbolTable = currentProgram.getSymbolTable()
externalManager = currentProgram.getExternalManager()

for extLoc in externalManager.getExternalLocations():
    import_info = {
        "name": extLoc.getLabel(),
        "library": extLoc.getLibraryName(),
        "address": str(extLoc.getAddress()) if extLoc.getAddress() else None
    }
    results["imports"].append(import_info)

# Output results as JSON
print(json.dumps(results, indent=2))


# 6. Configuration Files
# requirements.txt
"""
Flask==2.3.3
Flask-SQLAlchemy==3.0.5
Flask-Migrate==4.0.5
Celery==5.3.4
Redis==5.0.1
Psycopg2-binary==2.9.7
Werkzeug==2.3.7
Gunicorn==21.2.0
python-dotenv==1.0.0
"""

# celeryconfig.py
"""
broker_url = 'redis://localhost:6379/0'
result_backend = 'redis://localhost:6379/0'
task_serializer = 'json'
accept_content = ['json']
result_serializer = 'json'
timezone = 'UTC'
enable_utc = True
task_routes = {
    'tasks.analysis_tasks.analyze_binary_task': {'queue': 'analysis'},
}
"""

# docker-compose.yml
"""
version: '3.8'

services:
  web:
    build: .
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://ghidra:password@db:5432/ghidra_db
      - CELERY_BROKER_URL=redis://redis:6379/0
      - GHIDRA_INSTALL_DIR=/opt/ghidra
    volumes:
      - ./uploads:/tmp/uploads
      - ./ghidra:/opt/ghidra
    depends_on:
      - db
      - redis

  celery:
    build: .
    command: celery -A tasks.celery_app worker --loglevel=info
    environment:
      - DATABASE_URL=postgresql://ghidra:password@db:5432/ghidra_db
      - CELERY_BROKER_URL=redis://redis:6379/0
      - GHIDRA_INSTALL_DIR=/opt/ghidra
    volumes:
      - ./uploads:/tmp/uploads
      - ./ghidra:/opt/ghidra
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=ghidra_db
      - POSTGRES_USER=ghidra
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
"""

if __name__ == '__main__':
    app.run(debug=True)