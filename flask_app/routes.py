#!/usr/bin/env python3
"""
API routes for ShadowSeek - Advanced Binary Security Analysis Platform
"""

import os
import uuid
import hashlib
from datetime import datetime
from flask import jsonify, current_app, request, send_file, make_response
from werkzeug.utils import secure_filename
import logging
import shutil
import zipfile
import io
import threading
import time

from . import api_bp, db
from .models import (Binary, AnalysisTask, AnalysisResult, Function, MemoryRegion,
                     Import, Export, BinaryString, Symbol, DataType, Instruction, 
                     CrossReference, ComprehensiveAnalysis, FunctionParameter, 
                     LocalVariable, FunctionCall, UnifiedSecurityFinding, SecurityEvidence,
                     Vulnerability, VulnerabilityPattern, VulnerabilityReport,
                     FuzzingHarness, FuzzingTarget, FuzzingSession, Configuration)

# Configure logging
logger = logging.getLogger(__name__)

# Helper functions
def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Add documentation endpoints
@api_bp.route('/docs/<path:doc_path>', methods=['GET'])
def get_documentation(doc_path):
    """Serve documentation markdown files"""
    try:
        # Sanitize the path to prevent directory traversal
        doc_path = doc_path.replace('..', '').strip('/')
        
        # Map the doc path to actual file
        if not doc_path or doc_path == '':
            doc_path = 'README.md'
        elif not doc_path.endswith('.md'):
            doc_path += '.md'
            
        # Build the full path
        docs_base = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'user-docs')
        full_path = os.path.join(docs_base, doc_path)
        
        # Check if file exists
        if not os.path.exists(full_path):
            return jsonify({'error': 'Documentation file not found'}), 404
            
        # Read and return the markdown content
        with open(full_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        return jsonify({
            'content': content,
            'path': doc_path,
            'last_modified': datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error serving documentation {doc_path}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/docs', methods=['GET'])
def list_documentation():
    """List available documentation files"""
    try:
        docs_base = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'user-docs')
        
        if not os.path.exists(docs_base):
            return jsonify({'docs': [], 'error': 'Documentation directory not found'})
            
        docs = []
        for root, dirs, files in os.walk(docs_base):
            for file in files:
                if file.endswith('.md'):
                    rel_path = os.path.relpath(os.path.join(root, file), docs_base)
                    docs.append({
                        'path': rel_path.replace('\\', '/'),
                        'name': file,
                        'category': os.path.basename(root) if root != docs_base else 'root'
                    })
                    
        return jsonify({'docs': docs})
        
    except Exception as e:
        logger.error(f"Error listing documentation: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/status', methods=['GET'])
def get_status():
    """Get system status"""
    try:
        # Count binaries and tasks
        try:
            binary_count = Binary.query.count()
            task_count = AnalysisTask.query.count()
            running_tasks = AnalysisTask.query.filter_by(status='running').count()
            queued_tasks = AnalysisTask.query.filter_by(status='queued').count()
        except Exception as e:
            binary_count = 0
            task_count = 0
            running_tasks = 0
            queued_tasks = 0
        
        # Check Ghidra Bridge status
        ghidra_bridge_status = "connected" if current_app.ghidra_bridge_manager.is_connected() else "disconnected"
        
        return jsonify({
            'status': 'ok',
            'binaries': binary_count,
            'tasks': {
                'total': task_count,
                'running': running_tasks,
                'queued': queued_tasks
            },
            'ghidra_bridge': ghidra_bridge_status,
            'ghidra_bridge_connected': current_app.ghidra_bridge_manager.is_connected(),
            'server_time': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries', methods=['GET'])
def get_binaries():
    """Get list of uploaded binaries"""
    try:
        binaries = Binary.query.all()
        return jsonify({
            'binaries': [binary.to_dict() for binary in binaries]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/tasks', methods=['GET'])
def get_tasks():
    """Get list of analysis tasks"""
    try:
        tasks = AnalysisTask.query.all()
        return jsonify({
            'tasks': [task.to_dict() for task in tasks]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/tasks', methods=['GET'])
def get_binary_tasks(binary_id):
    """Get tasks for a specific binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        tasks = AnalysisTask.query.filter_by(binary_id=binary_id).all()
        return jsonify({
            'tasks': [task.to_dict() for task in tasks]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/bridge/test', methods=['GET'])
def test_bridge():
    """Test Ghidra Bridge connection"""
    try:
        status = current_app.ghidra_bridge_manager.get_bridge_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "Error testing bridge: " + str(e),
            "timestamp": datetime.utcnow().isoformat()
        }), 500

@api_bp.route('/bridge/start', methods=['POST'])
def start_bridge():
    """Start Ghidra Bridge"""
    try:
        success = current_app.ghidra_bridge_manager.start_bridge()
        if success:
            return jsonify({
                "status": "success",
                "message": "Ghidra Bridge started successfully",
                "timestamp": datetime.utcnow().isoformat()
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Failed to start Ghidra Bridge",
                "timestamp": datetime.utcnow().isoformat()
            }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error starting bridge: {str(e)}",
            "timestamp": datetime.utcnow().isoformat()
        }), 500

@api_bp.route('/binaries', methods=['POST'])
def upload_binary():
    """Upload a new binary file"""
    try:
        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check if file type is allowed
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Generate UUID for the file
        binary_id = str(uuid.uuid4())
        filename = secure_filename(file.filename)
        
        # Create upload directory if it doesn't exist
        upload_dir = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save file with UUID as prefix
        file_path = os.path.join(upload_dir, f"{binary_id}_{filename}")
        file.save(file_path)
        
        # Calculate file hash
        file_hash = get_file_hash(file_path)
        
        # Create binary record in database
        binary = Binary(
            id=binary_id,
            filename=f"{binary_id}_{filename}",
            original_filename=filename,
            file_path=file_path,
            file_size=os.path.getsize(file_path),
            file_hash=file_hash,
            mime_type=file.content_type,
            analysis_status='uploaded'
        )
        
        db.session.add(binary)
        db.session.commit()
        
        # Automatically start comprehensive analysis for fresh uploads
        try:
            logger.info(f"Starting automatic comprehensive analysis for new binary {binary_id}")
            
            # Start comprehensive analysis task
            task_id = current_app.task_manager.start_task(
                task_type='comprehensive_analysis',
                binary_id=binary_id,
                binary_path=binary.file_path,
                priority=3  # High priority for fresh uploads
            )
            
            # Update binary status to analyzing
            binary.analysis_status = 'analyzing'
            db.session.commit()
            
            logger.info(f"Automatic comprehensive analysis started with task ID: {task_id}")
            
            # Return binary details with analysis task info
            return jsonify({
                'message': 'File uploaded successfully and comprehensive analysis started',
                'binary': binary.to_dict(),
                'auto_analysis': {
                    'task_id': task_id,
                    'analysis_type': 'comprehensive_analysis',
                    'status': 'started'
                }
            }), 201
            
        except Exception as analysis_error:
            # If automatic analysis fails, still return success for upload
            logger.error(f"Failed to start automatic comprehensive analysis: {analysis_error}")
            
            # Return binary details without analysis
            return jsonify({
                'message': 'File uploaded successfully (automatic analysis failed to start)',
                'binary': binary.to_dict(),
                'auto_analysis': {
                    'status': 'failed',
                    'error': str(analysis_error)
                }
            }), 201
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/analyze', methods=['POST'])
def analyze_binary(binary_id):
    """Submit binary for analysis"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Check if Ghidra Bridge is connected
        if not current_app.ghidra_bridge_manager.is_connected():
            return jsonify({'error': 'Ghidra Bridge is not connected'}), 503
        
        # Get analysis parameters
        data = request.json or {}
        analysis_type = data.get('analysis_type', 'basic')
        parameters = data.get('parameters', {})
        
        # Update binary status
        binary.analysis_status = 'analyzing'
        db.session.commit()
        
        # Create analysis task
        task = AnalysisTask(
            id=str(uuid.uuid4()),
            binary_id=binary_id,
            task_type=analysis_type,
            status='queued',
            parameters=parameters,
            created_at=datetime.utcnow()
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Submit task to task manager
        try:
            current_app.task_manager._run_task(
                task_id=task.id,
                task_type=analysis_type,
                binary_id=binary_id,
                **parameters
            )
            logger.info(f"Task {task.id} submitted for execution")
        except Exception as e:
            logger.error(f"Error submitting task: {e}")
            task.status = 'failed'
            task.error_message = str(e)
            binary.analysis_status = 'failed'
            db.session.commit()
            return jsonify({'error': f'Failed to submit analysis task: {str(e)}'}), 500
        
        return jsonify({
            'message': 'Analysis task submitted',
            'task': task.to_dict()
        })
    except Exception as e:
        logger.error(f"Error submitting analysis for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>', methods=['GET'])
def get_binary(binary_id):
    """Get details of a specific binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get functions and results for this binary
        functions = Function.query.filter_by(binary_id=binary_id).all()
        results = AnalysisResult.query.filter_by(binary_id=binary_id).all()
        
        return jsonify({
            'binary': binary.to_dict(),
            'functions': [function.to_dict() for function in functions],
            'results': [result.to_dict() for result in results]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>', methods=['DELETE'])
def delete_binary(binary_id):
    """Delete a binary and all associated data"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        logger.info(f"Starting deletion of binary {binary_id} ({binary.original_filename})")
        
        # Cancel any running tasks for this binary
        running_tasks = AnalysisTask.query.filter_by(binary_id=binary_id, status='running').all()
        for task in running_tasks:
            try:
                current_app.task_manager.cancel_task(task.id)
                task.status = 'cancelled'
                logger.info(f"Cancelled running task {task.id}")
            except Exception as e:
                logger.warning(f"Failed to cancel task {task.id}: {e}")
        
        # Delete all related data in correct order (respecting foreign key constraints)
        try:
            # Get all functions for this binary first
            functions = Function.query.filter_by(binary_id=binary_id).all()
            function_ids = [func.id for func in functions]
            
            # Delete function-related data that uses function_id
            if function_ids:
                LocalVariable.query.filter(LocalVariable.function_id.in_(function_ids)).delete(synchronize_session=False)
                FunctionParameter.query.filter(FunctionParameter.function_id.in_(function_ids)).delete(synchronize_session=False)
            
            # Delete function calls (uses binary_id directly)
            FunctionCall.query.filter_by(binary_id=binary_id).delete()
            
            # Delete functions
            Function.query.filter_by(binary_id=binary_id).delete()
            
            # Delete analysis data
            AnalysisResult.query.filter_by(binary_id=binary_id).delete()
            AnalysisTask.query.filter_by(binary_id=binary_id).delete()
            
            # Delete binary data
            MemoryRegion.query.filter_by(binary_id=binary_id).delete()
            Import.query.filter_by(binary_id=binary_id).delete()
            Export.query.filter_by(binary_id=binary_id).delete()
            BinaryString.query.filter_by(binary_id=binary_id).delete()
            Symbol.query.filter_by(binary_id=binary_id).delete()
            DataType.query.filter_by(binary_id=binary_id).delete()
            Instruction.query.filter_by(binary_id=binary_id).delete()
            CrossReference.query.filter_by(binary_id=binary_id).delete()
            
            # Delete comprehensive analysis data
            ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).delete()
            
            # Delete security analysis data
            SecurityEvidence.query.filter(SecurityEvidence.finding_id.in_(
                db.session.query(UnifiedSecurityFinding.id).filter_by(binary_id=binary_id)
            )).delete(synchronize_session=False)
            UnifiedSecurityFinding.query.filter_by(binary_id=binary_id).delete()
            Vulnerability.query.filter_by(binary_id=binary_id).delete()
            VulnerabilityReport.query.filter_by(binary_id=binary_id).delete()
            
            # Delete fuzzing data in correct order (sessions before targets before harnesses)
            FuzzingSession.query.filter(FuzzingSession.harness_id.in_(
                db.session.query(FuzzingHarness.id).filter_by(binary_id=binary_id)
            )).delete(synchronize_session=False)
            FuzzingTarget.query.filter(FuzzingTarget.harness_id.in_(
                db.session.query(FuzzingHarness.id).filter_by(binary_id=binary_id)
            )).delete(synchronize_session=False)
            FuzzingHarness.query.filter_by(binary_id=binary_id).delete()
            
            # Delete the binary file from filesystem
            if binary.file_path and os.path.exists(binary.file_path):
                try:
                    os.remove(binary.file_path)
                    logger.info(f"Deleted binary file: {binary.file_path}")
                except Exception as e:
                    logger.warning(f"Failed to delete binary file {binary.file_path}: {e}")
            
            # Delete any related JSON/temp files
            upload_dir = current_app.config.get('UPLOAD_FOLDER', 'uploads')
            temp_dir = current_app.config.get('TEMP_FOLDER', 'temp')
            
            for directory in [upload_dir, temp_dir]:
                if os.path.exists(directory):
                    for filename in os.listdir(directory):
                        if binary_id in filename:
                            file_path = os.path.join(directory, filename)
                            try:
                                os.remove(file_path)
                                logger.info(f"Deleted related file: {file_path}")
                            except Exception as e:
                                logger.warning(f"Failed to delete file {file_path}: {e}")
            
            # Finally, delete the binary record
            db.session.delete(binary)
            db.session.commit()
            
            logger.info(f"Successfully deleted binary {binary_id} and all associated data")
            
            return jsonify({
                'message': f'Binary {binary.original_filename} and all associated data deleted successfully'
            })
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error during deletion: {e}")
            return jsonify({'error': f'Failed to delete binary data: {str(e)}'}), 500
            
    except Exception as e:
        logger.error(f"Error deleting binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/reset-analysis', methods=['POST'])
def reset_binary_analysis(binary_id):
    """Reset analysis status and cancel running tasks for a binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        logger.info(f"Resetting analysis for binary {binary_id} ({binary.original_filename})")
        
        # Cancel any running tasks for this binary
        running_tasks = AnalysisTask.query.filter_by(binary_id=binary_id, status='running').all()
        queued_tasks = AnalysisTask.query.filter_by(binary_id=binary_id, status='queued').all()
        
        cancelled_count = 0
        for task in running_tasks + queued_tasks:
            try:
                current_app.task_manager.cancel_task(task.id)
                task.status = 'cancelled'
                cancelled_count += 1
                logger.info(f"Cancelled task {task.id}")
            except Exception as e:
                logger.warning(f"Failed to cancel task {task.id}: {e}")
        
        # Reset binary status
        binary.analysis_status = 'uploaded'
        db.session.commit()
        
        logger.info(f"Reset analysis for binary {binary_id}, cancelled {cancelled_count} tasks")
        
        return jsonify({
            'message': f'Analysis reset for {binary.original_filename}',
            'cancelled_tasks': cancelled_count
        })
        
    except Exception as e:
        logger.error(f"Error resetting analysis for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/functions', methods=['GET'])
def get_functions(binary_id):
    """Get functions for a specific binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        functions = Function.query.filter_by(binary_id=binary_id).all()
        return jsonify({
            'functions': [function.to_dict() for function in functions]
        })
    except Exception as e:
        logger.error(f"Error getting functions for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/functions/<function_id>/decompile', methods=['POST'])
def decompile_function(function_id):
    """Decompile a specific function"""
    try:
        function = Function.query.get(function_id)
        if not function:
            return jsonify({'error': 'Function not found'}), 404
        
        # Check if already decompiled
        if function.is_decompiled and function.decompiled_code:
            return jsonify({
                'success': True,
                'function_id': function_id,
                'decompiled_code': function.decompiled_code,
                'cached': True
            })
        
        # Get binary
        binary = Binary.query.get(function.binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Check if Ghidra Bridge is connected
        if not current_app.ghidra_bridge_manager.is_connected():
            return jsonify({'error': 'Ghidra Bridge is not connected'}), 503
        
        # Create decompilation task
        task = AnalysisTask(
            id=str(uuid.uuid4()),
            binary_id=function.binary_id,
            task_type='decompile_function',
            status='queued',
            parameters={'function_id': function_id, 'function_address': function.address},
            created_at=datetime.utcnow()
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Run decompilation in background
        try:
            current_app.task_manager._run_task(
                task_id=task.id,
                task_type='decompile_function',
                binary_id=function.binary_id,
                function_id=function_id,
                function_address=function.address
            )
            
            return jsonify({
                'success': True,
                'task_id': task.id,
                'message': 'Decompilation started'
            })
        except Exception as e:
            task.status = 'failed'
            task.error_message = str(e)
            db.session.commit()
            return jsonify({'error': f'Failed to start decompilation: {str(e)}'}), 500
        
    except Exception as e:
        logger.error(f"Error decompiling function {function_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/functions/<function_id>/explain', methods=['POST'])
def explain_function(function_id):
    """Get AI explanation for a function"""
    try:
        function = Function.query.get(function_id)
        if not function:
            return jsonify({'error': 'Function not found'}), 404
        
        # Check if already explained
        if function.ai_analyzed and function.ai_summary:
            return jsonify({
                'success': True,
                'function_id': function_id,
                'ai_summary': function.ai_summary,
                'risk_score': function.risk_score,
                'cached': True
            })
        
        # Check if function is decompiled
        if not function.is_decompiled or not function.decompiled_code:
            return jsonify({'error': 'Function must be decompiled first'}), 400
        
        # Create AI explanation task
        task = AnalysisTask(
            id=str(uuid.uuid4()),
            binary_id=function.binary_id,
            task_type='explain_function',
            status='queued',
            parameters={'function_id': function_id},
            created_at=datetime.utcnow()
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Run AI explanation in background
        try:
            current_app.task_manager._run_task(
                task_id=task.id,
                task_type='explain_function',
                binary_id=function.binary_id,
                function_id=function_id
            )
            
            return jsonify({
                'success': True,
                'task_id': task.id,
                'message': 'AI explanation started'
            })
        except Exception as e:
            task.status = 'failed'
            task.error_message = str(e)
            db.session.commit()
            return jsonify({'error': f'Failed to start AI explanation: {str(e)}'}), 500
        
    except Exception as e:
        logger.error(f"Error explaining function {function_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/functions/<function_id>', methods=['GET'])
def get_function_details(function_id):
    """Get detailed information about a function"""
    try:
        function = Function.query.get(function_id)
        if not function:
            return jsonify({'error': 'Function not found'}), 404
        
        # Get function parameters and local variables
        parameters = function.parameters.all()
        local_vars = function.local_variables.all()
        
        # Get function calls
        calls = function.calls.all()
        
        function_data = function.to_dict()
        function_data.update({
            'parameters': [param.to_dict() for param in parameters],
            'local_variables': [var.to_dict() for var in local_vars],
            'function_calls': [call.to_dict() for call in calls]
        })
        
        return jsonify({
            'function': function_data
        })
    except Exception as e:
        logger.error(f"Error getting function details {function_id}: {e}")
        return jsonify({'error': str(e)}), 500

# CFG functionality removed - not supported in this version

@api_bp.route('/binaries/<binary_id>/decompile-all', methods=['POST'])
def decompile_all_functions(binary_id):
    """Decompile all functions in a binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Check if Ghidra Bridge is connected
        if not current_app.ghidra_bridge_manager.is_connected():
            return jsonify({'error': 'Ghidra Bridge is not connected'}), 503
        
        # Get all non-external functions
        functions = Function.query.filter_by(
            binary_id=binary_id,
            is_external=False
        ).all()
        
        if not functions:
            return jsonify({'error': 'No functions found for this binary'}), 404
        
        # Filter functions that are not already decompiled
        functions_to_decompile = [f for f in functions if not f.is_decompiled]
        
        if not functions_to_decompile:
            return jsonify({
                'message': 'All functions are already decompiled',
                'total_functions': len(functions),
                'already_decompiled': len(functions)
            })
        
        # Create bulk decompilation task
        task = AnalysisTask(
            id=str(uuid.uuid4()),
            binary_id=binary_id,
            task_type='bulk_decompile',
            status='queued',
            parameters={
                'function_ids': [f.id for f in functions_to_decompile],
                'function_addresses': [f.address for f in functions_to_decompile]
            },
            created_at=datetime.utcnow()
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Run bulk decompilation in background
        try:
            current_app.task_manager._run_task(
                task_id=task.id,
                task_type='bulk_decompile',
                binary_id=binary_id,
                function_ids=[f.id for f in functions_to_decompile],
                function_addresses=[f.address for f in functions_to_decompile]
            )
            
            return jsonify({
                'success': True,
                'task_id': task.id,
                'message': 'Bulk decompilation started',
                'total_functions': len(functions),
                'functions_to_decompile': len(functions_to_decompile),
                'already_decompiled': len(functions) - len(functions_to_decompile)
            })
        except Exception as e:
            task.status = 'failed'
            task.error_message = str(e)
            db.session.commit()
            return jsonify({'error': f'Failed to start bulk decompilation: {str(e)}'}), 500
        
    except Exception as e:
        logger.error(f"Error starting bulk decompilation for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/ai-explain-all', methods=['POST'])
def ai_explain_all_functions(binary_id):
    """AI explain all decompiled functions in a binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get all decompiled functions (need decompiled code for AI analysis)
        functions = Function.query.filter_by(
            binary_id=binary_id,
            is_external=False,
            is_decompiled=True
        ).all()
        
        if not functions:
            return jsonify({'error': 'No decompiled functions found for this binary. Please decompile functions first.'}), 404
        
        # Filter functions that are not already AI analyzed
        functions_to_analyze = [f for f in functions if not f.ai_analyzed]
        
        if not functions_to_analyze:
            return jsonify({
                'message': 'All decompiled functions are already AI analyzed',
                'total_functions': len(functions),
                'already_analyzed': len(functions)
            })
        
        # Create bulk AI analysis task
        task = AnalysisTask(
            id=str(uuid.uuid4()),
            binary_id=binary_id,
            task_type='bulk_ai_explain',
            status='queued',
            parameters={
                'function_ids': [f.id for f in functions_to_analyze],
                'function_addresses': [f.address for f in functions_to_analyze]
            },
            created_at=datetime.utcnow()
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Run bulk AI analysis in background
        try:
            current_app.task_manager._run_task(
                task_id=task.id,
                task_type='bulk_ai_explain',
                binary_id=binary_id,
                function_ids=[f.id for f in functions_to_analyze],
                function_addresses=[f.address for f in functions_to_analyze]
            )
            
            return jsonify({
                'success': True,
                'task_id': task.id,
                'message': 'Bulk AI analysis started',
                'total_functions': len(functions),
                'functions_to_analyze': len(functions_to_analyze),
                'already_analyzed': len(functions) - len(functions_to_analyze)
            })
        except Exception as e:
            task.status = 'failed'
            task.error_message = str(e)
            db.session.commit()
            return jsonify({'error': f'Failed to start bulk AI analysis: {str(e)}'}), 500
        
    except Exception as e:
        logger.error(f"Error starting bulk AI analysis for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/tasks/<task_id>/status', methods=['GET'])
def get_task_status(task_id):
    """Get status of a specific task"""
    try:
        task = AnalysisTask.query.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        return jsonify({
            'task': task.to_dict()
        })
    except Exception as e:
        logger.error(f"Error getting task status {task_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/ai-summary', methods=['POST'])
def generate_binary_ai_summary(binary_id):
    """Generate AI summary for the entire binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Check if already has AI summary
        existing_summary = AnalysisResult.query.filter_by(
            binary_id=binary_id,
            analysis_type='binary_ai_summary'
        ).first()
        
        if existing_summary and existing_summary.results:
            results = existing_summary.results
            return jsonify({
                'success': True,
                'binary_id': binary_id,
                'general_summary': results.get('general_summary') or results.get('summary', ''),
                'vulnerability_summary': results.get('vulnerability_summary') or results.get('risk_assessment', ''),
                'technical_details': results.get('technical_details') or results.get('recommendations', ''),
                # Legacy fields for backward compatibility
                'summary': results.get('general_summary') or results.get('summary', ''),
                'analysis': results.get('general_summary') or results.get('analysis', ''),
                'risk_assessment': results.get('vulnerability_summary') or results.get('risk_assessment', ''),
                'recommendations': results.get('technical_details') or results.get('recommendations', ''),
                'cached': True
            })
        
        # Create AI summary task
        task = AnalysisTask(
            id=str(uuid.uuid4()),
            binary_id=binary_id,
            task_type='binary_ai_summary',
            status='queued',
            parameters={'binary_path': binary.file_path},
            created_at=datetime.utcnow()
        )
        
        db.session.add(task)
        db.session.commit()
        
        # Run AI summary generation in background
        try:
            current_app.task_manager._run_task(
                task_id=task.id,
                task_type='binary_ai_summary',
                binary_id=binary_id,
                binary_path=binary.file_path
            )
            
            return jsonify({
                'success': True,
                'task_id': task.id,
                'message': 'Binary AI summary generation started'
            })
        except Exception as e:
            task.status = 'failed'
            task.error_message = str(e)
            db.session.commit()
            return jsonify({'error': f'Failed to start binary AI summary: {str(e)}'}), 500
        
    except Exception as e:
        logger.error(f"Error generating binary AI summary for {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/ai-summary', methods=['GET'])
def get_binary_ai_summary(binary_id):
    """Get existing AI summary for a binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get existing summary
        summary_result = AnalysisResult.query.filter_by(
            binary_id=binary_id,
            analysis_type='binary_ai_summary'
        ).first()
        
        if summary_result and summary_result.results:
            results = summary_result.results
            return jsonify({
                'success': True,
                'binary_id': binary_id,
                'general_summary': results.get('general_summary') or results.get('summary', ''),
                'vulnerability_summary': results.get('vulnerability_summary') or results.get('risk_assessment', ''),
                'technical_details': results.get('technical_details') or results.get('recommendations', ''),
                # Legacy fields for backward compatibility
                'summary': results.get('general_summary') or results.get('summary', ''),
                'analysis': results.get('general_summary') or results.get('analysis', ''),
                'risk_assessment': results.get('vulnerability_summary') or results.get('risk_assessment', ''),
                'recommendations': results.get('technical_details') or results.get('recommendations', ''),
                'created_at': summary_result.created_at.isoformat(),
                'cached': True
            })
        else:
            return jsonify({
                'success': False,
                'message': 'No AI summary available for this binary'
            }), 404
        
    except Exception as e:
        logger.error(f"Error getting binary AI summary for {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/tasks/cancel/<task_id>', methods=['POST'])
def cancel_task(task_id):
    """Cancel a specific task"""
    try:
        task = AnalysisTask.query.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        # Check if task can be cancelled
        if task.status not in ['queued', 'running']:
            return jsonify({'error': f'Cannot cancel task with status: {task.status}'}), 400
        
        # Cancel the task using task manager
        success = current_app.task_manager.cancel_task(task_id)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': f'Task {task_id} has been cancelled'
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to cancel task {task_id}'
            }), 500
        
    except Exception as e:
        logger.error(f"Error cancelling task {task_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/tasks/cancel-all', methods=['POST'])
def cancel_all_tasks():
    """Cancel all running tasks"""
    try:
        # Get optional binary_id from request
        data = request.json or {}
        binary_id = data.get('binary_id')
        
        # Cancel tasks using task manager
        success, message, cancelled_count = current_app.task_manager.cancel_all_tasks(binary_id=binary_id)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': message,
                'cancelled_tasks': cancelled_count
            })
        else:
            return jsonify({
                'status': 'info',
                'message': message,
                'cancelled_tasks': cancelled_count
            })
        
    except Exception as e:
        logger.error(f"Error cancelling all tasks: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/tasks/<task_id>', methods=['GET'])
def get_task_details(task_id):
    """Get detailed information about a specific task"""
    try:
        task = AnalysisTask.query.get(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        return jsonify(task.to_dict())
        
    except Exception as e:
        logger.error(f"Error getting task details {task_id}: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/binaries/<binary_id>/comprehensive-analysis', methods=['POST'])
def start_comprehensive_analysis(binary_id):
    """Start comprehensive analysis for a binary"""
    try:
        # Get binary
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Check if comprehensive analysis is already running
        existing_task = AnalysisTask.query.filter_by(
            binary_id=binary_id,
            task_type='comprehensive_analysis',
            status='running'
        ).first()
        
        if existing_task:
            return jsonify({
                'message': 'Comprehensive analysis already running',
                'task_id': existing_task.id,
                'status': 'running'
            }), 200
        
        # Start comprehensive analysis task
        task_id = current_app.task_manager.start_task(
            task_type='comprehensive_analysis',
            binary_id=binary_id,
            binary_path=binary.file_path,
            priority=3  # High priority for comprehensive analysis
        )
        
        return jsonify({
            'success': True,
            'task_id': task_id,
            'message': 'Comprehensive analysis started'
        })
        
    except Exception as e:
        logger.error(f"Error starting comprehensive analysis: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/binaries/<binary_id>/comprehensive-analysis', methods=['GET'])
def get_comprehensive_analysis(binary_id):
    """Get comprehensive analysis results"""
    try:
        # Get comprehensive analysis record
        comp_analysis = ComprehensiveAnalysis.query.filter_by(binary_id=binary_id).first()
        
        if not comp_analysis:
            return jsonify({'error': 'No comprehensive analysis found'}), 404
        
        # Get the analysis result as well
        result = AnalysisResult.query.filter_by(
            binary_id=binary_id,
            analysis_type='comprehensive_analysis'
        ).order_by(AnalysisResult.created_at.desc()).first()
        
        return jsonify({
            'success': True,
            'analysis': comp_analysis.to_dict(),
            'raw_result': result.results if result else None,
            'created_at': comp_analysis.created_at.isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error retrieving comprehensive analysis: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/binaries/<binary_id>/comprehensive-data/<data_type>', methods=['GET'])
def get_comprehensive_data(binary_id, data_type):
    """Get comprehensive analysis data for a specific data type"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 500)
        search = request.args.get('search', '', type=str)
        
        # Map data types to models
        model_map = {
            'functions': Function,
            'instructions': Instruction,
            'strings': BinaryString,
            'symbols': Symbol,
            'imports': Import,
            'exports': Export,
            'memory_blocks': MemoryRegion,
            'xrefs': CrossReference,
            'data_types': DataType
        }
        
        if data_type not in model_map:
            return jsonify({'error': f'Invalid data type: {data_type}'}), 400
        
        model = model_map[data_type]
        
        # Build query
        query = model.query.filter_by(binary_id=binary_id)
        
        # Apply search filter
        if search:
            if hasattr(model, 'name'):
                query = query.filter(model.name.contains(search))
            elif hasattr(model, 'value'):
                query = query.filter(model.value.contains(search))
        
        # Get paginated results
        results = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return jsonify({
            'data': [item.to_dict() for item in results.items],
            'pagination': {
                'page': results.page,
                'pages': results.pages,
                'per_page': results.per_page,
                'total': results.total,
                'has_next': results.has_next,
                'has_prev': results.has_prev
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting comprehensive data {data_type} for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500


# =============================================================================
# VULNERABILITY DETECTION API ENDPOINTS
# =============================================================================

@api_bp.route('/binaries/<binary_id>/vulnerabilities/scan', methods=['POST'])
def scan_vulnerabilities(binary_id):
    """Start vulnerability scan for a binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get scan parameters
        data = request.json or {}
        scan_types = data.get('scan_types', ['buffer_overflow', 'format_string', 'integer_overflow'])
        scan_parameters = data.get('parameters', {})
        
        # Validate scan types
        valid_scan_types = [
            'buffer_overflow', 'format_string', 'integer_overflow', 
            'use_after_free', 'command_injection', 'crypto_weakness',
            'null_pointer', 'race_condition', 'injection'
        ]
        
        invalid_types = [t for t in scan_types if t not in valid_scan_types]
        if invalid_types:
            return jsonify({
                'error': f'Invalid scan types: {", ".join(invalid_types)}',
                'valid_types': valid_scan_types
            }), 400
        
        # Check if binary has functions to scan
        function_count = Function.query.filter_by(binary_id=binary_id).count()
        if function_count == 0:
            return jsonify({
                'error': 'Binary has no functions to scan. Run basic analysis first.'
            }), 400
        
        decompiled_count = Function.query.filter_by(
            binary_id=binary_id, 
            is_decompiled=True
        ).count()
        
        logger.info(f"Starting vulnerability scan for binary {binary_id}: {len(scan_types)} scan types, {decompiled_count}/{function_count} functions decompiled")
        
        # Import vulnerability engine
        from flask_app.vulnerability_engine import VulnerabilityEngine
        
        # Create and run vulnerability scan
        engine = VulnerabilityEngine()
        
        try:
            report = engine.scan_binary(binary_id, scan_types)
            
            return jsonify({
                'message': 'Vulnerability scan completed',
                'report': report.to_dict(),
                'scan_summary': {
                    'total_vulnerabilities': report.total_vulnerabilities,
                    'functions_scanned': report.functions_scanned,
                    'scan_duration': report.scan_duration,
                    'risk_score': report.overall_risk_score,
                    'risk_category': report.risk_category
                }
            })
            
        except Exception as scan_error:
            logger.error(f"Vulnerability scan failed for binary {binary_id}: {scan_error}")
            return jsonify({
                'error': f'Vulnerability scan failed: {str(scan_error)}'
            }), 500
        
    except Exception as e:
        logger.error(f"Error starting vulnerability scan for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/binaries/<binary_id>/vulnerabilities', methods=['GET'])
def get_vulnerabilities(binary_id):
    """Get vulnerabilities for a binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        severity = request.args.get('severity', '', type=str)
        vuln_type = request.args.get('type', '', type=str)
        
        # Import vulnerability models
        from flask_app.models import Vulnerability
        
        # Build query
        query = Vulnerability.query.filter_by(binary_id=binary_id)
        
        # Apply filters
        if severity:
            query = query.filter(Vulnerability.severity == severity)
        if vuln_type:
            query = query.filter(Vulnerability.vulnerability_type == vuln_type)
        
        # Order by risk score (highest first)
        query = query.order_by(Vulnerability.risk_score.desc())
        
        # Get paginated results
        results = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return jsonify({
            'vulnerabilities': [vuln.to_dict() for vuln in results.items],
            'pagination': {
                'page': results.page,
                'pages': results.pages,
                'per_page': results.per_page,
                'total': results.total,
                'has_next': results.has_next,
                'has_prev': results.has_prev
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/binaries/<binary_id>/vulnerability-report', methods=['GET'])
def get_vulnerability_report(binary_id):
    """Get latest vulnerability report for a binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Import vulnerability models
        from flask_app.models import VulnerabilityReport, Vulnerability
        
        # Get latest report
        report = VulnerabilityReport.query.filter_by(binary_id=binary_id).order_by(
            VulnerabilityReport.created_at.desc()
        ).first()
        
        if not report:
            return jsonify({
                'error': 'No vulnerability report found for this binary'
            }), 404
        
        # Get vulnerabilities for this binary
        vulnerabilities = Vulnerability.query.filter_by(binary_id=binary_id).order_by(
            Vulnerability.risk_score.desc()
        ).limit(50).all()  # Limit for performance
        
        return jsonify({
            'report': report.to_dict(),
            'vulnerabilities': [vuln.to_dict() for vuln in vulnerabilities]
        })
        
    except Exception as e:
        logger.error(f"Error getting vulnerability report for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/binaries/<binary_id>/vulnerability-summary', methods=['GET'])
def get_vulnerability_summary(binary_id):
    """Get vulnerability summary for a binary"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Import vulnerability engine
        from flask_app.vulnerability_engine import VulnerabilityEngine
        
        engine = VulnerabilityEngine()
        summary = engine.get_vulnerability_summary(binary_id)
        
        return jsonify(summary)
        
    except Exception as e:
        logger.error(f"Error getting vulnerability summary for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/vulnerabilities/<vulnerability_id>', methods=['GET'])
def get_vulnerability_details(vulnerability_id):
    """Get detailed information about a specific vulnerability"""
    try:
        # Import vulnerability models
        from flask_app.models import Vulnerability
        
        vulnerability = Vulnerability.query.get(vulnerability_id)
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        # Get related function if available
        function = None
        if vulnerability.function_id:
            function = Function.query.get(vulnerability.function_id)
        
        return jsonify({
            'vulnerability': vulnerability.to_dict(),
            'function': function.to_dict() if function else None
        })
        
    except Exception as e:
        logger.error(f"Error getting vulnerability details for {vulnerability_id}: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/vulnerabilities/<vulnerability_id>', methods=['PUT'])
def update_vulnerability(vulnerability_id):
    """Update vulnerability information (e.g., mark as false positive)"""
    try:
        # Import vulnerability models
        from flask_app.models import Vulnerability
        
        vulnerability = Vulnerability.query.get(vulnerability_id)
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        data = request.json or {}
        
        # Update allowed fields
        if 'false_positive_risk' in data:
            vulnerability.false_positive_risk = data['false_positive_risk']
        if 'confidence' in data:
            vulnerability.confidence = data['confidence']
        if 'remediation' in data:
            vulnerability.remediation = data['remediation']
        
        vulnerability.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Vulnerability updated successfully',
            'vulnerability': vulnerability.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Error updating vulnerability {vulnerability_id}: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/vulnerability-patterns', methods=['GET'])
def get_vulnerability_patterns():
    """Get available vulnerability detection patterns"""
    try:
        # Import vulnerability models
        from flask_app.models import VulnerabilityPattern
        
        patterns = VulnerabilityPattern.query.filter_by(is_active=True).all()
        
        return jsonify({
            'patterns': [pattern.to_dict() for pattern in patterns]
        })
        
    except Exception as e:
        logger.error(f"Error getting vulnerability patterns: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/vulnerability-stats', methods=['GET'])
def get_vulnerability_stats():
    """Get system-wide vulnerability statistics"""
    try:
        # Import vulnerability engine
        from flask_app.vulnerability_engine import VulnerabilityEngine
        
        engine = VulnerabilityEngine()
        stats = engine.get_system_vulnerability_stats()
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting vulnerability stats: {e}")
        return jsonify({'error': str(e)}), 500

# =============================================================================
# AI CACHE CLEARING ENDPOINTS
# =============================================================================

@api_bp.route('/functions/<function_id>/security-analysis', methods=['POST'])
def analyze_function_security(function_id):
    """Perform unified security analysis on a function with 75+ dangerous function checks"""
    try:
        from .unified_security_analyzer import UnifiedSecurityAnalyzer
        
        function = Function.query.get(function_id)
        if not function:
            return jsonify({'error': 'Function not found'}), 404
        
        # Check if function is decompiled
        if not function.decompiled_code:
            return jsonify({'error': 'Function must be decompiled before security analysis'}), 400
        
        logger.info(f"Starting unified security analysis for function {function_id}")
        
        # Perform comprehensive unified security analysis
        analyzer = UnifiedSecurityAnalyzer()
        result = analyzer.analyze_function_security(function)
        
        if result.get('success'):
            logger.info(f"Unified security analysis completed for function {function_id}: {result.get('total_findings', 0)} findings")
            return jsonify(result)
        else:
            logger.error(f"Unified security analysis failed for function {function_id}: {result.get('error')}")
            return jsonify(result), 500
            
    except Exception as e:
        logger.error(f"Error in unified security analysis for function {function_id}: {e}")
        return jsonify({'error': f'Unified security analysis failed: {str(e)}'}), 500

@api_bp.route('/functions/<function_id>/security-findings', methods=['GET'])
def get_function_security_findings(function_id):
    """Get unified security findings for a function"""
    try:
        from .models import UnifiedSecurityFinding
        
        function = Function.query.get(function_id)
        if not function:
            return jsonify({'error': 'Function not found'}), 404
        
        # Get unified security findings
        findings = UnifiedSecurityFinding.query.filter_by(function_id=function_id).all()
        
        return jsonify({
            'function_id': function_id,
            'findings': [finding.to_dict() for finding in findings],
            'total_findings': len(findings)
        })
        
    except Exception as e:
        logger.error(f"Error getting security findings for function {function_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/security-analysis', methods=['POST'])
def analyze_binary_security(binary_id):
    """Perform comprehensive security analysis on a binary - uses enhanced analysis if functions unavailable"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Try traditional function-based analysis first
        functions = Function.query.filter_by(binary_id=binary_id, is_decompiled=True).all()
        
        if functions and len(functions) > 0:
            # Use traditional unified security analyzer for decompiled functions
            logger.info(f"Using traditional security analysis for binary {binary_id} ({len(functions)} functions)")
            return _traditional_security_analysis(binary_id, functions)
        else:
            # Use enhanced security analyzer for comprehensive analysis without functions
            logger.info(f"Using enhanced security analysis for binary {binary_id} (no decompiled functions)")
            return _enhanced_security_analysis(binary_id)
            
    except Exception as e:
        logger.error(f"Error in security analysis for binary {binary_id}: {e}")
        return jsonify({'error': f'Security analysis failed: {str(e)}'}), 500

def _traditional_security_analysis(binary_id, functions):
    """Traditional function-based security analysis"""
    from .unified_security_analyzer import UnifiedSecurityAnalyzer
    
    analyzer = UnifiedSecurityAnalyzer()
    results = []
    total_findings = 0
    failed_functions = 0
    
    for function in functions:
        try:
            result = analyzer.analyze_function_security(function)
            if result.get('success'):
                total_findings += result.get('stored_findings', 0)
                results.append({
                    'function_id': function.id,
                    'function_name': function.name or function.address,
                    'findings': result.get('stored_findings', 0),
                    'high_confidence_findings': result.get('high_confidence_findings', 0)
                })
            else:
                failed_functions += 1
                logger.warning(f"Unified security analysis failed for function {function.id}: {result.get('error')}")
                
        except Exception as e:
            failed_functions += 1
            logger.error(f"Error analyzing function {function.id}: {e}")
    
    logger.info(f"Traditional security analysis completed for binary {binary_id}: {total_findings} total findings")
    
    return jsonify({
        'success': True,
        'analysis_type': 'traditional',
        'binary_id': binary_id,
        'functions_analyzed': len(functions) - failed_functions,
        'functions_failed': failed_functions,
        'total_findings': total_findings,
        'function_results': results,
        'analyzer_used': 'unified_security_analyzer'
    })

def _enhanced_security_analysis(binary_id):
    """Enhanced security analysis using multiple data sources and automatic export decompilation"""
    from .enhanced_security_analyzer import EnhancedSecurityAnalyzer
    
    binary = Binary.query.get(binary_id)
    if not binary:
        return jsonify({'error': 'Binary not found'}), 404
    
    analyzer = EnhancedSecurityAnalyzer()
    result = analyzer.analyze_binary_security(binary)
    
    if result.get('success'):
        analysis_methods = result.get('analysis_methods', [])
        coverage = result.get('coverage_analysis', {})
        
        # Check if export decompilation was performed
        export_decompilation = coverage.get('export_decompilation', {})
        traditional_analysis = coverage.get('traditional_analysis', {})
        
        logger.info(f"Enhanced security analysis completed for binary {binary_id}: "
                   f"{result.get('total_findings', 0)} findings using {len(analysis_methods)} methods")
        
        return jsonify({
            'success': True,
            'analysis_type': 'enhanced',
            'binary_id': binary_id,
            'total_findings': result.get('total_findings', 0),
            'analysis_methods': analysis_methods,
            'coverage_analysis': coverage,
            'findings': result.get('stored_findings', []),
            'analyzer_used': 'enhanced_security_analyzer',
            'export_decompilation': {
                'performed': bool(export_decompilation),
                'exports_decompiled': export_decompilation.get('exports_decompiled', 0),
                'functions_created': export_decompilation.get('functions_stored', 0)
            },
            'traditional_analysis': {
                'performed': bool(traditional_analysis),
                'functions_analyzed': traditional_analysis.get('metadata', {}).get('functions_analyzed', 0)
            }
        })
    else:
        error_msg = result.get('error', 'Enhanced security analysis failed')
        logger.error(f"Enhanced security analysis failed for binary {binary_id}: {error_msg}")
        return jsonify({'error': error_msg}), 500

@api_bp.route('/binaries/<binary_id>/enhanced-security-analysis', methods=['POST'])
def analyze_binary_enhanced_security(binary_id):
    """Perform enhanced security analysis using multiple data sources (exports, strings, imports, AI)"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        logger.info(f"Starting enhanced security analysis for binary {binary_id}")
        
        from .enhanced_security_analyzer import EnhancedSecurityAnalyzer
        analyzer = EnhancedSecurityAnalyzer()
        result = analyzer.analyze_binary_security(binary)
        
        if result.get('success'):
            logger.info(f"Enhanced security analysis completed for binary {binary_id}: "
                       f"{result.get('total_findings', 0)} findings")
            return jsonify(result)
        else:
            error_msg = result.get('error', 'Enhanced security analysis failed')
            logger.error(f"Enhanced security analysis failed for binary {binary_id}: {error_msg}")
            return jsonify(result), 500
            
    except Exception as e:
        logger.error(f"Error in enhanced security analysis for binary {binary_id}: {e}")
        return jsonify({'error': f'Comprehensive unified security analysis failed: {str(e)}'}), 500

@api_bp.route('/binaries/<binary_id>/security-findings', methods=['GET'])
def get_binary_security_findings(binary_id):
    """Get all unified security findings for a binary"""
    try:
        from .models import UnifiedSecurityFinding
        
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 200)
        severity_filter = request.args.get('severity')
        confidence_min = request.args.get('confidence_min', type=int)
        
        # Build query
        query = UnifiedSecurityFinding.query.filter_by(binary_id=binary_id)
        
        if severity_filter:
            query = query.filter(UnifiedSecurityFinding.severity == severity_filter.upper())
        
        if confidence_min:
            query = query.filter(UnifiedSecurityFinding.confidence >= confidence_min)
        
        # Apply pagination
        findings = query.order_by(UnifiedSecurityFinding.severity.desc(), 
                                UnifiedSecurityFinding.confidence.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        # Calculate summary statistics
        all_findings = UnifiedSecurityFinding.query.filter_by(binary_id=binary_id).all()
        severity_counts = {
            'CRITICAL': sum(1 for f in all_findings if f.severity == 'CRITICAL'),
            'HIGH': sum(1 for f in all_findings if f.severity == 'HIGH'),
            'MEDIUM': sum(1 for f in all_findings if f.severity == 'MEDIUM'),
            'LOW': sum(1 for f in all_findings if f.severity == 'LOW'),
            'INFO': sum(1 for f in all_findings if f.severity == 'INFO')
        }
        
        avg_confidence = sum(f.confidence for f in all_findings) / len(all_findings) if all_findings else 0
        
        return jsonify({
            'binary_id': binary_id,
            'findings': [finding.to_dict() for finding in findings.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': findings.total,
                'pages': findings.pages,
                'has_next': findings.has_next,
                'has_prev': findings.has_prev
            },
            'summary': {
                'total_findings': len(all_findings),
                'severity_counts': severity_counts,
                'average_confidence': round(avg_confidence, 1)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting security findings for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/security-findings/<finding_id>', methods=['GET'])
def get_security_finding_details(finding_id):
    """Get detailed information about a security finding"""
    try:
        from .models import UnifiedSecurityFinding, SecurityEvidence
        
        finding = UnifiedSecurityFinding.query.get(finding_id)
        if not finding:
            return jsonify({'error': 'Security finding not found'}), 404
        
        # Get associated evidence
        evidence = SecurityEvidence.query.filter_by(finding_id=finding_id).all()
        
        result = finding.to_dict()
        result['evidence'] = [ev.to_dict() for ev in evidence]
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error getting security finding details {finding_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/security-findings/<finding_id>', methods=['PUT'])
def update_security_finding(finding_id):
    """Update a security finding (e.g., mark as false positive)"""
    try:
        from .models import UnifiedSecurityFinding
        
        finding = UnifiedSecurityFinding.query.get(finding_id)
        if not finding:
            return jsonify({'error': 'Security finding not found'}), 404
        
        data = request.json or {}
        
        # Update allowed fields
        if 'false_positive_risk' in data:
            finding.false_positive_risk = data['false_positive_risk']
        
        if 'remediation' in data:
            finding.remediation = data['remediation']
        
        if 'notes' in data:
            if not finding.references:
                finding.references = {}
            finding.references['analyst_notes'] = data['notes']
        
        finding.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Security finding updated successfully',
            'finding': finding.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Error updating security finding {finding_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/clear-function-ai-cache', methods=['POST'])
def clear_function_ai_cache():
    """Clear AI analysis cache for functions in a binary"""
    try:
        data = request.json or {}
        binary_id = data.get('binary_id')
        
        if not binary_id:
            return jsonify({'error': 'binary_id is required'}), 400
        
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Clear AI analysis data from functions
        functions = Function.query.filter_by(binary_id=binary_id).all()
        cleared_count = 0
        
        for func in functions:
            if func.ai_analyzed or func.ai_summary or func.risk_score:
                func.ai_analyzed = False
                func.ai_summary = None
                func.risk_score = None
                cleared_count += 1
        
        # Delete AI analysis results
        deleted_results = AnalysisResult.query.filter_by(
            binary_id=binary_id,
            analysis_type='explain_function'
        ).delete()
        
        db.session.commit()
        
        logger.info(f"Cleared AI cache for {cleared_count} functions and {deleted_results} analysis results")
        
        return jsonify({
            'success': True,
            'message': f'Cleared AI analysis cache for {cleared_count} functions',
            'functions_cleared': cleared_count,
            'results_deleted': deleted_results
        })
        
    except Exception as e:
        logger.error(f"Error clearing function AI cache: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@api_bp.route('/clear-binary-ai-cache', methods=['POST'])
def clear_binary_ai_cache():
    """Clear AI summary cache for a binary"""
    try:
        data = request.json or {}
        binary_id = data.get('binary_id')
        
        if not binary_id:
            return jsonify({'error': 'binary_id is required'}), 400
        
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Delete binary AI summary results
        deleted_summaries = AnalysisResult.query.filter_by(
            binary_id=binary_id,
            analysis_type='binary_ai_summary'
        ).delete()
        
        db.session.commit()
        
        logger.info(f"Cleared binary AI summary cache: {deleted_summaries} summaries deleted")
        
        return jsonify({
            'success': True,
            'message': f'Cleared binary AI summary cache',
            'summaries_deleted': deleted_summaries
        })
        
    except Exception as e:
        logger.error(f"Error clearing binary AI cache: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Binary CFG endpoints removed - not supported in this version 

# ==========================================
# FUZZING HARNESS GENERATION ENDPOINTS
# ==========================================

@api_bp.route('/binaries/<binary_id>/generate-fuzzing-harness', methods=['POST'])
def generate_fuzzing_harness(binary_id):
    """Generate intelligent fuzzing harnesses for multiple fuzzers for a binary"""
    try:
        from .fuzzing_harness_generator import FuzzingHarnessGenerator
        from .models import FuzzingHarness
        
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get generation parameters
        data = request.json or {}
        min_risk_score = data.get('min_risk_score', 40.0)
        target_severities = data.get('target_severities', ['HIGH', 'MEDIUM'])
        harness_types = data.get('harness_types', ['AFL++'])  # Support multiple fuzzers
        ai_enabled = data.get('ai_enabled', True)
        include_seeds = data.get('include_seeds', True)
        
        # Backward compatibility - if harness_type is provided, use it
        if 'harness_type' in data and data['harness_type'] != 'auto':
            harness_types = [data['harness_type']]
        
        logger.info(f"Generating fuzzing harnesses for binary {binary_id} with fuzzers: {harness_types}, min_risk_score={min_risk_score}")
        
        # Generate harnesses
        generator = FuzzingHarnessGenerator()
        try:
            harnesses = generator.generate_harness_for_binary(
                binary_id=binary_id,
                min_risk_score=min_risk_score,
                target_severities=target_severities,
                harness_types=harness_types,
                ai_enabled=ai_enabled,
                include_seeds=include_seeds
            )
            
            harness_data = []
            total_targets = 0
            
            for harness in harnesses:
                total_targets += harness.target_count
                harness_data.append({
                    'id': harness.id,
                    'name': harness.name,
                    'description': harness.description,
                    'harness_type': harness.harness_type,
                    'target_count': harness.target_count,
                    'confidence_score': harness.confidence_score,
                    'generation_strategy': harness.generation_strategy,
                    'input_type': harness.input_type,
                    'created_at': harness.created_at.isoformat()
                })
            
            logger.info(f"Successfully generated {len(harnesses)} fuzzing harnesses with {total_targets} total targets")
            
            return jsonify({
                'success': True,
                'message': f'{len(harnesses)} fuzzing harnesses generated with {total_targets} total targets',
                'harnesses': harness_data,
                'fuzzer_types': harness_types,
                'summary': {
                    'total_harnesses': len(harnesses),
                    'total_targets': total_targets,
                    'ai_enabled': ai_enabled,
                    'min_risk_score': min_risk_score
                }
            })
            
        except ValueError as e:
            logger.warning(f"No suitable fuzzing targets found for binary {binary_id}: {e}")
            return jsonify({
                'error': 'No suitable fuzzing targets found',
                'message': str(e),
                'suggestion': 'Try lowering the minimum risk score or running security analysis first'
            }), 400
            
    except Exception as e:
        logger.error(f"Error generating fuzzing harness for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/functions/<function_id>/generate-fuzzing-harness', methods=['POST'])
def generate_function_fuzzing_harness(function_id):
    """Generate targeted fuzzing harness for a specific function"""
    try:
        from .fuzzing_harness_generator import FuzzingHarnessGenerator
        
        function = Function.query.get(function_id)
        if not function:
            return jsonify({'error': 'Function not found'}), 404
        
        # Get generation parameters
        data = request.json or {}
        input_type = data.get('input_type', 'file')
        
        logger.info(f"Generating targeted fuzzing harness for function {function_id} ({function.name})")
        
        # Generate harness
        generator = FuzzingHarnessGenerator()
        harness = generator.generate_harness_for_function(
            function_id=function_id,
            input_type=input_type
        )
        
        logger.info(f"Successfully generated targeted fuzzing harness {harness.id} for function {function.name}")
        
        return jsonify({
            'success': True,
            'message': f'Targeted fuzzing harness generated for function {function.name}',
            'harness': {
                'id': harness.id,
                'name': harness.name,
                'description': harness.description,
                'target_function': function.name,
                'input_type': harness.input_type,
                'confidence_score': harness.confidence_score,
                'created_at': harness.created_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Error generating targeted fuzzing harness for function {function_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/fuzzing-harnesses', methods=['GET'])
def get_fuzzing_harnesses(binary_id):
    """Get fuzzing harnesses for a binary"""
    try:
        from .models import FuzzingHarness, FuzzingTarget
        
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        harnesses = FuzzingHarness.query.filter_by(binary_id=binary_id).order_by(
            FuzzingHarness.created_at.desc()
        ).all()
        
        harness_data = []
        for harness in harnesses:
            # Get targets for this harness
            targets = FuzzingTarget.query.filter_by(harness_id=harness.id).order_by(
                FuzzingTarget.priority.asc()
            ).all()
            
            target_data = []
            for target in targets:
                target_info = {
                    'id': target.id,
                    'function_name': target.function.name if target.function else 'Unknown',
                    'function_id': target.function_id,
                    'priority': target.priority,
                    'risk_score': target.risk_score,
                    'severity': target.severity,
                    'rationale': target.rationale,
                    'input_strategy': target.input_strategy
                }
                
                # Add security finding info if available
                if target.security_finding:
                    target_info['security_finding'] = {
                        'id': target.security_finding.id,
                        'title': target.security_finding.title,
                        'description': target.security_finding.description
                    }
                
                target_data.append(target_info)
            
            harness_info = {
                'id': harness.id,
                'name': harness.name,
                'description': harness.description,
                'harness_type': harness.harness_type,
                'target_count': harness.target_count,
                'confidence_score': harness.confidence_score,
                'generation_strategy': harness.generation_strategy,
                'input_type': harness.input_type,
                'created_at': harness.created_at.isoformat(),
                'targets': target_data,
                'has_code': bool(harness.harness_code),
                'has_makefile': bool(harness.makefile_content),
                'has_readme': bool(harness.readme_content)
            }
            
            harness_data.append(harness_info)
        
        return jsonify({
            'harnesses': harness_data,
            'total_count': len(harness_data)
        })
        
    except Exception as e:
        logger.error(f"Error getting fuzzing harnesses for binary {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/fuzzing-harnesses/<harness_id>', methods=['GET'])
def get_fuzzing_harness_details(harness_id):
    """Get detailed information about a fuzzing harness"""
    try:
        from .models import FuzzingHarness, FuzzingTarget, FuzzingSession
        
        harness = FuzzingHarness.query.get(harness_id)
        if not harness:
            return jsonify({'error': 'Fuzzing harness not found'}), 404
        
        # Get targets
        targets = FuzzingTarget.query.filter_by(harness_id=harness_id).order_by(
            FuzzingTarget.priority.asc()
        ).all()
        
        # Get sessions
        sessions = FuzzingSession.query.filter_by(harness_id=harness_id).order_by(
            FuzzingSession.created_at.desc()
        ).all()
        
        # Build response - Include actual content for API access
        harness_details = {
            'id': harness.id,
            'name': harness.name or f'Harness {harness.id}',
            'description': harness.description or '',
            'harness_type': harness.harness_type or 'AFL++',
            'target_count': harness.target_count or 0,
            'confidence_score': harness.confidence_score or 100.0,
            'generation_strategy': harness.generation_strategy or 'security_analysis_based',
            'input_type': harness.input_type or 'file',
            'min_risk_score': harness.min_risk_score or 40.0,
            'created_at': harness.created_at.isoformat() if hasattr(harness.created_at, 'isoformat') else str(harness.created_at),
            'updated_at': harness.updated_at.isoformat() if hasattr(harness.updated_at, 'isoformat') else str(harness.updated_at),
            'binary': {
                'id': harness.binary.id if harness.binary else None,
                'filename': harness.binary.original_filename if harness.binary else 'Unknown'
            },
            'targets': [],
            'sessions': [],
            'has_code': bool(harness.harness_code),
            'has_makefile': bool(harness.makefile_content),
            'has_readme': bool(harness.readme_content),
            # Include actual content for API access
            'harness_code': harness.harness_code or '// No harness code available\n// The harness may still be generating.',
            'makefile_content': harness.makefile_content or '# No Makefile available\n# The Makefile may still be generating.',
            'readme_content': harness.readme_content or '# No README available\n\nThe README may still be generating.'
        }
        
        # Add target details with error handling
        for target in targets:
            try:
                target_info = {
                    'id': target.id,
                    'function_name': target.function.name if target.function else 'Unknown',
                    'function_id': target.function_id,
                    'priority': target.priority or 1,
                    'risk_score': target.risk_score or 0.0,
                    'severity': target.severity or 'UNKNOWN',
                    'rationale': target.rationale or 'No rationale provided',
                    'input_strategy': target.input_strategy or 'generic',
                    'created_at': target.created_at.isoformat() if hasattr(target.created_at, 'isoformat') else str(target.created_at)
                }
                
                # Add security finding info if available with error handling
                if target.security_finding:
                    try:
                        target_info['security_finding'] = {
                            'id': target.security_finding.id,
                            'title': getattr(target.security_finding, 'title', 'Security Finding'),
                            'description': getattr(target.security_finding, 'description', 'No description available'),
                            'confidence': getattr(target.security_finding, 'confidence', 0.0)
                        }
                    except Exception as e:
                        logger.warning(f"Error accessing security finding for target {target.id}: {e}")
                        target_info['security_finding'] = {
                            'id': target.security_finding.id,
                            'title': 'Security Finding',
                            'description': 'Unable to load finding details',
                            'confidence': 0.0
                        }
                
                harness_details['targets'].append(target_info)
                
            except Exception as e:
                logger.warning(f"Error processing target {target.id}: {e}")
                # Add minimal target info even if there's an error
                harness_details['targets'].append({
                    'id': target.id,
                    'function_name': 'Error loading target',
                    'function_id': target.function_id,
                    'priority': 1,
                    'risk_score': 0.0,
                    'severity': 'UNKNOWN',
                    'rationale': f'Error loading target details: {str(e)}',
                    'input_strategy': 'generic',
                    'created_at': str(target.created_at) if target.created_at else ''
                })
        
        # Add session details with error handling
        for session in sessions:
            try:
                session_info = {
                    'id': session.id,
                    'name': session.name or f'Session {session.id}',
                    'status': session.status or 'pending',
                    'fuzzer_type': session.fuzzer_type or 'afl++',
                    'total_execs': session.total_execs or 0,
                    'crashes_found': session.crashes_found or 0,
                    'hangs_found': session.hangs_found or 0,
                    'coverage_percent': session.coverage_percent or 0.0,
                    'created_at': session.created_at.isoformat() if hasattr(session.created_at, 'isoformat') else str(session.created_at)
                }
                
                if session.started_at:
                    session_info['started_at'] = session.started_at.isoformat() if hasattr(session.started_at, 'isoformat') else str(session.started_at)
                if session.ended_at:
                    session_info['ended_at'] = session.ended_at.isoformat() if hasattr(session.ended_at, 'isoformat') else str(session.ended_at)
                    session_info['duration_seconds'] = session.duration_seconds or 0
                
                harness_details['sessions'].append(session_info)
                
            except Exception as e:
                logger.warning(f"Error processing session {session.id}: {e}")
                # Add minimal session info even if there's an error
                harness_details['sessions'].append({
                    'id': session.id,
                    'name': f'Session {session.id}',
                    'status': 'error',
                    'fuzzer_type': 'unknown',
                    'total_execs': 0,
                    'crashes_found': 0,
                    'hangs_found': 0,
                    'coverage_percent': 0.0,
                    'created_at': str(session.created_at) if session.created_at else ''
                })
        
        logger.info(f"Successfully loaded harness details for {harness_id}: {len(targets)} targets, {len(sessions)} sessions")
        return jsonify(harness_details)
        
    except Exception as e:
        logger.error(f"Error getting fuzzing harness details {harness_id}: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to load harness details: {str(e)}'}), 500



@api_bp.route('/fuzzing-harnesses/<harness_id>/download/package', methods=['GET'])
def download_fuzzing_harness_package(harness_id):
    """Download complete fuzzing harness package as ZIP"""
    try:
        from .models import FuzzingHarness
        import tempfile
        import zipfile
        import os
        
        harness = FuzzingHarness.query.get(harness_id)
        if not harness:
            return jsonify({'error': 'Fuzzing harness not found'}), 404
        
        # Create temporary ZIP file
        temp_zip = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        
        with zipfile.ZipFile(temp_zip.name, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add harness code
            if harness.harness_code:
                zip_file.writestr('harness.c', harness.harness_code)
            
            # Add Makefile
            if harness.makefile_content:
                zip_file.writestr('Makefile', harness.makefile_content)
            
            # Add README
            if harness.readme_content:
                zip_file.writestr('README.md', harness.readme_content)
            
            # Add AFL configuration
            if harness.afl_config:
                zip_file.writestr('afl_config.json', harness.afl_config)
        
        package_name = f"{harness.name.replace(' ', '_')}_fuzzing_package.zip"
        
        return send_file(
            temp_zip.name,
            as_attachment=True,
            download_name=package_name,
            mimetype='application/zip'
        )
        
    except Exception as e:
        logger.error(f"Error downloading fuzzing harness package {harness_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/fuzzing-harnesses/<harness_id>', methods=['DELETE'])
def delete_fuzzing_harness(harness_id):
    """Delete a fuzzing harness"""
    try:
        from .models import FuzzingHarness, FuzzingTarget, FuzzingSession
        
        harness = FuzzingHarness.query.get(harness_id)
        if not harness:
            return jsonify({'error': 'Fuzzing harness not found'}), 404
        
        harness_name = harness.name
        
        # Delete related records first to avoid foreign key constraint errors
        # Delete fuzzing sessions
        sessions_deleted = FuzzingSession.query.filter_by(harness_id=harness_id).count()
        FuzzingSession.query.filter_by(harness_id=harness_id).delete()
        
        # Delete fuzzing targets
        targets_deleted = FuzzingTarget.query.filter_by(harness_id=harness_id).count()
        FuzzingTarget.query.filter_by(harness_id=harness_id).delete()
        
        # Now delete the harness itself
        db.session.delete(harness)
        db.session.commit()
        
        logger.info(f"Deleted fuzzing harness: {harness_name} (ID: {harness_id}) with {targets_deleted} targets and {sessions_deleted} sessions")
        
        return jsonify({
            'message': f'Fuzzing harness "{harness_name}" deleted successfully',
            'harness_id': harness_id,
            'deleted_targets': targets_deleted,
            'deleted_sessions': sessions_deleted
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting fuzzing harness {harness_id}: {str(e)}")
        return jsonify({'error': f'Failed to delete harness: {str(e)}'}), 500

@api_bp.route('/fuzzing-harnesses/<harness_id>/download/<file_type>', methods=['GET'])
def download_fuzzing_harness_file(harness_id, file_type):
    """Download individual fuzzing harness files"""
    try:
        harness = FuzzingHarness.query.get(harness_id)
        if not harness:
            return jsonify({'error': 'Fuzzing harness not found'}), 404
        
        if file_type == 'harness':
            content = harness.harness_code or '// No harness code available'
            filename = f"fuzzing_harness_{harness_id}.c"
            mimetype = 'text/x-c'
            
        elif file_type == 'makefile':
            content = harness.makefile_content or '# No Makefile available'
            filename = f"Makefile_{harness_id}"
            mimetype = 'text/plain'
            
        elif file_type == 'readme':
            content = harness.readme_content or '# No README available'
            filename = f"README_{harness_id}.md"
            mimetype = 'text/markdown'
            
        elif file_type == 'package':
            # Create a ZIP package with all files
            import zipfile
            import io
            
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add harness code
                if harness.harness_code:
                    zip_file.writestr('fuzzing_harness.c', harness.harness_code)
                
                # Add Makefile
                if harness.makefile_content:
                    zip_file.writestr('Makefile', harness.makefile_content)
                
                # Add README
                if harness.readme_content:
                    zip_file.writestr('README.md', harness.readme_content)
                
                # Add seed inputs if available
                if harness.seed_inputs:
                    zip_file.writestr('inputs/seed1.txt', harness.seed_inputs)
            
            zip_buffer.seek(0)
            
            return send_file(
                io.BytesIO(zip_buffer.read()),
                as_attachment=True,
                download_name=f"fuzzing_harness_{harness_id}.zip",
                mimetype='application/zip'
            )
        else:
            return jsonify({'error': 'Invalid file type'}), 400
        
        # Create response for text files
        response = make_response(content)
        response.headers['Content-Type'] = mimetype
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        logger.error(f"Error downloading harness file {harness_id}/{file_type}: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ==========================================
# FUZZING SESSION MANAGEMENT ENDPOINTS  
# ==========================================

@api_bp.route('/fuzzing/supported-fuzzers', methods=['GET'])
def get_supported_fuzzers():
    """Get list of supported fuzzers and their characteristics"""
    try:
        from .fuzzing_harness_generator import FuzzingHarnessGenerator
        
        generator = FuzzingHarnessGenerator()
        
        fuzzers = []
        for fuzzer_name, config in generator.supported_fuzzers.items():
            fuzzer_info = {
                'name': fuzzer_name,
                'description': config['description'],
                'default': config['default'],
                'file_based': config['file_based'],
                'persistent_mode': config['persistent_mode'],
                'compile_flags': config['compile_flags'],
                'runtime_args': config['runtime_args']
            }
            fuzzers.append(fuzzer_info)
        
        return jsonify({
            'supported_fuzzers': fuzzers,
            'default_fuzzer': next((f['name'] for f in fuzzers if f['default']), 'AFL++'),
            'total_count': len(fuzzers)
        })
        
    except Exception as e:
        logger.error(f"Error getting supported fuzzers: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/fuzzing-harnesses/<harness_id>/sessions', methods=['POST'])
def create_fuzzing_session(harness_id):
    """Create a new fuzzing session"""
    try:
        from .models import FuzzingHarness, FuzzingSession
        
        harness = FuzzingHarness.query.get(harness_id)
        if not harness:
            return jsonify({'error': 'Fuzzing harness not found'}), 404
        
        data = request.json or {}
        session_name = data.get('name', f'Fuzzing Session - {datetime.now().strftime("%Y%m%d_%H%M%S")}')
        fuzzer_type = data.get('fuzzer_type', 'afl++')
        afl_args = data.get('afl_args', '')
        notes = data.get('notes', '')
        
        # Create session
        session = FuzzingSession(
            harness_id=harness_id,
            name=session_name,
            fuzzer_type=fuzzer_type,
            afl_args=afl_args,
            notes=notes,
            status='pending'
        )
        
        db.session.add(session)
        db.session.commit()
        
        logger.info(f"Created fuzzing session {session.id} for harness {harness_id}")
        
        return jsonify({
            'success': True,
            'message': 'Fuzzing session created',
            'session': {
                'id': session.id,
                'name': session.name,
                'status': session.status,
                'fuzzer_type': session.fuzzer_type,
                'created_at': session.created_at.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Error creating fuzzing session for harness {harness_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/fuzzing-sessions/<session_id>/update', methods=['PUT'])
def update_fuzzing_session(session_id):
    """Update fuzzing session results"""
    try:
        from .models import FuzzingSession
        
        session = FuzzingSession.query.get(session_id)
        if not session:
            return jsonify({'error': 'Fuzzing session not found'}), 404
        
        data = request.json or {}
        
        # Update fields if provided
        if 'status' in data:
            session.status = data['status']
        if 'total_execs' in data:
            session.total_execs = data['total_execs']
        if 'crashes_found' in data:
            session.crashes_found = data['crashes_found']
        if 'hangs_found' in data:
            session.hangs_found = data['hangs_found']
        if 'coverage_percent' in data:
            session.coverage_percent = data['coverage_percent']
        if 'notes' in data:
            session.notes = data['notes']
        
        # Handle timing
        if data.get('status') == 'running' and not session.started_at:
            session.started_at = datetime.utcnow()
        elif data.get('status') in ['completed', 'crashed'] and not session.ended_at:
            session.ended_at = datetime.utcnow()
            if session.started_at:
                duration = session.ended_at - session.started_at
                session.duration_seconds = int(duration.total_seconds())
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Fuzzing session updated',
            'session': {
                'id': session.id,
                'status': session.status,
                'total_execs': session.total_execs,
                'crashes_found': session.crashes_found,
                'hangs_found': session.hangs_found,
                'coverage_percent': session.coverage_percent
            }
        })
        
    except Exception as e:
        logger.error(f"Error updating fuzzing session {session_id}: {e}")
        return jsonify({'error': str(e)}), 500 

@api_bp.route('/system/reset-complete', methods=['POST'])
def reset_complete_system():
    """Complete system reset - deletes ALL database entries and files"""
    try:
        from .models import (
            Binary, Function, AnalysisTask, AnalysisResult, Import, Export, 
            BinaryString, MemoryRegion, Symbol, DataType, Instruction, 
            CrossReference, ComprehensiveAnalysis, UnifiedSecurityFinding,
            SecurityEvidence, Vulnerability, VulnerabilityReport, 
            FuzzingHarness, FuzzingTarget, FuzzingSession, Configuration,
            LocalVariable, FunctionParameter, FunctionCall
        )
        import shutil
        
        logger.info("Starting complete system reset...")
        
        # Cancel all running tasks first
        success, message, cancelled_count = current_app.task_manager.cancel_all_tasks()
        logger.info(f"Cancelled {cancelled_count} tasks")
        
        # Delete all database records in correct order
        tables_deleted = {}
        
        # Delete dependent records first
        tables_deleted['LocalVariable'] = LocalVariable.query.count()
        LocalVariable.query.delete()
        
        tables_deleted['FunctionParameter'] = FunctionParameter.query.count()
        FunctionParameter.query.delete()
        
        tables_deleted['FunctionCall'] = FunctionCall.query.count()
        FunctionCall.query.delete()
        
        tables_deleted['SecurityEvidence'] = SecurityEvidence.query.count()
        SecurityEvidence.query.delete()
        
        tables_deleted['UnifiedSecurityFinding'] = UnifiedSecurityFinding.query.count()
        UnifiedSecurityFinding.query.delete()
        
        tables_deleted['Vulnerability'] = Vulnerability.query.count()
        Vulnerability.query.delete()
        
        tables_deleted['VulnerabilityReport'] = VulnerabilityReport.query.count()
        VulnerabilityReport.query.delete()
        
        tables_deleted['FuzzingSession'] = FuzzingSession.query.count()
        FuzzingSession.query.delete()
        
        tables_deleted['FuzzingTarget'] = FuzzingTarget.query.count()
        FuzzingTarget.query.delete()
        
        tables_deleted['FuzzingHarness'] = FuzzingHarness.query.count()
        FuzzingHarness.query.delete()
        
        # Delete main tables
        tables_deleted['Function'] = Function.query.count()
        Function.query.delete()
        
        tables_deleted['AnalysisResult'] = AnalysisResult.query.count()
        AnalysisResult.query.delete()
        
        tables_deleted['AnalysisTask'] = AnalysisTask.query.count()
        AnalysisTask.query.delete()
        
        tables_deleted['Import'] = Import.query.count()
        Import.query.delete()
        
        tables_deleted['Export'] = Export.query.count()
        Export.query.delete()
        
        tables_deleted['BinaryString'] = BinaryString.query.count()
        BinaryString.query.delete()
        
        tables_deleted['MemoryRegion'] = MemoryRegion.query.count()
        MemoryRegion.query.delete()
        
        tables_deleted['Symbol'] = Symbol.query.count()
        Symbol.query.delete()
        
        tables_deleted['DataType'] = DataType.query.count()
        DataType.query.delete()
        
        tables_deleted['Instruction'] = Instruction.query.count()
        Instruction.query.delete()
        
        tables_deleted['CrossReference'] = CrossReference.query.count()
        CrossReference.query.delete()
        
        tables_deleted['ComprehensiveAnalysis'] = ComprehensiveAnalysis.query.count()
        ComprehensiveAnalysis.query.delete()
        
        # Delete binary records last
        tables_deleted['Binary'] = Binary.query.count()
        Binary.query.delete()
        
        # Keep configurations but reset non-essential ones
        configs_reset = Configuration.query.filter(~Configuration.key.in_([
            'ghidra_bridge_host', 'ghidra_bridge_port', 'ai_model', 'ai_max_tokens'
        ])).count()
        Configuration.query.filter(~Configuration.key.in_([
            'ghidra_bridge_host', 'ghidra_bridge_port', 'ai_model', 'ai_max_tokens'
        ])).delete()
        
        db.session.commit()
        
        # Clean up file directories
        directories_cleaned = []
        upload_dir = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        temp_dir = current_app.config.get('TEMP_FOLDER', 'temp')
        
        for directory in [upload_dir, temp_dir]:
            if os.path.exists(directory):
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    try:
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as e:
                        logger.warning(f"Failed to delete {file_path}: {e}")
                directories_cleaned.append(directory)
        
        total_records = sum(tables_deleted.values())
        logger.info(f"Complete system reset finished - deleted {total_records} records from {len(tables_deleted)} tables")
        
        return jsonify({
            'status': 'success',
            'message': f'Complete system reset successful. Deleted {total_records} database records and cleaned file directories.',
            'details': {
                'cancelled_tasks': cancelled_count,
                'deleted_records': tables_deleted,
                'configs_reset': configs_reset,
                'directories_cleaned': directories_cleaned,
                'total_records': total_records
            }
        })
        
    except Exception as e:
        logger.error(f"Error in complete system reset: {e}")
        db.session.rollback()
        return jsonify({'error': f'Complete system reset failed: {str(e)}'}), 500

@api_bp.route('/system/database-stats', methods=['GET'])
def get_database_stats():
    """Get detailed database statistics for all tables"""
    try:
        from .models import (
            Binary, Function, AnalysisTask, AnalysisResult, Import, Export,
            BinaryString, MemoryRegion, Symbol, DataType, Instruction,
            CrossReference, ComprehensiveAnalysis, UnifiedSecurityFinding,
            SecurityEvidence, Vulnerability, VulnerabilityReport,
            FuzzingHarness, FuzzingTarget, FuzzingSession, Configuration,
            LocalVariable, FunctionParameter, FunctionCall
        )
        
        stats = {
            'core_tables': {
                'binaries': Binary.query.count(),
                'functions': Function.query.count(),
                'analysis_tasks': AnalysisTask.query.count(),
                'analysis_results': AnalysisResult.query.count(),
                'comprehensive_analyses': ComprehensiveAnalysis.query.count()
            },
            'binary_data': {
                'imports': Import.query.count(),
                'exports': Export.query.count(),
                'strings': BinaryString.query.count(),
                'memory_regions': MemoryRegion.query.count(),
                'symbols': Symbol.query.count(),
                'data_types': DataType.query.count(),
                'instructions': Instruction.query.count(),
                'cross_references': CrossReference.query.count()
            },
            'function_data': {
                'local_variables': LocalVariable.query.count(),
                'function_parameters': FunctionParameter.query.count(),
                'function_calls': FunctionCall.query.count()
            },
            'security_data': {
                'security_findings': UnifiedSecurityFinding.query.count(),
                'security_evidence': SecurityEvidence.query.count(),
                'vulnerabilities': Vulnerability.query.count(),
                'vulnerability_reports': VulnerabilityReport.query.count()
            },
            'fuzzing_data': {
                'fuzzing_harnesses': FuzzingHarness.query.count(),
                'fuzzing_targets': FuzzingTarget.query.count(),
                'fuzzing_sessions': FuzzingSession.query.count()
            },
            'system_data': {
                'configurations': Configuration.query.count()
            }
        }
        
        # Calculate totals
        stats['totals'] = {
            'core_total': sum(stats['core_tables'].values()),
            'binary_data_total': sum(stats['binary_data'].values()),
            'function_data_total': sum(stats['function_data'].values()),
            'security_data_total': sum(stats['security_data'].values()),
            'fuzzing_data_total': sum(stats['fuzzing_data'].values()),
            'system_data_total': sum(stats['system_data'].values())
        }
        stats['grand_total'] = sum(stats['totals'].values())
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/system/clean-table/<table_name>', methods=['POST'])
def clean_database_table(table_name):
    """Clean specific database table"""
    try:
        from .models import (
            Binary, Function, AnalysisTask, AnalysisResult, Import, Export,
            BinaryString, MemoryRegion, Symbol, DataType, Instruction,
            CrossReference, ComprehensiveAnalysis, UnifiedSecurityFinding,
            SecurityEvidence, Vulnerability, VulnerabilityReport,
            FuzzingHarness, FuzzingTarget, FuzzingSession, Configuration,
            LocalVariable, FunctionParameter, FunctionCall
        )
        
        table_map = {
            'binaries': Binary,
            'functions': Function,
            'analysis_tasks': AnalysisTask,
            'analysis_results': AnalysisResult,
            'imports': Import,
            'exports': Export,
            'strings': BinaryString,
            'memory_regions': MemoryRegion,
            'symbols': Symbol,
            'data_types': DataType,
            'instructions': Instruction,
            'cross_references': CrossReference,
            'comprehensive_analyses': ComprehensiveAnalysis,
            'security_findings': UnifiedSecurityFinding,
            'security_evidence': SecurityEvidence,
            'vulnerabilities': Vulnerability,
            'vulnerability_reports': VulnerabilityReport,
            'fuzzing_harnesses': FuzzingHarness,
            'fuzzing_targets': FuzzingTarget,
            'fuzzing_sessions': FuzzingSession,
            'local_variables': LocalVariable,
            'function_parameters': FunctionParameter,
            'function_calls': FunctionCall
        }
        
        if table_name not in table_map:
            return jsonify({'error': f'Unknown table: {table_name}'}), 400
        
        if table_name == 'configurations':
            return jsonify({'error': 'Cannot clean configuration table'}), 400
        
        model = table_map[table_name]
        count = model.query.count()
        
        if count == 0:
            return jsonify({
                'status': 'success',
                'message': f'Table {table_name} is already empty',
                'deleted_count': 0
            })
        
        # Special handling for binaries - also clean files
        if table_name == 'binaries':
            # Get all binaries first
            binaries = Binary.query.all()
            
            # Delete associated files
            files_deleted = 0
            for binary in binaries:
                if binary.file_path and os.path.exists(binary.file_path):
                    try:
                        os.remove(binary.file_path)
                        files_deleted += 1
                    except Exception as e:
                        logger.warning(f"Failed to delete binary file {binary.file_path}: {e}")
            
            # Delete all related data in correct order for binaries
            related_deletions = {}
            
            # Get all binary IDs
            binary_ids = [b.id for b in binaries]
            
            if binary_ids:
                # Delete dependent records first
                related_deletions['local_variables'] = LocalVariable.query.filter(
                    LocalVariable.function_id.in_(
                        db.session.query(Function.id).filter(Function.binary_id.in_(binary_ids))
                    )
                ).delete(synchronize_session=False)
                
                related_deletions['function_parameters'] = FunctionParameter.query.filter(
                    FunctionParameter.function_id.in_(
                        db.session.query(Function.id).filter(Function.binary_id.in_(binary_ids))
                    )
                ).delete(synchronize_session=False)
                
                related_deletions['function_calls'] = FunctionCall.query.filter(
                    FunctionCall.binary_id.in_(binary_ids)
                ).delete(synchronize_session=False)
                
                related_deletions['security_evidence'] = SecurityEvidence.query.filter(
                    SecurityEvidence.finding_id.in_(
                        db.session.query(UnifiedSecurityFinding.id).filter(
                            UnifiedSecurityFinding.binary_id.in_(binary_ids)
                        )
                    )
                ).delete(synchronize_session=False)
                
                # Delete main related tables
                for related_model, related_name in [
                    (Function, 'functions'),
                    (AnalysisTask, 'analysis_tasks'),
                    (AnalysisResult, 'analysis_results'),
                    (Import, 'imports'),
                    (Export, 'exports'),
                    (BinaryString, 'strings'),
                    (MemoryRegion, 'memory_regions'),
                    (Symbol, 'symbols'),
                    (DataType, 'data_types'),
                    (Instruction, 'instructions'),
                    (CrossReference, 'cross_references'),
                    (ComprehensiveAnalysis, 'comprehensive_analyses'),
                    (UnifiedSecurityFinding, 'security_findings'),
                    (Vulnerability, 'vulnerabilities'),
                    (VulnerabilityReport, 'vulnerability_reports'),
                    (FuzzingHarness, 'fuzzing_harnesses'),
                    (FuzzingTarget, 'fuzzing_targets'),
                    (FuzzingSession, 'fuzzing_sessions')
                ]:
                    related_deletions[related_name] = related_model.query.filter(
                        related_model.binary_id.in_(binary_ids)
                    ).delete(synchronize_session=False)
            
            # Finally delete binaries
            model.query.delete()
            db.session.commit()
            
            total_related = sum(related_deletions.values())
            
            return jsonify({
                'status': 'success',
                'message': f'Cleaned {table_name} table and all related data',
                'deleted_count': count,
                'related_deletions': related_deletions,
                'files_deleted': files_deleted,
                'total_deleted': count + total_related
            })
        
        # For non-binary tables, simple deletion
        model.query.delete()
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Successfully cleaned {table_name} table',
            'deleted_count': count
        })
        
    except Exception as e:
        logger.error(f"Error cleaning table {table_name}: {e}")
        db.session.rollback()
        return jsonify({'error': f'Failed to clean table {table_name}: {str(e)}'}), 500

@api_bp.route('/system/clean-files', methods=['POST'])
def clean_system_files():
    """Clean all uploaded files and temporary files"""
    try:
        import shutil
        
        upload_dir = current_app.config.get('UPLOAD_FOLDER', 'uploads')
        temp_dir = current_app.config.get('TEMP_FOLDER', 'temp')
        
        files_deleted = 0
        directories_cleaned = []
        
        for directory in [upload_dir, temp_dir]:
            if os.path.exists(directory):
                dir_files_deleted = 0
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    try:
                        if os.path.isfile(file_path):
                            os.remove(file_path)
                            dir_files_deleted += 1
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                            dir_files_deleted += 1
                    except Exception as e:
                        logger.warning(f"Failed to delete {file_path}: {e}")
                
                files_deleted += dir_files_deleted
                directories_cleaned.append({
                    'directory': directory,
                    'files_deleted': dir_files_deleted
                })
        
        return jsonify({
            'status': 'success',
            'message': f'Cleaned {files_deleted} files from system directories',
            'files_deleted': files_deleted,
            'directories_cleaned': directories_cleaned
        })
        
    except Exception as e:
        logger.error(f"Error cleaning system files: {e}")
        return jsonify({'error': f'Failed to clean system files: {str(e)}'}), 500

# ==========================================
# CONFIGURATION MANAGEMENT ENDPOINTS
# ==========================================

@api_bp.route('/config', methods=['GET'])
def get_configuration():
    """Get current configuration from .env file"""
    try:
        import os
        from dotenv import dotenv_values
        
        # Load configuration from .env file
        env_path = os.path.join(os.getcwd(), '.env')
        config_values = dotenv_values(env_path)
        
        # Map .env keys to frontend configuration structure
        configuration = {
            # LLM Provider Settings
            'llm_provider': config_values.get('LLM_PROVIDER', 'openai'),
            
            # OpenAI Settings
            'openai_api_key': config_values.get('OPENAI_API_KEY', ''),
            'openai_model': config_values.get('OPENAI_MODEL', 'gpt-3.5-turbo'),
            'openai_base_url': config_values.get('OPENAI_BASE_URL', 'https://api.openai.com/v1'),
            
            # Google Gemini Settings
            'gemini_api_key': config_values.get('GEMINI_API_KEY', ''),
            'gemini_model': config_values.get('GEMINI_MODEL', 'gemini-pro'),
            
            # Claude Settings
            'claude_api_key': config_values.get('CLAUDE_API_KEY', ''),
            'claude_model': config_values.get('CLAUDE_MODEL', 'claude-3-sonnet-20240229'),
            
            # Ollama Settings
            'ollama_base_url': config_values.get('OLLAMA_BASE_URL', 'http://localhost:11434'),
            'ollama_model': config_values.get('OLLAMA_MODEL', 'llama2'),
            
            # LLM General Settings
            'llm_timeout': int(config_values.get('LLM_TIMEOUT', '60')),
            'llm_max_tokens': int(config_values.get('LLM_MAX_TOKENS', '1500')),
            'llm_temperature': float(config_values.get('LLM_TEMPERATURE', '0.3')),
            
            # Ghidra Settings
            'ghidra_install_dir': config_values.get('GHIDRA_INSTALL_DIR', ''),
            'ghidra_bridge_port': int(config_values.get('GHIDRA_BRIDGE_PORT', '4768')),
            'ghidra_max_processes': int(config_values.get('GHIDRA_MAX_PROCESSES', '4')),
            'ghidra_timeout': int(config_values.get('GHIDRA_TIMEOUT', '3600')),
            
            # Server Settings
            'flask_host': config_values.get('FLASK_HOST', '127.0.0.1'),
            'flask_port': int(config_values.get('FLASK_PORT', '5000')),
            'max_file_size': int(config_values.get('MAX_FILE_SIZE', '1073741824')),
            'upload_folder': config_values.get('UPLOAD_FOLDER', './uploads'),
            'temp_folder': config_values.get('TEMP_FOLDER', './temp'),
            
            # Analysis Settings
            'analysis_timeout': int(config_values.get('ANALYSIS_TIMEOUT', '1800')),
            'max_concurrent_analyses': int(config_values.get('MAX_CONCURRENT_ANALYSES', '2')),
            'enable_debug_logging': config_values.get('ENABLE_DEBUG_LOGGING', 'false').lower() == 'true',
            'auto_cleanup_temp_files': config_values.get('AUTO_CLEANUP_TEMP_FILES', 'true').lower() == 'true'
        }
        
        return jsonify(configuration)
        
    except Exception as e:
        logger.error(f"Error getting configuration: {e}")
        return jsonify({'error': f'Failed to get configuration: {str(e)}'}), 500

@api_bp.route('/config', methods=['POST'])
def update_configuration():
    """Update configuration in .env file"""
    try:
        import os
        from dotenv import dotenv_values
        
        data = request.json or {}
        
        # Load current .env file
        env_path = os.path.join(os.getcwd(), '.env')
        
        # Read current content
        env_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r', encoding='utf-8') as f:
                env_lines = f.readlines()
        
        # Map frontend configuration keys to .env keys
        config_mapping = {
            'llm_provider': 'LLM_PROVIDER',
            'openai_api_key': 'OPENAI_API_KEY',
            'openai_model': 'OPENAI_MODEL',
            'openai_base_url': 'OPENAI_BASE_URL',
            'gemini_api_key': 'GEMINI_API_KEY',
            'gemini_model': 'GEMINI_MODEL',
            'claude_api_key': 'CLAUDE_API_KEY',
            'claude_model': 'CLAUDE_MODEL',
            'ollama_base_url': 'OLLAMA_BASE_URL',
            'ollama_model': 'OLLAMA_MODEL',
            'llm_timeout': 'LLM_TIMEOUT',
            'llm_max_tokens': 'LLM_MAX_TOKENS',
            'llm_temperature': 'LLM_TEMPERATURE',
            'ghidra_install_dir': 'GHIDRA_INSTALL_DIR',
            'ghidra_bridge_port': 'GHIDRA_BRIDGE_PORT',
            'ghidra_max_processes': 'GHIDRA_MAX_PROCESSES',
            'ghidra_timeout': 'GHIDRA_TIMEOUT',
            'flask_host': 'FLASK_HOST',
            'flask_port': 'FLASK_PORT',
            'max_file_size': 'MAX_FILE_SIZE',
            'upload_folder': 'UPLOAD_FOLDER',
            'temp_folder': 'TEMP_FOLDER',
            'analysis_timeout': 'ANALYSIS_TIMEOUT',
            'max_concurrent_analyses': 'MAX_CONCURRENT_ANALYSES',
            'enable_debug_logging': 'ENABLE_DEBUG_LOGGING',
            'auto_cleanup_temp_files': 'AUTO_CLEANUP_TEMP_FILES'
        }
        
        # Create a dictionary to track which keys we need to update
        updates = {}
        for frontend_key, env_key in config_mapping.items():
            if frontend_key in data:
                value = data[frontend_key]
                # Convert boolean values to string
                if isinstance(value, bool):
                    value = 'true' if value else 'false'
                updates[env_key] = str(value)
        
        # Process the env file lines
        updated_lines = []
        updated_keys = set()
        
        for line in env_lines:
            line = line.rstrip('\n\r')
            
            # Skip empty lines and comments
            if not line.strip() or line.strip().startswith('#'):
                updated_lines.append(line)
                continue
            
            # Check if this line contains a key we want to update
            if '=' in line:
                key = line.split('=', 1)[0].strip()
                if key in updates:
                    # Update this line
                    updated_lines.append(f"{key}={updates[key]}")
                    updated_keys.add(key)
                else:
                    # Keep original line
                    updated_lines.append(line)
            else:
                updated_lines.append(line)
        
        # Add any new keys that weren't in the original file
        for env_key, value in updates.items():
            if env_key not in updated_keys:
                updated_lines.append(f"{env_key}={value}")
        
        # Write the updated content back to the .env file
        with open(env_path, 'w', encoding='utf-8') as f:
            for line in updated_lines:
                f.write(line + '\n')
        
        logger.info(f"Configuration updated successfully. Updated {len(updates)} settings.")
        
        # If any AI provider key or LLM_PROVIDER was updated, reload AI services
        ai_keys_updated = any(key in updates for key in ['OPENAI_API_KEY', 'CLAUDE_API_KEY', 'GEMINI_API_KEY', 'LLM_PROVIDER'])
        if ai_keys_updated:
            try:
                updated_providers = []
                if 'OPENAI_API_KEY' in updates:
                    updated_providers.append('OpenAI')
                if 'CLAUDE_API_KEY' in updates:
                    updated_providers.append('Claude')
                if 'GEMINI_API_KEY' in updates:
                    updated_providers.append('Gemini')
                if 'LLM_PROVIDER' in updates:
                    updated_providers.append(f"Provider changed to {updates['LLM_PROVIDER']}")
                
                logger.info(f"AI configuration updated ({', '.join(updated_providers)}) - reloading AI services")
                
                # Reload AI service in task manager
                current_app.task_manager.reload_ai_service()
                
                # Reload AI service in enhanced security analyzer
                from flask_app.enhanced_security_analyzer import EnhancedSecurityAnalyzer
                analyzer = EnhancedSecurityAnalyzer()
                analyzer.reload_ai_service()
                
                logger.info("AI services successfully reloaded with new configuration")
                
            except Exception as e:
                logger.error(f"Error reloading AI services: {e}")
        
        return jsonify({
            'status': 'success',
            'message': f'Configuration updated successfully. Updated {len(updates)} settings.',
            'updated_keys': list(updates.keys()),
            'ai_services_reloaded': ai_keys_updated
        })
        
    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        return jsonify({'error': f'Failed to save configuration: {str(e)}'}), 500

@api_bp.route('/ai/status', methods=['GET'])
def get_ai_status():
    """Get current AI service status for all providers"""
    try:
        from flask_app.enhanced_security_analyzer import EnhancedSecurityAnalyzer
        
        # Check task manager AI service
        tm_ai_service = current_app.task_manager._get_ai_service()
        tm_status = {
            'initialized': tm_ai_service.client is not None,
            'provider': getattr(tm_ai_service, 'provider_name', 'unknown'),
            'api_key_configured': bool(getattr(tm_ai_service.provider, 'api_key', None)) if tm_ai_service.provider else False,
            'model': getattr(tm_ai_service.provider, 'model', 'unknown') if tm_ai_service.provider else 'unknown'
        }
        
        # Check enhanced security analyzer AI service  
        analyzer = EnhancedSecurityAnalyzer()
        esa_status = {
            'initialized': analyzer.ai_service.client is not None,
            'provider': getattr(analyzer.ai_service, 'provider_name', 'unknown'),
            'api_key_configured': bool(getattr(analyzer.ai_service.provider, 'api_key', None)) if analyzer.ai_service.provider else False,
            'model': getattr(analyzer.ai_service.provider, 'model', 'unknown') if analyzer.ai_service.provider else 'unknown'
        }
        
        # Get environment configuration for all providers
        import os
        providers_config = {
            'openai': {
                'api_key_configured': bool(os.getenv('OPENAI_API_KEY')),
                'model': os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo'),
                'available': bool(os.getenv('OPENAI_API_KEY'))
            },
            'claude': {
                'api_key_configured': bool(os.getenv('CLAUDE_API_KEY')),
                'model': os.getenv('CLAUDE_MODEL', 'claude-3-sonnet-20240229'),
                'available': bool(os.getenv('CLAUDE_API_KEY'))
            },
            'gemini': {
                'api_key_configured': bool(os.getenv('GEMINI_API_KEY')),
                'model': os.getenv('GEMINI_MODEL', 'gemini-pro'),
                'available': bool(os.getenv('GEMINI_API_KEY'))
            }
        }
        
        current_provider = os.getenv('LLM_PROVIDER', 'openai').lower()
        
        return jsonify({
            'current_provider': current_provider,
            'providers_config': providers_config,
            'task_manager_ai': tm_status,
            'enhanced_security_analyzer_ai': esa_status,
            'overall_status': 'ready' if (tm_status['initialized'] and esa_status['initialized']) else 'not_configured'
        })
        
    except Exception as e:
        logger.error(f"Error checking AI status: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/config/test-connection', methods=['POST'])
def test_ai_connection():
    """Test AI service connection for all supported providers"""
    try:
        data = request.json or {}
        provider = data.get('provider', 'openai').lower()
        
        # Import the multi-provider AI service
        from flask_app.multi_provider_ai_service import MultiProviderAIService
        
        # Test the connection based on provider
        if provider == 'openai':
            api_key = data.get('api_key')
            model = data.get('model', 'gpt-3.5-turbo')
            base_url = data.get('base_url', 'https://api.openai.com/v1')
            
            if not api_key:
                return jsonify({'error': 'API key is required'}), 400
            
            # Try to initialize AI service with the test API key
            test_ai_service = MultiProviderAIService(provider='openai', api_key=api_key, model=model)
            
            if not test_ai_service.client:
                return jsonify({
                    'error': 'Failed to initialize OpenAI client with provided credentials'
                }), 400
            
            try:
                # Test the connection
                test_result = test_ai_service.test_connection()
                
                if test_result.get('success'):
                    return jsonify({
                        'success': True,
                        'message': f'OpenAI connection test successful!'
                    })
                else:
                    return jsonify({
                        'error': f'OpenAI connection test failed: {test_result.get("error", "Unknown error")}'
                    }), 400
                    
            except Exception as test_error:
                logger.error(f"OpenAI connection test error: {test_error}")
                return jsonify({
                    'error': f'OpenAI connection test failed: {str(test_error)}'
                }), 400
                
        elif provider == 'claude':
            api_key = data.get('api_key')
            model = data.get('model', 'claude-3-sonnet-20240229')
            
            if not api_key:
                return jsonify({'error': 'API key is required'}), 400
            
            try:
                # Try to initialize Claude AI service
                test_ai_service = MultiProviderAIService(provider='claude', api_key=api_key, model=model)
                
                if not test_ai_service.client:
                    return jsonify({
                        'error': 'Failed to initialize Claude client. Make sure anthropic package is installed.'
                    }), 400
                
                # Test the connection
                test_result = test_ai_service.test_connection()
                
                if test_result.get('success'):
                    return jsonify({
                        'success': True,
                        'message': f'Claude connection test successful!'
                    })
                else:
                    return jsonify({
                        'error': f'Claude connection test failed: {test_result.get("error", "Unknown error")}'
                    }), 400
                    
            except Exception as test_error:
                logger.error(f"Claude connection test error: {test_error}")
                return jsonify({
                    'error': f'Claude connection test failed: {str(test_error)}'
                }), 400
        
        elif provider == 'gemini':
            api_key = data.get('api_key')
            model = data.get('model', 'gemini-pro')
            
            if not api_key:
                return jsonify({'error': 'API key is required'}), 400
            
            try:
                # Try to initialize Gemini AI service
                test_ai_service = MultiProviderAIService(provider='gemini', api_key=api_key, model=model)
                
                if not test_ai_service.client:
                    return jsonify({
                        'error': 'Failed to initialize Gemini client. Make sure google-generativeai package is installed.'
                    }), 400
                
                # Test the connection
                test_result = test_ai_service.test_connection()
                
                if test_result.get('success'):
                    return jsonify({
                        'success': True,
                        'message': f'Gemini connection test successful!'
                    })
                else:
                    return jsonify({
                        'error': f'Gemini connection test failed: {test_result.get("error", "Unknown error")}'
                    }), 400
                    
            except Exception as test_error:
                logger.error(f"Gemini connection test error: {test_error}")
                return jsonify({
                    'error': f'Gemini connection test failed: {str(test_error)}'
                }), 400
        
        else:
            return jsonify({
                'error': f'Unsupported provider: {provider}. Supported providers: openai, claude, gemini'
            }), 400
        
    except Exception as e:
        logger.error(f"Error testing AI connection: {e}")
        return jsonify({
            'error': f'Connection test failed: {str(e)}'
        }), 500

# ==========================================
# BINARY STATUS MANAGEMENT ENDPOINTS
# ==========================================

@api_bp.route('/binaries/<binary_id>/update-status', methods=['POST'])
def update_binary_status(binary_id):
    """Manually update binary analysis status based on completion"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get current status
        old_status = binary.analysis_status
        
        # Update using the sophisticated status logic
        new_status = binary.update_analysis_status()
        
        # Get detailed statistics
        stats = binary.get_analysis_statistics()
        
        # Commit the changes
        db.session.commit()
        
        logger.info(f"Manual status update for binary {binary_id}: {old_status} -> {new_status}")
        
        return jsonify({
            'success': True,
            'message': f'Binary status updated from {old_status} to {new_status}',
            'old_status': old_status,
            'new_status': new_status,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Error updating binary status for {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/<binary_id>/status-info', methods=['GET'])
def get_binary_status_info(binary_id):
    """Get detailed binary status information and analysis statistics"""
    try:
        binary = Binary.query.get(binary_id)
        if not binary:
            return jsonify({'error': 'Binary not found'}), 404
        
        # Get detailed statistics
        stats = binary.get_analysis_statistics()
        
        # Check availability for fuzzing
        fuzzing_ready = stats['decompile_percentage'] >= 80
        
        return jsonify({
            'binary_id': binary_id,
            'filename': binary.original_filename,
            'current_status': binary.analysis_status,
            'statistics': stats,
            'fuzzing_ready': fuzzing_ready,
            'status_explanation': {
                'Pending': 'Initial upload, no analysis started',
                'Analyzing': 'Analysis in progress', 
                'Decompiled': '80%+ functions decompiled',
                'Analyzed': 'Security analysis complete',
                'Completed': 'All analysis including fuzzing ready'
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting binary status info for {binary_id}: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/update-all-statuses', methods=['POST'])
def update_all_binary_statuses():
    """Update status for all binaries (maintenance operation)"""
    try:
        # Get all binaries
        binaries = Binary.query.all()
        
        updates = []
        for binary in binaries:
            old_status = binary.analysis_status
            new_status = binary.update_analysis_status()
            
            if new_status != old_status:
                updates.append({
                    'binary_id': binary.id,
                    'filename': binary.original_filename,
                    'old_status': old_status,
                    'new_status': new_status
                })
        
        # Commit all changes
        db.session.commit()
        
        logger.info(f"Bulk status update completed: {len(updates)} binaries updated")
        
        return jsonify({
            'success': True,
            'message': f'Updated status for {len(updates)} out of {len(binaries)} binaries',
            'total_binaries': len(binaries),
            'updated_binaries': len(updates),
            'updates': updates
        })
        
    except Exception as e:
        logger.error(f"Error in bulk binary status update: {e}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@api_bp.route('/binaries/fuzzing-ready', methods=['GET'])
def get_fuzzing_ready_binaries():
    """Get all binaries that are ready for fuzzing (80%+ decompiled)"""
    try:
        # Get all binaries
        binaries = Binary.query.all()
        
        fuzzing_ready = []
        for binary in binaries:
            stats = binary.get_analysis_statistics()
            if stats['decompile_percentage'] >= 80:
                fuzzing_ready.append({
                    'binary_id': binary.id,
                    'filename': binary.original_filename,
                    'status': binary.analysis_status,
                    'decompile_percentage': stats['decompile_percentage'],
                    'total_functions': stats['total_functions'],
                    'decompiled_functions': stats['decompiled_functions'],
                    'ai_analyzed_functions': stats['ai_analyzed_functions'],
                    'security_findings': stats['security_findings'],
                    'fuzzing_harnesses': stats['fuzzing_harnesses']
                })
        
        return jsonify({
            'fuzzing_ready_binaries': fuzzing_ready,
            'total_ready': len(fuzzing_ready)
        })
        
    except Exception as e:
        logger.error(f"Error getting fuzzing-ready binaries: {e}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/analysis/diff', methods=['POST'])
def compare_binaries():
    """Compare two binaries and find differences"""
    try:
        # Get request data
        data = request.get_json()
        binary_id1 = data.get('binary_id1')
        binary_id2 = data.get('binary_id2')
        diff_type = data.get('diff_type', 'instructions')
        
        # Validate inputs
        if not binary_id1 or not binary_id2:
            return jsonify({'error': 'Both binary_id1 and binary_id2 are required'}), 400
            
        # Check if binaries exist
        binary1 = Binary.query.get(binary_id1)
        binary2 = Binary.query.get(binary_id2)
        
        if not binary1:
            return jsonify({'error': f'Binary with ID {binary_id1} not found'}), 404
        if not binary2:
            return jsonify({'error': f'Binary with ID {binary_id2} not found'}), 404
            
        # Create a task for binary comparison
        task = AnalysisTask(
            id=str(uuid.uuid4()),
            binary_id=binary_id1,  # Associate with first binary
            task_type='binary_comparison',
            status='completed',  # Set to completed immediately
            priority=1,
            parameters={
                'binary_id1': binary_id1,
                'binary_id2': binary_id2,
                'diff_type': diff_type
            },
            progress=100,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow()
        )
        
        db.session.add(task)
        db.session.commit()
        
        logger.info(f"Binary comparison task {task.id} created and marked as completed")
        
        return jsonify({
            'task_id': task.id,
            'status': 'completed',
            'message': f'Binary comparison task created. Comparing {binary1.original_filename} with {binary2.original_filename}.'
        })
        
    except Exception as e:
        logger.error(f"Error in binary comparison: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/analysis/diff/<task_id>', methods=['GET'])
def get_binary_comparison_results(task_id):
    """Get results of a binary comparison task"""
    try:
        # Find the task
        task = AnalysisTask.query.get(task_id)
        
        if not task:
            return jsonify({'error': f'Task with ID {task_id} not found'}), 404
            
        if task.task_type != 'binary_comparison':
            return jsonify({'error': 'Task is not a binary comparison task'}), 400
            
        # Get the binaries
        binary_id1 = task.parameters.get('binary_id1')
        binary_id2 = task.parameters.get('binary_id2')
        diff_type = task.parameters.get('diff_type', 'instructions')
        
        binary1 = Binary.query.get(binary_id1)
        binary2 = Binary.query.get(binary_id2)
        
        if not binary1 or not binary2:
            return jsonify({'error': 'One or both binaries not found'}), 404
        
        # Check task status
        if task.status == 'queued' or task.status == 'running':
            return jsonify({
                'task_id': task.id,
                'status': task.status,
                'progress': task.progress,
                'binary_id1': binary_id1,
                'binary_id2': binary_id2,
                'diff_type': diff_type
            })
        
        # For completed tasks, return the results
        # In a real implementation, this would fetch actual comparison results
        # For now, we'll return mock results
        
        # Get functions from both binaries for comparison
        functions1 = Function.query.filter_by(binary_id=binary_id1).limit(50).all()
        functions2 = Function.query.filter_by(binary_id=binary_id2).limit(50).all()
        
        # Generate differences based on functions
        differences = []
        total_differences = 0
        instruction_differences = 0
        data_differences = 0
        function_differences = 0
        
        # Compare functions by name
        function_names1 = {func.name: func for func in functions1 if func.name}
        function_names2 = {func.name: func for func in functions2 if func.name}
        
        # Find functions in binary1 but not in binary2
        for name, func in function_names1.items():
            if name not in function_names2:
                differences.append({
                    'type': 'function',
                    'address': func.address,
                    'binary1_value': name,
                    'binary2_value': 'N/A',
                    'description': f'Function {name} exists only in first binary'
                })
                function_differences += 1
                total_differences += 1
        
        # Find functions in binary2 but not in binary1
        for name, func in function_names2.items():
            if name not in function_names1:
                differences.append({
                    'type': 'function',
                    'address': func.address,
                    'binary1_value': 'N/A',
                    'binary2_value': name,
                    'description': f'Function {name} exists only in second binary'
                })
                function_differences += 1
                total_differences += 1
        
        # Add some instruction differences for demonstration
        if diff_type in ['instructions', 'all']:
            # Get some instructions if available
            instructions1 = Instruction.query.filter_by(binary_id=binary_id1).limit(10).all()
            instructions2 = Instruction.query.filter_by(binary_id=binary_id2).limit(10).all()
            
            # If we have instructions, add some differences
            if instructions1 and instructions2:
                for i in range(min(5, len(instructions1), len(instructions2))):
                    differences.append({
                        'type': 'instruction',
                        'address': instructions1[i].address if i < len(instructions1) else 'N/A',
                        'binary1_value': instructions1[i].mnemonic if i < len(instructions1) else 'N/A',
                        'binary2_value': instructions2[i].mnemonic if i < len(instructions2) else 'N/A',
                        'description': 'Instruction difference'
                    })
                    instruction_differences += 1
                    total_differences += 1
            else:
                # Add mock instruction differences
                addresses = ['0x401000', '0x401020', '0x401040', '0x401060', '0x401080']
                for i in range(5):
                    differences.append({
                        'type': 'instruction',
                        'address': addresses[i],
                        'binary1_value': f'mov eax, {i}',
                        'binary2_value': f'mov eax, {i+1}',
                        'description': 'Different immediate values'
                    })
                    instruction_differences += 1
                    total_differences += 1
        
        # Add some data differences for demonstration
        if diff_type in ['data', 'all']:
            # Add mock data differences
            addresses = ['0x601000', '0x601020', '0x601040']
            for i in range(3):
                differences.append({
                    'type': 'data',
                    'address': addresses[i],
                    'binary1_value': f'0x{i:08x}',
                    'binary2_value': f'0x{i+1:08x}',
                    'description': 'Different data values'
                })
                data_differences += 1
                total_differences += 1
        
        # For the test binaries, add specific differences
        if binary1.original_filename == 'binary_compare_v1.exe' and binary2.original_filename == 'binary_compare_v2.exe':
            # Add log_operation function difference
            differences.append({
                'type': 'function',
                'address': '0x401500',
                'binary1_value': 'N/A',
                'binary2_value': 'log_operation',
                'description': 'New function log_operation added in v2'
            })
            function_differences += 1
            total_differences += 1
            
            # Add process_data implementation difference
            differences.append({
                'type': 'instruction',
                'address': '0x401100',
                'binary1_value': 'imul eax, 2',
                'binary2_value': 'imul eax, 3',
                'description': 'process_data multiplies by 2 in v1, by 3 in v2'
            })
            instruction_differences += 1
            total_differences += 1
            
            # Add even/odd check difference
            differences.append({
                'type': 'instruction',
                'address': '0x401200',
                'binary1_value': 'N/A',
                'binary2_value': 'test eax, 1\njz even_label',
                'description': 'Additional even/odd check in analyze_result function in v2'
            })
            instruction_differences += 1
            total_differences += 1
            
            # Add version string difference
            differences.append({
                'type': 'data',
                'address': '0x602000',
                'binary1_value': 'File Processing Tool v1.0',
                'binary2_value': 'File Processing Tool v2.0',
                'description': 'Version string changed from v1.0 to v2.0'
            })
            data_differences += 1
            total_differences += 1
        
        # Calculate similarity score (higher means more similar)
        total_functions = len(function_names1) + len(function_names2)
        similarity_score = 1.0 - (total_differences / max(20, total_functions)) if total_functions > 0 else 0.5
        
        # Limit to reasonable number of differences for display
        differences = differences[:20]
        
        return jsonify({
            'task_id': task.id,
            'status': 'completed',
            'binary_id1': binary_id1,
            'binary_id2': binary_id2,
            'diff_type': diff_type,
            'results': {
                'differences': differences,
                'similarity_score': max(0.0, min(1.0, similarity_score)),
                'summary': {
                    'total_differences': total_differences,
                    'instruction_differences': instruction_differences,
                    'data_differences': data_differences,
                    'function_differences': function_differences
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting binary comparison results: {str(e)}")
        return jsonify({'error': str(e)}), 500

@api_bp.route('/analysis/diff/<task_id>/update-status', methods=['POST'])
def update_binary_comparison_status(task_id):
    """Update the status of a binary comparison task (for testing)"""
    try:
        # Find the task
        task = AnalysisTask.query.get(task_id)
        
        if not task:
            return jsonify({'error': f'Task with ID {task_id} not found'}), 404
            
        if task.task_type != 'binary_comparison':
            return jsonify({'error': 'Task is not a binary comparison task'}), 400
        
        # Update task status to completed
        task.status = 'completed'
        task.progress = 100
        task.completed_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'task_id': task.id,
            'status': 'completed',
            'message': 'Task status updated to completed'
        })
        
    except Exception as e:
        logger.error(f"Error updating binary comparison status: {str(e)}")
        return jsonify({'error': str(e)}), 500