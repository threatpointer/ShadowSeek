#!/usr/bin/env python3
"""
Import Existing Results Endpoint
Simple endpoint to import all existing ghidriff results into the database
"""

import os
import json
import glob
from pathlib import Path
from datetime import datetime
from flask import Blueprint, jsonify
from flask_app.models import db, AnalysisResult, AnalysisTask, Binary

import_bp = Blueprint('import', __name__)

@import_bp.route('/import-results', methods=['POST'])
def import_existing_results():
    """Import all existing ghidriff results into the database"""
    
    try:
        results_dir = Path("uploads/diff_results")
        imported_count = 0
        failed_count = 0
        results = []
        
        # Import directory-based results
        for task_dir in results_dir.glob("*"):
            if task_dir.is_dir() and task_dir.name != "ghidra_projects":
                try:
                    result = import_task_directory(task_dir)
                    if result:
                        imported_count += 1
                        results.append(f"✅ Imported: {task_dir.name}")
                    else:
                        results.append(f"⚠️  Skipped: {task_dir.name} (already exists)")
                except Exception as e:
                    failed_count += 1
                    results.append(f"❌ Failed: {task_dir.name} - {str(e)}")
        
        # Import standalone JSON files
        for json_file in results_dir.glob("*.json"):
            try:
                result = import_json_file(json_file)
                if result:
                    imported_count += 1
                    results.append(f"✅ Imported JSON: {json_file.name}")
                else:
                    results.append(f"⚠️  Skipped JSON: {json_file.name} (already exists)")
            except Exception as e:
                failed_count += 1
                results.append(f"❌ Failed JSON: {json_file.name} - {str(e)}")
        
        # Commit all changes
        db.session.commit()
        
        return jsonify({
            'success': True,
            'imported_count': imported_count,
            'failed_count': failed_count,
            'total_processed': imported_count + failed_count,
            'details': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def import_task_directory(task_dir: Path):
    """Import results from a task directory"""
    task_id = task_dir.name
    
    # Check if already imported
    existing = AnalysisResult.query.filter_by(task_id=task_id).first()
    if existing:
        return False
    
    # Look for result files
    json_files = list(task_dir.glob("*.json"))
    md_files = list(task_dir.glob("*.md"))
    log_files = list(task_dir.glob("*.log"))
    
    # Read ghidriff log to extract binary info
    binary_info = extract_binary_info_from_log(task_dir)
    if not binary_info:
        # Create a basic entry even without binary info
        binary_info = {'binary_id1': 'unknown', 'binary_id2': 'unknown'}
    
    # Build structured result
    structured_result = {
        'engine': 'SimpleDiff',
        'binary1': binary_info.get('binary1', 'Unknown'),
        'binary2': binary_info.get('binary2', 'Unknown'),
        'summary': {},
        'markdown': '',
        'json_data': {},
        'output_files': [],
        'stdout': '',
        'execution_time': 0,
        'task_directory': str(task_dir.name)
    }
    
    # Read JSON results
    if json_files:
        json_file = json_files[0]
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                json_data = json.load(f)
                structured_result['json_data'] = json_data
                structured_result['summary'] = extract_summary_from_json(json_data)
        except Exception as e:
            print(f"Error reading JSON {json_file}: {e}")
    
    # Read markdown results
    if md_files:
        md_file = md_files[0]
        try:
            with open(md_file, 'r', encoding='utf-8') as f:
                structured_result['markdown'] = f.read()
        except Exception as e:
            print(f"Error reading markdown {md_file}: {e}")
    
    # Read log files
    if log_files:
        log_file = log_files[0]
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                log_content = f.read()
                structured_result['stdout'] = log_content[-10000:]  # Last 10KB of logs
        except Exception as e:
            print(f"Error reading log {log_file}: {e}")
    
    # List output files
    all_files = list(task_dir.glob("*"))
    structured_result['output_files'] = [f.name for f in all_files]
    
    # Get or create task
    task = AnalysisTask.query.filter_by(id=task_id).first()
    if not task:
        # Create a placeholder task
        task = AnalysisTask(
            id=task_id,
            task_type='binary_comparison',
            status='completed',
            priority=1,
            progress=100,
            binary_id=binary_info.get('binary_id1', 'unknown'),
            parameters={
                'binary_id1': binary_info.get('binary_id1', 'unknown'),
                'binary_id2': binary_info.get('binary_id2', 'unknown'),
                'diff_type': 'simple'
            },
            created_at=datetime.now(),
            started_at=datetime.now(),
            completed_at=datetime.now()
        )
        db.session.add(task)
        db.session.flush()
    
    # Create AnalysisResult
    analysis_result = AnalysisResult(
        binary_id=binary_info.get('binary_id1', 'unknown'),
        task_id=task_id,
        analysis_type='binary_diff',
        results=json.dumps(structured_result, indent=2),
        meta_data={
            'binary_id2': binary_info.get('binary_id2', 'unknown'),
            'results_dir': str(task_dir),
            'engine_type': 'SimpleDiff',
            'diff_type': 'simple',
            'imported': True,
            'import_timestamp': datetime.now().isoformat()
        },
        created_at=datetime.now()
    )
    
    db.session.add(analysis_result)
    return True

def import_json_file(json_file: Path):
    """Import results from a standalone JSON file"""
    # Extract task ID from filename
    task_id = json_file.stem.replace('_diff', '')
    
    # Check if already imported
    existing = AnalysisResult.query.filter_by(task_id=task_id).first()
    if existing:
        return False
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        return False
    
    # Build structured result from JSON
    structured_result = {
        'engine': 'SimpleDiff',
        'binary1': 'Unknown',
        'binary2': 'Unknown', 
        'summary': extract_summary_from_json(json_data),
        'markdown': '',
        'json_data': json_data,
        'output_files': [json_file.name],
        'stdout': '',
        'execution_time': 0,
        'source_file': str(json_file.name)
    }
    
    # Create placeholder task
    task = AnalysisTask(
        id=task_id,
        task_type='binary_comparison',
        status='completed',
        priority=1,
        progress=100,
        binary_id='unknown',
        parameters={'diff_type': 'simple'},
        created_at=datetime.now(),
        started_at=datetime.now(),
        completed_at=datetime.now()
    )
    db.session.add(task)
    db.session.flush()
    
    # Create AnalysisResult
    analysis_result = AnalysisResult(
        binary_id='unknown',
        task_id=task_id,
        analysis_type='binary_diff',
        results=json.dumps(structured_result, indent=2),
        meta_data={
            'source_file': str(json_file),
            'engine_type': 'SimpleDiff',
            'diff_type': 'simple',
            'imported': True,
            'import_timestamp': datetime.now().isoformat()
        },
        created_at=datetime.now()
    )
    
    db.session.add(analysis_result)
    return True

def extract_binary_info_from_log(task_dir: Path):
    """Extract binary information from ghidriff log files"""
    log_files = list(task_dir.glob("*.log"))
    if not log_files:
        return None
    
    try:
        with open(log_files[0], 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Look for binary paths in log
        lines = content.split('\n')
        binary1_path = None
        binary2_path = None
        
        for line in lines:
            if 'Binary 1:' in line:
                binary1_path = line.split('Binary 1:')[-1].strip()
            elif 'Binary 2:' in line:
                binary2_path = line.split('Binary 2:')[-1].strip()
                
        if not binary1_path or not binary2_path:
            # Try alternate patterns
            for line in lines:
                if 'uploads\\' in line and '.exe' in line:
                    parts = line.split()
                    for part in parts:
                        if 'uploads\\' in part and '.exe' in part:
                            if not binary1_path:
                                binary1_path = part
                            elif not binary2_path and part != binary1_path:
                                binary2_path = part
                                break
        
        result = {}
        
        # Extract binary IDs from paths
        if binary1_path:
            binary_id = extract_binary_id_from_path(binary1_path)
            if binary_id:
                result['binary_id1'] = binary_id
                binary = Binary.query.filter_by(id=binary_id).first()
                if binary:
                    result['binary1'] = binary.original_filename
        
        if binary2_path:
            binary_id = extract_binary_id_from_path(binary2_path)
            if binary_id:
                result['binary_id2'] = binary_id
                binary = Binary.query.filter_by(id=binary_id).first()
                if binary:
                    result['binary2'] = binary.original_filename
        
        return result if result else None
        
    except Exception as e:
        print(f"Error reading log file: {e}")
        return None

def extract_binary_id_from_path(path: str):
    """Extract binary ID from file path"""
    if 'uploads\\' in path or 'uploads/' in path:
        filename = Path(path).name
        if '_' in filename:
            return filename.split('_')[0]
    return None

def extract_summary_from_json(json_data):
    """Extract summary information from ghidriff JSON output"""
    summary = {
        'analysis_completed': True,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    try:
        if isinstance(json_data, dict):
            # Look for function counts
            if 'total_funcs_len' in json_data:
                summary['total_functions'] = json_data['total_funcs_len']
            if 'matched_funcs_len' in json_data:
                summary['matched_functions'] = json_data['matched_funcs_len']
            if 'added_funcs_len' in json_data:
                summary['added_functions'] = json_data['added_funcs_len']
            if 'deleted_funcs_len' in json_data:
                summary['deleted_functions'] = json_data['deleted_funcs_len']
            if 'modified_funcs_len' in json_data:
                summary['modified_functions'] = json_data['modified_funcs_len']
            
            # Look for similarity
            if 'func_match_overall_percent' in json_data:
                summary['similarity_percent'] = json_data['func_match_overall_percent']
            
            # Look for execution time
            if 'diff_time' in json_data:
                summary['execution_time_seconds'] = json_data['diff_time']
        
        if len(summary) == 2:  # Only timestamp and analysis_completed
            summary['notes'] = 'Analysis completed - detailed metrics not available'
        
    except Exception as e:
        summary['extraction_error'] = str(e)
    
    return summary 