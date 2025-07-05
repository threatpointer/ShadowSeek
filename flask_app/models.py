"""
Database Models for ShadowSeek - Advanced Binary Security Analysis Platform
"""

import uuid
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Text, Integer, String, DateTime, Boolean, JSON

from flask_app import db


class Binary(db.Model):
    """Model for uploaded binary files"""
    __tablename__ = 'binaries'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = db.Column(String(255), nullable=False)
    original_filename = db.Column(String(255), nullable=False)
    file_path = db.Column(String(500), nullable=False)
    file_size = db.Column(Integer, nullable=False)
    file_hash = db.Column(String(64), nullable=True)  # SHA-256 hash
    mime_type = db.Column(String(100), nullable=True)
    architecture = db.Column(String(50), nullable=True)
    upload_time = db.Column(DateTime, default=datetime.utcnow)
    analysis_status = db.Column(String(50), default='pending')  # pending, analyzing, completed, failed
    meta_data = db.Column(JSON, nullable=True)
    
    # Relationships
    analysis_tasks = db.relationship('AnalysisTask', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    analysis_results = db.relationship('AnalysisResult', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    functions = db.relationship('Function', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    imports = db.relationship('Import', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    exports = db.relationship('Export', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    strings = db.relationship('BinaryString', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    memory_regions = db.relationship('MemoryRegion', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    symbols = db.relationship('Symbol', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    data_types = db.relationship('DataType', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    instructions = db.relationship('Instruction', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    cross_references = db.relationship('CrossReference', backref='binary', lazy='dynamic', cascade='all, delete-orphan')
    comprehensive_analysis = db.relationship('ComprehensiveAnalysis', backref='binary', uselist=False, cascade='all, delete-orphan')
    
    # Security analysis relationships (note: VulnerabilityReport already has backref='vulnerability_reports') 
    unified_findings = db.relationship('UnifiedSecurityFinding', backref='binary_ref', lazy='dynamic', cascade='all, delete-orphan')
    
    # Indexes for common queries
    __table_args__ = (
        db.Index('idx_binary_status', 'analysis_status'),
        db.Index('idx_binary_upload', 'upload_time'),
    )
    
    def __repr__(self):
        return f'<Binary {self.original_filename}>'
    
    def update_analysis_status(self):
        """
        Update binary analysis status based on completion percentages
        
        Status progression:
        - Pending: Initial upload
        - Analyzing: Analysis in progress
        - Decompiled: 80%+ functions decompiled
        - Analyzed: Security analysis complete
        - Completed: All analysis including fuzzing ready
        """
        try:
            # Get function statistics
            total_functions = Function.query.filter_by(
                binary_id=self.id,
                is_external=False
            ).count()
            
            if total_functions == 0:
                # No functions found - check if this is a processing issue
                if self.analysis_status == 'processed':
                    # Analysis completed but found no functions - likely not a valid executable
                    new_status = 'Failed'
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.warning(f"Binary {self.original_filename} analysis completed but found 0 functions - marking as failed")
                    
                    if new_status != self.analysis_status:
                        old_status = self.analysis_status
                        self.analysis_status = new_status
                        logger.info(f"Binary {self.original_filename} status updated: {old_status} -> {new_status} (0 functions found)")
                        return new_status
                
                # For other statuses with 0 functions, keep current status
                return self.analysis_status
            
            decompiled_functions = Function.query.filter_by(
                binary_id=self.id,
                is_external=False,
                is_decompiled=True
            ).count()
            
            ai_analyzed_functions = Function.query.filter_by(
                binary_id=self.id,
                is_external=False,
                ai_analyzed=True
            ).count()
            
            # Check security analysis
            from flask_app.models import UnifiedSecurityFinding
            security_findings = UnifiedSecurityFinding.query.filter_by(binary_id=self.id).count()
            
            # Check fuzzing harnesses
            from flask_app.models import FuzzingHarness
            fuzzing_harnesses = FuzzingHarness.query.filter_by(binary_id=self.id).count()
            
            # Calculate percentages
            decompile_percentage = (decompiled_functions / total_functions) * 100
            ai_percentage = (ai_analyzed_functions / total_functions) * 100
            
            # Determine new status based on completion
            new_status = self.analysis_status
            
            if decompile_percentage >= 80:
                if security_findings > 0 and fuzzing_harnesses > 0:
                    new_status = 'Completed'
                elif security_findings > 0:
                    new_status = 'Analyzed'  
                else:
                    new_status = 'Decompiled'
            elif decompile_percentage > 0 or self.analysis_status in ['Analyzing', 'analyzing']:
                new_status = 'Analyzing'
            else:
                new_status = 'Pending'
            
            # Only update if status actually changed
            if new_status != self.analysis_status:
                old_status = self.analysis_status
                self.analysis_status = new_status
                
                # Log the status change
                import logging
                logger = logging.getLogger(__name__)
                logger.info(f"Binary {self.original_filename} status updated: {old_status} -> {new_status} "
                          f"(decompiled: {decompile_percentage:.1f}%, AI: {ai_percentage:.1f}%, "
                          f"security: {security_findings}, fuzzing: {fuzzing_harnesses})")
                
                return new_status
            
            return self.analysis_status
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error updating binary status for {self.id}: {e}")
            return self.analysis_status
    
    def get_analysis_statistics(self):
        """Get detailed analysis statistics for this binary"""
        try:
            total_functions = Function.query.filter_by(
                binary_id=self.id,
                is_external=False
            ).count()
            
            if total_functions == 0:
                return {
                    'total_functions': 0,
                    'decompiled_functions': 0,
                    'ai_analyzed_functions': 0,
                    'decompile_percentage': 0,
                    'ai_percentage': 0,
                    'security_findings': 0,
                    'fuzzing_harnesses': 0
                }
            
            decompiled_functions = Function.query.filter_by(
                binary_id=self.id,
                is_external=False,
                is_decompiled=True
            ).count()
            
            ai_analyzed_functions = Function.query.filter_by(
                binary_id=self.id,
                is_external=False,
                ai_analyzed=True
            ).count()
            
            # Check security analysis
            from flask_app.models import UnifiedSecurityFinding
            security_findings = UnifiedSecurityFinding.query.filter_by(binary_id=self.id).count()
            
            # Check fuzzing harnesses
            from flask_app.models import FuzzingHarness
            fuzzing_harnesses = FuzzingHarness.query.filter_by(binary_id=self.id).count()
            
            return {
                'total_functions': total_functions,
                'decompiled_functions': decompiled_functions,
                'ai_analyzed_functions': ai_analyzed_functions,
                'decompile_percentage': (decompiled_functions / total_functions) * 100,
                'ai_percentage': (ai_analyzed_functions / total_functions) * 100,
                'security_findings': security_findings,
                'fuzzing_harnesses': fuzzing_harnesses
            }
            
        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error getting binary statistics for {self.id}: {e}")
            return {}
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_path': self.file_path,
            'file_size': self.file_size,
            'file_hash': self.file_hash,
            'mime_type': self.mime_type,
            'architecture': self.architecture,
            'upload_time': self.upload_time.isoformat() if self.upload_time else None,
            'analysis_status': self.analysis_status,
            'meta_data': self.meta_data
        }


class AnalysisTask(db.Model):
    """Model for analysis tasks"""
    __tablename__ = 'analysis_tasks'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    task_type = db.Column(String(100), nullable=False)  # decompileFunction, getCFG, etc.
    status = db.Column(String(50), default='queued')  # queued, running, completed, failed
    priority = db.Column(Integer, default=5)  # 1-10, lower = higher priority
    created_at = db.Column(DateTime, default=datetime.utcnow)
    started_at = db.Column(DateTime, nullable=True)
    completed_at = db.Column(DateTime, nullable=True)
    parameters = db.Column(JSON, nullable=True)
    progress = db.Column(Integer, default=0)  # 0-100
    error_message = db.Column(Text, nullable=True)
    
    def __repr__(self):
        return f'<AnalysisTask {self.task_type} for {self.binary_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'task_type': self.task_type,
            'status': self.status,
            'priority': self.priority,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'parameters': self.parameters,
            'progress': self.progress,
            'error_message': self.error_message
        }


class AnalysisResult(db.Model):
    """Model for storing analysis results"""
    __tablename__ = 'analysis_results'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    task_id = db.Column(String(36), db.ForeignKey('analysis_tasks.id'), nullable=True)
    analysis_type = db.Column(String(100), nullable=False)
    function_address = db.Column(String(20), nullable=True)  # For function-specific results
    created_at = db.Column(DateTime, default=datetime.utcnow)
    results = db.Column(JSON, nullable=False)  # Main results data
    meta_data = db.Column(JSON, nullable=True)  # Additional metadata
    
    # Indexes for common queries
    __table_args__ = (
        db.Index('idx_binary_analysis', 'binary_id', 'analysis_type'),
        db.Index('idx_function_address', 'binary_id', 'function_address'),
    )
    
    def __repr__(self):
        return f'<AnalysisResult {self.analysis_type} for {self.binary_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'task_id': self.task_id,
            'analysis_type': self.analysis_type,
            'function_address': self.function_address,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'results': self.results,
            'metadata': self.meta_data
        }


class Function(db.Model):
    """Model for functions discovered in binaries"""
    __tablename__ = 'functions'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    address = db.Column(String(20), nullable=False)  # Hex address
    name = db.Column(String(255), nullable=True)
    original_name = db.Column(String(255), nullable=True)
    size = db.Column(Integer, nullable=True)
    parameter_count = db.Column(Integer, nullable=True)
    return_type = db.Column(String(100), nullable=True)
    calling_convention = db.Column(String(50), nullable=True)
    is_analyzed = db.Column(Boolean, default=False)
    is_decompiled = db.Column(Boolean, default=False)
    has_cfg = db.Column(Boolean, default=False)
    is_thunk = db.Column(Boolean, default=False)
    is_external = db.Column(Boolean, default=False)
    has_no_return = db.Column(Boolean, default=False)
    has_var_args = db.Column(Boolean, default=False)
    stack_frame_size = db.Column(Integer, nullable=True)
    stack_purge_size = db.Column(Integer, nullable=True)
    signature = db.Column(String(500), nullable=True)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    meta_data = db.Column(JSON, nullable=True)  # Additional metadata
    
    # Feature Expansion: Function-Level Decompilation + AI
    decompiled_code = db.Column(Text, nullable=True)  # Decompiled C code
    ai_summary = db.Column(Text, nullable=True)  # AI-generated explanation
    risk_score = db.Column(Integer, nullable=True)  # Risk score 0-100
    is_decompiled = db.Column(Boolean, default=False)  # Decompilation status
    ai_analyzed = db.Column(Boolean, default=False)  # AI analysis status
    
    # Relationships
    parameters = db.relationship('FunctionParameter', backref='function', lazy='dynamic', cascade='all, delete-orphan')
    local_variables = db.relationship('LocalVariable', backref='function', lazy='dynamic', cascade='all, delete-orphan')
    calls = db.relationship('FunctionCall', backref='source_function', 
                          foreign_keys='FunctionCall.source_function_id',
                          lazy='dynamic', cascade='all, delete-orphan')
    
    # Indexes
    __table_args__ = (
        db.Index('idx_binary_functions', 'binary_id'),
        db.Index('idx_func_addr', 'binary_id', 'address'),
        db.UniqueConstraint('binary_id', 'address', name='unique_binary_function'),
    )
    
    def __repr__(self):
        return f'<Function {self.name or self.address} in {self.binary_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'address': self.address,
            'name': self.name,
            'original_name': self.original_name,
            'size': self.size,
            'parameter_count': self.parameter_count,
            'return_type': self.return_type,
            'calling_convention': self.calling_convention,
            'is_analyzed': self.is_analyzed,
            'is_decompiled': self.is_decompiled,
            'has_cfg': self.has_cfg,
            'is_thunk': self.is_thunk,
            'is_external': self.is_external,
            'has_no_return': self.has_no_return,
            'has_var_args': self.has_var_args,
            'stack_frame_size': self.stack_frame_size,
            'stack_purge_size': self.stack_purge_size,
            'signature': self.signature,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'metadata': self.meta_data,
            'decompiled_code': self.decompiled_code,
            'ai_summary': self.ai_summary,
            'risk_score': self.risk_score,
            'is_decompiled': self.is_decompiled,
            'ai_analyzed': self.ai_analyzed
        }


class FunctionParameter(db.Model):
    """Model for function parameters"""
    __tablename__ = 'function_parameters'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    function_id = db.Column(String(36), db.ForeignKey('functions.id'), nullable=False)
    name = db.Column(String(100), nullable=True)
    data_type = db.Column(String(100), nullable=True)
    size = db.Column(Integer, nullable=True)
    ordinal = db.Column(Integer, nullable=True)
    
    def __repr__(self):
        return f'<Parameter {self.name} of {self.function_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'function_id': self.function_id,
            'name': self.name,
            'data_type': self.data_type,
            'size': self.size,
            'ordinal': self.ordinal
        }


class LocalVariable(db.Model):
    """Model for function local variables"""
    __tablename__ = 'local_variables'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    function_id = db.Column(String(36), db.ForeignKey('functions.id'), nullable=False)
    name = db.Column(String(100), nullable=True)
    data_type = db.Column(String(100), nullable=True)
    size = db.Column(Integer, nullable=True)
    storage = db.Column(String(100), nullable=True)
    
    def __repr__(self):
        return f'<LocalVar {self.name} of {self.function_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'function_id': self.function_id,
            'name': self.name,
            'data_type': self.data_type,
            'size': self.size,
            'storage': self.storage
        }


class FunctionCall(db.Model):
    """Model for function calls (call graph)"""
    __tablename__ = 'function_calls'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    source_function_id = db.Column(String(36), db.ForeignKey('functions.id'), nullable=False)
    target_function_id = db.Column(String(36), db.ForeignKey('functions.id'), nullable=True)
    source_address = db.Column(String(20), nullable=False)
    target_address = db.Column(String(20), nullable=False)
    call_type = db.Column(String(50), nullable=True)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_call_source', 'source_function_id'),
        db.Index('idx_call_target', 'target_function_id'),
        db.Index('idx_call_binary', 'binary_id'),
    )
    
    def __repr__(self):
        return f'<Call from {self.source_address} to {self.target_address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'source_function_id': self.source_function_id,
            'target_function_id': self.target_function_id,
            'source_address': self.source_address,
            'target_address': self.target_address,
            'call_type': self.call_type
        }


class Import(db.Model):
    """Model for imported functions"""
    __tablename__ = 'imports'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    name = db.Column(String(255), nullable=False)
    library = db.Column(String(255), nullable=True)
    address = db.Column(String(20), nullable=True)
    namespace = db.Column(String(255), nullable=True)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_import_binary', 'binary_id'),
        db.Index('idx_import_name', 'name'),
    )
    
    def __repr__(self):
        return f'<Import {self.name} from {self.library}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'name': self.name,
            'library': self.library,
            'address': self.address,
            'namespace': self.namespace
        }


class Export(db.Model):
    """Model for exported functions"""
    __tablename__ = 'exports'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    name = db.Column(String(255), nullable=False)
    address = db.Column(String(20), nullable=True)
    namespace = db.Column(String(255), nullable=True)
    ordinal = db.Column(Integer, nullable=True)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_export_binary', 'binary_id'),
        db.Index('idx_export_name', 'name'),
    )
    
    def __repr__(self):
        return f'<Export {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'name': self.name,
            'address': self.address,
            'namespace': self.namespace,
            'ordinal': self.ordinal
        }


class BinaryString(db.Model):
    """Model for strings found in binaries"""
    __tablename__ = 'strings'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    address = db.Column(String(20), nullable=False)
    value = db.Column(Text, nullable=False)
    length = db.Column(Integer, nullable=True)
    string_type = db.Column(String(50), nullable=True)  # ASCII, Unicode, etc.
    
    # Indexes
    __table_args__ = (
        db.Index('idx_string_binary', 'binary_id'),
        db.Index('idx_string_addr', 'binary_id', 'address'),
    )
    
    def __repr__(self):
        return f'<String at {self.address}: {self.value[:20]}{"..." if len(self.value) > 20 else ""}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'address': self.address,
            'value': self.value,
            'length': self.length,
            'string_type': self.string_type
        }


class MemoryRegion(db.Model):
    """Model for memory regions/segments"""
    __tablename__ = 'memory_regions'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    name = db.Column(String(100), nullable=False)
    start_address = db.Column(String(20), nullable=False)
    end_address = db.Column(String(20), nullable=False)
    size = db.Column(Integer, nullable=False)
    is_read = db.Column(Boolean, default=True)
    is_write = db.Column(Boolean, default=False)
    is_execute = db.Column(Boolean, default=False)
    is_volatile = db.Column(Boolean, default=False)
    is_initialized = db.Column(Boolean, default=True)
    is_mapped = db.Column(Boolean, default=False)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_memory_binary', 'binary_id'),
    )
    
    def __repr__(self):
        return f'<MemoryRegion {self.name} at {self.start_address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'name': self.name,
            'start_address': self.start_address,
            'end_address': self.end_address,
            'size': self.size,
            'permissions': {
                'read': self.is_read,
                'write': self.is_write,
                'execute': self.is_execute,
                'volatile': self.is_volatile
            },
            'is_initialized': self.is_initialized,
            'is_mapped': self.is_mapped
        }


class Symbol(db.Model):
    """Model for symbols"""
    __tablename__ = 'symbols'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    name = db.Column(String(255), nullable=False)
    address = db.Column(String(20), nullable=False)
    symbol_type = db.Column(String(50), nullable=True)
    namespace = db.Column(String(255), nullable=True)
    is_primary = db.Column(Boolean, default=False)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_symbol_binary', 'binary_id'),
        db.Index('idx_symbol_name', 'name'),
    )
    
    def __repr__(self):
        return f'<Symbol {self.name} at {self.address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'name': self.name,
            'address': self.address,
            'symbol_type': self.symbol_type,
            'namespace': self.namespace,
            'is_primary': self.is_primary
        }


class DataType(db.Model):
    """Model for custom data types"""
    __tablename__ = 'data_types'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    name = db.Column(String(255), nullable=False)
    category = db.Column(String(255), nullable=True)
    size = db.Column(Integer, nullable=True)
    type_class = db.Column(String(100), nullable=True)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_datatype_binary', 'binary_id'),
        db.Index('idx_datatype_name', 'name'),
    )
    
    def __repr__(self):
        return f'<DataType {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'name': self.name,
            'category': self.category,
            'size': self.size,
            'type_class': self.type_class
        }


class Instruction(db.Model):
    """Model for storing individual instructions"""
    __tablename__ = 'instructions'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    address = db.Column(String(20), nullable=False)
    mnemonic = db.Column(String(50), nullable=False)
    operands = db.Column(JSON, nullable=True)  # List of operands
    bytes_data = db.Column(JSON, nullable=True)  # Raw bytes
    length = db.Column(Integer, nullable=True)
    fall_through = db.Column(String(20), nullable=True)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_instruction_binary', 'binary_id'),
        db.Index('idx_instruction_addr', 'binary_id', 'address'),
    )
    
    def __repr__(self):
        return f'<Instruction {self.mnemonic} at {self.address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'address': self.address,
            'mnemonic': self.mnemonic,
            'operands': self.operands,
            'bytes': self.bytes_data,
            'length': self.length,
            'fall_through': self.fall_through
        }


class CrossReference(db.Model):
    """Model for storing cross-references (XREFs)"""
    __tablename__ = 'cross_references'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    from_address = db.Column(String(20), nullable=False)
    to_address = db.Column(String(20), nullable=False)
    reference_type = db.Column(String(50), nullable=False)
    operand_index = db.Column(Integer, nullable=True)
    is_primary = db.Column(Boolean, default=False)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_xref_binary', 'binary_id'),
        db.Index('idx_xref_from', 'binary_id', 'from_address'),
        db.Index('idx_xref_to', 'binary_id', 'to_address'),
    )
    
    def __repr__(self):
        return f'<XRef {self.from_address} -> {self.to_address}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'from_address': self.from_address,
            'to_address': self.to_address,
            'reference_type': self.reference_type,
            'operand_index': self.operand_index,
            'is_primary': self.is_primary
        }


class ComprehensiveAnalysis(db.Model):
    """Model for storing comprehensive analysis results"""
    __tablename__ = 'comprehensive_analyses'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    analysis_version = db.Column(String(20), default='1.0')
    created_at = db.Column(DateTime, default=datetime.utcnow)
    
    # Metadata
    program_metadata = db.Column(JSON, nullable=True)
    statistics = db.Column(JSON, nullable=True)
    
    # Status flags
    functions_extracted = db.Column(Boolean, default=False)
    instructions_extracted = db.Column(Boolean, default=False)
    strings_extracted = db.Column(Boolean, default=False)
    symbols_extracted = db.Column(Boolean, default=False)
    xrefs_extracted = db.Column(Boolean, default=False)
    imports_extracted = db.Column(Boolean, default=False)
    exports_extracted = db.Column(Boolean, default=False)
    memory_blocks_extracted = db.Column(Boolean, default=False)
    data_types_extracted = db.Column(Boolean, default=False)
    
    # Analysis completion status
    is_complete = db.Column(Boolean, default=False)
    error_message = db.Column(Text, nullable=True)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_comprehensive_binary', 'binary_id'),
        db.UniqueConstraint('binary_id', name='unique_comprehensive_analysis'),
    )
    
    def __repr__(self):
        return f'<ComprehensiveAnalysis for {self.binary_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'analysis_version': self.analysis_version,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'program_metadata': self.program_metadata,
            'statistics': self.statistics,
            'status': {
                'functions_extracted': self.functions_extracted,
                'instructions_extracted': self.instructions_extracted,
                'strings_extracted': self.strings_extracted,
                'symbols_extracted': self.symbols_extracted,
                'xrefs_extracted': self.xrefs_extracted,
                'imports_extracted': self.imports_extracted,
                'exports_extracted': self.exports_extracted,
                'memory_blocks_extracted': self.memory_blocks_extracted,
                'data_types_extracted': self.data_types_extracted,
                'is_complete': self.is_complete
            },
            'error_message': self.error_message
        }


class Configuration(db.Model):
    """Model for storing application configuration"""
    __tablename__ = 'configurations'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key = db.Column(String(100), nullable=False, unique=True)
    value = db.Column(Text, nullable=True)
    value_type = db.Column(String(20), default='string')  # string, int, bool, json
    description = db.Column(Text, nullable=True)
    is_public = db.Column(Boolean, default=False)  # Can be exposed to frontend
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_config_key', 'key'),
    )
    
    def __repr__(self):
        return f'<Configuration {self.key}>'
    
    def get_value(self):
        """Get typed value based on value_type"""
        if self.value_type == 'int':
            return int(self.value) if self.value else 0
        elif self.value_type == 'bool':
            return self.value.lower() in ('true', '1', 'yes') if self.value else False
        elif self.value_type == 'json':
            import json
            try:
                return json.loads(self.value) if self.value else {}
            except:
                return {}
        else:
            return self.value
    
    def set_value(self, value):
        """Set value with proper type conversion"""
        if self.value_type == 'json':
            import json
            self.value = json.dumps(value)
        else:
            self.value = str(value)
    
    def to_dict(self):
        return {
            'id': self.id,
            'key': self.key,
            'value': self.get_value(),
            'value_type': self.value_type,
            'description': self.description,
            'is_public': self.is_public,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class Vulnerability(db.Model):
    """Model for storing individual vulnerabilities found in binaries"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    function_id = db.Column(String(36), db.ForeignKey('functions.id'), nullable=True)
    
    # Vulnerability classification
    vulnerability_type = db.Column(String(100), nullable=False)  # buffer_overflow, format_string, etc.
    severity = db.Column(String(20), nullable=False)  # critical, high, medium, low, info
    title = db.Column(String(500), nullable=False)
    description = db.Column(Text, nullable=False)
    
    # Location information
    address = db.Column(String(20), nullable=True)  # Memory address where vulnerability was found
    file_offset = db.Column(Integer, nullable=True)  # File offset
    line_number = db.Column(Integer, nullable=True)  # Line in decompiled code
    
    # Classification and scoring
    cwe_id = db.Column(String(20), nullable=True)  # CWE identifier (e.g., CWE-120)
    cve_id = db.Column(String(20), nullable=True)  # CVE identifier if applicable
    cvss_score = db.Column(db.Float, nullable=True)  # CVSS score 0.0-10.0
    risk_score = db.Column(Integer, nullable=False, default=0)  # Internal risk score 0-100
    
    # Technical details
    affected_code = db.Column(Text, nullable=True)  # Code snippet containing vulnerability
    proof_of_concept = db.Column(Text, nullable=True)  # PoC code or explanation
    remediation = db.Column(Text, nullable=True)  # How to fix the vulnerability
    references = db.Column(JSON, nullable=True)  # List of reference URLs
    
    # Analysis metadata
    detection_method = db.Column(String(100), nullable=True)  # static_analysis, ai_analysis, pattern_match
    confidence = db.Column(Integer, nullable=False, default=50)  # Confidence level 0-100
    false_positive_risk = db.Column(String(20), nullable=False, default='medium')  # low, medium, high
    
    # Timestamps
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    binary_relationship = db.relationship('Binary', backref='vulnerabilities')
    function_relationship = db.relationship('Function', backref='vulnerabilities')
    
    # Indexes
    __table_args__ = (
        db.Index('idx_vuln_binary', 'binary_id'),
        db.Index('idx_vuln_function', 'function_id'),
        db.Index('idx_vuln_type', 'vulnerability_type'),
        db.Index('idx_vuln_severity', 'severity'),
        db.Index('idx_vuln_score', 'risk_score'),
    )
    
    def __repr__(self):
        return f'<Vulnerability {self.vulnerability_type} in {self.binary_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'function_id': self.function_id,
            'type': self.vulnerability_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'location': {
                'address': self.address,
                'file_offset': self.file_offset,
                'line_number': self.line_number
            },
            'cwe_id': self.cwe_id,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'risk_score': self.risk_score,
            'affected_code': self.affected_code,
            'proof_of_concept': self.proof_of_concept,
            'remediation': self.remediation,
            'references': self.references,
            'detection_method': self.detection_method,
            'confidence': self.confidence,
            'false_positive_risk': self.false_positive_risk,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class VulnerabilityPattern(db.Model):
    """Model for storing vulnerability detection patterns"""
    __tablename__ = 'vulnerability_patterns'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(String(200), nullable=False)
    vulnerability_type = db.Column(String(100), nullable=False)
    severity = db.Column(String(20), nullable=False)
    
    # Pattern matching
    pattern_type = db.Column(String(50), nullable=False)  # regex, function_call, ai_analysis
    pattern_data = db.Column(JSON, nullable=False)  # Pattern-specific data
    
    # Classification
    cwe_id = db.Column(String(20), nullable=True)
    default_risk_score = db.Column(Integer, nullable=False, default=50)
    confidence_modifier = db.Column(Integer, nullable=False, default=0)  # -50 to +50
    
    # Metadata
    description = db.Column(Text, nullable=True)
    remediation_template = db.Column(Text, nullable=True)
    references = db.Column(JSON, nullable=True)
    
    # Status
    is_active = db.Column(Boolean, default=True)
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_pattern_type', 'vulnerability_type'),
        db.Index('idx_pattern_active', 'is_active'),
    )
    
    def __repr__(self):
        return f'<VulnerabilityPattern {self.name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'pattern_type': self.pattern_type,
            'pattern_data': self.pattern_data,
            'cwe_id': self.cwe_id,
            'default_risk_score': self.default_risk_score,
            'confidence_modifier': self.confidence_modifier,
            'description': self.description,
            'remediation_template': self.remediation_template,
            'references': self.references,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class VulnerabilityReport(db.Model):
    """Model for storing vulnerability scan reports"""
    __tablename__ = 'vulnerability_reports'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    
    # Scan configuration
    scan_types = db.Column(JSON, nullable=False)  # List of scan types performed
    scan_parameters = db.Column(JSON, nullable=True)  # Additional scan parameters
    
    # Results summary
    total_vulnerabilities = db.Column(Integer, nullable=False, default=0)
    critical_count = db.Column(Integer, nullable=False, default=0)
    high_count = db.Column(Integer, nullable=False, default=0)
    medium_count = db.Column(Integer, nullable=False, default=0)
    low_count = db.Column(Integer, nullable=False, default=0)
    info_count = db.Column(Integer, nullable=False, default=0)
    
    # Risk assessment
    overall_risk_score = db.Column(Integer, nullable=False, default=0)  # 0-100
    risk_category = db.Column(String(20), nullable=False, default='low')  # low, medium, high, critical
    
    # Scan metadata
    scan_duration = db.Column(Integer, nullable=True)  # Duration in seconds
    functions_scanned = db.Column(Integer, nullable=True)
    patterns_applied = db.Column(Integer, nullable=True)
    
    # Analysis results
    executive_summary = db.Column(Text, nullable=True)
    detailed_analysis = db.Column(Text, nullable=True)
    recommendations = db.Column(Text, nullable=True)
    
    # Timestamps
    created_at = db.Column(DateTime, default=datetime.utcnow)
    completed_at = db.Column(DateTime, nullable=True)
    
    # Relationships
    binary_relationship = db.relationship('Binary', backref='vulnerability_reports')
    
    # Indexes
    __table_args__ = (
        db.Index('idx_vuln_report_binary', 'binary_id'),
        db.Index('idx_vuln_report_created', 'created_at'),
    )
    
    def __repr__(self):
        return f'<VulnerabilityReport for {self.binary_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'scan_types': self.scan_types,
            'scan_parameters': self.scan_parameters,
            'summary': {
                'total_vulnerabilities': self.total_vulnerabilities,
                'critical_count': self.critical_count,
                'high_count': self.high_count,
                'medium_count': self.medium_count,
                'low_count': self.low_count,
                'info_count': self.info_count
            },
            'risk_assessment': {
                'overall_risk_score': self.overall_risk_score,
                'risk_category': self.risk_category
            },
            'scan_metadata': {
                'scan_duration': self.scan_duration,
                'functions_scanned': self.functions_scanned,
                'patterns_applied': self.patterns_applied
            },
            'analysis': {
                'executive_summary': self.executive_summary,
                'detailed_analysis': self.detailed_analysis,
                'recommendations': self.recommendations
            },
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class UnifiedSecurityFinding(db.Model):
    """Model for storing unified security analysis findings"""
    __tablename__ = 'unified_security_findings'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    binary_id = db.Column(String(36), db.ForeignKey('binaries.id'), nullable=False)
    function_id = db.Column(String(36), db.ForeignKey('functions.id'), nullable=True)
    
    # Core finding information
    title = db.Column(String(500), nullable=False)
    description = db.Column(Text, nullable=False)
    severity = db.Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = db.Column(Integer, nullable=False, default=50)  # 0-100
    
    # Classification
    cwe_id = db.Column(String(20), nullable=True)  # CWE identifier
    cve_id = db.Column(String(20), nullable=True)  # CVE identifier if applicable
    category = db.Column(String(100), nullable=True)  # buffer_overflow, format_string, etc.
    
    # Analysis sources
    ai_explanation = db.Column(Text, nullable=True)  # AI-generated explanation
    pattern_matches = db.Column(JSON, nullable=True)  # List of matching vulnerability patterns
    detection_methods = db.Column(JSON, nullable=False)  # List of detection methods used
    
    # Location information
    address = db.Column(String(20), nullable=True)  # Memory address
    file_offset = db.Column(Integer, nullable=True)  # File offset
    line_number = db.Column(Integer, nullable=True)  # Line in decompiled code
    
    # Technical details
    affected_code = db.Column(Text, nullable=True)  # Code snippet
    proof_of_concept = db.Column(Text, nullable=True)  # PoC explanation
    remediation = db.Column(Text, nullable=True)  # How to fix
    references = db.Column(JSON, nullable=True)  # Reference URLs
    
    # Risk assessment
    risk_score = db.Column(Integer, nullable=False, default=0)  # 0-100
    exploit_difficulty = db.Column(String(20), nullable=False, default='MEDIUM')  # LOW, MEDIUM, HIGH
    false_positive_risk = db.Column(String(20), nullable=False, default='MEDIUM')  # LOW, MEDIUM, HIGH
    
    # Analysis metadata
    analysis_version = db.Column(String(20), default='1.0')
    correlation_score = db.Column(Integer, nullable=False, default=0)  # AI-Pattern correlation strength
    
    # Timestamps
    created_at = db.Column(DateTime, default=datetime.utcnow)
    updated_at = db.Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships (backref defined in Binary.unified_findings)
    function_relationship = db.relationship('Function', backref='unified_findings')
    evidence = db.relationship('SecurityEvidence', backref='finding', lazy='dynamic', cascade='all, delete-orphan')
    
    # Indexes
    __table_args__ = (
        db.Index('idx_unified_binary', 'binary_id'),
        db.Index('idx_unified_function', 'function_id'),
        db.Index('idx_unified_severity', 'severity'),
        db.Index('idx_unified_confidence', 'confidence'),
        db.Index('idx_unified_created', 'created_at'),
    )
    
    def __repr__(self):
        return f'<UnifiedSecurityFinding {self.title} ({self.severity})>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'binary_id': self.binary_id,
            'function_id': self.function_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'classification': {
                'cwe_id': self.cwe_id,
                'cve_id': self.cve_id,
                'category': self.category
            },
            'analysis': {
                'ai_explanation': self.ai_explanation,
                'pattern_matches': self.pattern_matches,
                'detection_methods': self.detection_methods
            },
            'location': {
                'address': self.address,
                'file_offset': self.file_offset,
                'line_number': self.line_number
            },
            'technical_details': {
                'affected_code': self.affected_code,
                'proof_of_concept': self.proof_of_concept,
                'remediation': self.remediation,
                'references': self.references
            },
            'risk_assessment': {
                'risk_score': self.risk_score,
                'exploit_difficulty': self.exploit_difficulty,
                'false_positive_risk': self.false_positive_risk
            },
            'metadata': {
                'analysis_version': self.analysis_version,
                'correlation_score': self.correlation_score
            },
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class SecurityEvidence(db.Model):
    """Model for storing evidence supporting security findings"""
    __tablename__ = 'security_evidence'
    
    id = db.Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = db.Column(String(36), db.ForeignKey('unified_security_findings.id'), nullable=False)
    
    # Evidence details
    evidence_type = db.Column(String(50), nullable=False)  # ai_analysis, pattern_match, static_analysis
    source = db.Column(String(100), nullable=False)  # openai, vulnerability_pattern, etc.
    confidence_impact = db.Column(Integer, nullable=False, default=0)  # -50 to +50
    
    # Evidence data
    raw_data = db.Column(JSON, nullable=True)  # Raw analysis data
    processed_data = db.Column(JSON, nullable=True)  # Processed evidence
    description = db.Column(Text, nullable=True)  # Human-readable description
    
    # Metadata
    created_at = db.Column(DateTime, default=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_evidence_finding', 'finding_id'),
        db.Index('idx_evidence_type', 'evidence_type'),
    )
    
    def __repr__(self):
        return f'<SecurityEvidence {self.evidence_type} for {self.finding_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'finding_id': self.finding_id,
            'evidence_type': self.evidence_type,
            'source': self.source,
            'confidence_impact': self.confidence_impact,
            'raw_data': self.raw_data,
            'processed_data': self.processed_data,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class FuzzingHarness(db.Model):
    """Model for storing generated fuzzing harnesses"""
    __tablename__ = 'fuzzing_harnesses'
    
    id = db.Column(db.Integer, primary_key=True)
    binary_id = db.Column(db.Integer, db.ForeignKey('binaries.id'), nullable=False)
    target_function_id = db.Column(db.Integer, db.ForeignKey('functions.id'), nullable=True)
    
    # Harness metadata
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    harness_type = db.Column(db.String(50), nullable=False)  # 'auto', 'manual', 'targeted'
    
    # Target selection criteria
    min_risk_score = db.Column(db.Float, default=40.0)
    target_severities = db.Column(db.Text)  # JSON array of severities ['HIGH', 'MEDIUM']
    target_functions = db.Column(db.Text)  # JSON array of function IDs
    
    # Generated harness content
    harness_code = db.Column(db.Text)
    makefile_content = db.Column(db.Text)
    readme_content = db.Column(db.Text)
    
    # AFL configuration
    afl_config = db.Column(db.Text)  # JSON configuration for AFL++
    input_type = db.Column(db.String(50), default='file')  # 'file', 'stdin', 'network'
    seed_inputs = db.Column(db.Text)  # JSON array of seed input examples
    
    # Generation metadata
    generation_strategy = db.Column(db.String(100))
    target_count = db.Column(db.Integer, default=0)
    confidence_score = db.Column(db.Float)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    binary = db.relationship('Binary', backref=db.backref('fuzzing_harnesses', lazy=True))
    target_function = db.relationship('Function', backref=db.backref('fuzzing_harnesses', lazy=True))


class FuzzingTarget(db.Model):
    """Model for individual fuzzing targets within a harness"""
    __tablename__ = 'fuzzing_targets'
    
    id = db.Column(db.Integer, primary_key=True)
    harness_id = db.Column(db.Integer, db.ForeignKey('fuzzing_harnesses.id'), nullable=False)
    function_id = db.Column(db.Integer, db.ForeignKey('functions.id'), nullable=False)
    security_finding_id = db.Column(db.Integer, db.ForeignKey('unified_security_findings.id'), nullable=True)
    
    # Target details
    priority = db.Column(db.Integer, default=1)  # 1=highest, 5=lowest
    rationale = db.Column(db.Text)  # Why this function was selected
    risk_score = db.Column(db.Float)
    severity = db.Column(db.String(20))
    
    # Fuzzing strategy
    input_strategy = db.Column(db.String(100))  # 'buffer_overflow', 'format_string', etc.
    wrapper_code = db.Column(db.Text)  # Generated wrapper code for this target
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    harness = db.relationship('FuzzingHarness', backref=db.backref('targets', lazy=True))
    function = db.relationship('Function', backref=db.backref('fuzzing_targets', lazy=True))
    security_finding = db.relationship('UnifiedSecurityFinding', backref=db.backref('fuzzing_targets', lazy=True))


class FuzzingSession(db.Model):
    """Model for tracking fuzzing sessions and results"""
    __tablename__ = 'fuzzing_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    harness_id = db.Column(db.Integer, db.ForeignKey('fuzzing_harnesses.id'), nullable=False)
    
    # Session metadata
    name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='pending')  # 'pending', 'running', 'completed', 'crashed'
    fuzzer_type = db.Column(db.String(50), default='afl++')  # 'afl', 'afl++', 'libfuzzer'
    
    # Results tracking
    total_execs = db.Column(db.BigInteger, default=0)
    crashes_found = db.Column(db.Integer, default=0)
    hangs_found = db.Column(db.Integer, default=0)
    coverage_percent = db.Column(db.Float, default=0.0)
    
    # Timing
    started_at = db.Column(db.DateTime)
    ended_at = db.Column(db.DateTime)
    duration_seconds = db.Column(db.Integer)
    
    # Configuration
    afl_args = db.Column(db.Text)  # AFL command line arguments used
    notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    harness = db.relationship('FuzzingHarness', backref=db.backref('sessions', lazy=True))


def init_db():
    """Initialize the database with all tables"""
    db.create_all()


def init_default_config(app):
    """Initialize default configuration values"""
    with app.app_context():
        # Check if we have any config
        if Configuration.query.count() == 0:
            defaults = [
                ('ghidra_bridge_host', '127.0.0.1', 'string', 'Ghidra Bridge host address'),
                ('ghidra_bridge_port', '13100', 'int', 'Ghidra Bridge port number'),
                ('max_analysis_time', '1800', 'int', 'Maximum analysis time in seconds'),
                ('ai_model', 'gpt-3.5-turbo', 'string', 'AI model for function analysis'),
                ('ai_max_tokens', '2000', 'int', 'Maximum tokens for AI responses'),
                ('vulnerability_scan_timeout', '300', 'int', 'Vulnerability scan timeout in seconds'),
                ('default_scan_types', '["buffer_overflow", "format_string", "integer_overflow"]', 'json', 'Default vulnerability scan types')
            ]
            
            for key, value, value_type, description in defaults:
                config = Configuration(
                    key=key,
                    value=value,
                    value_type=value_type,
                    description=description,
                    is_public=True
                )
                db.session.add(config)
            
            db.session.commit()
            print("Default configuration values created")
        else:
            print("Configuration already exists, skipping defaults") 