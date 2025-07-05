#!/usr/bin/env python3
"""
Swagger API Documentation for ShadowSeek - Advanced Binary Security Analysis Platform
This module provides comprehensive API documentation using Flask-RESTX
"""

from flask import Flask
from flask_restx import Api, Resource, fields, Namespace
from werkzeug.datastructures import FileStorage

def create_swagger_api(app: Flask):
    """Create and configure Swagger API documentation"""
    
    api = Api(
        app,
        version='2.0',
        title='ShadowSeek API',
        description='''
        Comprehensive REST API for Ghidra binary analysis platform.
        
        This API provides endpoints for:
        - Binary file upload and management
        - Analysis task management and monitoring
        - Function decompilation and AI analysis
        - Control Flow Graph generation
        - Comprehensive binary analysis
        - System status and Ghidra Bridge management
        
        **Base URL:** `/api`
        **Documentation:** `/api/docs/`
        ''',
        doc='/api/docs/',
        prefix='/api',
            contact='ShadowSeek Team',
    contact_email='support@shadowseek.security',
        license='MIT',
        license_url='https://opensource.org/licenses/MIT'
    )

    # Define common models for responses
    error_model = api.model('Error', {
        'error': fields.String(required=True, description='Error message', example='Binary not found')
    })

    success_model = api.model('Success', {
        'status': fields.String(required=True, description='Success status', example='success'),
        'message': fields.String(required=True, description='Success message', example='Operation completed successfully')
    })

    status_model = api.model('SystemStatus', {
        'status': fields.String(required=True, description='System status', example='ok'),
        'binaries': fields.Integer(required=True, description='Total number of binaries', example=42),
        'tasks': fields.Nested(api.model('TasksSummary', {
            'total': fields.Integer(description='Total tasks', example=156),
            'running': fields.Integer(description='Running tasks', example=3),
            'queued': fields.Integer(description='Queued tasks', example=7)
        })),
        'ghidra_bridge': fields.String(description='Ghidra Bridge status', example='connected'),
        'ghidra_bridge_connected': fields.Boolean(description='Is Ghidra Bridge connected', example=True),
        'server_time': fields.String(description='Server timestamp', example='2024-01-15T10:30:00Z')
    })

    binary_model = api.model('Binary', {
        'id': fields.String(required=True, description='Binary UUID', example='550e8400-e29b-41d4-a716-446655440000'),
        'filename': fields.String(required=True, description='Binary filename', example='malware.exe'),
        'original_filename': fields.String(description='Original uploaded filename', example='suspicious_file.exe'),
        'file_path': fields.String(description='File path on server', example='/uploads/550e8400_malware.exe'),
        'file_size': fields.Integer(description='File size in bytes', example=1048576),
        'file_hash': fields.String(description='SHA-256 hash', example='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
        'mime_type': fields.String(description='MIME type', example='application/x-msdownload'),
        'architecture': fields.String(description='Binary architecture', example='x86_64'),
        'analysis_status': fields.String(description='Analysis status', enum=['uploaded', 'analyzing', 'completed', 'failed'], example='completed'),
        'upload_time': fields.String(description='Upload timestamp', example='2024-01-15T10:30:00Z'),
        'metadata': fields.Raw(description='Additional metadata')
    })

    task_model = api.model('AnalysisTask', {
        'id': fields.String(required=True, description='Task UUID', example='550e8400-e29b-41d4-a716-446655440001'),
        'binary_id': fields.String(required=True, description='Associated binary ID', example='550e8400-e29b-41d4-a716-446655440000'),
        'task_type': fields.String(required=True, description='Type of analysis task', enum=['basic', 'comprehensive_analysis', 'decompile_function', 'bulk_decompile', 'explain_function', 'generate_cfg', 'binary_ai_summary'], example='comprehensive_analysis'),
        'status': fields.String(required=True, description='Task status', enum=['queued', 'running', 'completed', 'failed', 'cancelled'], example='running'),
        'priority': fields.Integer(description='Task priority (1-5, higher is more urgent)', example=3),
        'created_at': fields.String(description='Creation timestamp', example='2024-01-15T10:30:00Z'),
        'started_at': fields.String(description='Start timestamp', example='2024-01-15T10:31:00Z'),
        'completed_at': fields.String(description='Completion timestamp', example='2024-01-15T10:45:00Z'),
        'progress': fields.Integer(description='Progress percentage (0-100)', example=75),
        'error_message': fields.String(description='Error message if failed', example='Ghidra Bridge connection lost'),
        'parameters': fields.Raw(description='Task parameters')
    })

    function_model = api.model('Function', {
        'id': fields.String(required=True, description='Function UUID', example='550e8400-e29b-41d4-a716-446655440002'),
        'binary_id': fields.String(required=True, description='Associated binary ID', example='550e8400-e29b-41d4-a716-446655440000'),
        'address': fields.String(required=True, description='Function address (hex)', example='0x140001000'),
        'name': fields.String(description='Function name', example='main'),
        'original_name': fields.String(description='Original function name', example='FUN_140001000'),
        'size': fields.Integer(description='Function size in bytes', example=256),
        'parameter_count': fields.Integer(description='Number of parameters', example=2),
        'return_type': fields.String(description='Return type', example='int'),
        'calling_convention': fields.String(description='Calling convention', example='__stdcall'),
        'is_analyzed': fields.Boolean(description='Is function analyzed', example=True),
        'is_decompiled': fields.Boolean(description='Is function decompiled', example=True),
        'has_cfg': fields.Boolean(description='Has control flow graph', example=True),
        'is_thunk': fields.Boolean(description='Is thunk function', example=False),
        'is_external': fields.Boolean(description='Is external function', example=False),
        'ai_analyzed': fields.Boolean(description='Has AI analysis', example=True),
        'decompiled_code': fields.String(description='Decompiled C code'),
        'ai_summary': fields.String(description='AI-generated summary'),
        'risk_score': fields.Float(description='Risk assessment score (0.0-1.0)', example=0.75),
        'created_at': fields.String(description='Creation timestamp', example='2024-01-15T10:30:00Z'),
        'updated_at': fields.String(description='Last update timestamp', example='2024-01-15T10:45:00Z')
    })

    upload_response_model = api.model('UploadResponse', {
        'message': fields.String(required=True, description='Upload status message', example='File uploaded successfully and comprehensive analysis started'),
        'binary': fields.Nested(binary_model, description='Uploaded binary details'),
        'auto_analysis': fields.Nested(api.model('AutoAnalysis', {
            'task_id': fields.String(description='Analysis task ID', example='550e8400-e29b-41d4-a716-446655440001'),
            'analysis_type': fields.String(description='Type of analysis', example='comprehensive'),
            'status': fields.String(description='Analysis status', example='started'),
            'error': fields.String(description='Error message if failed')
        }), description='Automatic analysis details')
    })

    # File upload parser
    upload_parser = api.parser()
    upload_parser.add_argument('file', location='files', type=FileStorage, required=True, help='Binary file to upload (.exe, .dll, .so, .dylib, .bin, .elf)')

    # Analysis request parser
    analysis_parser = api.parser()
    analysis_parser.add_argument('analysis_type', type=str, help='Type of analysis to perform', default='basic', choices=['basic', 'comprehensive'])
    analysis_parser.add_argument('parameters', type=dict, help='Analysis parameters (JSON object)')

    # Pagination parser
    pagination_parser = api.parser()
    pagination_parser.add_argument('page', type=int, help='Page number', default=1, location='args')
    pagination_parser.add_argument('per_page', type=int, help='Items per page (max 1000)', default=100, location='args')
    pagination_parser.add_argument('search', type=str, help='Search term', location='args')

    # Create namespaces with detailed descriptions
    system_ns = Namespace('system', description='System status and health monitoring')
    binary_ns = Namespace('binaries', description='Binary file upload, management, and analysis')
    task_ns = Namespace('tasks', description='Analysis task management and monitoring')
    function_ns = Namespace('functions', description='Function-level analysis and decompilation')
    bridge_ns = Namespace('bridge', description='Ghidra Bridge connection management')

    api.add_namespace(system_ns)
    api.add_namespace(binary_ns)
    api.add_namespace(task_ns)
    api.add_namespace(function_ns)
    api.add_namespace(bridge_ns)

    # System endpoints
    @system_ns.route('/status')
    class SystemStatus(Resource):
        @system_ns.doc('get_system_status', 
            description='Get comprehensive system status including binary count, task statistics, and Ghidra Bridge connection status')
        @system_ns.marshal_with(status_model)
        @system_ns.response(200, 'Success')
        @system_ns.response(500, 'Internal Server Error', error_model)
        def get(self):
            """Get system status and statistics"""
            pass

    # Bridge endpoints
    @bridge_ns.route('/test')
    class BridgeTest(Resource):
        @bridge_ns.doc('test_bridge_connection',
            description='Test the connection to Ghidra Bridge and return detailed connection status')
        @bridge_ns.response(200, 'Bridge connection test result')
        @bridge_ns.response(500, 'Internal Server Error', error_model)
        def get(self):
            """Test Ghidra Bridge connection"""
            pass

    @bridge_ns.route('/start')
    class BridgeStart(Resource):
        @bridge_ns.doc('start_bridge',
            description='Start the Ghidra Bridge connection if not already running')
        @bridge_ns.marshal_with(success_model)
        @bridge_ns.response(200, 'Bridge started successfully')
        @bridge_ns.response(500, 'Failed to start bridge', error_model)
        def post(self):
            """Start Ghidra Bridge"""
            pass

    # Binary endpoints
    @binary_ns.route('')
    class BinaryList(Resource):
        @binary_ns.doc('get_binaries',
            description='Get a list of all uploaded binaries with their analysis status')
        @binary_ns.marshal_with(api.model('BinaryList', {
            'binaries': fields.List(fields.Nested(binary_model))
        }))
        @binary_ns.response(200, 'Success')
        @binary_ns.response(500, 'Internal Server Error', error_model)
        def get(self):
            """Get list of all uploaded binaries"""
            pass

        @binary_ns.doc('upload_binary',
            description='Upload a binary file for analysis. Automatically starts comprehensive analysis for fresh uploads.')
        @binary_ns.expect(upload_parser)
        @binary_ns.marshal_with(upload_response_model, code=201)
        @binary_ns.response(201, 'Binary uploaded successfully')
        @binary_ns.response(400, 'Bad Request - Invalid file type or missing file', error_model)
        @binary_ns.response(500, 'Internal Server Error', error_model)
        def post(self):
            """Upload a new binary file for analysis"""
            pass

    @binary_ns.route('/<string:binary_id>')
    @binary_ns.param('binary_id', 'Binary UUID', example='550e8400-e29b-41d4-a716-446655440000')
    class BinaryDetails(Resource):
        @binary_ns.doc('get_binary_details',
            description='Get detailed information about a specific binary including associated functions and analysis results')
        @binary_ns.marshal_with(api.model('BinaryDetails', {
            'binary': fields.Nested(binary_model),
            'functions': fields.List(fields.Nested(function_model)),
            'results': fields.List(fields.Raw(description='Analysis results'))
        }))
        @binary_ns.response(200, 'Success')
        @binary_ns.response(404, 'Binary not found', error_model)
        @binary_ns.response(500, 'Internal Server Error', error_model)
        def get(self, binary_id):
            """Get detailed information about a specific binary"""
            pass

    @binary_ns.route('/<string:binary_id>/analyze')
    @binary_ns.param('binary_id', 'Binary UUID')
    class BinaryAnalysis(Resource):
        @binary_ns.doc('analyze_binary',
            description='Start analysis for a specific binary. Requires Ghidra Bridge to be connected.')
        @binary_ns.expect(analysis_parser)
        @binary_ns.marshal_with(api.model('AnalysisResponse', {
            'message': fields.String(description='Analysis status message'),
            'task': fields.Nested(task_model)
        }))
        @binary_ns.response(200, 'Analysis started')
        @binary_ns.response(404, 'Binary not found', error_model)
        @binary_ns.response(503, 'Ghidra Bridge not connected', error_model)
        def post(self, binary_id):
            """Start analysis for a specific binary"""
            pass

    @binary_ns.route('/<string:binary_id>/functions')
    @binary_ns.param('binary_id', 'Binary UUID')
    class BinaryFunctions(Resource):
        @binary_ns.doc('get_binary_functions',
            description='Get all functions discovered in a specific binary')
        @binary_ns.marshal_with(api.model('FunctionList', {
            'functions': fields.List(fields.Nested(function_model))
        }))
        @binary_ns.response(200, 'Success')
        @binary_ns.response(404, 'Binary not found', error_model)
        def get(self, binary_id):
            """Get all functions for a specific binary"""
            pass

    @binary_ns.route('/<string:binary_id>/tasks')
    @binary_ns.param('binary_id', 'Binary UUID')
    class BinaryTasks(Resource):
        @binary_ns.doc('get_binary_tasks',
            description='Get all analysis tasks for a specific binary')
        @binary_ns.marshal_with(api.model('TaskList', {
            'tasks': fields.List(fields.Nested(task_model))
        }))
        @binary_ns.response(200, 'Success')
        @binary_ns.response(404, 'Binary not found', error_model)
        def get(self, binary_id):
            """Get all tasks for a specific binary"""
            pass

    @binary_ns.route('/<string:binary_id>/decompile-all')
    @binary_ns.param('binary_id', 'Binary UUID')
    class BinaryDecompileAll(Resource):
        @binary_ns.doc('decompile_all_functions',
            description='Start bulk decompilation of all functions in a binary. Only decompiles functions that are not already decompiled.')
        @binary_ns.marshal_with(api.model('BulkDecompileResponse', {
            'success': fields.Boolean(description='Operation success'),
            'task_id': fields.String(description='Bulk decompilation task ID'),
            'message': fields.String(description='Status message'),
            'total_functions': fields.Integer(description='Total functions in binary'),
            'functions_to_decompile': fields.Integer(description='Functions that will be decompiled'),
            'already_decompiled': fields.Integer(description='Functions already decompiled')
        }))
        @binary_ns.response(200, 'Decompilation started')
        @binary_ns.response(404, 'Binary not found', error_model)
        @binary_ns.response(503, 'Ghidra Bridge not connected', error_model)
        def post(self, binary_id):
            """Decompile all functions in a binary"""
            pass

    @binary_ns.route('/<string:binary_id>/comprehensive-analysis')
    @binary_ns.param('binary_id', 'Binary UUID')
    class ComprehensiveAnalysis(Resource):
        @binary_ns.doc('start_comprehensive_analysis',
            description='Start comprehensive analysis for a binary including function extraction, imports/exports, strings, and more')
        @binary_ns.marshal_with(api.model('ComprehensiveAnalysisResponse', {
            'success': fields.Boolean(description='Operation success'),
            'task_id': fields.String(description='Analysis task ID'),
            'message': fields.String(description='Status message')
        }))
        @binary_ns.response(200, 'Comprehensive analysis started')
        @binary_ns.response(404, 'Binary not found', error_model)
        def post(self, binary_id):
            """Start comprehensive analysis for a binary"""
            pass

        @binary_ns.doc('get_comprehensive_analysis',
            description='Get comprehensive analysis results for a binary')
        @binary_ns.response(200, 'Comprehensive analysis results')
        @binary_ns.response(404, 'Analysis not found', error_model)
        def get(self, binary_id):
            """Get comprehensive analysis results"""
            pass

    @binary_ns.route('/<string:binary_id>/comprehensive-data/<string:data_type>')
    @binary_ns.param('binary_id', 'Binary UUID')
    @binary_ns.param('data_type', 'Type of data to retrieve')
    class ComprehensiveData(Resource):
        @binary_ns.doc('get_comprehensive_data',
            description='Get specific comprehensive analysis data with pagination and search capabilities')
        @binary_ns.expect(pagination_parser)
        @binary_ns.response(200, 'Comprehensive data results')
        @binary_ns.response(400, 'Invalid data type', error_model)
        @binary_ns.response(404, 'Binary not found', error_model)
        def get(self, binary_id, data_type):
            """Get specific comprehensive analysis data with pagination
            
            **Available data types:**
            - `functions`: Function definitions and metadata
            - `imports`: Imported functions and libraries
            - `exports`: Exported functions
            - `strings`: String literals found in binary
            - `memory-regions`: Memory layout information
            - `symbols`: Symbol table entries
            - `data-types`: Data type definitions
            - `instructions`: Assembly instructions
            - `cross-references`: Cross-reference information
            """
            pass

    @binary_ns.route('/<string:binary_id>/ai-summary')
    @binary_ns.param('binary_id', 'Binary UUID')
    class BinaryAISummary(Resource):
        @binary_ns.doc('generate_binary_ai_summary',
            description='Generate AI-powered summary and analysis of the entire binary')
        @binary_ns.response(200, 'AI summary generation started or cached result')
        @binary_ns.response(404, 'Binary not found', error_model)
        def post(self, binary_id):
            """Generate AI summary for the entire binary"""
            pass

        @binary_ns.doc('get_binary_ai_summary',
            description='Get existing AI summary for a binary')
        @binary_ns.response(200, 'AI summary results')
        @binary_ns.response(404, 'Binary or summary not found', error_model)
        def get(self, binary_id):
            """Get existing AI summary for a binary"""
            pass

    # Task endpoints
    @task_ns.route('')
    class TaskList(Resource):
        @task_ns.doc('get_all_tasks',
            description='Get list of all analysis tasks across all binaries')
        @task_ns.marshal_with(api.model('AllTasks', {
            'tasks': fields.List(fields.Nested(task_model))
        }))
        @task_ns.response(200, 'Success')
        def get(self):
            """Get list of all analysis tasks"""
            pass

    @task_ns.route('/<string:task_id>')
    @task_ns.param('task_id', 'Task UUID', example='550e8400-e29b-41d4-a716-446655440001')
    class TaskDetails(Resource):
        @task_ns.doc('get_task_details',
            description='Get detailed information about a specific task including progress and results')
        @task_ns.marshal_with(task_model)
        @task_ns.response(200, 'Success')
        @task_ns.response(404, 'Task not found', error_model)
        def get(self, task_id):
            """Get detailed information about a specific task"""
            pass

    @task_ns.route('/<string:task_id>/status')
    @task_ns.param('task_id', 'Task UUID')
    class TaskStatus(Resource):
        @task_ns.doc('get_task_status',
            description='Get current status and progress of a specific task')
        @task_ns.marshal_with(api.model('TaskStatusResponse', {
            'task': fields.Nested(task_model)
        }))
        @task_ns.response(200, 'Success')
        @task_ns.response(404, 'Task not found', error_model)
        def get(self, task_id):
            """Get status of a specific task"""
            pass

    @task_ns.route('/cancel/<string:task_id>')
    @task_ns.param('task_id', 'Task UUID')
    class TaskCancel(Resource):
        @task_ns.doc('cancel_task',
            description='Cancel a specific task. Only queued and running tasks can be cancelled.')
        @task_ns.marshal_with(success_model)
        @task_ns.response(200, 'Task cancelled successfully')
        @task_ns.response(400, 'Cannot cancel task - invalid status', error_model)
        @task_ns.response(404, 'Task not found', error_model)
        def post(self, task_id):
            """Cancel a specific task"""
            pass

    @task_ns.route('/cancel-all')
    class TaskCancelAll(Resource):
        @task_ns.doc('cancel_all_tasks',
            description='Cancel all running and queued tasks, optionally for a specific binary')
        @task_ns.expect(api.model('CancelAllRequest', {
            'binary_id': fields.String(description='Optional: Cancel only tasks for specific binary', example='550e8400-e29b-41d4-a716-446655440000')
        }), validate=False)
        @task_ns.marshal_with(success_model)
        @task_ns.response(200, 'Tasks cancelled successfully')
        def post(self):
            """Cancel all running tasks"""
            pass

    # Function endpoints
    @function_ns.route('/<string:function_id>')
    @function_ns.param('function_id', 'Function UUID', example='550e8400-e29b-41d4-a716-446655440002')
    class FunctionDetails(Resource):
        @function_ns.doc('get_function_details',
            description='Get detailed information about a function including parameters, local variables, and call graph')
        @function_ns.marshal_with(api.model('FunctionDetails', {
            'function': fields.Nested(function_model)
        }))
        @function_ns.response(200, 'Success')
        @function_ns.response(404, 'Function not found', error_model)
        def get(self, function_id):
            """Get detailed information about a function"""
            pass

    @function_ns.route('/<string:function_id>/decompile')
    @function_ns.param('function_id', 'Function UUID')
    class FunctionDecompile(Resource):
        @function_ns.doc('decompile_function',
            description='Decompile a specific function to C-like pseudocode. Returns cached result if already decompiled.')
        @function_ns.marshal_with(api.model('DecompileResponse', {
            'success': fields.Boolean(description='Operation success'),
            'function_id': fields.String(description='Function ID'),
            'decompiled_code': fields.String(description='Decompiled C code'),
            'cached': fields.Boolean(description='Whether result was cached'),
            'task_id': fields.String(description='Task ID if decompilation started')
        }))
        @function_ns.response(200, 'Decompilation result or task started')
        @function_ns.response(404, 'Function not found', error_model)
        @function_ns.response(503, 'Ghidra Bridge not connected', error_model)
        def post(self, function_id):
            """Decompile a specific function"""
            pass

    @function_ns.route('/<string:function_id>/explain')
    @function_ns.param('function_id', 'Function UUID')
    class FunctionExplain(Resource):
        @function_ns.doc('explain_function',
            description='Get AI-powered explanation and analysis of a function. Function must be decompiled first.')
        @function_ns.marshal_with(api.model('ExplainResponse', {
            'success': fields.Boolean(description='Operation success'),
            'function_id': fields.String(description='Function ID'),
            'ai_summary': fields.String(description='AI-generated explanation'),
            'risk_score': fields.Float(description='Risk assessment score'),
            'cached': fields.Boolean(description='Whether result was cached'),
            'task_id': fields.String(description='Task ID if analysis started')
        }))
        @function_ns.response(200, 'AI explanation result or task started')
        @function_ns.response(400, 'Function must be decompiled first', error_model)
        @function_ns.response(404, 'Function not found', error_model)
        def post(self, function_id):
            """Get AI explanation for a function"""
            pass

    @function_ns.route('/<string:function_id>/cfg')
    @function_ns.param('function_id', 'Function UUID')
    class FunctionCFG(Resource):
        @function_ns.doc('get_function_cfg',
            description='Get Control Flow Graph data for a specific function. Returns cached result if available.')
        @function_ns.marshal_with(api.model('CFGResponse', {
            'success': fields.Boolean(description='Operation success'),
            'function_id': fields.String(description='Function ID'),
            'cfg_data': fields.Raw(description='Control Flow Graph data'),
            'cached': fields.Boolean(description='Whether result was cached'),
            'task_id': fields.String(description='Task ID if generation started')
        }))
        @function_ns.response(200, 'Control Flow Graph data or task started')
        @function_ns.response(404, 'Function not found', error_model)
        @function_ns.response(503, 'Ghidra Bridge not connected', error_model)
        def get(self, function_id):
            """Get Control Flow Graph for a specific function"""
            pass

    return api

def setup_swagger_docs(app: Flask):
    """Setup Swagger documentation for the Flask app"""
    return create_swagger_api(app) 