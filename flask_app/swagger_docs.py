#!/usr/bin/env python3
"""
Swagger API Documentation Blueprint for ShadowSeek - Advanced Binary Security Analysis Platform
"""

from flask import Blueprint
from flask_restx import Api, Resource, fields, Namespace
from werkzeug.datastructures import FileStorage

def create_swagger_blueprint():
    """Create Swagger documentation blueprint"""
    
    # Create blueprint for documentation
    docs_bp = Blueprint('swagger_docs', __name__)
    
    # Create API instance
    api = Api(
        docs_bp,
        version='2.0',
        title='ShadowSeek API',
        description='''
        ## Comprehensive REST API for Ghidra Binary Analysis Platform
        
        This API provides endpoints for:
        - **Binary Management**: Upload, analyze, and manage binary files
        - **Task Management**: Monitor and control analysis tasks
        - **Function Analysis**: Decompile and analyze individual functions
        - **AI Integration**: Get AI-powered analysis and explanations
        - **System Management**: Monitor system status and Ghidra Bridge
        
        **📍 Base URL:** `/api`  
        **🔗 Interactive Documentation:** `/api/docs/`
        
        ### Quick Start Examples
        
        **Upload a binary:**
        ```bash
        curl -X POST "http://localhost:5000/api/binaries" \\
             -H "Content-Type: multipart/form-data" \\
             -F "file=@your_binary.exe"
        ```
        
        **Check system status:**
        ```bash
        curl "http://localhost:5000/api/status"
        ```
        
        **Monitor tasks:**
        ```bash
        curl "http://localhost:5000/api/tasks"
        ```
        ''',
        doc='/docs/',
            contact='ShadowSeek Team',
    contact_email='support@shadowseek.security',
        license='MIT',
        license_url='https://opensource.org/licenses/MIT'
    )
    
    # Common models
    error_model = api.model('Error', {
        'error': fields.String(required=True, description='Error message', example='Binary not found')
    })
    
    success_model = api.model('Success', {
        'status': fields.String(required=True, description='Success status', example='success'),
        'message': fields.String(required=True, description='Success message')
    })
    
    # System Status Model
    system_status_model = api.model('SystemStatus', {
        'status': fields.String(required=True, description='System status', example='ok'),
        'binaries': fields.Integer(required=True, description='Total number of binaries', example=42),
        'tasks': fields.Nested(api.model('TasksSummary', {
            'total': fields.Integer(description='Total tasks', example=156),
            'running': fields.Integer(description='Running tasks', example=3),
            'queued': fields.Integer(description='Queued tasks', example=7)
        })),
        'ghidra_bridge': fields.String(description='Bridge status', example='connected'),
        'ghidra_bridge_connected': fields.Boolean(description='Is bridge connected', example=True),
        'server_time': fields.String(description='Server timestamp', example='2024-01-15T10:30:00Z')
    })
    
    # Binary Model
    binary_model = api.model('Binary', {
        'id': fields.String(required=True, description='Binary UUID'),
        'filename': fields.String(required=True, description='Binary filename'),
        'original_filename': fields.String(description='Original uploaded filename'),
        'file_size': fields.Integer(description='File size in bytes'),
        'file_hash': fields.String(description='SHA-256 hash'),
        'analysis_status': fields.String(description='Analysis status', 
                                       enum=['uploaded', 'analyzing', 'completed', 'failed']),
        'upload_time': fields.String(description='Upload timestamp'),
        'architecture': fields.String(description='Binary architecture'),
        'metadata': fields.Raw(description='Additional metadata')
    })
    
    # Task Model
    task_model = api.model('AnalysisTask', {
        'id': fields.String(required=True, description='Task UUID'),
        'binary_id': fields.String(required=True, description='Associated binary ID'),
        'task_type': fields.String(required=True, description='Type of analysis task',
                                 enum=['basic', 'comprehensive_analysis', 'decompile_function', 
                                      'bulk_decompile', 'explain_function', 'generate_cfg', 'binary_ai_summary']),
        'status': fields.String(required=True, description='Task status',
                               enum=['queued', 'running', 'completed', 'failed', 'cancelled']),
        'priority': fields.Integer(description='Task priority (1-5)', example=3),
        'progress': fields.Integer(description='Progress percentage (0-100)', example=75),
        'created_at': fields.String(description='Creation timestamp'),
        'started_at': fields.String(description='Start timestamp'),
        'completed_at': fields.String(description='Completion timestamp'),
        'error_message': fields.String(description='Error message if failed'),
        'parameters': fields.Raw(description='Task parameters')
    })
    
    # Function Model
    function_model = api.model('Function', {
        'id': fields.String(required=True, description='Function UUID'),
        'binary_id': fields.String(required=True, description='Associated binary ID'),
        'address': fields.String(required=True, description='Function address (hex)'),
        'name': fields.String(description='Function name'),
        'size': fields.Integer(description='Function size in bytes'),
        'is_analyzed': fields.Boolean(description='Is function analyzed'),
        'is_decompiled': fields.Boolean(description='Is function decompiled'),
        'has_cfg': fields.Boolean(description='Has control flow graph'),
        'ai_analyzed': fields.Boolean(description='Has AI analysis'),
        'decompiled_code': fields.String(description='Decompiled C code'),
        'ai_summary': fields.String(description='AI-generated summary'),
        'risk_score': fields.Float(description='Risk assessment score (0.0-1.0)'),
        'created_at': fields.String(description='Creation timestamp')
    })
    
    # Create namespaces for organization
    system_ns = Namespace('system', description='🔧 System Status & Management')
    binaries_ns = Namespace('binaries', description='📁 Binary File Management & Analysis')
    tasks_ns = Namespace('tasks', description='📋 Analysis Task Management')
    functions_ns = Namespace('functions', description='🔧 Function-Level Analysis')
    bridge_ns = Namespace('bridge', description='🌉 Ghidra Bridge Management')
    
    # Add namespaces
    api.add_namespace(system_ns)
    api.add_namespace(binaries_ns)
    api.add_namespace(tasks_ns)
    api.add_namespace(functions_ns)
    api.add_namespace(bridge_ns)
    
    # DOCUMENTATION-ONLY ENDPOINTS (These document the actual API)
    
    # System Management
    @system_ns.route('/status')
    class SystemStatusDoc(Resource):
        @system_ns.doc('get_system_status', 
                      description='Get comprehensive system status including binary count, task statistics, and Ghidra Bridge connection status')
        @system_ns.marshal_with(system_status_model)
        @system_ns.response(200, 'Success')
        @system_ns.response(500, 'Internal Server Error', error_model)
        def get(self):
            """Get system status and statistics
            
            Returns real-time information about:
            - Total number of uploaded binaries
            - Task queue statistics (running, queued, completed)
            - Ghidra Bridge connection status
            - Server timestamp
            
            **Example Response:**
            ```json
            {
              "status": "ok",
              "binaries": 42,
              "tasks": {"total": 156, "running": 3, "queued": 7},
              "ghidra_bridge_connected": true,
              "server_time": "2024-01-15T10:30:00Z"
            }
            ```
            
            **Note:** This documentation endpoint shows the schema. 
            Use `/api/status` for the actual endpoint.
            """
            return {"message": "This is documentation only. Use /api/status for actual endpoint."}, 501
    
    # Add informational endpoints
    @api.route('/endpoints')
    class APIEndpointsDoc(Resource):
        @api.doc('list_endpoints')
        def get(self):
            """📋 Complete API Endpoint Reference
            
            This endpoint provides a comprehensive overview of all available API endpoints
            organized by category with descriptions and examples.
            """
            endpoints = {
                "base_url": "http://localhost:5000/api",
                "interactive_docs": "http://localhost:5000/api/docs/",
                "system_management": {
                    "GET /api/status": {
                        "description": "Get system status and statistics",
                        "example": "curl http://localhost:5000/api/status"
                    }
                },
                "ghidra_bridge": {
                    "GET /api/bridge/test": {
                        "description": "Test Ghidra Bridge connection",
                        "example": "curl http://localhost:5000/api/bridge/test"
                    },
                    "POST /api/bridge/start": {
                        "description": "Start Ghidra Bridge",
                        "example": "curl -X POST http://localhost:5000/api/bridge/start"
                    }
                },
                "binary_management": {
                    "GET /api/binaries": {
                        "description": "Get list of all binaries",
                        "example": "curl http://localhost:5000/api/binaries"
                    },
                    "POST /api/binaries": {
                        "description": "Upload new binary file",
                        "example": "curl -X POST -F 'file=@binary.exe' http://localhost:5000/api/binaries"
                    },
                    "GET /api/binaries/{id}": {
                        "description": "Get binary details",
                        "example": "curl http://localhost:5000/api/binaries/550e8400-e29b-41d4-a716-446655440000"
                    },
                    "POST /api/binaries/{id}/analyze": {
                        "description": "Start binary analysis",
                        "example": "curl -X POST -H 'Content-Type: application/json' -d '{\"analysis_type\":\"comprehensive\"}' http://localhost:5000/api/binaries/{id}/analyze"
                    },
                    "GET /api/binaries/{id}/functions": {
                        "description": "Get binary functions",
                        "example": "curl http://localhost:5000/api/binaries/{id}/functions"
                    },
                    "GET /api/binaries/{id}/tasks": {
                        "description": "Get binary tasks",
                        "example": "curl http://localhost:5000/api/binaries/{id}/tasks"
                    },
                    "POST /api/binaries/{id}/decompile-all": {
                        "description": "Decompile all functions",
                        "example": "curl -X POST http://localhost:5000/api/binaries/{id}/decompile-all"
                    },
                    "POST /api/binaries/{id}/comprehensive-analysis": {
                        "description": "Start comprehensive analysis",
                        "example": "curl -X POST http://localhost:5000/api/binaries/{id}/comprehensive-analysis"
                    },
                    "GET /api/binaries/{id}/comprehensive-analysis": {
                        "description": "Get comprehensive results",
                        "example": "curl http://localhost:5000/api/binaries/{id}/comprehensive-analysis"
                    },
                    "GET /api/binaries/{id}/comprehensive-data/{type}": {
                        "description": "Get specific analysis data (functions, imports, exports, strings, etc.)",
                        "example": "curl 'http://localhost:5000/api/binaries/{id}/comprehensive-data/functions?page=1&per_page=100'"
                    },
                    "POST /api/binaries/{id}/ai-summary": {
                        "description": "Generate AI summary",
                        "example": "curl -X POST http://localhost:5000/api/binaries/{id}/ai-summary"
                    },
                    "GET /api/binaries/{id}/ai-summary": {
                        "description": "Get AI summary",
                        "example": "curl http://localhost:5000/api/binaries/{id}/ai-summary"
                    }
                },
                "task_management": {
                    "GET /api/tasks": {
                        "description": "Get all tasks",
                        "example": "curl http://localhost:5000/api/tasks"
                    },
                    "GET /api/tasks/{id}": {
                        "description": "Get task details",
                        "example": "curl http://localhost:5000/api/tasks/550e8400-e29b-41d4-a716-446655440001"
                    },
                    "GET /api/tasks/{id}/status": {
                        "description": "Get task status",
                        "example": "curl http://localhost:5000/api/tasks/{id}/status"
                    },
                    "POST /api/tasks/cancel/{id}": {
                        "description": "Cancel specific task",
                        "example": "curl -X POST http://localhost:5000/api/tasks/cancel/{id}"
                    },
                    "POST /api/tasks/cancel-all": {
                        "description": "Cancel all tasks",
                        "example": "curl -X POST http://localhost:5000/api/tasks/cancel-all"
                    }
                },
                "function_analysis": {
                    "GET /api/functions/{id}": {
                        "description": "Get function details",
                        "example": "curl http://localhost:5000/api/functions/550e8400-e29b-41d4-a716-446655440002"
                    },
                    "POST /api/functions/{id}/decompile": {
                        "description": "Decompile function",
                        "example": "curl -X POST http://localhost:5000/api/functions/{id}/decompile"
                    },
                    "POST /api/functions/{id}/explain": {
                        "description": "Get AI explanation",
                        "example": "curl -X POST http://localhost:5000/api/functions/{id}/explain"
                    },
                    "GET /api/functions/{id}/cfg": {
                        "description": "Get control flow graph",
                        "example": "curl http://localhost:5000/api/functions/{id}/cfg"
                    }
                },
                "supported_file_types": [
                    ".exe - Windows executables",
                    ".dll - Windows libraries",
                    ".so - Linux shared objects", 
                    ".dylib - macOS dynamic libraries",
                    ".bin - Generic binary files",
                    ".elf - Linux executables"
                ],
                "task_types": [
                    "basic - Basic binary analysis",
                    "comprehensive_analysis - Complete analysis",
                    "decompile_function - Decompile specific function",
                    "bulk_decompile - Decompile all functions",
                    "explain_function - AI function analysis",
                    "generate_cfg - Control flow graph generation",
                    "binary_ai_summary - AI binary summary"
                ],
                "task_statuses": [
                    "queued - Waiting for execution",
                    "running - Currently executing", 
                    "completed - Finished successfully",
                    "failed - Encountered an error",
                    "cancelled - Cancelled by user"
                ],
                "comprehensive_data_types": [
                    "functions - Function definitions and metadata",
                    "imports - Imported functions and libraries",
                    "exports - Exported functions",
                    "strings - String literals found in binary",
                    "memory-regions - Memory layout information",
                    "symbols - Symbol table entries",
                    "data-types - Data type definitions",
                    "instructions - Assembly instructions",
                    "cross-references - Cross-reference information"
                ],
                "authentication": "None required - All endpoints are publicly accessible",
                "rate_limiting": "No rate limits - Tasks are queued based on priority",
                "package_manager": "This project uses 'uv' for dependency management",
                "notes": [
                    "Most analysis operations require Ghidra Bridge to be connected",
                    "Long-running tasks are processed asynchronously",
                    "Task progress is updated in real-time",
                    "Results are cached to improve performance",
                    "File uploads have size limits (default: 16MB)"
                ]
            }
            
            return {
                "message": "ShadowSeek - Complete API Reference",
                "version": "2.0",
                "documentation": "Interactive Swagger documentation available at /api/docs/",
                "endpoints": endpoints
            }
    
    return docs_bp
