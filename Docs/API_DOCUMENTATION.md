# ShadowSeek - REST API Documentation

## Overview

ShadowSeek provides a comprehensive REST API for advanced binary security analysis using Ghidra. This API allows you to upload binaries, manage analysis tasks, decompile functions, perform AI-powered vulnerability detection, and generate intelligent fuzzing harnesses results.

**Version 2.0 Features:**
- **Enhanced Task Management**: Stop tasks for specific binaries, improved task cancellation
- **Robust Binary Lifecycle**: Delete processing binaries with automatic task stopping
- **Automatic Status Updates**: Binary status automatically updates when analysis completes
- **Improved Analysis**: Comprehensive analysis by default, better error handling

**Base URL:** `http://localhost:5000/api`  
**Interactive Documentation:** `http://localhost:5000/api/docs/`

## Quick Start

1. **Start the Flask application:**
   ```bash
   python run.py
   ```

2. **Access Swagger Documentation:**
   Open your browser and navigate to: `http://localhost:5000/api/docs/`

3. **Upload a binary:**
   ```bash
   curl -X POST "http://localhost:5000/api/binaries" \
        -H "Content-Type: multipart/form-data" \
        -F "file=@your_binary.exe"
   ```

## Authentication

Currently, the API does not require authentication. All endpoints are publicly accessible.

## Response Format

All responses are in JSON format. Success responses typically include relevant data, while error responses include an `error` field with a descriptive message.

**Success Response Example:**
```json
{
  "status": "success",
  "data": { ... }
}
```

**Error Response Example:**
```json
{
  "error": "Binary not found"
}
```

## API Endpoints

### 🔧 System Management

#### Get System Status
```http
GET /api/system/status
```

Returns comprehensive system status including binary count, task statistics, and Ghidra Bridge connection status.

**Response:**
```json
{
  "status": "ok",
  "binaries": 42,
  "tasks": {
    "total": 156,
    "running": 3,
    "queued": 7
  },
  "ghidra_bridge": "connected",
  "ghidra_bridge_connected": true,
  "server_time": "2024-01-15T10:30:00Z"
}
```

### 🌉 Ghidra Bridge Management

#### Test Bridge Connection
```http
GET /api/bridge/test
```

Test the connection to Ghidra Bridge and return detailed connection status.

#### Start Bridge
```http
POST /api/bridge/start
```

Start the Ghidra Bridge connection if not already running.

### 📁 Binary Management

#### Get All Binaries
```http
GET /api/binaries
```

Retrieve a list of all uploaded binaries with their analysis status.

**Response:**
```json
{
  "binaries": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "filename": "malware.exe",
      "original_filename": "suspicious_file.exe",
      "file_size": 1048576,
      "analysis_status": "completed",
      "upload_time": "2024-01-15T10:30:00Z"
    }
  ]
}
```

#### Upload Binary
```http
POST /api/binaries
```

Upload a binary file for analysis. Automatically starts comprehensive analysis for fresh uploads.

**Supported File Types:**
- `.exe` - Windows executables
- `.dll` - Windows libraries
- `.so` - Linux shared objects
- `.dylib` - macOS dynamic libraries
- `.bin` - Generic binary files
- `.elf` - Linux executables

**Request:**
```bash
curl -X POST "http://localhost:5000/api/binaries" \
     -H "Content-Type: multipart/form-data" \
     -F "file=@your_binary.exe"
```

**Response:**
```json
{
  "message": "File uploaded successfully and comprehensive analysis started",
  "binary": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "filename": "malware.exe",
    "analysis_status": "analyzing"
  },
  "auto_analysis": {
    "task_id": "550e8400-e29b-41d4-a716-446655440001",
    "analysis_type": "comprehensive",
    "status": "started"
  }
}
```

#### Get Binary Details
```http
GET /api/binaries/{binary_id}
```

Get detailed information about a specific binary including associated functions and analysis results.

#### Delete Binary
```http
DELETE /api/binaries/{binary_id}
```

Delete a binary and all associated data. **Enhanced in v2.0** to support deletion of processing binaries by automatically stopping all tasks first.

**What gets deleted:**
- Binary file and metadata
- All analysis results and function data
- All decompiled code and AI explanations
- All task history and logs
- All security findings and vulnerability data
- All fuzzing harnesses and test data

**Features:**
- **Automatic Task Stopping**: If binary is processing, all tasks are stopped first
- **Complete Cleanup**: Removes all associated database records and files
- **Status Updates**: Updates related binary statuses after task cancellation

**Response:**
```json
{
  "message": "Binary deleted successfully. Stopped 2 running tasks before deletion.",
  "deleted_data": {
    "functions": 156,
    "tasks": 8,
    "security_findings": 42,
    "fuzzing_harnesses": 3
  }
}
```

#### Start Binary Analysis
```http
POST /api/binaries/{binary_id}/analyze
```

Start analysis for a specific binary. Requires Ghidra Bridge to be connected.

**Request Body:**
```json
{
  "analysis_type": "comprehensive",
  "parameters": {}
}
```

#### Get Binary Functions
```http
GET /api/binaries/{binary_id}/functions
```

Get all functions discovered in a specific binary.

#### Get Binary Tasks
```http
GET /api/binaries/{binary_id}/tasks
```

Get all analysis tasks for a specific binary.

#### Decompile All Functions
```http
POST /api/binaries/{binary_id}/decompile-all
```

Start bulk decompilation of all functions in a binary. Only decompiles functions that are not already decompiled.

#### Comprehensive Analysis
```http
POST /api/binaries/{binary_id}/comprehensive-analysis
GET /api/binaries/{binary_id}/comprehensive-analysis
```

Start or retrieve comprehensive analysis results for a binary including function extraction, imports/exports, strings, and more.

#### Get Comprehensive Data
```http
GET /api/binaries/{binary_id}/comprehensive-data/{data_type}?page=1&per_page=100&search=term
```

Get specific comprehensive analysis data with pagination and search capabilities.

**Available Data Types:**
- `functions` - Function definitions and metadata
- `imports` - Imported functions and libraries
- `exports` - Exported functions
- `strings` - String literals found in binary
- `memory-regions` - Memory layout information
- `symbols` - Symbol table entries
- `data-types` - Data type definitions
- `instructions` - Assembly instructions
- `cross-references` - Cross-reference information

**Query Parameters:**
- `page` (integer) - Page number (default: 1)
- `per_page` (integer) - Items per page, max 1000 (default: 100)
- `search` (string) - Search term for filtering results

#### Binary AI Summary
```http
POST /api/binaries/{binary_id}/ai-summary
GET /api/binaries/{binary_id}/ai-summary
```

Generate or retrieve AI-powered summary and analysis of the entire binary.

#### Reset Binary Analysis
```http
POST /api/binaries/{binary_id}/reset-analysis
```

Reset analysis status and cancel running tasks for a binary. Useful for restarting stuck analysis.

**Response:**
```json
{
  "message": "Analysis reset for malware.exe",
  "cancelled_tasks": 2
}
```

### 📋 Task Management

#### Get All Tasks
```http
GET /api/tasks
```

Get list of all analysis tasks across all binaries.

#### Get Task Details
```http
GET /api/tasks/{task_id}
```

Get detailed information about a specific task including progress and results.

#### Get Task Status
```http
GET /api/tasks/{task_id}/status
```

Get current status and progress of a specific task.

**Response:**
```json
{
  "task": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "binary_id": "550e8400-e29b-41d4-a716-446655440000",
    "task_type": "comprehensive_analysis",
    "status": "running",
    "priority": 3,
    "progress": 75,
    "created_at": "2024-01-15T10:30:00Z",
    "started_at": "2024-01-15T10:31:00Z"
  }
}
```

#### Cancel Task
```http
POST /api/tasks/cancel/{task_id}
```

Cancel a specific task. Only queued and running tasks can be cancelled.

#### Cancel All Tasks
```http
POST /api/tasks/cancel-all
```

Cancel all running and queued tasks, optionally for a specific binary.

**Request Body (Optional):**
```json
{
  "binary_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Cancelled 3 tasks for binary 550e8400-e29b-41d4-a716-446655440000",
  "cancelled_tasks": 3
}
```

#### Stop Binary Tasks
```http
POST /api/tasks/cancel-all
```

Stop all running and queued tasks for a specific binary. This is useful before deleting a binary that's currently being processed.

**Request Body:**
```json
{
  "binary_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{
  "status": "success", 
  "message": "Cancelled 2 tasks for binary 550e8400-e29b-41d4-a716-446655440000",
  "cancelled_tasks": 2
}
```

### 🔧 Function Analysis

#### Get Function Details
```http
GET /api/functions/{function_id}
```

Get detailed information about a function including parameters, local variables, and call graph.

#### Decompile Function
```http
POST /api/functions/{function_id}/decompile
```

Decompile a specific function to C-like pseudocode. Returns cached result if already decompiled.

**Response:**
```json
{
  "success": true,
  "function_id": "550e8400-e29b-41d4-a716-446655440002",
  "decompiled_code": "int main(int argc, char** argv) {\n  // Decompiled code here\n  return 0;\n}",
  "cached": false,
  "task_id": "550e8400-e29b-41d4-a716-446655440003"
}
```

#### Explain Function (AI Analysis)
```http
POST /api/functions/{function_id}/explain
```

Get AI-powered explanation and analysis of a function. Function must be decompiled first.

**Response:**
```json
{
  "success": true,
  "function_id": "550e8400-e29b-41d4-a716-446655440002",
  "ai_summary": "This function appears to be the main entry point...",
  "risk_score": 0.75,
  "cached": false
}
```

#### Get Control Flow Graph
```http
GET /api/functions/{function_id}/cfg
```

Get Control Flow Graph data for a specific function. Returns cached result if available.

## Task Types

The API supports various types of analysis tasks:

- **`basic`** - Basic binary analysis
- **`comprehensive_analysis`** - Complete analysis including functions, imports, exports, strings
- **`decompile_function`** - Decompile a specific function
- **`bulk_decompile`** - Decompile all functions in a binary
- **`explain_function`** - AI analysis of a function
- **`generate_cfg`** - Generate Control Flow Graph
- **`binary_ai_summary`** - AI summary of entire binary

## Task Status Values

- **`queued`** - Task is waiting to be executed
- **`running`** - Task is currently being executed
- **`completed`** - Task finished successfully
- **`failed`** - Task encountered an error
- **`cancelled`** - Task was cancelled by user

## Error Codes

| HTTP Status | Description |
|-------------|-------------|
| 200 | Success |
| 201 | Created (successful upload) |
| 400 | Bad Request (invalid file type, missing parameters) |
| 404 | Not Found (binary, task, or function not found) |
| 500 | Internal Server Error |
| 503 | Service Unavailable (Ghidra Bridge not connected) |

## Rate Limiting

Currently, there are no rate limits imposed on the API. However, analysis tasks are queued and processed based on priority.

## Examples

### Complete Binary Analysis Workflow

1. **Upload a binary:**
   ```bash
   curl -X POST "http://localhost:5000/api/binaries" \
        -H "Content-Type: multipart/form-data" \
        -F "file=@malware.exe"
   ```

2. **Check analysis progress:**
   ```bash
   curl "http://localhost:5000/api/tasks/{task_id}/status"
   ```

3. **Get functions once analysis is complete:**
   ```bash
   curl "http://localhost:5000/api/binaries/{binary_id}/functions"
   ```

4. **Decompile a specific function:**
   ```bash
   curl -X POST "http://localhost:5000/api/functions/{function_id}/decompile"
   ```

5. **Get AI explanation:**
   ```bash
   curl -X POST "http://localhost:5000/api/functions/{function_id}/explain"
   ```

### Monitoring System Status

```bash
# Get system overview
curl "http://localhost:5000/api/system/status"

# Check Ghidra Bridge connection
curl "http://localhost:5000/api/bridge/test"

# View all running tasks
curl "http://localhost:5000/api/tasks"
```

## Interactive Documentation

For the best API exploration experience, use the interactive Swagger documentation:

🔗 **[http://localhost:5000/api/docs/](http://localhost:5000/api/docs/)**

The Swagger interface provides:
- Complete endpoint documentation
- Request/response examples
- Interactive API testing
- Model schemas
- Parameter descriptions

## Notes

- **Package Manager:** This project uses `uv` for dependency management. Use `uv add <package>` instead of `pip install`
- **Real-time Updates:** Task progress is updated in real-time. Poll task status endpoints for progress monitoring
- **File Uploads:** Maximum file size depends on Flask configuration (default: 16MB)
- **Ghidra Bridge:** Most analysis operations require an active Ghidra Bridge connection
- **Asynchronous Processing:** Long-running analysis tasks are processed asynchronously in the background

## Troubleshooting

### Common Issues

1. **Ghidra Bridge Not Connected:**
   - Ensure Ghidra is running with the bridge script
   - Check bridge status with `/api/bridge/test`
   - Restart bridge with `/api/bridge/start`

2. **Upload Failures:**
   - Verify file type is supported
   - Check file size limits
   - Ensure file is not corrupted

3. **Task Stuck or Failed:**
   - Check task status with `/api/tasks/{task_id}/status`
   - Cancel and retry with `/api/tasks/cancel/{task_id}`
   - Check system logs for detailed error information

### Getting Help

- Check the Swagger documentation at `/api/docs/`
- Review system status at `/api/system/status`
- Monitor tasks at `/api/tasks`
- Check application logs for detailed error information 