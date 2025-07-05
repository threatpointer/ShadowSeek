# REST API Reference

## 🔗 ShadowSeek REST API Documentation

ShadowSeek provides a comprehensive REST API for binary analysis, security detection, and fuzzing harness generation. All endpoints return JSON responses and follow RESTful conventions.

---

## 🌐 **Base Configuration**

### **API Base URL**
```
http://localhost:5000/api
```

### **Response Format**
All API responses follow a consistent JSON structure:

```json
{
  "success": true,
  "data": { /* response data */ },
  "message": "Operation completed successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Error Responses**
```json
{
  "success": false,
  "error": "Error description",
  "details": { /* additional error context */ },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **HTTP Status Codes**
- `200 OK` - Successful request
- `201 Created` - Resource created successfully
- `400 Bad Request` - Invalid request parameters
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service temporarily unavailable

---

## 🔧 **System Management**

### **Get System Status**
```http
GET /api/status
```

**Response:**
```json
{
  "status": "ok",
  "binaries": 15,
  "tasks": {
    "total": 42,
    "running": 2,
    "queued": 3
  },
  "ghidra_bridge": "connected",
  "ghidra_bridge_connected": true,
  "server_time": "2024-01-15T10:30:00Z"
}
```

### **Test Ghidra Bridge**
```http
GET /api/bridge/test
```

**Response:**
```json
{
  "status": "connected",
  "bridge_version": "ghidra.app.script.GhidraState@fe7667c",
  "port": 4768,
  "connection_time": "2024-01-15T10:25:00Z"
}
```

### **Start Ghidra Bridge**
```http
POST /api/bridge/start
```

**Response:**
```json
{
  "status": "success",
  "message": "Ghidra Bridge started successfully",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 📁 **Binary Management**

### **List Binaries**
```http
GET /api/binaries
```

**Response:**
```json
{
  "binaries": [
    {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "filename": "example.exe",
      "original_filename": "example.exe",
      "file_size": 1048576,
      "file_hash": "sha256:abc123...",
      "mime_type": "application/x-msdownload",
      "analysis_status": "completed",
      "upload_date": "2024-01-15T10:00:00Z",
      "function_count": 42,
      "ai_analyzed": true
    }
  ]
}
```

### **Upload Binary**
```http
POST /api/binaries
Content-Type: multipart/form-data

file: [binary file]
```

**Response:**
```json
{
  "message": "File uploaded successfully and basic analysis started",
  "binary": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "filename": "example.exe",
    "file_size": 1048576,
    "analysis_status": "analyzing"
  },
  "auto_analysis": {
    "task_id": "task_123",
    "analysis_type": "basic",
    "status": "started"
  }
}
```

### **Get Binary Details**
```http
GET /api/binaries/{binary_id}
```

**Response:**
```json
{
  "binary": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "filename": "example.exe",
    "analysis_status": "completed",
    "function_count": 42,
    "ai_summary": "This binary appears to be a system utility..."
  },
  "functions": [
    {
      "id": "func_123",
      "name": "main",
      "address": "0x401000",
      "size": 256,
      "decompiled": true,
      "ai_analyzed": true,
      "risk_score": 85.5
    }
  ],
  "results": [
    {
      "id": "result_456",
      "analysis_type": "comprehensive",
      "status": "completed",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### **Delete Binary**
```http
DELETE /api/binaries/{binary_id}
```

**Response:**
```json
{
  "message": "Binary example.exe and all associated data deleted successfully"
}
```

### **Analyze Binary**
```http
POST /api/binaries/{binary_id}/analyze
Content-Type: application/json

{
  "analysis_type": "comprehensive",
  "parameters": {
    "decompile_functions": true,
    "extract_strings": true
  }
}
```

**Response:**
```json
{
  "message": "Analysis task submitted",
  "task": {
    "id": "task_789",
    "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "task_type": "comprehensive",
    "status": "queued",
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

---

## 🔍 **Function Analysis**

### **Get Functions**
```http
GET /api/binaries/{binary_id}/functions
```

**Response:**
```json
{
  "functions": [
    {
      "id": "func_123",
      "name": "main",
      "address": "0x401000",
      "size": 256,
      "decompiled": true,
      "ai_analyzed": true,
      "risk_score": 85.5,
      "decompiled_code": "int main() { ... }",
      "ai_summary": "Main entry point function..."
    }
  ]
}
```

### **Decompile Function**
```http
POST /api/functions/{function_id}/decompile
```

**Response:**
```json
{
  "message": "Function decompiled successfully",
  "function": {
    "id": "func_123",
    "name": "main",
    "decompiled_code": "int main() {\n    // Function implementation\n}",
    "decompiled": true,
    "decompiled_at": "2024-01-15T10:30:00Z"
  }
}
```

### **AI Explain Function**
```http
POST /api/functions/{function_id}/explain
```

**Response:**
```json
{
  "message": "AI analysis completed",
  "function": {
    "id": "func_123",
    "name": "main",
    "ai_summary": "This function serves as the main entry point...",
    "risk_score": 85.5,
    "ai_analyzed": true,
    "ai_analyzed_at": "2024-01-15T10:30:00Z"
  }
}
```

### **Get Function Details**
```http
GET /api/functions/{function_id}
```

**Response:**
```json
{
  "function": {
    "id": "func_123",
    "name": "main",
    "address": "0x401000",
    "size": 256,
    "decompiled_code": "int main() { ... }",
    "ai_summary": "Main entry point function...",
    "risk_score": 85.5,
    "parameters": [
      {
        "name": "argc",
        "type": "int",
        "description": "Argument count"
      }
    ],
    "local_variables": [
      {
        "name": "buffer",
        "type": "char[256]",
        "stack_offset": -256
      }
    ]
  }
}
```

### **Bulk Decompile Functions**
```http
POST /api/binaries/{binary_id}/decompile-all
```

**Response:**
```json
{
  "message": "Bulk decompilation started",
  "total_functions": 42,
  "task_id": "task_decompile_all_123",
  "progress": {
    "completed": 0,
    "total": 42,
    "percentage": 0
  }
}
```

### **Bulk AI Analysis**
```http
POST /api/binaries/{binary_id}/ai-explain-all
```

**Response:**
```json
{
  "message": "Bulk AI analysis started",
  "total_functions": 42,
  "task_id": "task_ai_all_456",
  "progress": {
    "completed": 0,
    "total": 42,
    "percentage": 0
  }
}
```

---

## 🛡️ **Security Analysis**

### **Analyze Function Security**
```http
POST /api/functions/{function_id}/security-analysis
```

**Response:**
```json
{
  "message": "Security analysis completed",
  "findings": [
    {
      "id": "finding_123",
      "title": "Buffer Overflow Vulnerability",
      "severity": "HIGH",
      "confidence": 92.5,
      "description": "Function uses strcpy without bounds checking",
      "cwe_id": "CWE-120",
      "evidence": [
        {
          "type": "pattern_match",
          "description": "Detected strcpy usage at line 15"
        }
      ]
    }
  ]
}
```

### **Get Function Security Findings**
```http
GET /api/functions/{function_id}/security-findings
```

**Response:**
```json
{
  "findings": [
    {
      "id": "finding_123",
      "title": "Buffer Overflow Vulnerability",
      "severity": "HIGH",
      "confidence": 92.5,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### **Analyze Binary Security**
```http
POST /api/binaries/{binary_id}/security-analysis
```

**Response:**
```json
{
  "message": "Security analysis started for 42 functions",
  "task_id": "task_security_789",
  "progress": {
    "completed": 0,
    "total": 42,
    "percentage": 0
  }
}
```

### **Get Binary Security Findings**
```http
GET /api/binaries/{binary_id}/security-findings?page=1&per_page=10
```

**Response:**
```json
{
  "findings": [
    {
      "id": "finding_123",
      "title": "Buffer Overflow Vulnerability",
      "severity": "HIGH",
      "confidence": 92.5,
      "function_name": "strcpy_function",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "per_page": 10,
    "total": 25,
    "pages": 3
  }
}
```

### **Get Security Finding Details**
```http
GET /api/security-findings/{finding_id}
```

**Response:**
```json
{
  "finding": {
    "id": "finding_123",
    "title": "Buffer Overflow Vulnerability",
    "description": "Function uses strcpy without bounds checking",
    "severity": "HIGH",
    "confidence": 92.5,
    "cwe_id": "CWE-120",
    "cvss_score": 8.1,
    "function_name": "strcpy_function",
    "ai_analysis": "This function is vulnerable to buffer overflow attacks...",
    "evidence": [
      {
        "type": "pattern_match",
        "description": "Detected strcpy usage at line 15",
        "confidence": 90.0
      },
      {
        "type": "ai_analysis",
        "description": "AI confirmed buffer overflow risk",
        "confidence": 95.0
      }
    ],
    "remediation": "Replace strcpy with strncpy or safer alternatives"
  }
}
```

### **Update Security Finding**
```http
PUT /api/security-findings/{finding_id}
Content-Type: application/json

{
  "false_positive": false,
  "analyst_notes": "Confirmed vulnerability in production code",
  "severity": "CRITICAL"
}
```

---

## 🧪 **Fuzzing System**

### **Generate Fuzzing Harness**
```http
POST /api/binaries/{binary_id}/generate-fuzzing-harness
Content-Type: application/json

{
  "harness_types": ["AFL++", "LibFuzzer"],
  "min_risk_score": 60.0,
  "target_severities": ["HIGH", "MEDIUM"],
  "ai_enabled": true,
  "include_seeds": true
}
```

**Response:**
```json
{
  "message": "Fuzzing harnesses generated successfully",
  "harnesses": [
    {
      "id": "harness_123",
      "name": "AFL++ Fuzzing Harness - example.exe",
      "harness_type": "AFL++",
      "target_count": 5,
      "confidence_score": 87.2,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### **Get Fuzzing Harnesses**
```http
GET /api/binaries/{binary_id}/fuzzing-harnesses
```

**Response:**
```json
{
  "harnesses": [
    {
      "id": "harness_123",
      "name": "AFL++ Fuzzing Harness - example.exe",
      "harness_type": "AFL++",
      "target_count": 5,
      "confidence_score": 87.2,
      "status": "ready",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### **Get Fuzzing Harness Details**
```http
GET /api/fuzzing-harnesses/{harness_id}
```

**Response:**
```json
{
  "harness": {
    "id": "harness_123",
    "name": "AFL++ Fuzzing Harness - example.exe",
    "harness_type": "AFL++",
    "description": "Auto-generated AFL++ fuzzing harness for 5 high-risk functions",
    "harness_code": "/* AFL++ Fuzzing Harness */\n#include <stdio.h>...",
    "makefile_content": "CC=afl-gcc\nCFLAGS=-fsanitize=address...",
    "readme_content": "# AFL++ Fuzzing Harness\n\n## Overview...",
    "targets": [
      {
        "function_name": "strcpy_function",
        "priority": 1,
        "risk_score": 92.5,
        "rationale": "High-risk strcpy usage detected"
      }
    ],
    "afl_config": {
      "timeout": 1000,
      "memory_limit": "200M",
      "compile_flags": ["-fsanitize=address", "-g"]
    }
  }
}
```

### **Download Fuzzing Harness Package**
```http
GET /api/fuzzing-harnesses/{harness_id}/download/package
```

**Response:** ZIP file containing:
- `harness.c` - Main fuzzing harness code
- `Makefile` - Build configuration
- `README.md` - Setup and usage instructions
- `inputs/` - Sample input files

### **Download Fuzzing Harness File**
```http
GET /api/fuzzing-harnesses/{harness_id}/download/{file_type}
```

**File Types:**
- `harness` - Returns `harness.c`
- `makefile` - Returns `Makefile`
- `readme` - Returns `README.md`

### **Delete Fuzzing Harness**
```http
DELETE /api/fuzzing-harnesses/{harness_id}
```

**Response:**
```json
{
  "message": "Fuzzing harness deleted successfully"
}
```

### **Get Supported Fuzzers**
```http
GET /api/fuzzing/supported-fuzzers
```

**Response:**
```json
{
  "fuzzers": {
    "AFL++": {
      "description": "Enhanced AFL with improved features, mutations, and performance",
      "default": true,
      "file_based": true,
      "persistent_mode": true
    },
    "AFL": {
      "description": "Classic American Fuzzy Lop fuzzer",
      "default": false,
      "file_based": true,
      "persistent_mode": true
    },
    "LibFuzzer": {
      "description": "In-process, coverage-guided fuzzing engine (part of LLVM)",
      "default": false,
      "file_based": false,
      "persistent_mode": false
    },
    "Honggfuzz": {
      "description": "Security oriented fuzzer with powerful analysis options",
      "default": false,
      "file_based": true,
      "persistent_mode": false
    }
  }
}
```

---

## 📊 **Task Management**

### **Get Tasks**
```http
GET /api/tasks
```

**Response:**
```json
{
  "tasks": [
    {
      "id": "task_123",
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "task_type": "comprehensive",
      "status": "completed",
      "progress": 100,
      "created_at": "2024-01-15T10:00:00Z",
      "completed_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### **Get Task Status**
```http
GET /api/tasks/{task_id}/status
```

**Response:**
```json
{
  "task": {
    "id": "task_123",
    "status": "running",
    "progress": 65,
    "message": "Processing function 27 of 42",
    "created_at": "2024-01-15T10:00:00Z",
    "estimated_completion": "2024-01-15T10:45:00Z"
  }
}
```

### **Cancel Task**
```http
POST /api/tasks/cancel/{task_id}
```

**Response:**
```json
{
  "message": "Task cancelled successfully",
  "task_id": "task_123"
}
```

### **Cancel All Tasks**
```http
POST /api/tasks/cancel-all
```

**Response:**
```json
{
  "message": "All tasks cancelled successfully",
  "cancelled_count": 5
}
```

---

## 📈 **Comprehensive Analysis**

### **Start Comprehensive Analysis**
```http
POST /api/binaries/{binary_id}/comprehensive-analysis
```

**Response:**
```json
{
  "message": "Comprehensive analysis started",
  "task_id": "task_comprehensive_456",
  "estimated_duration": "10-15 minutes"
}
```

### **Get Comprehensive Analysis**
```http
GET /api/binaries/{binary_id}/comprehensive-analysis
```

**Response:**
```json
{
  "analysis": {
    "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "status": "completed",
    "function_count": 42,
    "string_count": 128,
    "import_count": 15,
    "export_count": 8,
    "memory_regions": 6,
    "completed_at": "2024-01-15T10:30:00Z"
  }
}
```

### **Get Comprehensive Data**
```http
GET /api/binaries/{binary_id}/comprehensive-data/{data_type}
```

**Data Types:**
- `functions` - Function analysis data
- `strings` - Extracted strings
- `imports` - Imported functions
- `exports` - Exported functions
- `memory` - Memory regions
- `symbols` - Symbol table
- `instructions` - Disassembly instructions
- `xrefs` - Cross-references

**Response Example (functions):**
```json
{
  "data": [
    {
      "name": "main",
      "address": "0x401000",
      "size": 256,
      "type": "function",
      "parameters": ["argc", "argv"],
      "local_variables": ["buffer", "counter"]
    }
  ],
  "total_count": 42,
  "data_type": "functions"
}
```

---

## 🔄 **System Administration**

### **Reset Complete System**
```http
POST /api/system/reset-complete
```

**Response:**
```json
{
  "message": "System reset completed successfully",
  "deleted": {
    "binaries": 15,
    "functions": 642,
    "tasks": 28,
    "findings": 156
  }
}
```

### **Get Database Statistics**
```http
GET /api/system/database-stats
```

**Response:**
```json
{
  "stats": {
    "binaries": 15,
    "functions": 642,
    "security_findings": 156,
    "fuzzing_harnesses": 8,
    "analysis_tasks": 28,
    "total_records": 849
  }
}
```

### **Clean Database Table**
```http
POST /api/system/clean-table/{table_name}
```

**Response:**
```json
{
  "message": "Table cleaned successfully",
  "deleted_records": 25
}
```

---

## ⚙️ **Configuration**

### **Get Configuration**
```http
GET /api/config
```

**Response:**
```json
{
  "config": {
    "ai_service_type": "openai",
    "ghidra_install_dir": "/path/to/ghidra",
    "max_file_size": 104857600,
    "analysis_timeout": 3600,
    "ai_analysis_enabled": true
  }
}
```

### **Update Configuration**
```http
POST /api/config
Content-Type: application/json

{
  "ai_service_type": "anthropic",
  "analysis_timeout": 7200,
  "ai_analysis_enabled": true
}
```

### **Test AI Connection**
```http
POST /api/config/test-connection
```

**Response:**
```json
{
  "status": "success",
  "message": "AI service connection successful",
  "provider": "openai",
  "model": "gpt-4",
  "response_time": 1.2
}
```

---

## 📖 **Documentation**

### **Get Documentation**
```http
GET /api/docs/{doc_path}
```

**Response:**
```json
{
  "content": "# Documentation Content\n\nThis is the documentation...",
  "path": "getting-started/installation.md",
  "last_modified": "2024-01-15T10:30:00Z"
}
```

### **List Documentation**
```http
GET /api/docs
```

**Response:**
```json
{
  "docs": [
    {
      "path": "getting-started/installation.md",
      "name": "installation.md",
      "category": "getting-started"
    },
    {
      "path": "api-reference/rest-api.md",
      "name": "rest-api.md",
      "category": "api-reference"
    }
  ]
}
```

---

## 🔍 **Rate Limits & Best Practices**

### **Rate Limits**
- **General API calls**: 1000 requests/hour
- **AI Analysis**: 100 requests/hour
- **File uploads**: 50 uploads/hour
- **Fuzzing harness generation**: 20 requests/hour

### **Best Practices**
1. **Batch Operations**: Use bulk endpoints for multiple operations
2. **Polling**: Check task status every 5-10 seconds, not continuously
3. **Caching**: Cache function analysis results locally
4. **Error Handling**: Implement exponential backoff for failed requests
5. **File Size**: Keep binary files under 100MB for optimal performance

### **Authentication** (Future)
Currently, ShadowSeek runs in development mode without authentication. Production deployments should implement:
- API key authentication
- Role-based access control
- Rate limiting per user
- Audit logging

---

## 💡 **Example Usage**

### **Complete Analysis Workflow**
```bash
# 1. Upload binary
curl -X POST -F "file=@example.exe" http://localhost:5000/api/binaries

# 2. Get binary ID from response, then analyze
curl -X POST http://localhost:5000/api/binaries/{binary_id}/analyze \
  -H "Content-Type: application/json" \
  -d '{"analysis_type": "comprehensive"}'

# 3. Check analysis status
curl http://localhost:5000/api/tasks/{task_id}/status

# 4. Get security findings
curl http://localhost:5000/api/binaries/{binary_id}/security-findings

# 5. Generate fuzzing harness
curl -X POST http://localhost:5000/api/binaries/{binary_id}/generate-fuzzing-harness \
  -H "Content-Type: application/json" \
  -d '{"harness_types": ["AFL++"], "min_risk_score": 60.0}'
```

For more detailed examples, see the [API Examples](../examples/api-examples.md) documentation. 