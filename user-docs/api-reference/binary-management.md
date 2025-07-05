# Binary Management API

## 📁 Complete Binary Management API Reference

The Binary Management API provides comprehensive functionality for uploading, analyzing, and managing binary files in ShadowSeek. This API handles the complete binary lifecycle from upload through deletion.

---

## 🌐 **Base Configuration**

**Base URL**: `http://localhost:5000/api`
**Content-Type**: `application/json` (unless specified otherwise)

---

## 📋 **Binary Listing & Information**

### **List All Binaries**
```http
GET /api/binaries
```

Retrieve a list of all uploaded binaries with their current analysis status.

**Response:**
```json
{
  "success": true,
  "data": {
    "binaries": [
      {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "filename": "a1b2c3d4-e5f6-7890-abcd-ef1234567890_example.exe",
        "original_filename": "example.exe",
        "file_size": 1048576,
        "file_hash": "sha256:abc123def456789...",
        "mime_type": "application/x-msdownload",
        "analysis_status": "completed",
        "upload_date": "2024-01-15T10:00:00Z",
        "function_count": 42,
        "decompiled_functions": 35,
        "ai_analyzed_functions": 28,
        "security_findings_count": 5,
        "ai_summary": "This binary appears to be a system utility with network communication capabilities..."
      },
      {
        "id": "b2c3d4e5-f6g7-8901-bcde-f234567890ab",
        "filename": "b2c3d4e5-f6g7-8901-bcde-f234567890ab_malware.dll",
        "original_filename": "malware.dll",
        "file_size": 524288,
        "file_hash": "sha256:def456abc789123...",
        "mime_type": "application/x-msdownload",
        "analysis_status": "analyzing",
        "upload_date": "2024-01-15T11:30:00Z",
        "function_count": 23,
        "decompiled_functions": 15,
        "ai_analyzed_functions": 8,
        "security_findings_count": 0
      }
    ]
  },
  "message": "Successfully retrieved binary list",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Get Binary Details**
```http
GET /api/binaries/{binary_id}
```

Get comprehensive information about a specific binary including functions and analysis results.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary

**Response:**
```json
{
  "success": true,
  "data": {
    "binary": {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "filename": "a1b2c3d4-e5f6-7890-abcd-ef1234567890_example.exe",
      "original_filename": "example.exe",
      "file_path": "/uploads/a1b2c3d4-e5f6-7890-abcd-ef1234567890_example.exe",
      "file_size": 1048576,
      "file_hash": "sha256:abc123def456789...",
      "mime_type": "application/x-msdownload",
      "analysis_status": "completed",
      "upload_date": "2024-01-15T10:00:00Z",
      "ai_summary": "This binary appears to be a system utility...",
      "architecture": "x86_64",
      "compiler_info": "Microsoft Visual C++ 14.0",
      "security_mitigations": {
        "aslr": true,
        "dep": true,
        "stack_canaries": true,
        "cfg": false
      }
    },
    "functions": [
      {
        "id": 123,
        "name": "main",
        "address": "0x401000",
        "size": 256,
        "decompiled": true,
        "ai_analyzed": true,
        "risk_score": 85.5,
        "is_external": false,
        "decompiled_code": "int main(int argc, char** argv) {\n  // Function implementation\n}",
        "ai_summary": "Main entry point function that processes command line arguments..."
      }
    ],
    "analysis_results": [
      {
        "id": 456,
        "analysis_type": "comprehensive",
        "status": "completed",
        "created_at": "2024-01-15T10:05:00Z",
        "completed_at": "2024-01-15T10:15:00Z",
        "function_count": 42,
        "string_count": 128,
        "import_count": 15,
        "export_count": 8
      }
    ],
    "statistics": {
      "total_functions": 42,
      "decompiled_functions": 35,
      "ai_analyzed_functions": 28,
      "external_functions": 7,
      "security_findings": 5,
      "fuzzing_harnesses": 2
    }
  },
  "message": "Binary details retrieved successfully",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 📤 **Binary Upload**

### **Upload Binary File**
```http
POST /api/binaries
Content-Type: multipart/form-data

file: [binary file]
```

Upload a new binary file for analysis. The system automatically starts basic analysis upon successful upload.

**Form Parameters:**
- `file` (file) - Binary file to upload

**Supported File Types:**
- **Windows**: `.exe`, `.dll`, `.sys`, `.obj`
- **Linux**: `.so`, `.elf`, `.a`, `.o`
- **macOS**: `.dylib`, `.app`, `.framework`
- **Generic**: `.bin`, `.hex`, `.raw`

**File Size Limits:**
- Maximum file size: 100MB
- Minimum file size: 1KB

**Response (Success):**
```json
{
  "success": true,
  "data": {
    "message": "File uploaded successfully and basic analysis started",
    "binary": {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "filename": "a1b2c3d4-e5f6-7890-abcd-ef1234567890_example.exe",
      "original_filename": "example.exe",
      "file_size": 1048576,
      "file_hash": "sha256:abc123def456789...",
      "mime_type": "application/x-msdownload",
      "analysis_status": "analyzing",
      "upload_date": "2024-01-15T10:00:00Z"
    },
    "auto_analysis": {
      "task_id": "task_basic_123",
      "analysis_type": "basic",
      "status": "started",
      "estimated_duration": "2-5 minutes"
    }
  },
  "message": "Binary uploaded and analysis started",
  "timestamp": "2024-01-15T10:00:00Z"
}
```

**Response (Error - Invalid File Type):**
```json
{
  "success": false,
  "error": "File type not allowed",
  "details": {
    "filename": "document.pdf",
    "mime_type": "application/pdf",
    "allowed_types": [".exe", ".dll", ".so", ".elf", ".dylib", ".bin"]
  },
  "timestamp": "2024-01-15T10:00:00Z"
}
```

**Response (Error - File Too Large):**
```json
{
  "success": false,
  "error": "File size exceeds maximum limit",
  "details": {
    "file_size": 104857600,
    "max_size": 104857600,
    "size_limit": "100MB"
  },
  "timestamp": "2024-01-15T10:00:00Z"
}
```

---

## 🔍 **Binary Analysis**

### **Start Binary Analysis**
```http
POST /api/binaries/{binary_id}/analyze
Content-Type: application/json

{
  "analysis_type": "comprehensive",
  "parameters": {
    "decompile_functions": true,
    "extract_strings": true,
    "analyze_imports": true,
    "detect_crypto": true
  }
}
```

Submit a binary for comprehensive analysis using Ghidra Bridge.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary to analyze

**Request Body:**
```json
{
  "analysis_type": "basic|comprehensive|quick",
  "parameters": {
    "decompile_functions": true,
    "extract_strings": true,
    "analyze_imports": true,
    "analyze_exports": true,
    "detect_crypto": true,
    "find_vulnerabilities": true,
    "timeout": 3600
  }
}
```

**Analysis Types:**
- **`basic`** - Fast analysis with function discovery (2-5 minutes)
- **`comprehensive`** - Complete analysis with all features (10-30 minutes)
- **`quick`** - Minimal analysis for rapid overview (30 seconds)

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Analysis task submitted successfully",
    "task": {
      "id": "task_comprehensive_456",
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "task_type": "comprehensive",
      "status": "queued",
      "priority": 3,
      "created_at": "2024-01-15T10:30:00Z",
      "estimated_duration": "15-20 minutes",
      "parameters": {
        "decompile_functions": true,
        "extract_strings": true,
        "analyze_imports": true
      }
    },
    "binary_status": {
      "previous_status": "uploaded",
      "new_status": "analyzing"
    }
  },
  "message": "Analysis started",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Reset Binary Analysis**
```http
POST /api/binaries/{binary_id}/reset-analysis
```

Reset the analysis status and cancel any running tasks for a binary.

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Analysis reset for example.exe",
    "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "cancelled_tasks": [
      {
        "task_id": "task_123",
        "task_type": "comprehensive",
        "status": "cancelled"
      }
    ],
    "status_change": {
      "from": "analyzing",
      "to": "uploaded"
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Update Binary Status**
```http
POST /api/binaries/{binary_id}/update-status
```

Update the analysis status of a binary based on current analysis results.

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Status updated successfully",
    "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "status_change": {
      "old_status": "analyzing",
      "new_status": "completed"
    },
    "analysis_summary": {
      "functions_found": 42,
      "functions_decompiled": 35,
      "functions_ai_analyzed": 28,
      "security_findings": 5,
      "analysis_duration": "18 minutes"
    }
  },
  "timestamp": "2024-01-15T10:45:00Z"
}
```

### **Get Binary Status Information**
```http
GET /api/binaries/{binary_id}/status-info
```

Get detailed status information including analysis progress and statistics.

**Response:**
```json
{
  "success": true,
  "data": {
    "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "current_status": "analyzing",
    "progress": {
      "overall_progress": 65,
      "functions_discovered": 42,
      "functions_decompiled": 27,
      "functions_ai_analyzed": 18,
      "estimated_completion": "2024-01-15T10:45:00Z"
    },
    "active_tasks": [
      {
        "task_id": "task_456",
        "task_type": "ai_analysis",
        "progress": 60,
        "status": "running",
        "current_operation": "Analyzing function 'parse_input'"
      }
    ],
    "completed_operations": [
      "function_discovery",
      "decompilation",
      "string_extraction"
    ],
    "remaining_operations": [
      "ai_analysis",
      "security_analysis"
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 🗂️ **Binary Data & Results**

### **Get Binary Functions**
```http
GET /api/binaries/{binary_id}/functions?page=1&per_page=50&decompiled_only=false
```

Retrieve all functions discovered in a binary with optional filtering.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary

**Query Parameters:**
- `page` (integer, optional) - Page number (default: 1)
- `per_page` (integer, optional) - Items per page (default: 50, max: 100)
- `decompiled_only` (boolean, optional) - Show only decompiled functions (default: false)
- `ai_analyzed_only` (boolean, optional) - Show only AI-analyzed functions (default: false)
- `search` (string, optional) - Search term for function names

**Response:**
```json
{
  "success": true,
  "data": {
    "functions": [
      {
        "id": 123,
        "name": "main",
        "address": "0x401000",
        "size": 256,
        "decompiled": true,
        "ai_analyzed": true,
        "risk_score": 85.5,
        "is_external": false,
        "parameters": [
          {
            "name": "argc",
            "type": "int",
            "order": 0
          },
          {
            "name": "argv",
            "type": "char**",
            "order": 1
          }
        ],
        "local_variables": [
          {
            "name": "buffer",
            "type": "char[256]",
            "stack_offset": -256
          }
        ],
        "call_references": {
          "calls_to": ["strcpy", "printf", "exit"],
          "called_by": ["_start"]
        },
        "security_analysis": {
          "has_findings": true,
          "highest_severity": "HIGH",
          "finding_count": 2
        }
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 50,
      "total": 42,
      "pages": 1,
      "has_next": false,
      "has_prev": false
    },
    "summary": {
      "total_functions": 42,
      "decompiled_functions": 35,
      "ai_analyzed_functions": 28,
      "external_functions": 7,
      "functions_with_security_findings": 12
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Update All Binary Statuses**
```http
POST /api/binaries/update-all-statuses
```

Update the analysis status for all binaries based on their current analysis results.

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Updated status for 5 binaries",
    "updated_binaries": [
      {
        "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "filename": "example.exe",
        "old_status": "analyzing",
        "new_status": "completed"
      },
      {
        "binary_id": "b2c3d4e5-f6g7-8901-bcde-f234567890ab",
        "filename": "malware.dll",
        "old_status": "processed",
        "new_status": "failed",
        "reason": "No functions found - resource-only file"
      }
    ],
    "skipped_binaries": [
      {
        "binary_id": "c3d4e5f6-g7h8-9012-cdef-234567890abc",
        "filename": "library.so",
        "status": "analyzing",
        "reason": "Analysis still in progress"
      }
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Get Fuzzing-Ready Binaries**
```http
GET /api/binaries/fuzzing-ready
```

Get a list of binaries that are ready for fuzzing harness generation.

**Response:**
```json
{
  "success": true,
  "data": {
    "binaries": [
      {
        "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "filename": "example.exe",
        "analysis_status": "completed",
        "function_count": 42,
        "security_findings_count": 5,
        "high_risk_functions": 3,
        "fuzzing_potential": "HIGH",
        "existing_harnesses": 1
      }
    ],
    "summary": {
      "total_fuzzing_ready": 3,
      "high_potential": 2,
      "medium_potential": 1,
      "existing_harnesses": 4
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 🗑️ **Binary Deletion**

### **Delete Binary**
```http
DELETE /api/binaries/{binary_id}
```

Delete a binary and all associated data including functions, analysis results, security findings, and fuzzing harnesses.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary to delete

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Binary example.exe and all associated data deleted successfully",
    "deleted_data": {
      "binary_file": true,
      "database_records": {
        "functions": 42,
        "analysis_results": 3,
        "security_findings": 5,
        "fuzzing_harnesses": 1,
        "fuzzing_targets": 3,
        "tasks": 8
      },
      "related_files": {
        "temp_files": 2,
        "cache_files": 1,
        "project_files": 1
      }
    },
    "cleanup_summary": {
      "cancelled_tasks": 0,
      "freed_disk_space": "1.2MB",
      "database_records_removed": 62
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response (Error - Binary Not Found):**
```json
{
  "success": false,
  "error": "Binary not found",
  "details": {
    "binary_id": "invalid-uuid-12345",
    "possible_causes": [
      "Binary ID does not exist",
      "Binary was already deleted",
      "Invalid UUID format"
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Response (Error - Active Tasks):**
```json
{
  "success": false,
  "error": "Cannot delete binary with active analysis tasks",
  "details": {
    "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "active_tasks": [
      {
        "task_id": "task_456",
        "task_type": "comprehensive",
        "status": "running",
        "progress": 65
      }
    ],
    "suggestion": "Cancel active tasks first or wait for completion"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 📊 **Bulk Operations**

### **Bulk Analysis Status Update**
```http
POST /api/binaries/bulk-update-status
Content-Type: application/json

{
  "binary_ids": [
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "b2c3d4e5-f6g7-8901-bcde-f234567890ab"
  ]
}
```

Update analysis status for multiple binaries simultaneously.

**Request Body:**
```json
{
  "binary_ids": ["array of binary UUIDs"],
  "force_update": false
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "updated_count": 2,
    "failed_count": 0,
    "results": [
      {
        "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "filename": "example.exe",
        "status_updated": true,
        "old_status": "analyzing",
        "new_status": "completed"
      }
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Bulk Binary Deletion**
```http
POST /api/binaries/bulk-delete
Content-Type: application/json

{
  "binary_ids": [
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "b2c3d4e5-f6g7-8901-bcde-f234567890ab"
  ],
  "force_delete": false
}
```

Delete multiple binaries and their associated data.

**Request Body:**
```json
{
  "binary_ids": ["array of binary UUIDs"],
  "force_delete": false,
  "cancel_active_tasks": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "deleted_count": 2,
    "failed_count": 0,
    "total_records_deleted": 156,
    "total_disk_space_freed": "2.4MB",
    "results": [
      {
        "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "filename": "example.exe",
        "deleted": true,
        "records_deleted": 78
      }
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 🔧 **Error Handling**

### **Common Error Responses**

#### **Ghidra Bridge Not Connected**
```json
{
  "success": false,
  "error": "Ghidra Bridge is not connected",
  "details": {
    "service": "ghidra_bridge",
    "status": "disconnected",
    "last_connection": "2024-01-15T09:30:00Z",
    "troubleshooting": [
      "Check if Ghidra Bridge is running on port 4768",
      "Verify Ghidra installation path in configuration",
      "Restart Ghidra Bridge service"
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### **Analysis Task Failed**
```json
{
  "success": false,
  "error": "Analysis task failed",
  "details": {
    "task_id": "task_456",
    "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "error_type": "timeout",
    "error_message": "Analysis exceeded maximum timeout of 3600 seconds",
    "recovery_options": [
      "Retry with increased timeout",
      "Use quick analysis instead",
      "Check binary file integrity"
    ]
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

#### **Invalid Binary Format**
```json
{
  "success": false,
  "error": "Invalid binary format",
  "details": {
    "filename": "document.txt",
    "detected_type": "text/plain",
    "required_types": [
      "application/x-executable",
      "application/x-msdownload",
      "application/x-sharedlib"
    ],
    "suggestion": "Upload a valid binary executable file"
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 📈 **Usage Examples**

### **Complete Upload and Analysis Workflow**
```bash
#!/bin/bash

# 1. Upload a binary
UPLOAD_RESPONSE=$(curl -X POST "http://localhost:5000/api/binaries" \
  -F "file=@example.exe" \
  -H "Accept: application/json")

BINARY_ID=$(echo $UPLOAD_RESPONSE | jq -r '.data.binary.id')
echo "Binary uploaded with ID: $BINARY_ID"

# 2. Wait for automatic basic analysis to complete
echo "Waiting for basic analysis..."
while true; do
  STATUS=$(curl -s "http://localhost:5000/api/binaries/$BINARY_ID" | \
    jq -r '.data.binary.analysis_status')
  
  if [ "$STATUS" = "completed" ]; then
    echo "Basic analysis completed"
    break
  elif [ "$STATUS" = "failed" ]; then
    echo "Analysis failed"
    exit 1
  fi
  
  sleep 5
done

# 3. Start comprehensive analysis
echo "Starting comprehensive analysis..."
ANALYSIS_RESPONSE=$(curl -X POST "http://localhost:5000/api/binaries/$BINARY_ID/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "analysis_type": "comprehensive",
    "parameters": {
      "decompile_functions": true,
      "extract_strings": true,
      "analyze_imports": true
    }
  }')

TASK_ID=$(echo $ANALYSIS_RESPONSE | jq -r '.data.task.id')
echo "Comprehensive analysis started with task ID: $TASK_ID"

# 4. Monitor analysis progress
echo "Monitoring analysis progress..."
while true; do
  TASK_STATUS=$(curl -s "http://localhost:5000/api/tasks/$TASK_ID/status" | \
    jq -r '.task.status')
  
  if [ "$TASK_STATUS" = "completed" ]; then
    echo "Comprehensive analysis completed"
    break
  elif [ "$TASK_STATUS" = "failed" ]; then
    echo "Comprehensive analysis failed"
    exit 1
  fi
  
  PROGRESS=$(curl -s "http://localhost:5000/api/tasks/$TASK_ID/status" | \
    jq -r '.task.progress')
  echo "Progress: $PROGRESS%"
  
  sleep 10
done

# 5. Get final results
echo "Retrieving analysis results..."
curl -s "http://localhost:5000/api/binaries/$BINARY_ID" | jq '.data.statistics'
```

### **Batch Binary Processing**
```python
import requests
import time
import glob

API_BASE = "http://localhost:5000/api"

def upload_and_analyze_directory(directory_path):
    """Upload and analyze all binaries in a directory"""
    binary_files = glob.glob(f"{directory_path}/*.exe") + \
                   glob.glob(f"{directory_path}/*.dll")
    
    uploaded_binaries = []
    
    for file_path in binary_files:
        # Upload binary
        with open(file_path, 'rb') as f:
            files = {'file': f}
            response = requests.post(f"{API_BASE}/binaries", files=files)
            
        if response.status_code == 201:
            binary_data = response.json()['data']['binary']
            uploaded_binaries.append(binary_data)
            print(f"Uploaded: {binary_data['original_filename']}")
        else:
            print(f"Failed to upload: {file_path}")
    
    # Wait for all uploads to complete basic analysis
    for binary in uploaded_binaries:
        wait_for_analysis_completion(binary['id'])
        
    # Start comprehensive analysis for all
    for binary in uploaded_binaries:
        start_comprehensive_analysis(binary['id'])
    
    return uploaded_binaries

def wait_for_analysis_completion(binary_id):
    """Wait for binary analysis to complete"""
    while True:
        response = requests.get(f"{API_BASE}/binaries/{binary_id}")
        if response.status_code == 200:
            status = response.json()['data']['binary']['analysis_status']
            if status in ['completed', 'failed']:
                return status
        time.sleep(5)

def start_comprehensive_analysis(binary_id):
    """Start comprehensive analysis for a binary"""
    payload = {
        "analysis_type": "comprehensive",
        "parameters": {
            "decompile_functions": True,
            "extract_strings": True,
            "analyze_imports": True
        }
    }
    
    response = requests.post(
        f"{API_BASE}/binaries/{binary_id}/analyze",
        json=payload
    )
    
    if response.status_code == 200:
        task_id = response.json()['data']['task']['id']
        print(f"Started comprehensive analysis: {task_id}")
        return task_id
    else:
        print(f"Failed to start analysis for binary {binary_id}")
        return None

# Usage
if __name__ == "__main__":
    binaries = upload_and_analyze_directory("./samples")
    print(f"Processed {len(binaries)} binaries")
```

---

## 🔍 **Best Practices**

### **Optimal Upload Strategy**
1. **Batch Uploads**: Upload multiple related binaries together
2. **File Validation**: Verify file types before upload
3. **Size Management**: Keep files under 100MB for optimal performance
4. **Naming**: Use descriptive filenames for easy identification

### **Analysis Optimization**
1. **Start with Basic**: Let automatic basic analysis complete first
2. **Selective Comprehensive**: Use comprehensive analysis for important binaries
3. **Monitor Progress**: Check task status regularly during long analyses
4. **Resource Management**: Limit concurrent analyses to prevent overload

### **Error Recovery**
1. **Retry Logic**: Implement exponential backoff for failed requests
2. **Status Monitoring**: Regular status checks for long-running operations
3. **Graceful Degradation**: Handle service unavailability gracefully
4. **Cleanup**: Delete failed or unnecessary binaries to free resources

### **Performance Considerations**
1. **Pagination**: Use appropriate page sizes for large binary lists
2. **Filtering**: Use query parameters to reduce response sizes
3. **Caching**: Cache frequently accessed binary information
4. **Parallel Processing**: Process multiple binaries concurrently when possible

---

The Binary Management API provides comprehensive functionality for the complete binary analysis lifecycle in ShadowSeek. For additional examples and integration patterns, see the [API Examples](../examples/api-examples.md) documentation. 