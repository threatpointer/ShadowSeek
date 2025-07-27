# ShadowSeek - REST API Documentation

## 🔍 **Advanced Binary Security Analysis API**

ShadowSeek provides a comprehensive REST API for AI-powered binary security analysis. This API enables automated binary analysis, vulnerability detection, AI-enhanced explanations, and fuzzing harness generation.

**Current Version**: 2.1.0  
**Base URL**: `http://localhost:5000/api`  
**Interactive Documentation**: `http://localhost:5000/api/docs/`

---

## 🚀 **Quick Start**

### **Start the API Server**
```bash
# Method 1: Full platform startup
start_all.bat  # Windows
./start_all.sh # Linux/macOS

# Method 2: Backend only
python run.py
```

### **Test API Connection**
```bash
# Health check
curl http://localhost:5000/api/system/status

# Expected response
{
  "status": "ok",
  "binaries": 5,
  "ghidra_bridge": "connected",
  "server_time": "2024-01-15T10:30:00Z"
}
```

### **Upload Your First Binary**
```bash
curl -X POST "http://localhost:5000/api/binaries" \
     -H "Content-Type: multipart/form-data" \
     -F "file=@your_binary.exe"
```

### **Compare Two Binaries**
```bash
# Upload second binary first, then compare
curl -X POST "http://localhost:5000/api/analysis/diff" \
     -H "Content-Type: application/json" \
     -d '{"binary_id1":"uuid1","binary_id2":"uuid2","performance_mode":"balanced"}'
```

---

## 📊 **API Architecture**

```mermaid
graph TB
    A[Client Application] --> B[REST API :5000]
    B --> C[Task Manager]
    B --> D[AI Services]
    B --> E[Security Analyzer]
    B --> L[Binary Comparison Engine]
    B --> M[Web Search Service]
    
    C --> F[Ghidra Bridge :4768]
    F --> G[Ghidra Analysis]
    
    L --> N[ghidriff CLI]
    N --> G
    
    D --> H[OpenAI GPT-4]
    D --> I[Anthropic Claude]
    D --> O[Google Gemini]
    
    M --> P[DuckDuckGo API]
    M --> Q[CVE Databases]
    
    B --> J[SQLite Database]
    B --> K[File Storage]
    
    style A fill:#e3f2fd
    style B fill:#f3e5f5
    style J fill:#fff3e0
    style L fill:#e8f5e8
    style M fill:#fce4ec
```

---

## 🔍 **Binary Differential Analysis Engine**

### **Acknowledgments & Credits**

ShadowSeek's binary comparison capabilities are powered by **[ghidriff](https://github.com/clearbluejar/ghidriff)**, an exceptional open-source binary diffing engine created by **[@clearbluejar](https://clearbluejar.github.io/)** ([@clearbluejar on X/Twitter](https://x.com/clearbluejar)).

**ghidriff** is a powerful command-line binary diffing engine built on top of **Ghidra**, the NSA's flagship software reverse engineering framework. We extend our sincere gratitude to the original authors for their outstanding work and contribution to the reverse engineering community.

**Key Technologies:**
- **ghidriff**: Binary diffing engine (BSD 3-Clause License)
- **Ghidra**: NSA's Software Reverse Engineering Framework
- **Original Repository**: [github.com/clearbluejar/ghidriff](https://github.com/clearbluejar/ghidriff)
- **Documentation**: [clearbluejar.github.io](https://clearbluejar.github.io/)

### **System Architecture**

ShadowSeek integrates ghidriff through a sophisticated wrapper architecture that provides enterprise-grade features while maintaining the core functionality of the original tool:

```mermaid
graph TB
    A[ShadowSeek REST API] --> B[Binary Comparison Controller]
    B --> C[ghidriff Wrapper Service]
    C --> D[Performance Mode Manager]
    C --> E[Task Management System]
    C --> F[Database Integration Layer]
    
    D --> G[ghidriff CLI Process]
    G --> H[Ghidra Analysis Engine]
    H --> I[Binary Analysis Pipeline]
    
    I --> J[Simple Diff]
    I --> K[Version Tracking Diff] 
    I --> L[Structural Graph Diff]
    
    G --> M[Results Parser]
    M --> N[Markdown Report]
    M --> O[JSON Metadata]
    M --> P[Mermaid Diagrams]
    
    F --> Q[SQLite Database]
    E --> R[Background Task Queue]
    
    style A fill:#e3f2fd
    style G fill:#fff3e0
    style H fill:#f3e5f5
    style Q fill:#e8f5e8
```

### **Technical Implementation Details**

#### **Core Integration Components**

1. **ghidriff Wrapper Service** (`analysis_scripts/ghidriff_simple_wrapper.py`)
   - **Purpose**: Bridges ShadowSeek's REST API with ghidriff's command-line interface
   - **Features**: Process management, timeout handling, result parsing, database integration
   - **Performance Optimization**: Dynamic JVM tuning, memory management, multi-threading support

2. **Command Execution Engine**
   ```python
   # Example ghidriff command execution
   ghidriff_cmd = [
       "python", "-m", "ghidriff", 
       binary1_path, binary2_path,
       "--engine", diff_type,
       "--output-dir", results_dir,
       "--project-location", project_dir,
       "--log-level", "INFO"
   ]
   ```

3. **Performance Mode Configuration**
   - **Speed Mode**: Optimized for quick comparisons with reduced analysis depth
   - **Balanced Mode**: Standard analysis with reasonable performance/accuracy trade-off  
   - **Accuracy Mode**: Deep analysis with maximum precision and detail

#### **Supported Diff Types**

| Diff Type | Description | ghidriff Engine | Use Case |
|-----------|-------------|-----------------|----------|
| **Simple** | Basic function-level comparison | `SimpleDiff` | Quick version comparisons |
| **Version Tracking** | Advanced version tracking analysis | `VersionTrackingDiff` | Detailed change tracking |
| **Structural Graph** | Graph-based structural analysis | `StructuralGraphDiff` | Architecture comparisons |

#### **JVM & Memory Optimization**

Our implementation includes intelligent JVM tuning for optimal performance:

```python
# Dynamic JVM argument generation
jvm_args = [
    f"-Xmx{max_memory}g",      # Maximum heap size
    f"-Xms{initial_memory}g",   # Initial heap size  
    "-XX:+UseG1GC",            # G1 Garbage Collector
    "-XX:MaxGCPauseMillis=200", # GC pause time limit
    "-Dghidra.analysis.timeout=1800"  # Analysis timeout
]
```

**Memory allocation strategy:**
- **Speed Mode**: 4GB heap, simplified analysis
- **Balanced Mode**: 6GB heap, standard features
- **Accuracy Mode**: 8GB heap, comprehensive analysis

#### **Result Processing Pipeline**

1. **Raw Output Collection**
   - Markdown reports (`.ghidriff.md`)
   - JSON metadata files
   - Ghidra project artifacts
   - Analysis logs and statistics

2. **Content Parsing & Enhancement**
   - Markdown content extraction and validation
   - Mermaid diagram detection and rendering
   - Function statistics calculation
   - Performance metrics aggregation

3. **Database Integration**
   - Automatic result persistence
   - Metadata indexing for search
   - Historical comparison tracking
   - Task status management

#### **Error Handling & Resilience**

- **Timeout Management**: Configurable timeouts per performance mode
- **Process Monitoring**: Real-time process health checking
- **Graceful Degradation**: Partial results on analysis failures
- **Resource Cleanup**: Automatic cleanup of temporary files and processes

#### **Security & Isolation**

- **Process Sandboxing**: ghidriff runs in isolated subprocess
- **Resource Limits**: Memory and CPU usage constraints
- **File System Security**: Controlled access to analysis directories
- **Input Validation**: Binary file validation before analysis

### **API Integration Points**

#### **Primary Endpoints**
- `POST /api/analysis/diff` - Initiate binary comparison
- `GET /api/analysis/diff/{task_id}` - Monitor comparison progress
- `GET /api/analysis/results` - List historical comparisons
- `DELETE /api/analysis/results/{result_id}` - Clean up old results

#### **Performance Monitoring**
- Real-time progress tracking via task management system
- Execution time metrics and performance analytics
- Resource utilization monitoring (CPU, memory, disk I/O)
- Success/failure rate statistics

### **Usage Patterns & Best Practices**

#### **Recommended Workflows**

1. **Quick Version Comparison**
   ```bash
   # Fast comparison for similar binaries
   curl -X POST "/api/analysis/diff" \
        -d '{"binary_id1":"uuid1","binary_id2":"uuid2","performance_mode":"speed"}'
   ```

2. **Detailed Analysis**
   ```bash
   # Comprehensive analysis with structural graphs
   curl -X POST "/api/analysis/diff" \
        -d '{"diff_type":"structural_graph","performance_mode":"accuracy"}'
   ```

3. **Batch Processing**
   - Use "balanced" mode for multiple comparisons
   - Monitor system resources during bulk operations
   - Implement queue management for large-scale analysis

#### **Performance Optimization Tips**

- **Binary Size**: Larger binaries (>100MB) benefit from "speed" mode
- **Analysis Depth**: Use "simple" diff type for basic comparisons
- **System Resources**: Ensure adequate RAM (8GB+ recommended)
- **Concurrent Tasks**: Limit simultaneous comparisons based on available memory

### **Integration Benefits**

**Enhanced Features Over Standalone ghidriff:**
- ✅ **Web-based Interface**: User-friendly React frontend
- ✅ **REST API Access**: Programmatic integration capabilities  
- ✅ **Persistent Storage**: Database-backed result management
- ✅ **Task Management**: Background processing with progress tracking
- ✅ **Performance Modes**: Configurable analysis depth and speed
- ✅ **AI Integration**: Enhanced result interpretation with LLM analysis
- ✅ **Multi-format Support**: Enhanced rendering of reports and diagrams

**Maintained ghidriff Advantages:**
- ✅ **Ghidra Integration**: Full access to Ghidra's analysis capabilities
- ✅ **Multiple Diff Engines**: All three ghidriff diff types supported
- ✅ **Comprehensive Reports**: Rich markdown reports with diagrams
- ✅ **Open Source Foundation**: Built on proven, community-driven tools

---

## 🔧 **System Management**

### **Get System Status**
```http
GET /api/system/status
```

**Response:**
```json
{
  "status": "ok",
  "binaries": 42,
  "tasks": {
    "total": 156,
    "running": 3,
    "queued": 7,
    "completed": 146
  },
  "ghidra_bridge": "connected",
  "ghidra_bridge_connected": true,
  "ai_services": {
    "openai": "available",
    "task_manager": "ready",
    "security_analyzer": "ready"
  },
  "server_time": "2024-01-15T10:30:00Z",
  "version": "2.1.0"
}
```

### **Test Ghidra Bridge Connection**
```http
GET /api/bridge/test
```

**Response:**
```json
{
  "connected": true,
  "status": "Bridge connection successful",
  "ghidra_version": "10.4",
  "port": 4768,
  "response_time_ms": 45
}
```

### **Check AI Service Status**
```http
GET /api/ai/status
```

**Response:**
```json
{
  "task_manager_ai": {
    "initialized": true,
    "api_key_configured": true,
    "model": "gpt-4o-mini"
  },
  "enhanced_security_analyzer_ai": {
    "initialized": true,
    "api_key_configured": true,
    "model": "gpt-4o-mini"
  },
  "overall_status": "ready"
}
```

---

## 📁 **Binary Management**

### **Upload Binary**
```http
POST /api/binaries
Content-Type: multipart/form-data
```

**Parameters:**
- `file`: Binary file (required)
- `analysis_type`: Analysis type (optional, default: "comprehensive")

**Response:**
```json
{
  "success": true,
  "binary": {
    "id": "uuid-here",
    "filename": "example.exe",
    "file_size": 1024000,
    "file_hash": "sha256-hash",
    "analysis_status": "queued",
    "upload_time": "2024-01-15T10:30:00Z"
  },
  "task": {
    "id": "task-uuid",
    "type": "comprehensive_analysis",
    "status": "queued"
  }
}
```

### **List All Binaries**
```http
GET /api/binaries
```

**Query Parameters:**
- `page`: Page number (default: 1)
- `limit`: Results per page (default: 20)
- `status`: Filter by analysis status

**Response:**
```json
{
  "binaries": [
    {
      "id": "uuid-here",
      "filename": "example.exe",
      "file_size": 1024000,
      "analysis_status": "completed",
      "function_count": 157,
      "upload_time": "2024-01-15T10:30:00Z",
      "analysis_time": "2024-01-15T10:35:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 42,
    "pages": 3
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
    "id": "uuid-here",
    "filename": "example.exe",
    "file_size": 1024000,
    "file_hash": "sha256-hash",
    "analysis_status": "completed",
    "architecture": "x86_64",
    "file_type": "PE",
    "function_count": 157,
    "decompiled_functions": 134,
    "ai_analyzed_functions": 89,
    "upload_time": "2024-01-15T10:30:00Z"
  },
  "statistics": {
    "total_functions": 157,
    "total_strings": 342,
    "total_symbols": 89,
    "total_imports": 45,
    "total_exports": 12,
    "analysis_duration": 180.5
  }
}
```

### **Delete Binary**
```http
DELETE /api/binaries/{binary_id}
```

**Response:**
```json
{
  "success": true,
  "message": "Binary and all associated data deleted successfully"
}
```

---

## 🔧 **Function Analysis**

### **Get Function Details**
```http
GET /api/functions/{function_id}
```

**Response:**
```json
{
  "function": {
    "id": "function-uuid",
    "name": "validateInput",
    "address": "0x401000",
    "size": 256,
    "signature": "bool validateInput(char* input, int length)",
    "calling_convention": "__fastcall",
    "is_decompiled": true,
    "is_ai_analyzed": true,
    "decompiled_code": "bool validateInput(char* input, int length) {\n  // ... code ...\n}",
    "ai_summary": "This function validates user input but contains a buffer overflow vulnerability...",
    "risk_score": 85
  }
}
```

### **Decompile Function**
```http
POST /api/functions/{function_id}/decompile
```

**Response:**
```json
{
  "success": true,
  "function_id": "function-uuid",
  "decompiled_code": "bool validateInput(char* input, int length) {\n  // ... decompiled code ...\n}",
  "signature": "bool validateInput(char*, int)",
  "cached": false,
  "analysis_time": 3.2
}
```

### **AI Explain Function**
```http
POST /api/functions/{function_id}/explain
```

**Response:**
```json
{
  "success": true,
  "function_id": "function-uuid",
  "ai_summary": "This function validates user input for authentication. It checks input length and content but contains a critical buffer overflow vulnerability when processing inputs longer than the allocated buffer size. The function uses unsafe string operations without proper bounds checking.",
  "risk_score": 85,
  "vulnerabilities": ["buffer_overflow", "input_validation"],
  "cached": false,
  "analysis_time": 8.7,
  "model_used": "gpt-4o-mini"
}
```

### **Bulk Decompile Functions**
```http
POST /api/binaries/{binary_id}/decompile-all
```

**Response:**
```json
{
  "success": true,
  "task_id": "bulk-task-uuid",
  "message": "Bulk decompilation started",
  "total_functions": 157,
  "functions_to_decompile": 89,
  "already_decompiled": 68
}
```

### **Bulk AI Analysis**
```http
POST /api/binaries/{binary_id}/ai-explain-all
```

**Response:**
```json
{
  "success": true,
  "task_id": "ai-task-uuid",
  "message": "Bulk AI analysis started",
  "total_functions": 157,
  "functions_to_analyze": 134,
  "already_analyzed": 23
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
  "success": true,
  "total_findings": 3,
  "findings": [
    {
      "id": "finding-uuid",
      "vulnerability": "Buffer Overflow",
      "severity": "HIGH",
      "confidence": 94.2,
      "cwe": "CWE-120",
      "function_name": "validateInput",
      "function_address": "0x401000",
      "evidence": "strcpy() used without bounds checking",
      "ai_explanation": "Function copies user input to fixed buffer without length validation",
      "recommendation": "Use strncpy() or implement proper bounds checking"
    }
  ],
  "risk_assessment": {
    "overall_risk": "HIGH",
    "exploit_difficulty": "LOW",
    "impact_severity": "CRITICAL"
  }
}
```

### **Analyze Binary Security**
```http
POST /api/binaries/{binary_id}/security-analysis
```

**Response:**
```json
{
  "success": true,
  "binary_id": "binary-uuid",
  "analysis_method": "unified_security_analysis",
  "total_findings": 15,
  "findings_by_severity": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 6,
    "LOW": 2
  },
  "confidence_metrics": {
    "average_confidence": 91.3,
    "high_confidence_findings": 12,
    "validated_by_ai": 15
  },
  "analysis_summary": {
    "buffer_overflows": 3,
    "format_string_bugs": 1,
    "command_injection": 2,
    "crypto_weaknesses": 1,
    "other_vulnerabilities": 8
  }
}
```

### **Enhanced Security Analysis** (for binaries without functions)
```http
POST /api/binaries/{binary_id}/enhanced-security-analysis
```

**Response:**
```json
{
  "success": true,
  "binary_id": "binary-uuid",
  "analysis_method": "enhanced_multi_modal",
  "data_sources": ["exports", "strings", "imports", "memory", "ai_analysis"],
  "total_findings": 8,
  "analysis_phases": {
    "export_analysis": "completed",
    "string_analysis": "completed", 
    "import_analysis": "completed",
    "ai_correlation": "completed"
  }
}
```

---

## 🔄 **Binary Comparison**

### **Compare Two Binaries**
```http
POST /api/analysis/diff
```

**Request Body:**
```json
{
  "binary_id1": "uuid-of-first-binary",
  "binary_id2": "uuid-of-second-binary", 
  "diff_type": "simple",
  "performance_mode": "balanced"
}
```

**Parameters:**
- `binary_id1` (required): UUID of the first binary to compare
- `binary_id2` (required): UUID of the second binary to compare  
- `diff_type` (optional): Analysis type - `"simple"`, `"version_tracking"`, or `"structural_graph"` (default: `"simple"`)
- `performance_mode` (optional): Performance mode - `"speed"`, `"balanced"`, or `"accuracy"` (default: `"balanced"`)

**Response:**
```json
{
  "success": true,
  "task_id": "comparison-task-uuid",
  "binary_id1": "uuid-of-first-binary",
  "binary_id2": "uuid-of-second-binary",
  "diff_type": "simple",
  "performance_mode": "balanced",
  "status": "running",
  "message": "Binary comparison started successfully"
}
```

### **Get Comparison Results**
```http
GET /api/analysis/diff/{task_id}
```

**Response:**
```json
{
  "success": true,
  "task_id": "comparison-task-uuid",
  "status": "completed",
  "binary_names": {
    "binary1": "program_v1.exe",
    "binary2": "program_v2.exe"
  },
  "summary": {
    "functions_added": 12,
    "functions_deleted": 5,
    "functions_modified": 8,
    "match_percentage": 87.3
  },
  "markdown_report": "# Binary Comparison Report...",
  "execution_time": 145.7,
  "completed_at": "2024-01-15T10:30:00Z"
}
```

### **List Past Comparison Results**
```http
GET /api/analysis/results
```

**Query Parameters:**
- `limit` (optional): Maximum number of results (default: 50)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
  "results": [
    {
      "id": "result-uuid",
      "task_id": "comparison-task-uuid",
      "binary_names": {
        "binary1": "program_v1.exe", 
        "binary2": "program_v2.exe"
      },
      "success": true,
      "functions_added": 12,
      "functions_deleted": 5,
      "functions_modified": 8,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 25,
  "limit": 50,
  "offset": 0
}
```

### **Delete Comparison Result**
```http
DELETE /api/analysis/results/{result_id}
```

**Response:**
```json
{
  "success": true,
  "message": "Analysis result deleted successfully"
}
```

---

## 🤖 **AI-Powered Insights**

### **Get AI Insights for Binary Comparison**
```http
POST /api/ai/insights
```

**Request Body:**
```json
{
  "context": {
    "binary1": "program_v1.exe",
    "binary2": "program_v2.exe",
    "functionStats": {
      "total_funcs_len": 245,
      "total_changes": 25
    },
    "addedFunctions": 12,
    "deletedFunctions": 5,
    "modifiedFunctions": 8
  },
  "includeWebSearch": true,
  "searchQueries": [
    "program_v1.exe security vulnerabilities CVE",
    "program_v2.exe security vulnerabilities CVE", 
    "program_v1.exe program_v2.exe changelog release notes"
  ]
}
```

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "binaryNames": {
    "binary1": "program_v1.exe",
    "binary2": "program_v2.exe"
  },
  "securityFindings": [
    {
      "title": "CVE-2024-1234 - Buffer Overflow in program_v1.exe",
      "description": "Critical buffer overflow vulnerability found in version 1.0",
      "severity": "high",
      "cveId": "CVE-2024-1234",
      "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    }
  ],
  "versionAnalysis": {
    "summary": "The transition shows expansion with 12 new functions added and 5 removed, suggesting feature enhancements.",
    "releaseNotes": [
      "Modified 8 existing functions for improvements or bug fixes",
      "Added 12 new functions for enhanced functionality", 
      "Removed 5 deprecated or unnecessary functions"
    ]
  },
  "researchLinks": [
    {
      "title": "Security Analysis of Program Updates",
      "description": "Research paper analyzing security improvements in program updates",
      "url": "https://example.com/research-paper"
    }
  ],
  "recommendations": [
    "🧪 TESTING FOCUS: With 12 new functions, conduct comprehensive integration testing",
    "🔄 REGRESSION TESTING: 8 functions modified. Perform thorough regression testing",
    "📚 DOCUMENTATION: Update user documentation to reflect functional changes"
  ]
}
```

---

## 📥 **Data Management**

### **Import Existing Results**
```http
POST /api/import-results
```

**Description:** Import previously generated analysis results from the filesystem into the database.

**Response:**
```json
{
  "success": true,
  "imported_count": 15,
  "failed_count": 2,
  "total_processed": 17,
  "results": [
    "✅ Imported: task-uuid-1",
    "✅ Imported: task-uuid-2", 
    "❌ Failed: task-uuid-3 - Invalid JSON format",
    "⚠️  Skipped: task-uuid-4 (already exists)"
  ]
}
```

---

## 🎯 **Fuzzing Harness Generation**

### **Generate Fuzzing Harness**
```http
POST /api/binaries/{binary_id}/generate-fuzzing-harness
```

**Request Body:**
```json
{
  "target_functions": ["validateInput", "processCommand"],
  "fuzzer_type": "afl++",
  "coverage_guided": true,
  "include_setup": true
}
```

**Response:**
```json
{
  "success": true,
  "harness_id": "harness-uuid",
  "target_functions": ["validateInput", "processCommand"],
  "fuzzer_type": "afl++",
  "files_generated": [
    "fuzzing_harness.c",
    "Makefile",
    "README.md",
    "setup.sh"
  ],
  "ai_rationale": "Selected functions based on high-risk security findings and input processing capabilities"
}
```

### **List Fuzzing Harnesses**
```http
GET /api/binaries/{binary_id}/fuzzing-harnesses
```

**Response:**
```json
{
  "harnesses": [
    {
      "id": "harness-uuid",
      "binary_id": "binary-uuid",
      "target_functions": ["validateInput"],
      "fuzzer_type": "afl++",
      "created_at": "2024-01-15T10:30:00Z",
      "status": "ready",
      "performance_score": 87.3
    }
  ]
}
```

### **Download Harness**
```http
GET /api/fuzzing-harnesses/{harness_id}/download
```

**Response:** ZIP file containing fuzzing harness code and documentation

---

## 📊 **Task Management**

### **Get Task Status**
```http
GET /api/tasks/{task_id}
```

**Response:**
```json
{
  "task": {
    "id": "task-uuid",
    "type": "bulk_ai_explain",
    "status": "running",
    "progress": {
      "current": 45,
      "total": 157,
      "percentage": 28.7
    },
    "created_at": "2024-01-15T10:30:00Z",
    "started_at": "2024-01-15T10:30:15Z",
    "estimated_completion": "2024-01-15T10:45:00Z"
  }
}
```

### **Cancel Task**
```http
DELETE /api/tasks/{task_id}
```

**Response:**
```json
{
  "success": true,
  "message": "Task cancelled successfully"
}
```

### **List Tasks**
```http
GET /api/tasks?status=running&binary_id=uuid-here
```

**Response:**
```json
{
  "tasks": [
    {
      "id": "task-uuid",
      "type": "comprehensive_analysis",
      "status": "running",
      "binary_id": "binary-uuid",
      "created_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

## ⚙️ **Configuration Management**

### **Get Configuration**
```http
GET /api/config
```

**Response:**
```json
{
  "llm_provider": "openai",
  "openai_api_key": "sk-...",
  "openai_model": "gpt-4o-mini",
  "ghidra_install_dir": "/path/to/ghidra",
  "ghidra_bridge_port": 4768,
  "flask_port": 5000,
  "analysis_timeout": 1800,
  "max_file_size": 1073741824
}
```

### **Update Configuration**
```http
POST /api/config
Content-Type: application/json
```

**Request Body:**
```json
{
  "openai_api_key": "sk-new-api-key-here",
  "openai_model": "gpt-4o-mini",
  "analysis_timeout": 2400
}
```

**Response:**
```json
{
  "status": "success",
  "message": "Configuration updated successfully. Updated 3 settings.",
  "updated_keys": ["openai_api_key", "openai_model", "analysis_timeout"],
  "ai_services_reloaded": true
}
```

### **Test AI Connection**
```http
POST /api/config/test-connection
Content-Type: application/json
```

**Request Body:**
```json
{
  "provider": "openai",
  "api_key": "sk-test-key-here",
  "model": "gpt-4o-mini"
}
```

**Response:**
```json
{
  "success": true,
  "message": "OpenAI connection test successful!"
}
```

---

## 📋 **Supported File Types**

| Format | Extensions | Description |
|--------|------------|-------------|
| **Windows PE** | `.exe`, `.dll`, `.sys`, `.obj` | Windows executables and libraries |
| **Linux ELF** | `.so`, `.elf`, `.a`, `.o` | Linux executables and shared objects |
| **macOS Mach-O** | `.dylib`, `.app`, `.framework` | macOS binaries and frameworks |
| **Generic Binary** | `.bin`, `.hex`, `.raw` | Raw binary files |

---

## 🔧 **Error Handling**

### **Standard Error Response**
```json
{
  "error": "Binary not found",
  "error_code": "BINARY_NOT_FOUND",
  "status": 404,
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req-uuid-here"
}
```

### **Common Error Codes**

| Code | Status | Description |
|------|--------|-------------|
| `BINARY_NOT_FOUND` | 404 | Binary ID not found |
| `FUNCTION_NOT_FOUND` | 404 | Function ID not found |
| `ANALYSIS_FAILED` | 500 | Analysis process failed |
| `AI_SERVICE_ERROR` | 503 | AI service unavailable |
| `BRIDGE_DISCONNECTED` | 503 | Ghidra Bridge not connected |
| `INVALID_FILE_TYPE` | 400 | Unsupported file format |
| `FILE_TOO_LARGE` | 413 | File exceeds size limit |

---

## 🚀 **API Usage Examples**

### **Complete Analysis Workflow**
```python
import requests
import time

base_url = "http://localhost:5000/api"

# 1. Upload binaries
with open("target_v1.exe", "rb") as f:
    response1 = requests.post(f"{base_url}/binaries", files={"file": f})
    binary_id1 = response1.json()["binary"]["id"]

with open("target_v2.exe", "rb") as f:
    response2 = requests.post(f"{base_url}/binaries", files={"file": f})
    binary_id2 = response2.json()["binary"]["id"]

# 2. Wait for analysis completion
for binary_id in [binary_id1, binary_id2]:
while True:
    response = requests.get(f"{base_url}/binaries/{binary_id}")
    status = response.json()["binary"]["analysis_status"]
    if status == "completed":
        break
    time.sleep(10)

# 3. Compare binaries
compare_response = requests.post(f"{base_url}/analysis/diff", json={
    "binary_id1": binary_id1,
    "binary_id2": binary_id2,
    "performance_mode": "balanced"
})
task_id = compare_response.json()["task_id"]

# 4. Wait for comparison completion
while True:
    result = requests.get(f"{base_url}/analysis/diff/{task_id}")
    if result.json()["status"] == "completed":
        comparison_data = result.json()
        break
    time.sleep(15)

# 5. Get AI insights
ai_insights = requests.post(f"{base_url}/ai/insights", json={
    "context": {
        "binary1": "target_v1.exe",
        "binary2": "target_v2.exe",
        "addedFunctions": comparison_data["summary"]["functions_added"]
    },
    "includeWebSearch": True,
    "searchQueries": ["target_v1.exe security CVE", "target_v2.exe vulnerabilities"]
})

# 6. Perform security analysis on both binaries  
for binary_id in [binary_id1, binary_id2]:
security_response = requests.post(f"{base_url}/binaries/{binary_id}/security-analysis")
findings = security_response.json()["findings"]

# 7. Generate fuzzing harness
harness_response = requests.post(f"{base_url}/binaries/{binary_id1}/generate-fuzzing-harness")
harness_id = harness_response.json()["harness_id"]

# 8. Download harness
harness_zip = requests.get(f"{base_url}/fuzzing-harnesses/{harness_id}/download")
with open("fuzzing_harness.zip", "wb") as f:
    f.write(harness_zip.content)
```

### **Bulk Function Analysis**
```bash
#!/bin/bash
BINARY_ID="your-binary-uuid"
BASE_URL="http://localhost:5000/api"

# Start bulk decompilation
curl -X POST "$BASE_URL/binaries/$BINARY_ID/decompile-all"

# Wait for completion (check task status)
sleep 300

# Start bulk AI analysis
curl -X POST "$BASE_URL/binaries/$BINARY_ID/ai-explain-all"

# Check progress
curl "$BASE_URL/binaries/$BINARY_ID" | jq '.binary.ai_analyzed_functions'
```

---

## 🎯 **Rate Limits & Performance**

### **API Rate Limits**
- **General API**: 100 requests/minute per IP
- **File Upload**: 10 uploads/minute per IP  
- **AI Analysis**: Limited by configured AI provider
- **Bulk Operations**: 5 concurrent tasks per binary

### **Performance Optimization**
- **Batch Operations**: Use bulk endpoints for multiple functions
- **Caching**: Results cached automatically for repeated requests
- **Async Processing**: Long operations return task IDs for monitoring
- **Connection Pooling**: Reuse connections for better performance

---

## 📊 **API Monitoring**

### **Health Check Endpoint**
```http
GET /api/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "2.1.0",
  "uptime": 86400,
  "components": {
    "database": "healthy",
    "ghidra_bridge": "healthy", 
    "ai_services": "healthy",
    "file_system": "healthy",
    "binary_comparison": "healthy",
    "web_search": "healthy"
  }
}
```

### **Metrics Endpoint**
```http
GET /api/metrics
```

**Response:**
```json
{
  "requests_total": 15420,
  "requests_per_minute": 45.2,
  "active_tasks": 3,
  "average_response_time": 125.6,
  "binaries_analyzed": 234,
  "functions_decompiled": 12456,
  "ai_analyses_completed": 8901,
  "security_findings": 567
}
```

---

**🎉 Ready to integrate ShadowSeek into your security workflow?** Start with the examples above or explore our [complete API integration guide](../examples/api-examples.md).

---

*ShadowSeek API Documentation - Automate AI-Powered Binary Security Analysis*

**Version**: 2.1.0 | **Status**: ✅ Production Ready | **Support**: Check [troubleshooting guide](../user-docs/administration/troubleshooting.md) 