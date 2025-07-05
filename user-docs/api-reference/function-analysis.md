# Function Analysis API

## ⚙️ Function-Level Analysis & Decompilation API

The Function Analysis API provides comprehensive functionality for analyzing individual functions within binaries, including decompilation, AI-powered analysis, and detailed function metadata extraction.

---

## 🌐 **Base Configuration**

**Base URL**: `http://localhost:5000/api`
**Content-Type**: `application/json`

---

## 🔍 **Function Information & Listing**

### **Get Binary Functions**
```http
GET /api/binaries/{binary_id}/functions?page=1&per_page=50&decompiled_only=false&ai_analyzed_only=false&search=main
```

Retrieve all functions discovered in a specific binary with optional filtering and pagination.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary

**Query Parameters:**
- `page` (integer, optional) - Page number (default: 1)
- `per_page` (integer, optional) - Items per page (default: 50, max: 100)
- `decompiled_only` (boolean, optional) - Show only decompiled functions (default: false)
- `ai_analyzed_only` (boolean, optional) - Show only AI-analyzed functions (default: false)
- `search` (string, optional) - Search term for function names
- `external_only` (boolean, optional) - Show only external functions (default: false)
- `sort_by` (string, optional) - Sort field: name, address, size, risk_score (default: address)
- `sort_order` (string, optional) - Sort order: asc, desc (default: asc)

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
        "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "decompiled_at": "2024-01-15T10:15:00Z",
        "ai_analyzed_at": "2024-01-15T10:20:00Z",
        "call_count": 15,
        "complexity_score": 7.2,
        "cyclomatic_complexity": 4,
        "parameters": [
          {
            "id": 456,
            "name": "argc",
            "type": "int",
            "order": 0,
            "description": "Command line argument count"
          },
          {
            "id": 457,
            "name": "argv", 
            "type": "char**",
            "order": 1,
            "description": "Command line argument vector"
          }
        ],
        "local_variables": [
          {
            "id": 789,
            "name": "buffer",
            "type": "char[256]",
            "stack_offset": -256,
            "size": 256
          }
        ],
        "security_summary": {
          "has_findings": true,
          "highest_severity": "HIGH",
          "finding_count": 2,
          "confidence_score": 92.5
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
      "functions_with_security_findings": 12,
      "average_risk_score": 45.3,
      "highest_risk_function": {
        "name": "strcpy_vulnerable",
        "risk_score": 95.2
      }
    }
  },
  "message": "Functions retrieved successfully",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Get Function Details**
```http
GET /api/functions/{function_id}
```

Get comprehensive information about a specific function including decompiled code, AI analysis, and metadata.

**Path Parameters:**
- `function_id` (integer) - ID of the function

**Response:**
```json
{
  "success": true,
  "data": {
    "function": {
      "id": 123,
      "name": "main",
      "address": "0x401000",
      "size": 256,
      "decompiled": true,
      "ai_analyzed": true,
      "risk_score": 85.5,
      "is_external": false,
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "binary_name": "example.exe",
      "decompiled_code": "int main(int argc, char** argv) {\n    char buffer[256];\n    if (argc > 1) {\n        strcpy(buffer, argv[1]);  // Potential buffer overflow\n        printf(\"Input: %s\\n\", buffer);\n    }\n    return 0;\n}",
      "ai_summary": "This function serves as the main entry point for the application. It processes command line arguments but contains a potential buffer overflow vulnerability due to unchecked strcpy usage. The function copies the first command line argument directly into a fixed-size buffer without bounds checking.",
      "decompiled_at": "2024-01-15T10:15:00Z",
      "ai_analyzed_at": "2024-01-15T10:20:00Z",
      "function_type": "entry_point",
      "calling_convention": "cdecl",
      "return_type": "int",
      "complexity_metrics": {
        "cyclomatic_complexity": 4,
        "npath_complexity": 8,
        "lines_of_code": 12,
        "function_points": 3.2
      },
      "parameters": [
        {
          "id": 456,
          "name": "argc",
          "type": "int",
          "order": 0,
          "description": "Number of command line arguments",
          "usage_pattern": "bounds_check"
        },
        {
          "id": 457,
          "name": "argv",
          "type": "char**",
          "order": 1,
          "description": "Array of command line argument strings",
          "usage_pattern": "input_source"
        }
      ],
      "local_variables": [
        {
          "id": 789,
          "name": "buffer",
          "type": "char[256]",
          "stack_offset": -256,
          "size": 256,
          "usage": "temporary_storage",
          "security_risk": "high"
        }
      ],
      "function_calls": [
        {
          "target_function": "strcpy",
          "address": "0x401080",
          "is_external": true,
          "security_risk": "high",
          "call_type": "direct"
        },
        {
          "target_function": "printf",
          "address": "0x401090",
          "is_external": true,
          "security_risk": "low",
          "call_type": "direct"
        }
      ],
      "cross_references": {
        "called_by": [
          {
            "function_name": "_start",
            "address": "0x400500",
            "call_type": "direct"
          }
        ],
        "calls_to": [
          "strcpy",
          "printf"
        ],
        "data_references": [
          {
            "address": "0x402000",
            "type": "string_literal",
            "value": "Input: %s\\n"
          }
        ]
      },
      "control_flow": {
        "basic_blocks": 3,
        "branch_points": 2,
        "loops": 0,
        "entry_block": "0x401000",
        "exit_blocks": ["0x4010F0"]
      }
    }
  },
  "message": "Function details retrieved successfully",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 🔧 **Function Decompilation**

### **Decompile Single Function**
```http
POST /api/functions/{function_id}/decompile
```

Decompile a specific function to C-like pseudocode using Ghidra's decompiler.

**Path Parameters:**
- `function_id` (integer) - ID of the function to decompile

**Request Body (Optional):**
```json
{
  "force_redecompile": false,
  "timeout": 60,
  "decompiler_options": {
    "simplify_expressions": true,
    "eliminate_dead_code": true,
    "recover_prototypes": true
  }
}
```

**Response (Success):**
```json
{
  "success": true,
  "data": {
    "message": "Function decompiled successfully",
    "function": {
      "id": 123,
      "name": "main",
      "address": "0x401000",
      "decompiled_code": "int main(int argc, char** argv) {\n    char buffer[256];\n    if (argc > 1) {\n        strcpy(buffer, argv[1]);\n        printf(\"Input: %s\\n\", buffer);\n    }\n    return 0;\n}",
      "decompiled": true,
      "decompiled_at": "2024-01-15T10:15:00Z",
      "decompilation_quality": "high",
      "processing_time": 2.3,
      "cached": false
    },
    "decompilation_metadata": {
      "ghidra_version": "10.4",
      "decompiler_version": "5.0.3",
      "analysis_time": "2.3 seconds",
      "code_lines": 8,
      "complexity_score": 4.2
    }
  },
  "message": "Decompilation completed",
  "timestamp": "2024-01-15T10:15:00Z"
}
```

**Response (Cached Result):**
```json
{
  "success": true,
  "data": {
    "message": "Function decompilation retrieved from cache",
    "function": {
      "id": 123,
      "name": "main",
      "decompiled_code": "int main(int argc, char** argv) { ... }",
      "decompiled": true,
      "decompiled_at": "2024-01-15T10:15:00Z",
      "cached": true
    }
  },
  "message": "Cached decompilation returned",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Bulk Decompile Functions**
```http
POST /api/binaries/{binary_id}/decompile-all
```

Start bulk decompilation of all functions in a binary.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary

**Request Body (Optional):**
```json
{
  "exclude_external": true,
  "min_function_size": 16,
  "max_functions": 1000,
  "timeout_per_function": 60,
  "priority": 3
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Bulk decompilation started",
    "task": {
      "id": "task_decompile_all_456",
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "task_type": "bulk_decompile",
      "status": "queued",
      "created_at": "2024-01-15T10:30:00Z"
    },
    "scope": {
      "total_functions": 42,
      "functions_to_decompile": 35,
      "excluded_functions": 7,
      "exclusion_reasons": {
        "external_functions": 7,
        "too_small": 0,
        "already_decompiled": 0
      }
    },
    "estimates": {
      "estimated_duration": "5-8 minutes",
      "functions_per_minute": 6,
      "completion_time": "2024-01-15T10:38:00Z"
    }
  },
  "message": "Bulk decompilation task queued",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 🧠 **AI-Powered Function Analysis**

### **AI Explain Single Function**
```http
POST /api/functions/{function_id}/explain
```

Get AI-powered explanation and security analysis of a function using advanced LLM models.

**Path Parameters:**
- `function_id` (integer) - ID of the function to analyze

**Request Body (Optional):**
```json
{
  "force_reanalysis": false,
  "analysis_focus": "security",
  "include_recommendations": true,
  "ai_provider": "openai",
  "model": "gpt-4"
}
```

**Analysis Focus Options:**
- `security` - Focus on security vulnerabilities and risks
- `functionality` - Focus on understanding what the function does
- `performance` - Focus on performance characteristics
- `comprehensive` - Complete analysis covering all aspects

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "AI analysis completed successfully",
    "function": {
      "id": 123,
      "name": "main",
      "address": "0x401000",
      "ai_summary": "This function serves as the main entry point for the application. It processes command line arguments but contains a critical buffer overflow vulnerability. The function uses strcpy() to copy user-controlled input (argv[1]) into a fixed-size buffer without any bounds checking, which can lead to stack-based buffer overflow and potential code execution.",
      "risk_score": 92.5,
      "ai_analyzed": true,
      "ai_analyzed_at": "2024-01-15T10:20:00Z",
      "cached": false
    },
    "analysis_details": {
      "ai_provider": "openai",
      "model_used": "gpt-4",
      "analysis_focus": "security",
      "processing_time": 1.8,
      "token_usage": {
        "prompt_tokens": 450,
        "completion_tokens": 180,
        "total_tokens": 630
      },
      "confidence_score": 95.2
    },
    "vulnerabilities_identified": [
      {
        "type": "buffer_overflow",
        "severity": "CRITICAL",
        "description": "Unchecked strcpy() call allows buffer overflow",
        "evidence": "strcpy(buffer, argv[1]) at line 4",
        "exploitability": "HIGH",
        "impact": "Code execution, system compromise"
      }
    ],
    "security_recommendations": [
      "Replace strcpy() with strncpy() and validate input length",
      "Implement bounds checking before string operations",
      "Consider using safer string handling functions like strlcpy()",
      "Add input validation for command line arguments"
    ],
    "code_patterns": {
      "dangerous_functions": ["strcpy"],
      "safe_functions": ["printf"],
      "input_sources": ["argv"],
      "output_sinks": ["printf"]
    }
  },
  "message": "AI analysis completed",
  "timestamp": "2024-01-15T10:20:00Z"
}
```

### **Bulk AI Analysis**
```http
POST /api/binaries/{binary_id}/ai-explain-all
```

Start AI analysis of all decompiled functions in a binary.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary

**Request Body (Optional):**
```json
{
  "decompiled_only": true,
  "analysis_focus": "security",
  "ai_provider": "openai",
  "batch_size": 5,
  "max_functions": 100,
  "priority": 2
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Bulk AI analysis started",
    "task": {
      "id": "task_ai_all_789",
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "task_type": "bulk_ai_analysis",
      "status": "queued",
      "created_at": "2024-01-15T10:30:00Z"
    },
    "scope": {
      "total_functions": 42,
      "functions_to_analyze": 28,
      "excluded_functions": 14,
      "exclusion_reasons": {
        "not_decompiled": 7,
        "external_functions": 7,
        "already_analyzed": 0
      }
    },
    "processing_plan": {
      "batch_size": 5,
      "estimated_batches": 6,
      "estimated_duration": "8-12 minutes",
      "rate_limit_delays": "2 seconds between batches",
      "completion_time": "2024-01-15T10:42:00Z"
    },
    "cost_estimate": {
      "estimated_tokens": 15000,
      "estimated_cost": "$0.45",
      "ai_provider": "openai",
      "model": "gpt-4"
    }
  },
  "message": "Bulk AI analysis task queued",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## 🔍 **Function Search & Filtering**

### **Advanced Function Search**
```http
GET /api/binaries/{binary_id}/functions/search?query=strcpy&type=name&include_code=false
```

Advanced search functionality for finding specific functions based on various criteria.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary

**Query Parameters:**
- `query` (string) - Search query
- `type` (string) - Search type: name, code, calls, address (default: name)
- `include_code` (boolean) - Include decompiled code in results (default: false)
- `case_sensitive` (boolean) - Case-sensitive search (default: false)
- `regex` (boolean) - Use regex pattern matching (default: false)
- `risk_threshold` (float) - Minimum risk score (0-100)
- `limit` (integer) - Maximum results to return (default: 50)

**Search Types:**
- `name` - Search function names
- `code` - Search within decompiled code
- `calls` - Search functions that call specific functions
- `address` - Search by address range
- `signature` - Search by function signature patterns

**Response:**
```json
{
  "success": true,
  "data": {
    "results": [
      {
        "id": 123,
        "name": "vulnerable_strcpy",
        "address": "0x401200",
        "match_type": "name",
        "match_score": 100,
        "risk_score": 95.2,
        "decompiled": true,
        "ai_analyzed": true,
        "snippet": "strcpy(buffer, user_input)",
        "context": "Function contains dangerous strcpy call"
      }
    ],
    "search_metadata": {
      "query": "strcpy",
      "search_type": "name",
      "total_matches": 3,
      "search_time": "0.15 seconds",
      "total_functions_searched": 42
    }
  },
  "message": "Search completed",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Filter Functions by Risk**
```http
GET /api/binaries/{binary_id}/functions/high-risk?min_score=80&include_details=true
```

Get functions with high security risk scores for prioritized analysis.

**Query Parameters:**
- `min_score` (float) - Minimum risk score threshold (default: 70)
- `max_results` (integer) - Maximum number of results (default: 20)
- `include_details` (boolean) - Include detailed analysis (default: false)
- `sort_by` - Sort by: risk_score, name, address (default: risk_score)

**Response:**
```json
{
  "success": true,
  "data": {
    "high_risk_functions": [
      {
        "id": 123,
        "name": "strcpy_vulnerable",
        "address": "0x401200",
        "risk_score": 95.2,
        "vulnerability_summary": "Critical buffer overflow via strcpy",
        "ai_confidence": 98.5,
        "security_findings_count": 2
      }
    ],
    "risk_summary": {
      "critical_functions": 2,
      "high_risk_functions": 5,
      "medium_risk_functions": 8,
      "average_risk_score": 45.3,
      "highest_risk": 95.2,
      "risk_distribution": {
        "90-100": 2,
        "80-89": 3,
        "70-79": 3
      }
    }
  },
  "message": "High-risk functions identified",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 📊 **Function Analytics & Statistics**

### **Function Analysis Statistics**
```http
GET /api/binaries/{binary_id}/functions/stats
```

Get comprehensive statistics about function analysis progress and results.

**Response:**
```json
{
  "success": true,
  "data": {
    "analysis_statistics": {
      "total_functions": 42,
      "internal_functions": 35,
      "external_functions": 7,
      "decompiled_functions": 30,
      "ai_analyzed_functions": 25,
      "functions_with_security_findings": 12
    },
    "decompilation_stats": {
      "success_rate": 85.7,
      "average_decompilation_time": 2.1,
      "total_decompilation_time": "3.5 minutes",
      "failed_decompilations": 5,
      "quality_distribution": {
        "high": 20,
        "medium": 8,
        "low": 2
      }
    },
    "ai_analysis_stats": {
      "success_rate": 92.0,
      "average_analysis_time": 1.8,
      "total_analysis_time": "45 seconds",
      "average_risk_score": 45.3,
      "token_usage": {
        "total_tokens": 25000,
        "estimated_cost": "$0.75"
      }
    },
    "security_stats": {
      "functions_with_vulnerabilities": 12,
      "critical_vulnerabilities": 2,
      "high_vulnerabilities": 5,
      "medium_vulnerabilities": 8,
      "low_vulnerabilities": 3,
      "vulnerability_types": {
        "buffer_overflow": 5,
        "format_string": 2,
        "input_validation": 4,
        "memory_management": 1
      }
    },
    "complexity_metrics": {
      "average_cyclomatic_complexity": 4.2,
      "most_complex_function": {
        "name": "complex_parser",
        "complexity": 15,
        "address": "0x402000"
      },
      "functions_by_complexity": {
        "simple": 25,
        "moderate": 10,
        "complex": 5,
        "very_complex": 2
      }
    }
  },
  "message": "Function statistics generated",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 🔧 **Batch Operations & Utilities**

### **Clear Function AI Cache**
```http
POST /api/clear-function-ai-cache
```

Clear cached AI analysis results for all functions to force fresh analysis.

**Request Body (Optional):**
```json
{
  "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "function_ids": [123, 124, 125],
  "older_than": "2024-01-14T00:00:00Z"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "AI cache cleared successfully",
    "cleared_functions": 25,
    "cache_stats": {
      "total_cache_entries": 50,
      "entries_cleared": 25,
      "entries_remaining": 25,
      "disk_space_freed": "2.1MB"
    }
  },
  "message": "Cache cleared",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Export Function Analysis**
```http
GET /api/binaries/{binary_id}/functions/export?format=json&include_code=true&include_ai=true
```

Export comprehensive function analysis data in various formats.

**Query Parameters:**
- `format` (string) - Export format: json, csv, xml (default: json)
- `include_code` (boolean) - Include decompiled code (default: false)
- `include_ai` (boolean) - Include AI analysis (default: true)
- `include_security` (boolean) - Include security findings (default: true)
- `functions` (string) - Comma-separated function IDs (optional)

**Response (JSON Format):**
```json
{
  "success": true,
  "data": {
    "export_info": {
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "binary_name": "example.exe",
      "export_format": "json",
      "export_time": "2024-01-15T12:00:00Z",
      "total_functions": 42,
      "included_functions": 42
    },
    "functions": [
      {
        "id": 123,
        "name": "main",
        "address": "0x401000",
        "size": 256,
        "decompiled_code": "int main(int argc, char** argv) { ... }",
        "ai_analysis": {
          "summary": "Main entry point with buffer overflow vulnerability",
          "risk_score": 85.5,
          "vulnerabilities": [...]
        },
        "security_findings": [...],
        "metadata": {
          "decompiled_at": "2024-01-15T10:15:00Z",
          "ai_analyzed_at": "2024-01-15T10:20:00Z"
        }
      }
    ]
  },
  "message": "Function analysis exported",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## ⚠️ **Error Handling**

### **Common Error Scenarios**

#### **Function Not Found**
```json
{
  "success": false,
  "error": "Function not found",
  "details": {
    "function_id": 999,
    "possible_causes": [
      "Function ID does not exist",
      "Function was deleted during binary cleanup",
      "Invalid function ID format"
    ]
  },
  "timestamp": "2024-01-15T12:00:00Z"
}
```

#### **Decompilation Failed**
```json
{
  "success": false,
  "error": "Function decompilation failed",
  "details": {
    "function_id": 123,
    "function_name": "corrupted_function",
    "error_type": "decompiler_timeout",
    "error_message": "Decompilation exceeded 60 second timeout",
    "ghidra_error": "DecompilerTimeoutException: Analysis timeout",
    "recovery_options": [
      "Retry with increased timeout",
      "Try quick decompilation mode",
      "Skip this function and continue with others"
    ]
  },
  "timestamp": "2024-01-15T12:00:00Z"
}
```

#### **AI Analysis Failed**
```json
{
  "success": false,
  "error": "AI analysis failed",
  "details": {
    "function_id": 123,
    "ai_provider": "openai",
    "error_type": "rate_limit_exceeded",
    "error_message": "Rate limit exceeded for API key",
    "retry_after": 60,
    "cost_impact": "$0.05",
    "recovery_options": [
      "Wait 60 seconds and retry",
      "Switch to alternative AI provider",
      "Use cached analysis if available"
    ]
  },
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 💡 **Usage Examples**

### **Complete Function Analysis Workflow**
```bash
#!/bin/bash

BINARY_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
API_BASE="http://localhost:5000/api"

# 1. Get all functions in binary
echo "Getting function list..."
FUNCTIONS=$(curl -s "$API_BASE/binaries/$BINARY_ID/functions?per_page=100")
FUNCTION_COUNT=$(echo $FUNCTIONS | jq '.data.summary.total_functions')
echo "Found $FUNCTION_COUNT functions"

# 2. Start bulk decompilation
echo "Starting bulk decompilation..."
DECOMPILE_TASK=$(curl -s -X POST "$API_BASE/binaries/$BINARY_ID/decompile-all" \
  -H "Content-Type: application/json" \
  -d '{"exclude_external": true}')

TASK_ID=$(echo $DECOMPILE_TASK | jq -r '.data.task.id')
echo "Decompilation task started: $TASK_ID"

# 3. Wait for decompilation to complete
echo "Waiting for decompilation..."
while true; do
  STATUS=$(curl -s "$API_BASE/tasks/$TASK_ID/status" | jq -r '.task.status')
  if [ "$STATUS" = "completed" ]; then
    echo "Decompilation completed"
    break
  elif [ "$STATUS" = "failed" ]; then
    echo "Decompilation failed"
    exit 1
  fi
  sleep 10
done

# 4. Start AI analysis
echo "Starting AI analysis..."
AI_TASK=$(curl -s -X POST "$API_BASE/binaries/$BINARY_ID/ai-explain-all" \
  -H "Content-Type: application/json" \
  -d '{"decompiled_only": true, "analysis_focus": "security"}')

AI_TASK_ID=$(echo $AI_TASK | jq -r '.data.task.id')
echo "AI analysis task started: $AI_TASK_ID"

# 5. Wait for AI analysis to complete
echo "Waiting for AI analysis..."
while true; do
  AI_STATUS=$(curl -s "$API_BASE/tasks/$AI_TASK_ID/status" | jq -r '.task.status')
  if [ "$AI_STATUS" = "completed" ]; then
    echo "AI analysis completed"
    break
  elif [ "$AI_STATUS" = "failed" ]; then
    echo "AI analysis failed"
    exit 1
  fi
  sleep 15
done

# 6. Get high-risk functions
echo "Getting high-risk functions..."
HIGH_RISK=$(curl -s "$API_BASE/binaries/$BINARY_ID/functions/high-risk?min_score=80")
RISK_COUNT=$(echo $HIGH_RISK | jq '.data.high_risk_functions | length')
echo "Found $RISK_COUNT high-risk functions"

# 7. Export complete analysis
echo "Exporting analysis results..."
curl -s "$API_BASE/binaries/$BINARY_ID/functions/export?format=json&include_code=true&include_ai=true" \
  > "function_analysis_$BINARY_ID.json"

echo "Analysis complete! Results saved to function_analysis_$BINARY_ID.json"
```

### **Individual Function Deep Dive**
```python
import requests
import json

class FunctionAnalyzer:
    def __init__(self, api_base="http://localhost:5000/api"):
        self.api_base = api_base
    
    def analyze_function(self, function_id):
        """Perform complete analysis of a single function"""
        
        # Get basic function info
        response = requests.get(f"{self.api_base}/functions/{function_id}")
        if response.status_code != 200:
            print(f"Error getting function {function_id}")
            return None
        
        function_data = response.json()['data']['function']
        print(f"Analyzing function: {function_data['name']} @ {function_data['address']}")
        
        # Decompile if not already done
        if not function_data['decompiled']:
            print("Decompiling function...")
            decompile_response = requests.post(
                f"{self.api_base}/functions/{function_id}/decompile"
            )
            if decompile_response.status_code == 200:
                function_data = decompile_response.json()['data']['function']
                print("Decompilation completed")
            else:
                print("Decompilation failed")
                return function_data
        
        # AI analysis if not already done
        if not function_data['ai_analyzed']:
            print("Starting AI analysis...")
            ai_response = requests.post(
                f"{self.api_base}/functions/{function_id}/explain",
                json={"analysis_focus": "security", "include_recommendations": True}
            )
            if ai_response.status_code == 200:
                ai_data = ai_response.json()['data']
                function_data.update(ai_data['function'])
                print(f"AI analysis completed - Risk Score: {function_data['risk_score']}")
            else:
                print("AI analysis failed")
        
        return function_data
    
    def find_vulnerable_functions(self, binary_id, min_risk=80):
        """Find all vulnerable functions in a binary"""
        
        response = requests.get(
            f"{self.api_base}/binaries/{binary_id}/functions/high-risk",
            params={"min_score": min_risk, "include_details": True}
        )
        
        if response.status_code == 200:
            return response.json()['data']['high_risk_functions']
        return []
    
    def export_function_report(self, binary_id, output_file):
        """Export comprehensive function analysis report"""
        
        response = requests.get(
            f"{self.api_base}/binaries/{binary_id}/functions/export",
            params={
                "format": "json",
                "include_code": True,
                "include_ai": True,
                "include_security": True
            }
        )
        
        if response.status_code == 200:
            with open(output_file, 'w') as f:
                json.dump(response.json()['data'], f, indent=2)
            print(f"Report exported to {output_file}")
        else:
            print("Export failed")

# Usage example
if __name__ == "__main__":
    analyzer = FunctionAnalyzer()
    
    # Analyze a specific function
    function_data = analyzer.analyze_function(123)
    if function_data:
        print(f"Function: {function_data['name']}")
        print(f"Risk Score: {function_data.get('risk_score', 'Not analyzed')}")
        print(f"Summary: {function_data.get('ai_summary', 'No AI summary')}")
    
    # Find vulnerable functions in a binary
    binary_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    vulnerable_functions = analyzer.find_vulnerable_functions(binary_id)
    print(f"Found {len(vulnerable_functions)} vulnerable functions")
    
    # Export comprehensive report
    analyzer.export_function_report(binary_id, "function_report.json")
```

---

## 🎯 **Best Practices**

### **Efficient Function Analysis**
1. **Batch Operations**: Use bulk decompilation and AI analysis for multiple functions
2. **Prioritize High-Risk**: Start with functions that have high risk scores
3. **Cache Utilization**: Leverage cached results to reduce processing time
4. **Resource Management**: Monitor AI API usage and costs

### **Decompilation Optimization**
1. **Exclude External Functions**: Focus on internal functions for decompilation
2. **Size Filtering**: Skip very small functions that are unlikely to be interesting
3. **Timeout Management**: Set appropriate timeouts for complex functions
4. **Quality Assessment**: Use decompilation quality scores to prioritize analysis

### **AI Analysis Strategy**
1. **Focus Selection**: Use analysis focus to target specific aspects (security, functionality)
2. **Provider Selection**: Choose AI providers based on analysis needs and budget
3. **Batch Size**: Optimize batch sizes to balance speed and rate limits
4. **Cost Monitoring**: Track token usage and estimated costs

### **Security-Focused Workflow**
1. **Risk-Based Analysis**: Start with highest risk functions first
2. **Vulnerability Patterns**: Use search functionality to find specific vulnerability patterns
3. **Evidence Collection**: Gather comprehensive evidence for security findings
4. **Remediation Planning**: Use AI recommendations for vulnerability remediation

---

The Function Analysis API provides comprehensive capabilities for deep binary analysis at the function level. Combined with ShadowSeek's AI-powered insights, it enables security professionals to efficiently identify and analyze potential vulnerabilities in complex binaries. 