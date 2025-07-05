# Security Analysis API

## 🛡️ Advanced Security Analysis & Vulnerability Detection API

The Security Analysis API provides comprehensive security assessment capabilities, combining AI-powered analysis with pattern-based detection to identify vulnerabilities with high confidence and detailed evidence trails.

---

## 🌐 **Base Configuration**

**Base URL**: `http://localhost:5000/api`
**Content-Type**: `application/json`

---

## 🔍 **Function-Level Security Analysis**

### **Analyze Function Security**
```http
POST /api/functions/{function_id}/security-analysis
```

Perform comprehensive security analysis on a specific function using ShadowSeek's unified security engine.

**Path Parameters:**
- `function_id` (integer) - ID of the function to analyze

**Request Body (Optional):**
```json
{
  "analysis_mode": "comprehensive",
  "ai_enabled": true,
  "pattern_validation": true,
  "include_evidence": true,
  "confidence_threshold": 50.0,
  "target_severities": ["CRITICAL", "HIGH", "MEDIUM"]
}
```

**Analysis Modes:**
- `comprehensive` - Full AI + pattern analysis (default)
- `ai_only` - AI analysis without pattern validation
- `patterns_only` - Pattern-based detection only
- `fast` - Quick security scan with basic patterns

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Security analysis completed successfully",
    "function": {
      "id": 123,
      "name": "strcpy_vulnerable",
      "address": "0x401200",
      "analysis_completed_at": "2024-01-15T10:30:00Z"
    },
    "findings": [
      {
        "id": 456,
        "title": "Critical Buffer Overflow Vulnerability",
        "description": "Function uses strcpy() without bounds checking, allowing attackers to overflow the destination buffer and potentially execute arbitrary code",
        "severity": "CRITICAL",
        "confidence": 95.2,
        "cwe_id": "CWE-120",
        "cvss_score": 9.3,
        "exploitability": "HIGH",
        "impact": "Complete system compromise through stack-based buffer overflow",
        "ai_analysis": "The function accepts user-controlled input through the 'input' parameter and copies it to a fixed-size buffer using strcpy(). This is a classic buffer overflow vulnerability that can be exploited to overwrite the return address and execute shellcode.",
        "affected_code": "strcpy(buffer, input);",
        "detection_methods": ["ai_analysis", "pattern_match"],
        "evidence": [
          {
            "type": "ai_analysis",
            "description": "AI detected buffer overflow pattern with high confidence",
            "confidence_impact": 0.60,
            "details": "LLM identified strcpy usage with unbounded input as critical security risk"
          },
          {
            "type": "pattern_match",
            "description": "Dangerous function pattern detected: strcpy without bounds check",
            "confidence_impact": 0.35,
            "pattern": "strcpy\\s*\\([^,]+,\\s*[^)]+\\)",
            "matches": ["strcpy(buffer, input)"]
          }
        ],
        "remediation": {
          "priority": "IMMEDIATE",
          "steps": [
            "Replace strcpy() with strncpy() or strlcpy()",
            "Validate input length before copying",
            "Implement bounds checking for all string operations",
            "Consider using safer string handling libraries"
          ],
          "example_fix": "strncpy(buffer, input, sizeof(buffer) - 1);\nbuffer[sizeof(buffer) - 1] = '\\0';"
        },
        "references": [
          "https://cwe.mitre.org/data/definitions/120.html",
          "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow"
        ],
        "created_at": "2024-01-15T10:30:00Z"
      }
    ],
    "analysis_summary": {
      "total_findings": 1,
      "critical_findings": 1,
      "high_findings": 0,
      "medium_findings": 0,
      "low_findings": 0,
      "overall_risk_score": 95.2,
      "analysis_duration": 2.3,
      "detection_coverage": {
        "ai_detection": true,
        "pattern_validation": true,
        "static_analysis": true
      }
    }
  },
  "message": "Security analysis completed",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Get Function Security Findings**
```http
GET /api/functions/{function_id}/security-findings?include_evidence=true&severity=HIGH,CRITICAL
```

Retrieve existing security findings for a specific function.

**Path Parameters:**
- `function_id` (integer) - ID of the function

**Query Parameters:**
- `include_evidence` (boolean) - Include evidence trails (default: false)
- `severity` (string) - Filter by severity levels (comma-separated)
- `confirmed_only` (boolean) - Only confirmed findings (default: false)
- `sort_by` (string) - Sort by: severity, confidence, created_at (default: severity)

**Response:**
```json
{
  "success": true,
  "data": {
    "function": {
      "id": 123,
      "name": "strcpy_vulnerable",
      "address": "0x401200",
      "last_analyzed": "2024-01-15T10:30:00Z"
    },
    "findings": [
      {
        "id": 456,
        "title": "Critical Buffer Overflow Vulnerability",
        "severity": "CRITICAL",
        "confidence": 95.2,
        "cwe_id": "CWE-120",
        "confirmed": false,
        "false_positive": false,
        "analyst_notes": null,
        "created_at": "2024-01-15T10:30:00Z",
        "evidence": [
          {
            "type": "ai_analysis",
            "description": "AI detected buffer overflow pattern",
            "confidence_impact": 0.60
          }
        ]
      }
    ],
    "summary": {
      "total_findings": 1,
      "by_severity": {
        "CRITICAL": 1,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
      },
      "confirmed_findings": 0,
      "false_positives": 0,
      "pending_review": 1
    }
  },
  "message": "Security findings retrieved",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 🏢 **Binary-Level Security Analysis**

### **Analyze Binary Security**
```http
POST /api/binaries/{binary_id}/security-analysis
```

Perform comprehensive security analysis on all functions within a binary.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary

**Request Body (Optional):**
```json
{
  "min_risk_score": 40.0,
  "target_severities": ["CRITICAL", "HIGH", "MEDIUM"],
  "ai_enabled": true,
  "pattern_validation": true,
  "analysis_scope": "decompiled_only",
  "max_functions": 100,
  "priority": 2,
  "include_false_positive_filtering": true
}
```

**Analysis Scope Options:**
- `all_functions` - Analyze all discovered functions
- `decompiled_only` - Only analyze decompiled functions (default)
- `high_risk_only` - Only functions with existing high risk scores
- `external_excluded` - Exclude external/library functions

**Response:**
```json
{
  "success": true,
  "data": {
    "message": "Binary security analysis started",
    "task": {
      "id": "task_security_789",
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "task_type": "security_analysis",
      "status": "queued",
      "created_at": "2024-01-15T10:30:00Z",
      "priority": 2
    },
    "analysis_scope": {
      "total_functions": 42,
      "functions_to_analyze": 28,
      "excluded_functions": 14,
      "exclusion_reasons": {
        "not_decompiled": 7,
        "external_functions": 7,
        "below_risk_threshold": 0
      }
    },
    "processing_plan": {
      "estimated_duration": "12-18 minutes",
      "functions_per_minute": 2.5,
      "ai_analysis_enabled": true,
      "pattern_validation_enabled": true,
      "completion_time": "2024-01-15T10:48:00Z"
    },
    "cost_estimate": {
      "estimated_ai_calls": 28,
      "estimated_tokens": 42000,
      "estimated_cost": "$1.26",
      "ai_provider": "openai"
    }
  },
  "message": "Security analysis task queued",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### **Get Binary Security Findings**
```http
GET /api/binaries/{binary_id}/security-findings?page=1&per_page=20&severity=CRITICAL,HIGH&sort_by=confidence&order=desc
```

Retrieve security findings for all functions in a binary with pagination and filtering.

**Path Parameters:**
- `binary_id` (string) - UUID of the binary

**Query Parameters:**
- `page` (integer) - Page number (default: 1)
- `per_page` (integer) - Items per page (default: 20, max: 100)
- `severity` (string) - Filter by severity (comma-separated)
- `confirmed` (boolean) - Filter by confirmation status
- `false_positive` (boolean) - Include/exclude false positives
- `cwe_id` (string) - Filter by specific CWE ID
- `sort_by` (string) - Sort field: severity, confidence, created_at (default: severity)
- `order` (string) - Sort order: asc, desc (default: desc)
- `search` (string) - Search in titles and descriptions

**Response:**
```json
{
  "success": true,
  "data": {
    "binary": {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "filename": "example.exe",
      "last_security_analysis": "2024-01-15T10:45:00Z"
    },
    "findings": [
      {
        "id": 456,
        "title": "Critical Buffer Overflow Vulnerability",
        "description": "strcpy usage without bounds checking in strcpy_vulnerable function",
        "severity": "CRITICAL",
        "confidence": 95.2,
        "cwe_id": "CWE-120",
        "cvss_score": 9.3,
        "function_name": "strcpy_vulnerable",
        "function_address": "0x401200",
        "exploitability": "HIGH",
        "confirmed": false,
        "false_positive": false,
        "analyst_notes": null,
        "detection_methods": ["ai_analysis", "pattern_match"],
        "created_at": "2024-01-15T10:35:00Z",
        "evidence_count": 2
      },
      {
        "id": 457,
        "title": "Format String Vulnerability",
        "description": "printf called with user-controlled format string",
        "severity": "HIGH",
        "confidence": 87.8,
        "cwe_id": "CWE-134",
        "cvss_score": 7.5,
        "function_name": "log_message",
        "function_address": "0x401300",
        "exploitability": "MEDIUM",
        "confirmed": false,
        "false_positive": false,
        "analyst_notes": null,
        "detection_methods": ["ai_analysis", "pattern_match"],
        "created_at": "2024-01-15T10:36:00Z",
        "evidence_count": 2
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 15,
      "pages": 1,
      "has_next": false,
      "has_prev": false
    },
    "summary": {
      "total_findings": 15,
      "by_severity": {
        "CRITICAL": 2,
        "HIGH": 5,
        "MEDIUM": 6,
        "LOW": 2
      },
      "by_status": {
        "confirmed": 3,
        "pending_review": 10,
        "false_positive": 2
      },
      "unique_cwe_types": 8,
      "functions_with_findings": 12,
      "average_confidence": 78.5,
      "highest_risk_function": {
        "name": "strcpy_vulnerable",
        "finding_count": 2,
        "highest_severity": "CRITICAL"
      }
    }
  },
  "message": "Security findings retrieved",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 🔍 **Detailed Finding Management**

### **Get Security Finding Details**
```http
GET /api/security-findings/{finding_id}
```

Get comprehensive details about a specific security finding including complete evidence trail.

**Path Parameters:**
- `finding_id` (integer) - ID of the security finding

**Response:**
```json
{
  "success": true,
  "data": {
    "finding": {
      "id": 456,
      "title": "Critical Buffer Overflow Vulnerability",
      "description": "Function uses strcpy() without bounds checking, allowing attackers to overflow the destination buffer and potentially execute arbitrary code through stack-based buffer overflow",
      "severity": "CRITICAL",
      "confidence": 95.2,
      "cwe_id": "CWE-120",
      "cve_references": ["CVE-2019-14287", "CVE-2021-3156"],
      "cvss_score": 9.3,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "exploitability": "HIGH",
      "impact": "Complete system compromise through arbitrary code execution",
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "binary_name": "example.exe",
      "function_id": 123,
      "function_name": "strcpy_vulnerable",
      "function_address": "0x401200",
      "affected_code": "strcpy(buffer, input);",
      "line_number": 15,
      "ai_analysis": "The function accepts a user-controlled input parameter and copies it to a fixed-size stack buffer using strcpy(). This is a textbook example of a stack-based buffer overflow vulnerability. An attacker can provide input longer than the buffer size to overwrite adjacent memory, including the return address, enabling arbitrary code execution.",
      "detection_methods": ["ai_analysis", "pattern_match"],
      "confirmed": false,
      "false_positive": false,
      "analyst_notes": null,
      "created_at": "2024-01-15T10:35:00Z",
      "updated_at": "2024-01-15T10:35:00Z",
      "evidence": [
        {
          "id": 789,
          "type": "ai_analysis",
          "description": "Advanced AI model identified classic buffer overflow pattern with strcpy usage",
          "confidence_impact": 0.60,
          "details": {
            "ai_provider": "openai",
            "model": "gpt-4",
            "analysis_confidence": 98.5,
            "vulnerability_indicators": [
              "strcpy_without_bounds_check",
              "user_controlled_input",
              "fixed_size_buffer",
              "stack_allocation"
            ]
          },
          "raw_data": "AI detected strcpy(buffer, input) pattern where 'input' comes from user-controlled source",
          "created_at": "2024-01-15T10:35:00Z"
        },
        {
          "id": 790,
          "type": "pattern_match",
          "description": "Static pattern analysis confirmed dangerous strcpy usage",
          "confidence_impact": 0.35,
          "details": {
            "pattern_id": "strcpy_unbounded",
            "regex": "strcpy\\s*\\([^,]+,\\s*[^)]+\\)",
            "matches": ["strcpy(buffer, input)"],
            "context_analysis": "No bounds checking detected in surrounding code"
          },
          "raw_data": "Pattern match: strcpy(buffer, input) at offset 0x1234",
          "created_at": "2024-01-15T10:35:00Z"
        },
        {
          "id": 791,
          "type": "static_analysis",
          "description": "Control flow analysis confirms vulnerability path",
          "confidence_impact": 0.05,
          "details": {
            "data_flow": "user_input -> function_parameter -> strcpy_destination",
            "taint_analysis": "User input reaches dangerous sink without sanitization",
            "reachability": "Vulnerability is reachable from main execution path"
          },
          "raw_data": "CFG analysis shows direct path from entry point to vulnerable strcpy call",
          "created_at": "2024-01-15T10:35:00Z"
        }
      ],
      "remediation": {
        "priority": "IMMEDIATE",
        "difficulty": "LOW",
        "estimated_effort": "1-2 hours",
        "steps": [
          "Replace strcpy() with strncpy() or strlcpy()",
          "Add explicit bounds checking before string operations",
          "Null-terminate the destination buffer explicitly",
          "Consider using safer string handling libraries (e.g., SafeStr)",
          "Add input validation at function entry point"
        ],
        "code_examples": {
          "vulnerable": "strcpy(buffer, input);",
          "secure": "strncpy(buffer, input, sizeof(buffer) - 1);\nbuffer[sizeof(buffer) - 1] = '\\0';"
        },
        "testing_recommendations": [
          "Test with inputs longer than buffer size",
          "Use fuzzing to generate boundary condition inputs",
          "Verify fix with AddressSanitizer or Valgrind"
        ]
      },
      "references": [
        {
          "type": "CWE",
          "url": "https://cwe.mitre.org/data/definitions/120.html",
          "title": "CWE-120: Buffer Copy without Checking Size of Input"
        },
        {
          "type": "OWASP",
          "url": "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow",
          "title": "OWASP Buffer Overflow"
        },
        {
          "type": "NIST",
          "url": "https://nvd.nist.gov/vuln/categories/CWE-120",
          "title": "NIST NVD CWE-120 Vulnerabilities"
        }
      ],
      "exploitation_notes": {
        "attack_vector": "Remote or local depending on input source",
        "prerequisites": "Ability to control input parameter",
        "impact_assessment": "Complete system compromise possible",
        "mitigation_bypass": "None - direct memory corruption",
        "exploit_complexity": "Low - well-known vulnerability class"
      }
    }
  },
  "message": "Security finding details retrieved",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Update Security Finding**
```http
PUT /api/security-findings/{finding_id}
```

Update security finding status, add analyst notes, or mark as false positive.

**Path Parameters:**
- `finding_id` (integer) - ID of the security finding

**Request Body:**
```json
{
  "confirmed": true,
  "false_positive": false,
  "analyst_notes": "Confirmed vulnerability through manual code review. High priority for patching due to network exposure.",
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "remediation_status": "in_progress",
  "assigned_to": "security_team",
  "due_date": "2024-01-20T00:00:00Z",
  "tags": ["network_exposed", "high_priority", "buffer_overflow"]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "finding": {
      "id": 456,
      "title": "Critical Buffer Overflow Vulnerability",
      "confirmed": true,
      "false_positive": false,
      "analyst_notes": "Confirmed vulnerability through manual code review. High priority for patching due to network exposure.",
      "severity": "CRITICAL",
      "cvss_score": 9.8,
      "remediation_status": "in_progress",
      "assigned_to": "security_team",
      "due_date": "2024-01-20T00:00:00Z",
      "tags": ["network_exposed", "high_priority", "buffer_overflow"],
      "updated_at": "2024-01-15T12:15:00Z",
      "updated_by": "analyst@company.com"
    },
    "changes": {
      "confirmed": {"from": false, "to": true},
      "analyst_notes": {"from": null, "to": "Confirmed vulnerability..."},
      "cvss_score": {"from": 9.3, "to": 9.8},
      "remediation_status": {"from": null, "to": "in_progress"}
    }
  },
  "message": "Security finding updated successfully",
  "timestamp": "2024-01-15T12:15:00Z"
}
```

---

## 📊 **Security Analytics & Reporting**

### **Get Security Summary**
```http
GET /api/binaries/{binary_id}/security-summary
```

Get executive-level security summary for a binary with risk assessment.

**Response:**
```json
{
  "success": true,
  "data": {
    "binary": {
      "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "filename": "example.exe",
      "last_security_analysis": "2024-01-15T10:45:00Z"
    },
    "executive_summary": {
      "overall_risk_level": "HIGH",
      "security_score": 3.2,
      "total_vulnerabilities": 15,
      "critical_issues": 2,
      "immediate_action_required": true,
      "estimated_remediation_effort": "2-3 weeks",
      "business_impact": "High risk of data breach and system compromise"
    },
    "vulnerability_breakdown": {
      "by_severity": {
        "CRITICAL": {
          "count": 2,
          "percentage": 13.3,
          "examples": ["Buffer Overflow in strcpy_vulnerable", "SQL Injection in query_builder"]
        },
        "HIGH": {
          "count": 5,
          "percentage": 33.3,
          "examples": ["Format String in log_message", "Path Traversal in file_handler"]
        },
        "MEDIUM": {
          "count": 6,
          "percentage": 40.0,
          "examples": ["Input Validation in user_input", "Weak Crypto in encrypt_data"]
        },
        "LOW": {
          "count": 2,
          "percentage": 13.3,
          "examples": ["Info Disclosure in debug_print"]
        }
      },
      "by_category": {
        "Memory Safety": {
          "count": 7,
          "types": ["Buffer Overflow", "Use After Free", "Double Free"]
        },
        "Input Validation": {
          "count": 4,
          "types": ["SQL Injection", "Command Injection", "Path Traversal"]
        },
        "Cryptographic": {
          "count": 2,
          "types": ["Weak Algorithm", "Hardcoded Key"]
        },
        "Information Disclosure": {
          "count": 2,
          "types": ["Debug Information", "Error Messages"]
        }
      }
    },
    "risk_factors": {
      "network_exposure": true,
      "privileged_execution": true,
      "user_input_processing": true,
      "file_system_access": true,
      "cryptographic_operations": true,
      "database_connectivity": false
    },
    "remediation_priorities": [
      {
        "priority": 1,
        "finding_id": 456,
        "title": "Critical Buffer Overflow",
        "reason": "Network exposed with high exploit probability",
        "effort": "Low",
        "impact": "Prevents complete system compromise"
      },
      {
        "priority": 2,
        "finding_id": 457,
        "title": "SQL Injection",
        "reason": "Database access with potential data breach",
        "effort": "Medium",
        "impact": "Protects sensitive data"
      }
    ],
    "compliance_status": {
      "owasp_top_10": {
        "A01_broken_access_control": "FAIL",
        "A02_cryptographic_failures": "FAIL",
        "A03_injection": "FAIL",
        "A04_insecure_design": "PASS",
        "A05_security_misconfiguration": "PASS",
        "A06_vulnerable_components": "UNKNOWN",
        "A07_identification_failures": "PASS",
        "A08_software_integrity_failures": "PASS",
        "A09_logging_failures": "PASS",
        "A10_ssrf": "PASS"
      },
      "cwe_top_25": {
        "coverage": 8,
        "total": 25,
        "percentage": 32.0,
        "missing_checks": ["CWE-78", "CWE-79", "CWE-89"]
      }
    }
  },
  "message": "Security summary generated",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Generate Security Report**
```http
POST /api/binaries/{binary_id}/security-report
```

Generate comprehensive security assessment report with detailed findings and recommendations.

**Request Body (Optional):**
```json
{
  "report_format": "json",
  "include_evidence": true,
  "include_remediation": true,
  "include_references": true,
  "severity_filter": ["CRITICAL", "HIGH"],
  "executive_summary": true,
  "technical_details": true,
  "compliance_mapping": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "report": {
      "metadata": {
        "report_id": "report_456",
        "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "binary_name": "example.exe",
        "generated_at": "2024-01-15T12:30:00Z",
        "analyst": "ShadowSeek Security Engine",
        "report_version": "1.0",
        "analysis_date": "2024-01-15T10:45:00Z"
      },
      "executive_summary": {
        "overall_risk": "HIGH",
        "critical_findings": 2,
        "high_findings": 5,
        "recommendation": "Immediate remediation required for critical vulnerabilities",
        "business_impact": "High risk of security breach with potential for complete system compromise"
      },
      "technical_findings": [
        {
          "finding_id": 456,
          "title": "Critical Buffer Overflow Vulnerability",
          "severity": "CRITICAL",
          "confidence": 95.2,
          "cwe_id": "CWE-120",
          "location": "strcpy_vulnerable @ 0x401200",
          "description": "Comprehensive vulnerability description...",
          "evidence": "Complete evidence trail...",
          "remediation": "Detailed remediation steps...",
          "references": ["CWE-120", "OWASP Buffer Overflow"]
        }
      ],
      "remediation_plan": {
        "immediate_actions": [
          "Patch critical buffer overflow vulnerabilities",
          "Implement input validation for all user inputs"
        ],
        "short_term": [
          "Replace dangerous functions with safe alternatives",
          "Add comprehensive error handling"
        ],
        "long_term": [
          "Implement secure coding practices",
          "Regular security assessments"
        ]
      },
      "compliance_assessment": {
        "standards": ["OWASP Top 10", "CWE Top 25", "NIST"],
        "compliance_score": 6.5,
        "gaps": ["Missing injection protection", "Weak cryptography"]
      }
    },
    "download_links": {
      "json_report": "/api/reports/report_456.json",
      "pdf_report": "/api/reports/report_456.pdf",
      "csv_findings": "/api/reports/report_456_findings.csv"
    }
  },
  "message": "Security report generated",
  "timestamp": "2024-01-15T12:30:00Z"
}
```

---

## 🎯 **Advanced Security Features**

### **Vulnerability Pattern Search**
```http
GET /api/vulnerabilities/patterns/search?pattern=strcpy&category=buffer_overflow&severity=HIGH
```

Search for specific vulnerability patterns across all analyzed binaries.

**Query Parameters:**
- `pattern` (string) - Pattern to search for (function name, code pattern, etc.)
- `category` (string) - Vulnerability category filter
- `severity` (string) - Minimum severity level
- `cwe_id` (string) - Specific CWE ID filter
- `confirmed_only` (boolean) - Only confirmed vulnerabilities
- `limit` (integer) - Maximum results (default: 50)

**Response:**
```json
{
  "success": true,
  "data": {
    "search_results": [
      {
        "finding_id": 456,
        "binary_name": "example.exe",
        "function_name": "strcpy_vulnerable",
        "pattern_match": "strcpy(buffer, input)",
        "severity": "CRITICAL",
        "confidence": 95.2,
        "cwe_id": "CWE-120"
      }
    ],
    "search_metadata": {
      "pattern": "strcpy",
      "total_matches": 15,
      "unique_binaries": 8,
      "severity_distribution": {
        "CRITICAL": 5,
        "HIGH": 7,
        "MEDIUM": 3
      }
    }
  },
  "message": "Pattern search completed",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **False Positive Analysis**
```http
POST /api/security-findings/analyze-false-positives
```

Analyze potential false positives using advanced heuristics and machine learning.

**Request Body:**
```json
{
  "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "confidence_threshold": 80.0,
  "include_context_analysis": true,
  "ml_validation": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "analysis_results": [
      {
        "finding_id": 458,
        "current_status": "pending_review",
        "false_positive_probability": 78.5,
        "recommendation": "LIKELY_FALSE_POSITIVE",
        "reasons": [
          "Bounds checking detected in calling function",
          "Input source is trusted/validated",
          "Pattern appears in dead code path"
        ],
        "suggested_action": "Mark as false positive with manual review"
      }
    ],
    "summary": {
      "total_analyzed": 15,
      "likely_false_positives": 3,
      "confirmed_vulnerabilities": 10,
      "requires_manual_review": 2,
      "confidence_improvement": 12.5
    }
  },
  "message": "False positive analysis completed",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 🔧 **Batch Operations**

### **Bulk Security Analysis**
```http
POST /api/binaries/bulk-security-analysis
```

Perform security analysis on multiple binaries simultaneously.

**Request Body:**
```json
{
  "binary_ids": [
    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "b2c3d4e5-f6g7-8901-bcde-f234567890ab"
  ],
  "analysis_config": {
    "ai_enabled": true,
    "pattern_validation": true,
    "min_risk_score": 50.0,
    "target_severities": ["CRITICAL", "HIGH", "MEDIUM"]
  },
  "priority": 2
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "batch_job": {
      "id": "batch_security_789",
      "status": "queued",
      "total_binaries": 2,
      "estimated_duration": "25-35 minutes",
      "created_at": "2024-01-15T11:00:00Z"
    },
    "individual_tasks": [
      {
        "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "task_id": "task_security_101",
        "status": "queued"
      },
      {
        "binary_id": "b2c3d4e5-f6g7-8901-bcde-f234567890ab",
        "task_id": "task_security_102",
        "status": "queued"
      }
    ]
  },
  "message": "Bulk security analysis started",
  "timestamp": "2024-01-15T11:00:00Z"
}
```

---

## 💡 **Usage Examples**

### **Complete Security Assessment Workflow**
```bash
#!/bin/bash

BINARY_ID="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
API_BASE="http://localhost:5000/api"

echo "Starting comprehensive security assessment..."

# 1. Start binary-wide security analysis
SECURITY_TASK=$(curl -s -X POST "$API_BASE/binaries/$BINARY_ID/security-analysis" \
  -H "Content-Type: application/json" \
  -d '{
    "ai_enabled": true,
    "pattern_validation": true,
    "target_severities": ["CRITICAL", "HIGH", "MEDIUM"],
    "analysis_scope": "decompiled_only"
  }')

TASK_ID=$(echo $SECURITY_TASK | jq -r '.data.task.id')
echo "Security analysis started: $TASK_ID"

# 2. Monitor progress
echo "Monitoring security analysis progress..."
while true; do
  STATUS=$(curl -s "$API_BASE/tasks/$TASK_ID/status" | jq -r '.task.status')
  PROGRESS=$(curl -s "$API_BASE/tasks/$TASK_ID/status" | jq -r '.task.progress')
  
  echo "Status: $STATUS, Progress: $PROGRESS%"
  
  if [ "$STATUS" = "completed" ]; then
    echo "Security analysis completed"
    break
  elif [ "$STATUS" = "failed" ]; then
    echo "Security analysis failed"
    exit 1
  fi
  
  sleep 30
done

# 3. Get security findings
echo "Retrieving security findings..."
FINDINGS=$(curl -s "$API_BASE/binaries/$BINARY_ID/security-findings?severity=CRITICAL,HIGH")
CRITICAL_COUNT=$(echo $FINDINGS | jq '.data.summary.by_severity.CRITICAL')
HIGH_COUNT=$(echo $FINDINGS | jq '.data.summary.by_severity.HIGH')

echo "Found $CRITICAL_COUNT critical and $HIGH_COUNT high severity vulnerabilities"

# 4. Generate security report
echo "Generating comprehensive security report..."
REPORT=$(curl -s -X POST "$API_BASE/binaries/$BINARY_ID/security-report" \
  -H "Content-Type: application/json" \
  -d '{
    "include_evidence": true,
    "include_remediation": true,
    "executive_summary": true,
    "compliance_mapping": true
  }')

REPORT_ID=$(echo $REPORT | jq -r '.data.report.metadata.report_id')
echo "Security report generated: $REPORT_ID"

# 5. Download report
curl -s "$API_BASE/reports/$REPORT_ID.json" > "security_report_$BINARY_ID.json"
echo "Report saved to security_report_$BINARY_ID.json"

echo "Security assessment complete!"
```

### **Vulnerability Management Dashboard**
```python
import requests
import json
from datetime import datetime

class SecurityDashboard:
    def __init__(self, api_base="http://localhost:5000/api"):
        self.api_base = api_base
    
    def get_critical_vulnerabilities(self):
        """Get all critical vulnerabilities across all binaries"""
        response = requests.get(
            f"{self.api_base}/vulnerabilities/patterns/search",
            params={"severity": "CRITICAL", "confirmed_only": False}
        )
        
        if response.status_code == 200:
            return response.json()['data']['search_results']
        return []
    
    def analyze_binary_security(self, binary_id):
        """Perform comprehensive security analysis on a binary"""
        
        # Start security analysis
        response = requests.post(
            f"{self.api_base}/binaries/{binary_id}/security-analysis",
            json={
                "ai_enabled": True,
                "pattern_validation": True,
                "target_severities": ["CRITICAL", "HIGH", "MEDIUM"]
            }
        )
        
        if response.status_code == 200:
            task_id = response.json()['data']['task']['id']
            print(f"Security analysis started: {task_id}")
            return self.wait_for_task_completion(task_id)
        
        return False
    
    def wait_for_task_completion(self, task_id, timeout=1800):
        """Wait for analysis task to complete"""
        import time
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            response = requests.get(f"{self.api_base}/tasks/{task_id}/status")
            if response.status_code == 200:
                status = response.json()['task']['status']
                if status == 'completed':
                    return True
                elif status == 'failed':
                    return False
            time.sleep(30)
        
        return False
    
    def get_security_summary(self, binary_id):
        """Get executive security summary for a binary"""
        response = requests.get(f"{self.api_base}/binaries/{binary_id}/security-summary")
        
        if response.status_code == 200:
            return response.json()['data']
        return None
    
    def update_finding_status(self, finding_id, confirmed=True, notes=""):
        """Update security finding with analyst review"""
        response = requests.put(
            f"{self.api_base}/security-findings/{finding_id}",
            json={
                "confirmed": confirmed,
                "analyst_notes": notes,
                "updated_at": datetime.now().isoformat()
            }
        )
        
        return response.status_code == 200
    
    def generate_executive_report(self, binary_ids):
        """Generate executive report for multiple binaries"""
        report_data = {
            "report_date": datetime.now().isoformat(),
            "binaries_analyzed": len(binary_ids),
            "executive_summary": {},
            "critical_findings": [],
            "remediation_priorities": []
        }
        
        total_critical = 0
        total_high = 0
        
        for binary_id in binary_ids:
            summary = self.get_security_summary(binary_id)
            if summary:
                total_critical += summary['vulnerability_breakdown']['by_severity']['CRITICAL']['count']
                total_high += summary['vulnerability_breakdown']['by_severity']['HIGH']['count']
                
                # Add critical findings
                findings = requests.get(
                    f"{self.api_base}/binaries/{binary_id}/security-findings",
                    params={"severity": "CRITICAL"}
                ).json()
                
                report_data["critical_findings"].extend(findings['data']['findings'])
        
        report_data["executive_summary"] = {
            "total_critical": total_critical,
            "total_high": total_high,
            "overall_risk": "HIGH" if total_critical > 0 else "MEDIUM",
            "action_required": total_critical > 0 or total_high > 5
        }
        
        return report_data

# Usage example
if __name__ == "__main__":
    dashboard = SecurityDashboard()
    
    binary_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    
    # Analyze binary security
    if dashboard.analyze_binary_security(binary_id):
        print("Security analysis completed")
        
        # Get security summary
        summary = dashboard.get_security_summary(binary_id)
        if summary:
            print(f"Overall risk: {summary['executive_summary']['overall_risk_level']}")
            print(f"Critical issues: {summary['executive_summary']['critical_issues']}")
        
        # Get critical vulnerabilities
        critical_vulns = dashboard.get_critical_vulnerabilities()
        print(f"Found {len(critical_vulns)} critical vulnerabilities")
        
        # Generate executive report
        report = dashboard.generate_executive_report([binary_id])
        with open("executive_security_report.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print("Executive report saved to executive_security_report.json")
```

---

## 🎯 **Best Practices**

### **Efficient Security Analysis**
1. **Staged Analysis**: Start with pattern-based detection, then use AI for high-confidence findings
2. **Risk-Based Prioritization**: Focus on critical and high severity findings first
3. **Batch Processing**: Analyze multiple binaries together for efficiency
4. **False Positive Management**: Regular review and classification of findings

### **Quality Assurance**
1. **Evidence Review**: Always examine evidence trails for high-impact findings
2. **Manual Validation**: Confirm critical vulnerabilities through manual analysis
3. **Context Analysis**: Consider the broader application context for each finding
4. **Update Management**: Regularly update finding status and analyst notes

### **Reporting & Communication**
1. **Executive Summaries**: Provide business-focused summaries for management
2. **Technical Details**: Include comprehensive technical information for developers
3. **Remediation Guidance**: Provide actionable steps for vulnerability remediation
4. **Compliance Mapping**: Map findings to relevant security standards and frameworks

---

The Security Analysis API provides enterprise-grade vulnerability detection capabilities, combining the power of AI with proven static analysis techniques to deliver high-confidence security assessments with comprehensive evidence trails and actionable remediation guidance. 