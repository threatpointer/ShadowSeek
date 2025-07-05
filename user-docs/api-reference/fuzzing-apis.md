# Fuzzing API Reference

## 🎯 Intelligent Fuzzing & Harness Generation API

ShadowSeek's Fuzzing API provides comprehensive intelligent fuzzing capabilities with support for AFL++, AFL, LibFuzzer, and Honggfuzz. Generate custom fuzzing harnesses, manage fuzzing campaigns, and analyze results through AI-powered insights.

---

## 🌐 **Base Configuration**

**Base URL**: `http://localhost:5000/api`
**Content-Type**: `application/json`

---

## 🎯 **Fuzzing Campaign Management**

### **Create Fuzzing Campaign**
```http
POST /api/fuzzing/campaigns
```

Create a new intelligent fuzzing campaign with automatic harness generation.

**Request Body:**
```json
{
  "name": "Buffer Overflow Testing",
  "description": "Comprehensive fuzzing campaign for buffer overflow vulnerabilities",
  "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "target_functions": ["strcpy_vulnerable", "parse_input", "process_data"],
  "fuzzing_engines": ["afl++", "libfuzzer", "honggfuzz"],
  "duration": 3600,
  "harness_generation": {
    "ai_enabled": true,
    "coverage_guided": true,
    "input_formats": ["text", "binary", "structured"],
    "seed_generation": "ai_assisted"
  },
  "configuration": {
    "max_memory": "2GB",
    "cpu_cores": 4,
    "timeout": 30,
    "dictionary_enabled": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "campaign": {
      "id": "campaign_456",
      "name": "Buffer Overflow Testing",
      "status": "initializing",
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "created_at": "2024-01-15T11:00:00Z",
      "target_functions": ["strcpy_vulnerable", "parse_input", "process_data"],
      "fuzzing_engines": ["afl++", "libfuzzer", "honggfuzz"],
      "harness_tasks": [
        {
          "function": "strcpy_vulnerable",
          "task_id": "harness_gen_789",
          "status": "queued"
        }
      ]
    },
    "estimates": {
      "harness_generation_time": "5-8 minutes",
      "total_setup_time": "10-15 minutes",
      "fuzzing_duration": "1 hour",
      "completion_time": "2024-01-15T12:15:00Z"
    }
  },
  "message": "Fuzzing campaign created",
  "timestamp": "2024-01-15T11:00:00Z"
}
```

### **Get Campaign Status**
```http
GET /api/fuzzing/campaigns/{campaign_id}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "campaign": {
      "id": "campaign_456",
      "name": "Buffer Overflow Testing",
      "status": "running",
      "progress": 45.2,
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "started_at": "2024-01-15T11:15:00Z",
      "estimated_completion": "2024-01-15T12:15:00Z",
      "active_fuzzers": 3,
      "total_executions": 1250000,
      "crashes_found": 5,
      "unique_crashes": 3,
      "coverage_percentage": 78.5
    },
    "fuzzer_details": [
      {
        "engine": "afl++",
        "status": "running",
        "executions": 650000,
        "crashes": 2,
        "paths": 1523,
        "coverage": 82.1
      },
      {
        "engine": "libfuzzer",
        "status": "running", 
        "executions": 400000,
        "crashes": 2,
        "features": 2847,
        "coverage": 75.3
      },
      {
        "engine": "honggfuzz",
        "status": "running",
        "executions": 200000,
        "crashes": 1,
        "coverage": 79.2
      }
    ]
  },
  "message": "Campaign status retrieved",
  "timestamp": "2024-01-15T11:45:00Z"
}
```

### **List Fuzzing Campaigns**
```http
GET /api/fuzzing/campaigns?status=running&page=1&per_page=20
```

**Response:**
```json
{
  "success": true,
  "data": {
    "campaigns": [
      {
        "id": "campaign_456",
        "name": "Buffer Overflow Testing",
        "status": "running",
        "binary_name": "example.exe",
        "created_at": "2024-01-15T11:00:00Z",
        "duration": 3600,
        "progress": 45.2,
        "crashes_found": 5,
        "active_fuzzers": 3
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 1,
      "pages": 1
    }
  },
  "message": "Campaigns retrieved",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 🔧 **Fuzzing Harness Generation**

### **Generate Function Harness**
```http
POST /api/fuzzing/harness/generate
```

Generate AI-powered fuzzing harness for specific functions.

**Request Body:**
```json
{
  "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "function_name": "strcpy_vulnerable",
  "harness_type": "afl++",
  "ai_analysis": true,
  "input_types": ["string", "buffer"],
  "coverage_targets": ["branches", "functions", "basic_blocks"],
  "seed_generation": {
    "enabled": true,
    "count": 100,
    "ai_assisted": true
  }
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "harness": {
      "id": "harness_789",
      "function_name": "strcpy_vulnerable",
      "harness_type": "afl++",
      "status": "generated",
      "source_code": "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n// AI-Generated Harness for strcpy_vulnerable\nint main(int argc, char** argv) {\n    if (argc != 2) {\n        fprintf(stderr, \"Usage: %s <input_file>\\n\", argv[0]);\n        return 1;\n    }\n    \n    FILE* fp = fopen(argv[1], \"rb\");\n    if (!fp) {\n        perror(\"fopen\");\n        return 1;\n    }\n    \n    // Read input data\n    fseek(fp, 0, SEEK_END);\n    long size = ftell(fp);\n    fseek(fp, 0, SEEK_SET);\n    \n    char* input = malloc(size + 1);\n    if (!input) {\n        fclose(fp);\n        return 1;\n    }\n    \n    fread(input, 1, size, fp);\n    input[size] = '\\0';\n    fclose(fp);\n    \n    // Call target function\n    strcpy_vulnerable(input);\n    \n    free(input);\n    return 0;\n}",
      "compilation_flags": "-fsanitize=address -fsanitize=fuzzer-no-link -g -O1",
      "generated_at": "2024-01-15T11:10:00Z"
    },
    "ai_analysis": {
      "function_signature": "void strcpy_vulnerable(char* input)",
      "vulnerability_assessment": "High probability buffer overflow vulnerability",
      "input_constraints": "String input, no length validation detected",
      "recommended_seeds": ["normal_string", "long_string", "special_chars"],
      "coverage_strategy": "Focus on buffer boundary conditions"
    },
    "seeds": [
      {
        "name": "normal_input",
        "content": "Hello World",
        "description": "Normal string input"
      },
      {
        "name": "boundary_test",
        "content": "A" * 255,
        "description": "Boundary condition test"
      },
      {
        "name": "overflow_test", 
        "content": "A" * 512,
        "description": "Potential buffer overflow"
      }
    ]
  },
  "message": "Fuzzing harness generated",
  "timestamp": "2024-01-15T11:10:00Z"
}
```

### **Get Harness Details**
```http
GET /api/fuzzing/harness/{harness_id}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "harness": {
      "id": "harness_789",
      "function_name": "strcpy_vulnerable",
      "harness_type": "afl++",
      "status": "ready",
      "source_code": "// Complete harness source code...",
      "compiled_binary": "/tmp/harness_789",
      "compilation_flags": "-fsanitize=address -fsanitize=fuzzer-no-link -g -O1",
      "generated_at": "2024-01-15T11:10:00Z",
      "compiled_at": "2024-01-15T11:12:00Z"
    },
    "usage_instructions": {
      "compilation": "gcc -o harness harness.c target_binary.o -fsanitize=address",
      "execution": "afl-fuzz -i seeds/ -o results/ ./harness @@",
      "sanitizers": ["AddressSanitizer", "UndefinedBehaviorSanitizer"]
    }
  },
  "message": "Harness details retrieved",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

---

## 🚀 **Fuzzing Execution**

### **Start Fuzzing Session**
```http
POST /api/fuzzing/sessions
```

Start a new fuzzing session with specified configuration.

**Request Body:**
```json
{
  "campaign_id": "campaign_456",
  "harness_id": "harness_789",
  "fuzzer_engine": "afl++",
  "duration": 3600,
  "configuration": {
    "memory_limit": "2GB",
    "timeout": 30,
    "cpu_cores": 2,
    "dictionary": true,
    "deterministic": false,
    "power_schedules": ["fast", "explore", "exploit"]
  },
  "seed_corpus": [
    "normal_input",
    "boundary_test", 
    "overflow_test"
  ]
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "session": {
      "id": "session_123",
      "campaign_id": "campaign_456",
      "harness_id": "harness_789",
      "fuzzer_engine": "afl++",
      "status": "starting",
      "started_at": "2024-01-15T11:20:00Z",
      "estimated_completion": "2024-01-15T12:20:00Z",
      "pid": 12345,
      "working_directory": "/tmp/fuzzing_session_123"
    },
    "configuration": {
      "memory_limit": "2GB",
      "timeout": 30,
      "cpu_cores": 2,
      "seed_count": 3
    }
  },
  "message": "Fuzzing session started",
  "timestamp": "2024-01-15T11:20:00Z"
}
```

### **Get Session Status**
```http
GET /api/fuzzing/sessions/{session_id}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "session": {
      "id": "session_123",
      "status": "running",
      "fuzzer_engine": "afl++",
      "started_at": "2024-01-15T11:20:00Z",
      "runtime": "00:25:30",
      "estimated_completion": "2024-01-15T12:20:00Z",
      "progress": 42.5
    },
    "statistics": {
      "total_executions": 850000,
      "executions_per_second": 567,
      "total_paths": 1847,
      "unique_crashes": 2,
      "unique_hangs": 0,
      "coverage_percentage": 78.5,
      "last_new_path": "2024-01-15T11:43:00Z"
    },
    "recent_findings": [
      {
        "type": "crash",
        "found_at": "2024-01-15T11:35:00Z",
        "input_hash": "a1b2c3d4e5f6",
        "crash_details": "SIGSEGV in strcpy_vulnerable+0x15"
      }
    ]
  },
  "message": "Session status retrieved",
  "timestamp": "2024-01-15T11:45:00Z"
}
```

---

## 🐛 **Crash Analysis**

### **Get Crashes**
```http
GET /api/fuzzing/sessions/{session_id}/crashes
```

**Response:**
```json
{
  "success": true,
  "data": {
    "crashes": [
      {
        "id": "crash_456",
        "session_id": "session_123",
        "found_at": "2024-01-15T11:35:00Z",
        "signal": "SIGSEGV",
        "crash_hash": "a1b2c3d4e5f6",
        "severity": "HIGH",
        "exploitability": "PROBABLE",
        "input_file": "id:000001,sig:11,src:000000,op:havoc,rep:128",
        "input_size": 512,
        "crash_details": {
          "signal": "SIGSEGV",
          "address": "0x00007fff5fbff000",
          "instruction": "strcpy_vulnerable+0x15",
          "stack_trace": [
            "strcpy_vulnerable+0x15",
            "main+0x45",
            "__libc_start_main+0xe7"
          ]
        }
      }
    ],
    "summary": {
      "total_crashes": 2,
      "unique_crashes": 2,
      "exploitable_crashes": 1,
      "severity_distribution": {
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 0
      }
    }
  },
  "message": "Crashes retrieved",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Analyze Crash**
```http
POST /api/fuzzing/crashes/{crash_id}/analyze
```

**Request Body:**
```json
{
  "ai_analysis": true,
  "exploitability_assessment": true,
  "root_cause_analysis": true,
  "generate_poc": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "crash": {
      "id": "crash_456",
      "analysis_completed_at": "2024-01-15T12:05:00Z"
    },
    "analysis": {
      "root_cause": "Buffer overflow in strcpy_vulnerable function",
      "exploitability": "HIGH",
      "severity": "CRITICAL",
      "confidence": 92.5,
      "description": "The crash is caused by a buffer overflow when copying a 512-byte input to a 256-byte buffer. The overflow overwrites the return address, leading to a segmentation fault when the function attempts to return.",
      "technical_details": {
        "vulnerability_type": "Stack-based buffer overflow",
        "affected_function": "strcpy_vulnerable",
        "overflow_size": 256,
        "control_flow_hijack": true,
        "mitigations_bypassed": ["ASLR", "DEP"]
      }
    },
    "ai_assessment": {
      "exploitability_score": 8.5,
      "impact_assessment": "Complete system compromise possible",
      "attack_vector": "Input vector can be controlled to achieve arbitrary code execution",
      "mitigation_recommendations": [
        "Replace strcpy with strncpy",
        "Implement bounds checking",
        "Use stack canaries"
      ]
    },
    "proof_of_concept": {
      "input_file": "crash_456_poc.bin",
      "exploit_payload": "A" * 280 + "\\x41\\x41\\x41\\x41",
      "execution_steps": [
        "Compile harness with debug symbols",
        "Run with provided input file",
        "Observe crash at strcpy_vulnerable+0x15"
      ]
    }
  },
  "message": "Crash analysis completed",
  "timestamp": "2024-01-15T12:05:00Z"
}
```

---

## 📊 **Fuzzing Results & Analytics**

### **Get Campaign Results**
```http
GET /api/fuzzing/campaigns/{campaign_id}/results
```

**Response:**
```json
{
  "success": true,
  "data": {
    "campaign": {
      "id": "campaign_456",
      "name": "Buffer Overflow Testing",
      "status": "completed",
      "duration": 3600,
      "completed_at": "2024-01-15T12:15:00Z"
    },
    "summary": {
      "total_executions": 2500000,
      "unique_crashes": 5,
      "total_crashes": 12,
      "unique_hangs": 1,
      "coverage_achieved": 85.2,
      "new_paths_discovered": 2847,
      "vulnerabilities_found": 3
    },
    "fuzzer_performance": [
      {
        "engine": "afl++",
        "executions": 1500000,
        "crashes_found": 8,
        "coverage": 87.1,
        "efficiency": "HIGH"
      },
      {
        "engine": "libfuzzer",
        "executions": 700000,
        "crashes_found": 3,
        "coverage": 82.3,
        "efficiency": "MEDIUM"
      },
      {
        "engine": "honggfuzz",
        "executions": 300000,
        "crashes_found": 1,
        "coverage": 86.2,
        "efficiency": "MEDIUM"
      }
    ],
    "vulnerability_summary": [
      {
        "type": "Buffer Overflow",
        "count": 2,
        "severity": "CRITICAL",
        "functions": ["strcpy_vulnerable", "process_data"]
      },
      {
        "type": "Integer Overflow",
        "count": 1,
        "severity": "HIGH",
        "functions": ["parse_input"]
      }
    ]
  },
  "message": "Campaign results retrieved",
  "timestamp": "2024-01-15T12:15:00Z"
}
```

### **Generate Fuzzing Report**
```http
POST /api/fuzzing/campaigns/{campaign_id}/report
```

**Request Body:**
```json
{
  "report_format": "json",
  "include_crashes": true,
  "include_coverage": true,
  "include_performance": true,
  "include_recommendations": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "report": {
      "metadata": {
        "campaign_id": "campaign_456",
        "report_generated_at": "2024-01-15T12:20:00Z",
        "report_type": "fuzzing_summary"
      },
      "executive_summary": {
        "campaign_name": "Buffer Overflow Testing",
        "duration": "1 hour",
        "vulnerabilities_found": 3,
        "overall_assessment": "Multiple critical vulnerabilities discovered",
        "immediate_actions": [
          "Fix buffer overflow in strcpy_vulnerable",
          "Implement bounds checking in process_data",
          "Add input validation in parse_input"
        ]
      },
      "technical_results": {
        "total_executions": 2500000,
        "coverage_achieved": 85.2,
        "crash_analysis": [
          {
            "crash_id": "crash_456",
            "vulnerability": "Buffer Overflow",
            "severity": "CRITICAL",
            "exploitability": "HIGH",
            "affected_function": "strcpy_vulnerable"
          }
        ]
      },
      "recommendations": {
        "immediate": [
          "Address critical buffer overflow vulnerabilities",
          "Implement proper input validation"
        ],
        "short_term": [
          "Integrate continuous fuzzing into CI/CD pipeline",
          "Expand fuzzing coverage to additional functions"
        ],
        "long_term": [
          "Implement comprehensive security testing strategy",
          "Regular security code reviews"
        ]
      }
    }
  },
  "message": "Fuzzing report generated",
  "timestamp": "2024-01-15T12:20:00Z"
}
```

---

## 🔧 **Fuzzing Configuration**

### **Get Fuzzing Engines**
```http
GET /api/fuzzing/engines
```

**Response:**
```json
{
  "success": true,
  "data": {
    "engines": [
      {
        "name": "afl++",
        "version": "4.09c",
        "description": "Advanced AFL with improved performance and features",
        "supported_targets": ["x86_64", "i386", "arm64"],
        "features": ["coverage_guided", "mutation_scheduling", "power_scheduling"],
        "status": "available"
      },
      {
        "name": "libfuzzer",
        "version": "16.0.0",
        "description": "LLVM's in-process evolutionary fuzzer",
        "supported_targets": ["x86_64", "i386", "arm64"],
        "features": ["coverage_guided", "structure_aware", "corpus_minimization"],
        "status": "available"
      },
      {
        "name": "honggfuzz",
        "version": "2.5",
        "description": "Security-oriented fuzzer with advanced features",
        "supported_targets": ["x86_64", "i386", "arm64"],
        "features": ["coverage_guided", "feedback_driven", "crash_analysis"],
        "status": "available"
      }
    ]
  },
  "message": "Fuzzing engines retrieved",
  "timestamp": "2024-01-15T12:00:00Z"
}
```

### **Update Fuzzing Configuration**
```http
PUT /api/fuzzing/config
```

**Request Body:**
```json
{
  "default_engine": "afl++",
  "default_timeout": 30,
  "default_memory_limit": "2GB",
  "max_concurrent_sessions": 10,
  "ai_harness_generation": true,
  "crash_analysis_enabled": true,
  "coverage_tracking": true
}
```

---

## 💡 **Complete Fuzzing Workflow Example**

```python
import requests
import time
import json

class FuzzingManager:
    def __init__(self, api_base="http://localhost:5000/api"):
        self.api_base = api_base
    
    def create_fuzzing_campaign(self, binary_id, target_functions):
        """Create comprehensive fuzzing campaign"""
        campaign_data = {
            "name": f"Security Fuzzing - {binary_id[:8]}",
            "description": "AI-powered security fuzzing campaign",
            "binary_id": binary_id,
            "target_functions": target_functions,
            "fuzzing_engines": ["afl++", "libfuzzer", "honggfuzz"],
            "duration": 3600,
            "harness_generation": {
                "ai_enabled": True,
                "coverage_guided": True,
                "seed_generation": "ai_assisted"
            }
        }
        
        response = requests.post(
            f"{self.api_base}/fuzzing/campaigns",
            json=campaign_data
        )
        
        if response.status_code == 200:
            return response.json()['data']['campaign']
        return None
    
    def monitor_campaign(self, campaign_id):
        """Monitor fuzzing campaign progress"""
        while True:
            response = requests.get(f"{self.api_base}/fuzzing/campaigns/{campaign_id}")
            if response.status_code == 200:
                campaign = response.json()['data']['campaign']
                
                print(f"Status: {campaign['status']}")
                print(f"Progress: {campaign.get('progress', 0):.1f}%")
                print(f"Crashes: {campaign.get('crashes_found', 0)}")
                print(f"Coverage: {campaign.get('coverage_percentage', 0):.1f}%")
                
                if campaign['status'] in ['completed', 'failed']:
                    return campaign
                    
            time.sleep(30)
    
    def analyze_campaign_results(self, campaign_id):
        """Analyze fuzzing campaign results"""
        response = requests.get(f"{self.api_base}/fuzzing/campaigns/{campaign_id}/results")
        
        if response.status_code == 200:
            results = response.json()['data']
            
            print(f"Campaign completed successfully!")
            print(f"Total executions: {results['summary']['total_executions']:,}")
            print(f"Unique crashes: {results['summary']['unique_crashes']}")
            print(f"Coverage achieved: {results['summary']['coverage_achieved']:.1f}%")
            print(f"Vulnerabilities found: {results['summary']['vulnerabilities_found']}")
            
            return results
        return None
    
    def generate_report(self, campaign_id):
        """Generate comprehensive fuzzing report"""
        response = requests.post(
            f"{self.api_base}/fuzzing/campaigns/{campaign_id}/report",
            json={
                "report_format": "json",
                "include_crashes": True,
                "include_coverage": True,
                "include_recommendations": True
            }
        )
        
        if response.status_code == 200:
            report = response.json()['data']['report']
            
            # Save report to file
            with open(f"fuzzing_report_{campaign_id}.json", "w") as f:
                json.dump(report, f, indent=2)
            
            print(f"Report saved to fuzzing_report_{campaign_id}.json")
            return report
        return None

# Usage example
if __name__ == "__main__":
    fuzzer = FuzzingManager()
    
    binary_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    target_functions = ["strcpy_vulnerable", "parse_input", "process_data"]
    
    # Create fuzzing campaign
    campaign = fuzzer.create_fuzzing_campaign(binary_id, target_functions)
    if campaign:
        print(f"Fuzzing campaign created: {campaign['id']}")
        
        # Monitor progress
        final_campaign = fuzzer.monitor_campaign(campaign['id'])
        
        # Analyze results
        if final_campaign['status'] == 'completed':
            results = fuzzer.analyze_campaign_results(campaign['id'])
            
            # Generate report
            report = fuzzer.generate_report(campaign['id'])
            
            print("Fuzzing campaign completed successfully!")
```

---

## 🎯 **Best Practices**

### **Campaign Planning**
1. **Function Selection**: Target functions with user input or high complexity
2. **Engine Selection**: Use multiple engines for comprehensive coverage
3. **Duration Planning**: Allow sufficient time for thorough testing
4. **Resource Allocation**: Ensure adequate CPU and memory resources

### **Harness Generation**
1. **AI Assistance**: Enable AI-powered harness generation for better coverage
2. **Seed Quality**: Use high-quality seeds that exercise different code paths
3. **Input Validation**: Focus on functions with poor input validation
4. **Coverage Targets**: Prioritize branch and function coverage

### **Results Analysis**
1. **Crash Triage**: Prioritize unique crashes over duplicate crashes
2. **Exploitability Assessment**: Focus on crashes with high exploitability
3. **Root Cause Analysis**: Understand the underlying vulnerability
4. **Remediation Planning**: Develop actionable fix recommendations

The Fuzzing API provides enterprise-grade intelligent fuzzing capabilities with AI-powered harness generation, comprehensive crash analysis, and detailed reporting to identify security vulnerabilities efficiently. 