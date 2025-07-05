# API Examples

## 🔗 ShadowSeek API Usage Examples

This guide provides comprehensive examples of using the ShadowSeek REST API for various tasks.

---

## 🚀 **Getting Started**

### **Authentication**
```bash
# All API requests require authentication
API_KEY="your-api-key-here"
BASE_URL="http://localhost:5000"

# Include API key in requests
curl -H "Authorization: Bearer $API_KEY" "$BASE_URL/api/health"
```

### **Common Headers**
```bash
# Standard headers for API requests
HEADERS=(
    -H "Authorization: Bearer $API_KEY"
    -H "Content-Type: application/json"
    -H "Accept: application/json"
)
```

---

## 📁 **Binary Management Examples**

### **Upload Binary**
```bash
# Upload a binary file
curl -X POST "${HEADERS[@]}" \
  -F "file=@/path/to/malware.exe" \
  -F "name=malware_sample" \
  -F "description=Suspected malware sample" \
  "$BASE_URL/api/binary/upload"

# Response
{
  "id": 123,
  "name": "malware_sample",
  "size": 1048576,
  "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "sha1_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "file_type": "PE32 executable",
  "upload_date": "2024-01-20T10:30:00Z",
  "analysis_status": "pending"
}
```

### **List Binaries**
```bash
# Get all binaries
curl "${HEADERS[@]}" \
  "$BASE_URL/api/binary"

# Get binaries with filtering
curl "${HEADERS[@]}" \
  "$BASE_URL/api/binary?file_type=PE32&status=completed&limit=10"

# Get binaries with specific fields
curl "${HEADERS[@]}" \
  "$BASE_URL/api/binary?fields=id,name,size,analysis_status"
```

### **Get Binary Details**
```bash
# Get detailed binary information
curl "${HEADERS[@]}" \
  "$BASE_URL/api/binary/123"

# Get binary with function analysis
curl "${HEADERS[@]}" \
  "$BASE_URL/api/binary/123?include=functions,security_findings"

# Response
{
  "id": 123,
  "name": "malware_sample",
  "size": 1048576,
  "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
  "file_type": "PE32 executable",
  "analysis_status": "completed",
  "functions": [
    {
      "id": 456,
      "name": "main",
      "address": "0x401000",
      "size": 256,
      "function_type": "standard"
    }
  ],
  "security_findings": [
    {
      "id": 789,
      "finding_type": "buffer_overflow",
      "severity": "HIGH",
      "confidence": 0.85,
      "description": "Potential buffer overflow in strcpy usage"
    }
  ]
}
```

### **Download Binary**
```bash
# Download original binary file
curl "${HEADERS[@]}" -o "downloaded_malware.exe" \
  "$BASE_URL/api/binary/123/download"
```

---

## 🔍 **Function Analysis Examples**

### **Get Function Details**
```bash
# Get function information
curl "${HEADERS[@]}" "$BASE_URL/api/function/456"

# Response
{
  "id": 456,
  "binary_id": 123,
  "name": "main",
  "address": "0x401000",
  "size": 256,
  "function_type": "standard",
  "complexity_score": 3.2,
  "decompiled_code": "int main(int argc, char* argv[]) {\n    // decompiled code\n}",
  "assembly_code": "push rbp\nmov rbp, rsp\n...",
  "ai_analysis": {
    "summary": "Main function with command line argument processing",
    "confidence": 0.92,
    "security_assessment": "Low risk - standard main function"
  }
}
```

### **Analyze Function with AI**
```bash
# Request AI analysis for a function
curl -X POST "${HEADERS[@]}" \
  -d '{"provider": "openai", "model": "gpt-4", "analysis_type": "security"}' \
  "$BASE_URL/api/function/456/analyze"

# Response
{
  "task_id": "ai_analysis_789",
  "status": "pending",
  "message": "AI analysis started"
}

# Check analysis status
curl "${HEADERS[@]}" "$BASE_URL/api/task/ai_analysis_789"

# Get analysis results
curl "${HEADERS[@]}" "$BASE_URL/api/function/456/ai_analysis"
```

### **Search Functions**
```bash
# Search functions by name
curl "${HEADERS[@]}" \
  "$BASE_URL/api/function/search?name=main"

# Search functions by pattern
curl "${HEADERS[@]}" \
  "$BASE_URL/api/function/search?pattern=strcpy"

# Search functions by complexity
curl "${HEADERS[@]}" \
  "$BASE_URL/api/function/search?complexity_min=5.0"
```

---

## 🔐 **Security Analysis Examples**

### **Get Security Findings**
```bash
# Get all security findings for a binary
curl "${HEADERS[@]}" \
  "$BASE_URL/api/security/findings?binary_id=123"

# Get high-severity findings
curl "${HEADERS[@]}" \
  "$BASE_URL/api/security/findings?severity=HIGH,CRITICAL"

# Get findings by type
curl "${HEADERS[@]}" \
  "$BASE_URL/api/security/findings?type=buffer_overflow,format_string"
```

### **Security Analysis Report**
```bash
# Generate security report
curl -X POST "${HEADERS[@]}" \
  -d '{"binary_id": 123, "format": "json", "include_details": true}' \
  "$BASE_URL/api/security/report"

# Response
{
  "binary_id": 123,
  "report_id": "security_report_456",
  "generated_at": "2024-01-20T10:30:00Z",
  "summary": {
    "total_findings": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2
  },
  "findings": [
    {
      "id": 789,
      "finding_type": "buffer_overflow",
      "severity": "HIGH",
      "confidence": 0.85,
      "function": "vulnerable_function",
      "location": "line 45",
      "description": "strcpy usage without bounds checking",
      "cwe": "CWE-120",
      "remediation": "Replace strcpy with strncpy or use safer alternatives"
    }
  ]
}
```

### **Vulnerability Analytics**
```bash
# Get vulnerability statistics
curl "${HEADERS[@]}" "$BASE_URL/api/security/analytics"

# Get trend analysis
curl "${HEADERS[@]}" "$BASE_URL/api/security/analytics/trends?period=30d"

# Get CWE distribution
curl "${HEADERS[@]}" "$BASE_URL/api/security/analytics/cwe_distribution"
```

---

## 🎯 **Fuzzing Examples**

### **Create Fuzzing Campaign**
```bash
# Create a new fuzzing campaign
curl -X POST "${HEADERS[@]}" \
  -d '{
    "name": "buffer_overflow_test",
    "binary_id": 123,
    "target_function": "vulnerable_function",
    "fuzzer": "afl++",
    "config": {
      "timeout": 5000,
      "memory_limit": 1024,
      "dictionary": "common_words.dict"
    }
  }' \
  "$BASE_URL/api/fuzzing/campaigns"

# Response
{
  "id": 456,
  "name": "buffer_overflow_test",
  "binary_id": 123,
  "status": "created",
  "target_function": "vulnerable_function",
  "fuzzer": "afl++",
  "created_at": "2024-01-20T10:30:00Z"
}
```

### **Start Fuzzing Campaign**
```bash
# Start fuzzing campaign
curl -X POST "${HEADERS[@]}" \
  "$BASE_URL/api/fuzzing/campaigns/456/start"

# Response
{
  "campaign_id": 456,
  "status": "starting",
  "task_id": "fuzzing_task_789"
}
```

### **Monitor Fuzzing Progress**
```bash
# Get campaign status
curl "${HEADERS[@]}" "$BASE_URL/api/fuzzing/campaigns/456"

# Get fuzzing statistics
curl "${HEADERS[@]}" "$BASE_URL/api/fuzzing/campaigns/456/stats"

# Response
{
  "campaign_id": 456,
  "status": "running",
  "start_time": "2024-01-20T10:30:00Z",
  "runtime": "00:15:30",
  "executions": 150000,
  "exec_per_sec": 325.5,
  "coverage": 68.5,
  "crashes": 5,
  "unique_crashes": 3,
  "timeouts": 12,
  "memory_usage": 456
}
```

### **Get Fuzzing Results**
```bash
# Get crash information
curl "${HEADERS[@]}" "$BASE_URL/api/fuzzing/campaigns/456/crashes"

# Get specific crash details
curl "${HEADERS[@]}" "$BASE_URL/api/fuzzing/crashes/789"

# Response
{
  "id": 789,
  "campaign_id": 456,
  "crash_type": "segmentation_fault",
  "crash_location": "0x401234",
  "exploitability": "medium",
  "stack_trace": "...",
  "registers": {
    "rax": "0x41414141",
    "rbx": "0x00000000",
    "rcx": "0x41414141"
  },
  "input_data": "AAAABBBBCCCCDDDD...",
  "severity": "HIGH"
}
```

---

## 📊 **Task Management Examples**

### **Monitor Tasks**
```bash
# Get all tasks
curl "${HEADERS[@]}" "$BASE_URL/api/tasks"

# Get running tasks
curl "${HEADERS[@]}" "$BASE_URL/api/tasks?status=running"

# Get tasks for specific binary
curl "${HEADERS[@]}" "$BASE_URL/api/tasks?binary_id=123"
```

### **Task Details**
```bash
# Get task details
curl "${HEADERS[@]}" "$BASE_URL/api/task/task_id_123"

# Response
{
  "id": "task_id_123",
  "task_type": "binary_analysis",
  "status": "completed",
  "progress": 100,
  "started_at": "2024-01-20T10:30:00Z",
  "completed_at": "2024-01-20T10:45:00Z",
  "result": {
    "functions_analyzed": 45,
    "security_findings": 12,
    "analysis_time": "00:15:00"
  }
}
```

### **Control Tasks**
```bash
# Cancel a task
curl -X POST "${HEADERS[@]}" \
  "$BASE_URL/api/task/task_id_123/cancel"

# Retry failed task
curl -X POST "${HEADERS[@]}" \
  "$BASE_URL/api/task/task_id_123/retry"

# Get task logs
curl "${HEADERS[@]}" "$BASE_URL/api/task/task_id_123/logs"
```

---

## 🔄 **Batch Operations Examples**

### **Batch Binary Upload**
```bash
# Upload multiple binaries
curl -X POST "${HEADERS[@]}" \
  -F "files=@malware1.exe" \
  -F "files=@malware2.exe" \
  -F "files=@malware3.exe" \
  -F "auto_analyze=true" \
  "$BASE_URL/api/binary/batch_upload"

# Response
{
  "uploaded": [
    {"id": 123, "name": "malware1.exe", "status": "uploaded"},
    {"id": 124, "name": "malware2.exe", "status": "uploaded"},
    {"id": 125, "name": "malware3.exe", "status": "uploaded"}
  ],
  "failed": [],
  "analysis_tasks": ["task_123", "task_124", "task_125"]
}
```

### **Batch Analysis**
```bash
# Start batch analysis
curl -X POST "${HEADERS[@]}" \
  -d '{
    "binary_ids": [123, 124, 125],
    "analysis_types": ["static", "ai", "security"],
    "priority": "high"
  }' \
  "$BASE_URL/api/analysis/batch"

# Response
{
  "batch_id": "batch_789",
  "tasks": [
    {"binary_id": 123, "task_id": "task_456"},
    {"binary_id": 124, "task_id": "task_457"},
    {"binary_id": 125, "task_id": "task_458"}
  ]
}
```

### **Batch Status Check**
```bash
# Check batch status
curl "${HEADERS[@]}" "$BASE_URL/api/analysis/batch/batch_789"

# Response
{
  "batch_id": "batch_789",
  "status": "running",
  "progress": 66.7,
  "total_tasks": 3,
  "completed_tasks": 2,
  "failed_tasks": 0,
  "tasks": [
    {"binary_id": 123, "task_id": "task_456", "status": "completed"},
    {"binary_id": 124, "task_id": "task_457", "status": "completed"},
    {"binary_id": 125, "task_id": "task_458", "status": "running"}
  ]
}
```

---

## 🐍 **Python SDK Examples**

### **Installation and Setup**
```python
# Install the ShadowSeek Python SDK
pip install shadowseek-sdk

# Initialize client
from shadowseek import ShadowSeekClient

client = ShadowSeekClient(
    base_url="http://localhost:5000",
    api_key="your-api-key-here"
)
```

### **Binary Operations**
```python
# Upload binary
with open("malware.exe", "rb") as f:
    binary = client.upload_binary(
        file=f,
        name="malware_sample",
        description="Suspected malware"
    )

print(f"Uploaded binary ID: {binary.id}")

# Get binary details
binary_details = client.get_binary(binary.id)
print(f"Analysis status: {binary_details.analysis_status}")

# Start analysis
analysis_task = client.analyze_binary(
    binary.id,
    analysis_types=["static", "ai", "security"]
)

# Wait for completion
result = client.wait_for_task(analysis_task.task_id, timeout=300)
print(f"Analysis completed: {result.status}")
```

### **Security Analysis**
```python
# Get security findings
findings = client.get_security_findings(binary.id)

for finding in findings:
    print(f"Finding: {finding.finding_type}")
    print(f"Severity: {finding.severity}")
    print(f"Confidence: {finding.confidence}")
    print(f"Description: {finding.description}")
    print("---")

# Generate security report
report = client.generate_security_report(
    binary.id,
    format="json",
    include_details=True
)

print(f"Total findings: {report.summary.total_findings}")
print(f"Critical: {report.summary.critical}")
print(f"High: {report.summary.high}")
```

### **Fuzzing Operations**
```python
# Create fuzzing campaign
campaign = client.create_fuzzing_campaign(
    name="buffer_overflow_test",
    binary_id=binary.id,
    target_function="vulnerable_function",
    fuzzer="afl++",
    config={
        "timeout": 5000,
        "memory_limit": 1024,
        "dictionary": "common_words.dict"
    }
)

# Start fuzzing
client.start_fuzzing_campaign(campaign.id)

# Monitor progress
while True:
    status = client.get_fuzzing_status(campaign.id)
    print(f"Status: {status.status}")
    print(f"Executions: {status.executions}")
    print(f"Crashes: {status.crashes}")
    
    if status.status in ["completed", "failed"]:
        break
    
    time.sleep(10)

# Get results
crashes = client.get_fuzzing_crashes(campaign.id)
for crash in crashes:
    print(f"Crash: {crash.crash_type}")
    print(f"Exploitability: {crash.exploitability}")
```

---

## 📝 **JavaScript SDK Examples**

### **Installation and Setup**
```javascript
// Install the ShadowSeek JavaScript SDK
npm install shadowseek-js

// Initialize client
import { ShadowSeekClient } from 'shadowseek-js';

const client = new ShadowSeekClient({
  baseUrl: 'http://localhost:5000',
  apiKey: 'your-api-key-here'
});
```

### **Binary Operations**
```javascript
// Upload binary
const formData = new FormData();
formData.append('file', fileInput.files[0]);
formData.append('name', 'malware_sample');
formData.append('description', 'Suspected malware');

const binary = await client.uploadBinary(formData);
console.log(`Uploaded binary ID: ${binary.id}`);

// Get binary details
const binaryDetails = await client.getBinary(binary.id);
console.log(`Analysis status: ${binaryDetails.analysis_status}`);

// Start analysis
const analysisTask = await client.analyzeBinary(binary.id, {
  analysis_types: ['static', 'ai', 'security']
});

// Wait for completion
const result = await client.waitForTask(analysisTask.task_id, { timeout: 300000 });
console.log(`Analysis completed: ${result.status}`);
```

### **Real-time Updates**
```javascript
// Subscribe to real-time updates
const eventSource = client.subscribeToUpdates();

eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data);
  
  switch (data.type) {
    case 'analysis_complete':
      console.log(`Analysis completed for binary ${data.binary_id}`);
      break;
    case 'security_finding':
      console.log(`New security finding: ${data.finding.finding_type}`);
      break;
    case 'fuzzing_crash':
      console.log(`Fuzzing crash detected: ${data.crash.crash_type}`);
      break;
  }
};

// Close connection when done
eventSource.close();
```

---

## 🔧 **Advanced Examples**

### **Custom Analysis Pipeline**
```python
# Create custom analysis pipeline
class CustomAnalysisPipeline:
    def __init__(self, client):
        self.client = client
    
    async def analyze_binary(self, binary_path):
        # Step 1: Upload binary
        with open(binary_path, "rb") as f:
            binary = await self.client.upload_binary(f)
        
        # Step 2: Static analysis
        static_task = await self.client.analyze_binary(
            binary.id, analysis_types=["static"]
        )
        await self.client.wait_for_task(static_task.task_id)
        
        # Step 3: Get functions and analyze with AI
        functions = await self.client.get_functions(binary.id)
        
        for func in functions:
            if func.size > 100:  # Only analyze larger functions
                ai_task = await self.client.analyze_function_with_ai(
                    func.id, provider="openai"
                )
                await self.client.wait_for_task(ai_task.task_id)
        
        # Step 4: Security analysis
        security_task = await self.client.analyze_security(binary.id)
        await self.client.wait_for_task(security_task.task_id)
        
        # Step 5: Generate report
        report = await self.client.generate_security_report(
            binary.id, format="json", include_details=True
        )
        
        return report

# Usage
pipeline = CustomAnalysisPipeline(client)
result = await pipeline.analyze_binary("malware.exe")
```

### **Automated Threat Intelligence**
```python
# Automated threat intelligence gathering
class ThreatIntelligence:
    def __init__(self, client):
        self.client = client
    
    async def analyze_threat_sample(self, sample_path):
        # Upload and analyze
        with open(sample_path, "rb") as f:
            binary = await self.client.upload_binary(f)
        
        # Full analysis
        tasks = await self.client.analyze_binary(
            binary.id, 
            analysis_types=["static", "ai", "security", "behavioral"]
        )
        
        # Wait for all tasks
        for task in tasks:
            await self.client.wait_for_task(task.task_id)
        
        # Gather intelligence
        intelligence = {
            "binary_info": await self.client.get_binary(binary.id),
            "functions": await self.client.get_functions(binary.id),
            "security_findings": await self.client.get_security_findings(binary.id),
            "iocs": await self.client.extract_iocs(binary.id),
            "yara_rules": await self.client.generate_yara_rules(binary.id)
        }
        
        return intelligence

# Usage
ti = ThreatIntelligence(client)
threat_data = await ti.analyze_threat_sample("suspicious.exe")
```

---

## 🎯 **Best Practices**

### **Error Handling**
```python
# Proper error handling
try:
    binary = client.upload_binary(file_path)
    analysis = client.analyze_binary(binary.id)
    result = client.wait_for_task(analysis.task_id, timeout=300)
except ShadowSeekAPIError as e:
    print(f"API Error: {e.message}")
    print(f"Status Code: {e.status_code}")
except ShadowSeekTimeoutError as e:
    print(f"Timeout Error: {e.message}")
except Exception as e:
    print(f"Unexpected Error: {e}")
```

### **Rate Limiting**
```python
# Handle rate limiting
import time

def rate_limited_requests(client, requests, delay=1.0):
    results = []
    for i, request in enumerate(requests):
        try:
            result = request()
            results.append(result)
        except ShadowSeekRateLimitError as e:
            print(f"Rate limited, waiting {e.retry_after} seconds...")
            time.sleep(e.retry_after)
            result = request()
            results.append(result)
        
        # Add delay between requests
        if i < len(requests) - 1:
            time.sleep(delay)
    
    return results
```

### **Pagination**
```python
# Handle paginated responses
def get_all_binaries(client):
    all_binaries = []
    page = 1
    
    while True:
        response = client.get_binaries(page=page, per_page=50)
        all_binaries.extend(response.binaries)
        
        if not response.has_next:
            break
        
        page += 1
    
    return all_binaries
```

These examples demonstrate the comprehensive capabilities of the ShadowSeek API. Remember to handle errors appropriately, respect rate limits, and use authentication for all requests. 