# Fuzzing Examples

## 🎯 ShadowSeek Fuzzing Examples

This guide provides comprehensive examples of using ShadowSeek's fuzzing capabilities to discover vulnerabilities in binary applications.

> **✅ Production Status**: As of December 2024, all fuzzing harness compilation issues have been resolved. Generated harnesses compile cleanly with AFL++ and execute successfully in real fuzzing campaigns.

---

## 🚀 **Getting Started with Fuzzing**

### **Basic Fuzzing Workflow**
```mermaid
graph TB
    subgraph "Fuzzing Workflow"
        A[Upload Binary] --> B[Analyze Functions]
        B --> C[Select Target Function]
        C --> D[Generate Harness]
        D --> E[Configure Fuzzer]
        E --> F[Start Fuzzing Campaign]
        F --> G[Monitor Progress]
        G --> H[Analyze Crashes]
        H --> I[Generate Report]
    end
```

### **Prerequisites**
- Binary uploaded to ShadowSeek
- Target function identified
- Fuzzer installed (AFL++, LibFuzzer, etc.)
- Sufficient system resources

---

## 🔍 **Target Function Selection**

### **Identifying Vulnerable Functions**
```python
# Example: Finding functions with potential vulnerabilities
import requests

def find_vulnerable_functions(binary_id):
    """Find functions that are good fuzzing targets"""
    
    # Get all functions
    response = requests.get(f"/api/binary/{binary_id}/functions")
    functions = response.json()
    
    vulnerable_functions = []
    
    for func in functions:
        # Look for functions with:
        # 1. String operations
        # 2. Buffer operations
        # 3. User input handling
        # 4. Network operations
        
        if any(keyword in func['name'].lower() for keyword in [
            'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
            'memcpy', 'memmove', 'read', 'recv', 'input'
        ]):
            vulnerable_functions.append(func)
    
    return vulnerable_functions

# Usage
vulnerable_funcs = find_vulnerable_functions(123)
for func in vulnerable_funcs:
    print(f"Vulnerable function: {func['name']} at {func['address']}")
```

### **Function Analysis for Fuzzing**
```bash
# Get function details for fuzzing analysis
curl -H "Authorization: Bearer $API_KEY" \
  "http://localhost:5000/api/function/456?include=decompiled_code,assembly_code,security_findings"

# Response includes:
# - Function signature
# - Parameter types
# - Buffer operations
# - Input validation
# - Security findings
```

---

## 🛠️ **Harness Generation Examples**

### **Basic Buffer Overflow Harness** ⭐ **Updated for Production**
```c
// Example: Fuzzing a vulnerable strcpy function
// Compilation-verified harness structure
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// AFL++ specific includes - no config.h needed for basic fuzzing

// Target function declarations
void target_vulnerable_strcpy(const char *input, size_t len);

// Stub function implementation - replace with actual binary function call
void target_vulnerable_strcpy(const char *input, size_t len) {
    // STUB: Replace this with actual function call to vulnerable_strcpy
    // For demonstration purposes, this stub just validates input
    if (input && len > 0) {
        volatile char temp = input[0];  // Prevent optimization
        (void)temp;  // Suppress unused variable warning
    }
    // TODO: Link against original binary and call actual vulnerable_strcpy function
}

int main(int argc, char* argv[]) {
    // AFL++ setup
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif
    
    // Read input file (outside AFL++ loop for proper scoping)
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // Limit input size to prevent excessive memory usage
    if (file_size > 1024 * 1024) {
        fprintf(stderr, "Input file too large (max 1MB)\n");
        fclose(fp);
        return 1;
    }
    
    // Read input data
    unsigned char *input_data = malloc(file_size + 1);
    if (!input_data) {
        perror("malloc");
        fclose(fp);
        return 1;
    }
    
    size_t bytes_read = fread(input_data, 1, file_size, fp);
    fclose(fp);
    input_data[bytes_read] = '\0';
    
    #ifdef __AFL_LOOP
        while (__AFL_LOOP(1000)) {
    #endif
    
    // Execute fuzzing target
    target_vulnerable_strcpy((char*)input_data, bytes_read);
    
    // AFL++ loop closing
    #ifdef __AFL_LOOP
        }
    #endif
    
    free(input_data);
    return 0;
}
```

#### **Compilation and Testing**
```bash
# Compile with AFL++
$ afl-clang-fast -fsanitize=address -g -O1 -fno-omit-frame-pointer -o harness harness.c
afl-cc++4.34a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-PCGUARD
[+] Instrumented 15 locations with no collisions

# Test execution
$ echo "AAAABBBBCCCC" > test_input.txt
$ ./harness test_input.txt
# Harness executes successfully

# Start fuzzing campaign
$ mkdir -p inputs outputs
$ echo "test" > inputs/seed1
$ afl-fuzz -i inputs -o outputs -d ./harness @@
```

### **Network Input Fuzzing Harness**
```c
// Example: Fuzzing network protocol parser
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

extern int parse_network_packet(const char* packet, size_t len);

int main(int argc, char* argv[]) {
    #ifdef __AFL_FUZZ_TESTCASE_LEN
    __AFL_INIT();
    
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    
    while (__AFL_LOOP(1000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        if (len > 0 && len < 4096) {
            // Simulate network packet
            parse_network_packet((char*)buf, len);
        }
    }
    
    #else
    // File input fuzzing
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE* fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    
    char buffer[4096];
    size_t len = fread(buffer, 1, sizeof(buffer), fp);
    fclose(fp);
    
    if (len > 0) {
        parse_network_packet(buffer, len);
    }
    #endif
    
    return 0;
}
```

### **File Format Fuzzing Harness**
```c
// Example: Fuzzing image parser
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int parse_image_file(const char* filename);

// LibFuzzer harness
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create temporary file
    char temp_filename[] = "/tmp/fuzz_image_XXXXXX";
    int fd = mkstemp(temp_filename);
    
    if (fd == -1) {
        return 0;
    }
    
    // Write fuzz data to temp file
    write(fd, data, size);
    close(fd);
    
    // Parse the file
    parse_image_file(temp_filename);
    
    // Clean up
    unlink(temp_filename);
    
    return 0;
}

// AFL++ harness
int main(int argc, char* argv[]) {
    #ifdef __AFL_FUZZ_TESTCASE_LEN
    __AFL_INIT();
    
    while (__AFL_LOOP(1000)) {
        // Create temp file with fuzz data
        char temp_filename[] = "/tmp/fuzz_image_XXXXXX";
        int fd = mkstemp(temp_filename);
        
        if (fd != -1) {
            write(fd, __AFL_FUZZ_TESTCASE_BUF, __AFL_FUZZ_TESTCASE_LEN);
            close(fd);
            
            parse_image_file(temp_filename);
            unlink(temp_filename);
        }
    }
    
    #else
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    parse_image_file(argv[1]);
    #endif
    
    return 0;
}
```

---

## 🔧 **Fuzzer Configuration Examples**

### **AFL++ Configuration**
```bash
# AFL++ fuzzing campaign configuration
CAMPAIGN_CONFIG='{
  "name": "buffer_overflow_campaign",
  "binary_id": 123,
  "target_function": "vulnerable_strcpy",
  "fuzzer": "afl++",
  "config": {
    "timeout": 5000,
    "memory_limit": 1024,
    "cpu_cores": 4,
    "dictionary": "strings.dict",
    "deterministic_fuzzing": true,
    "persistent_mode": true,
    "environment": {
      "AFL_FAST_CAL": "1",
      "AFL_SKIP_CPUFREQ": "1",
      "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"
    }
  }
}'

# Create campaign
curl -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$CAMPAIGN_CONFIG" \
  "http://localhost:5000/api/fuzzing/campaigns"
```

### **LibFuzzer Configuration**
```bash
# LibFuzzer configuration
LIBFUZZER_CONFIG='{
  "name": "libfuzzer_campaign",
  "binary_id": 123,
  "target_function": "parse_network_packet",
  "fuzzer": "libfuzzer",
  "config": {
    "max_len": 4096,
    "timeout": 10,
    "rss_limit_mb": 2048,
    "malloc_limit_mb": 2048,
    "max_total_time": 3600,
    "runs": 1000000,
    "dict": "network_protocols.dict",
    "use_counters": true,
    "use_memmem": true,
    "use_cmp": true
  }
}'

# Create and start campaign
curl -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$LIBFUZZER_CONFIG" \
  "http://localhost:5000/api/fuzzing/campaigns"
```

### **Honggfuzz Configuration**
```bash
# Honggfuzz configuration
HONGGFUZZ_CONFIG='{
  "name": "honggfuzz_campaign",
  "binary_id": 123,
  "target_function": "parse_image_file",
  "fuzzer": "honggfuzz",
  "config": {
    "timeout": 30,
    "threads": 8,
    "mutations_per_run": 6,
    "dict": "image_formats.dict",
    "sanitizers": ["address", "undefined"],
    "feedback": ["hardware", "software"],
    "persistent": true,
    "tmout_sigvtalrm": true
  }
}'

# Create campaign
curl -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$HONGGFUZZ_CONFIG" \
  "http://localhost:5000/api/fuzzing/campaigns"
```

---

## 📊 **Monitoring and Analytics**

### **Real-time Monitoring**
```python
# Monitor fuzzing campaign in real-time
import time
import requests

def monitor_fuzzing_campaign(campaign_id):
    """Monitor fuzzing campaign progress"""
    
    while True:
        # Get campaign status
        response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}")
        campaign = response.json()
        
        # Get statistics
        stats_response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}/stats")
        stats = stats_response.json()
        
        # Display progress
        print(f"Campaign: {campaign['name']}")
        print(f"Status: {campaign['status']}")
        print(f"Runtime: {stats['runtime']}")
        print(f"Executions: {stats['executions']:,}")
        print(f"Exec/sec: {stats['exec_per_sec']:.2f}")
        print(f"Coverage: {stats['coverage']:.2f}%")
        print(f"Crashes: {stats['crashes']}")
        print(f"Unique crashes: {stats['unique_crashes']}")
        print(f"Memory: {stats['memory_usage']} MB")
        print("-" * 50)
        
        # Check if campaign is complete
        if campaign['status'] in ['completed', 'failed', 'cancelled']:
            print(f"Campaign {campaign['status']}")
            break
        
        time.sleep(10)

# Usage
monitor_fuzzing_campaign(456)
```

### **Coverage Analysis**
```python
# Analyze code coverage
def analyze_coverage(campaign_id):
    """Analyze code coverage from fuzzing campaign"""
    
    response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}/coverage")
    coverage = response.json()
    
    print(f"Total basic blocks: {coverage['total_blocks']}")
    print(f"Covered blocks: {coverage['covered_blocks']}")
    print(f"Coverage percentage: {coverage['percentage']:.2f}%")
    
    # Coverage by function
    for func_coverage in coverage['functions']:
        print(f"Function: {func_coverage['name']}")
        print(f"  Blocks: {func_coverage['covered']}/{func_coverage['total']}")
        print(f"  Coverage: {func_coverage['percentage']:.2f}%")
    
    # Hot paths (most executed)
    print("\nHot paths:")
    for path in coverage['hot_paths']:
        print(f"  {path['address']}: {path['hit_count']} hits")
    
    # Uncovered code
    print("\nUncovered functions:")
    for func in coverage['uncovered_functions']:
        print(f"  {func['name']} at {func['address']}")

# Usage
analyze_coverage(456)
```

---

## 💥 **Crash Analysis Examples**

### **Crash Triage**
```python
# Analyze and triage crashes
def triage_crashes(campaign_id):
    """Triage crashes from fuzzing campaign"""
    
    response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}/crashes")
    crashes = response.json()
    
    crash_types = {}
    exploitable_crashes = []
    
    for crash in crashes:
        # Group by crash type
        crash_type = crash['crash_type']
        if crash_type not in crash_types:
            crash_types[crash_type] = []
        crash_types[crash_type].append(crash)
        
        # Check exploitability
        if crash['exploitability'] in ['high', 'medium']:
            exploitable_crashes.append(crash)
    
    # Summary
    print(f"Total crashes: {len(crashes)}")
    print(f"Exploitable crashes: {len(exploitable_crashes)}")
    print(f"Crash types: {list(crash_types.keys())}")
    
    # Detailed analysis
    for crash_type, type_crashes in crash_types.items():
        print(f"\n{crash_type.upper()} ({len(type_crashes)} crashes):")
        
        for crash in type_crashes[:5]:  # Show top 5
            print(f"  ID: {crash['id']}")
            print(f"  Location: {crash['crash_location']}")
            print(f"  Exploitability: {crash['exploitability']}")
            print(f"  Input size: {len(crash['input_data'])} bytes")
            print()
    
    return crash_types, exploitable_crashes

# Usage
crash_types, exploitable = triage_crashes(456)
```

### **Crash Reproduction**
```python
# Reproduce crashes locally
def reproduce_crash(crash_id):
    """Reproduce a specific crash"""
    
    response = requests.get(f"/api/fuzzing/crashes/{crash_id}")
    crash = response.json()
    
    # Save crash input to file
    input_file = f"crash_input_{crash_id}.bin"
    with open(input_file, "wb") as f:
        f.write(bytes.fromhex(crash['input_data']))
    
    # Generate reproduction script
    script = f"""#!/bin/bash
# Crash reproduction script for crash ID {crash_id}

echo "Reproducing crash {crash_id}..."
echo "Crash type: {crash['crash_type']}"
echo "Location: {crash['crash_location']}"
echo "Exploitability: {crash['exploitability']}"

# Run with debugger
gdb --batch --ex run --ex bt --ex quit --args \\
  ./harness_binary {input_file}

# Run with AddressSanitizer
./harness_binary_asan {input_file}

# Run with Valgrind
valgrind --tool=memcheck --leak-check=full \\
  ./harness_binary {input_file}
"""
    
    with open(f"reproduce_crash_{crash_id}.sh", "w") as f:
        f.write(script)
    
    print(f"Crash reproduction files created:")
    print(f"  Input: {input_file}")
    print(f"  Script: reproduce_crash_{crash_id}.sh")

# Usage
reproduce_crash(789)
```

### **Crash Minimization**
```python
# Minimize crash inputs
def minimize_crash_input(crash_id):
    """Minimize crash input to smallest reproducing case"""
    
    response = requests.get(f"/api/fuzzing/crashes/{crash_id}")
    crash = response.json()
    
    original_input = bytes.fromhex(crash['input_data'])
    
    # Binary search for minimal input
    def test_input(input_data):
        # Test if input still triggers crash
        # This would call the actual harness
        return True  # Placeholder
    
    # Start with original input
    minimal_input = original_input
    
    # Try progressively smaller inputs
    for size in range(len(original_input) // 2, 0, -1):
        test_input = original_input[:size]
        
        if test_input(test_input):
            minimal_input = test_input
            print(f"Reduced input to {len(minimal_input)} bytes")
    
    # Save minimized input
    with open(f"minimal_crash_{crash_id}.bin", "wb") as f:
        f.write(minimal_input)
    
    reduction = (len(original_input) - len(minimal_input)) / len(original_input) * 100
    print(f"Input reduced from {len(original_input)} to {len(minimal_input)} bytes ({reduction:.1f}% reduction)")
    
    return minimal_input

# Usage
minimal_input = minimize_crash_input(789)
```

---

## 🔍 **Advanced Fuzzing Techniques**

### **Dictionary-based Fuzzing**
```python
# Generate fuzzing dictionary
def generate_fuzzing_dictionary(binary_id):
    """Generate dictionary from binary strings and patterns"""
    
    # Get strings from binary
    response = requests.get(f"/api/binary/{binary_id}/strings")
    strings = response.json()
    
    # Get function names
    response = requests.get(f"/api/binary/{binary_id}/functions")
    functions = response.json()
    
    dictionary = set()
    
    # Add interesting strings
    for string in strings:
        if len(string) > 2 and len(string) < 100:
            dictionary.add(string)
    
    # Add function names
    for func in functions:
        dictionary.add(func['name'])
    
    # Add common vulnerability patterns
    vuln_patterns = [
        "admin", "password", "login", "auth", "token",
        "GET", "POST", "PUT", "DELETE", "HEAD",
        "Content-Type", "Content-Length", "User-Agent",
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
        "../", "..\\", "%s", "%d", "%x", "%n",
        "javascript:", "data:", "file:", "ftp:",
        "<script>", "</script>", "alert(", "eval(",
        "AAAA", "BBBB", "CCCC", "\x00", "\xFF"
    ]
    
    dictionary.update(vuln_patterns)
    
    # Save dictionary
    with open(f"fuzzing_dict_{binary_id}.txt", "w") as f:
        for entry in sorted(dictionary):
            f.write(f'"{entry}"\n')
    
    print(f"Generated dictionary with {len(dictionary)} entries")
    return dictionary

# Usage
dict_entries = generate_fuzzing_dictionary(123)
```

### **Directed Fuzzing**
```python
# Directed fuzzing towards specific targets
def directed_fuzzing(binary_id, target_addresses):
    """Direct fuzzing towards specific addresses"""
    
    config = {
        "name": "directed_fuzzing_campaign",
        "binary_id": binary_id,
        "fuzzer": "afl++",
        "config": {
            "directed": True,
            "target_addresses": target_addresses,
            "distance_metric": "call_graph",
            "power_schedule": "explore",
            "environment": {
                "AFL_DIRECTED_FUZZING": "1",
                "AFL_TARGETS": ",".join(target_addresses)
            }
        }
    }
    
    # Create campaign
    response = requests.post("/api/fuzzing/campaigns", json=config)
    campaign = response.json()
    
    print(f"Started directed fuzzing campaign: {campaign['id']}")
    print(f"Target addresses: {target_addresses}")
    
    return campaign

# Usage - target specific vulnerable functions
target_addrs = ["0x401234", "0x401567", "0x401890"]
campaign = directed_fuzzing(123, target_addrs)
```

### **Differential Fuzzing**
```python
# Differential fuzzing between implementations
def differential_fuzzing(binary_id_1, binary_id_2):
    """Compare two binary implementations"""
    
    config = {
        "name": "differential_fuzzing_campaign",
        "type": "differential",
        "primary_binary": binary_id_1,
        "secondary_binary": binary_id_2,
        "fuzzer": "afl++",
        "config": {
            "timeout": 10000,
            "compare_outputs": True,
            "compare_return_codes": True,
            "compare_memory_usage": True,
            "ignore_crashes": False
        }
    }
    
    # Create campaign
    response = requests.post("/api/fuzzing/campaigns", json=config)
    campaign = response.json()
    
    print(f"Started differential fuzzing campaign: {campaign['id']}")
    print(f"Comparing binaries: {binary_id_1} vs {binary_id_2}")
    
    return campaign

# Usage
diff_campaign = differential_fuzzing(123, 124)
```

---

## 📈 **Performance Optimization**

### **Fuzzing Performance Tuning**
```python
# Optimize fuzzing performance
def optimize_fuzzing_performance(campaign_id):
    """Optimize fuzzing campaign performance"""
    
    # Get current performance metrics
    response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}/performance")
    metrics = response.json()
    
    optimizations = []
    
    # Check execution speed
    if metrics['exec_per_sec'] < 100:
        optimizations.append({
            "type": "performance",
            "issue": "Low execution speed",
            "recommendation": "Enable persistent mode or reduce timeout"
        })
    
    # Check memory usage
    if metrics['memory_usage'] > 2048:
        optimizations.append({
            "type": "memory",
            "issue": "High memory usage",
            "recommendation": "Reduce memory limit or use smaller inputs"
        })
    
    # Check coverage growth
    if metrics['coverage_growth_rate'] < 0.1:
        optimizations.append({
            "type": "coverage",
            "issue": "Poor coverage growth",
            "recommendation": "Add dictionary or use different mutation strategy"
        })
    
    # Apply optimizations
    for opt in optimizations:
        print(f"Optimization: {opt['type']}")
        print(f"Issue: {opt['issue']}")
        print(f"Recommendation: {opt['recommendation']}")
        print()
    
    return optimizations

# Usage
optimizations = optimize_fuzzing_performance(456)
```

### **Resource Management**
```python
# Manage fuzzing resources
def manage_fuzzing_resources():
    """Monitor and manage fuzzing resources"""
    
    # Get system resources
    response = requests.get("/api/system/resources")
    resources = response.json()
    
    # Get active campaigns
    response = requests.get("/api/fuzzing/campaigns?status=running")
    active_campaigns = response.json()
    
    print(f"System Resources:")
    print(f"  CPU Usage: {resources['cpu_usage']:.1f}%")
    print(f"  Memory Usage: {resources['memory_usage']:.1f}%")
    print(f"  Disk Usage: {resources['disk_usage']:.1f}%")
    print(f"  Active Campaigns: {len(active_campaigns)}")
    
    # Resource-based recommendations
    recommendations = []
    
    if resources['cpu_usage'] > 90:
        recommendations.append("High CPU usage - consider reducing concurrent campaigns")
    
    if resources['memory_usage'] > 85:
        recommendations.append("High memory usage - reduce memory limits or pause campaigns")
    
    if resources['disk_usage'] > 90:
        recommendations.append("Low disk space - archive old campaigns or increase storage")
    
    if len(active_campaigns) > 10:
        recommendations.append("Many active campaigns - consider prioritizing critical ones")
    
    for rec in recommendations:
        print(f"⚠️  {rec}")
    
    return recommendations

# Usage
recommendations = manage_fuzzing_resources()
```

---

## 📊 **Reporting and Analysis**

### **Comprehensive Fuzzing Report**
```python
# Generate comprehensive fuzzing report
def generate_fuzzing_report(campaign_id):
    """Generate comprehensive fuzzing report"""
    
    # Get campaign details
    response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}")
    campaign = response.json()
    
    # Get statistics
    response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}/stats")
    stats = response.json()
    
    # Get crashes
    response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}/crashes")
    crashes = response.json()
    
    # Get coverage
    response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}/coverage")
    coverage = response.json()
    
    report = {
        "campaign": campaign,
        "statistics": stats,
        "crashes": crashes,
        "coverage": coverage,
        "summary": {
            "total_executions": stats['executions'],
            "runtime_hours": stats['runtime_seconds'] / 3600,
            "average_exec_per_sec": stats['exec_per_sec'],
            "total_crashes": len(crashes),
            "unique_crashes": len(set(c['crash_hash'] for c in crashes)),
            "exploitable_crashes": len([c for c in crashes if c['exploitability'] in ['high', 'medium']]),
            "code_coverage": coverage['percentage']
        }
    }
    
    # Save report
    with open(f"fuzzing_report_{campaign_id}.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"Fuzzing report generated: fuzzing_report_{campaign_id}.json")
    return report

# Usage
report = generate_fuzzing_report(456)
```

### **Campaign Comparison**
```python
# Compare multiple fuzzing campaigns
def compare_campaigns(campaign_ids):
    """Compare multiple fuzzing campaigns"""
    
    campaigns = []
    
    for campaign_id in campaign_ids:
        response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}")
        campaign = response.json()
        
        response = requests.get(f"/api/fuzzing/campaigns/{campaign_id}/stats")
        stats = response.json()
        
        campaigns.append({
            "id": campaign_id,
            "name": campaign['name'],
            "fuzzer": campaign['fuzzer'],
            "executions": stats['executions'],
            "crashes": stats['crashes'],
            "coverage": stats['coverage'],
            "exec_per_sec": stats['exec_per_sec']
        })
    
    # Print comparison table
    print(f"{'Campaign':<20} {'Fuzzer':<10} {'Executions':<12} {'Crashes':<8} {'Coverage':<10} {'Exec/sec':<10}")
    print("-" * 80)
    
    for campaign in campaigns:
        print(f"{campaign['name']:<20} {campaign['fuzzer']:<10} {campaign['executions']:<12} {campaign['crashes']:<8} {campaign['coverage']:<10.1f} {campaign['exec_per_sec']:<10.1f}")
    
    return campaigns

# Usage
campaigns = compare_campaigns([456, 457, 458])
```

## 🔧 **Compilation Best Practices** ⭐ **December 2024 Update**

### **Production-Ready Harness Generation**

ShadowSeek now generates fully compilable harnesses with these verified practices:

#### **Key Compilation Requirements**
1. **Use C Compiler for C Files**: Always use `afl-clang-fast` (not `afl-clang-fast++`) for `.c` files
2. **No config.h Required**: Modern AFL++ doesn't require config.h for basic fuzzing
3. **Proper Variable Scoping**: Declare variables outside AFL++ loops for proper scope
4. **Function Deduplication**: Avoid multiple declarations/definitions of the same function
5. **Stub Implementations**: Provide compilable placeholder functions with clear TODO guidance

#### **Verified Compilation Commands**
```bash
# Correct compilation (✅ Works)
afl-clang-fast -fsanitize=address -g -O1 -fno-omit-frame-pointer -o harness harness.c

# Incorrect compilation (❌ Causes warnings)
afl-clang-fast++ -fsanitize=address -g -O1 -fno-omit-frame-pointer -o harness harness.c
```

#### **Testing Your Harness**
```bash
# 1. Compile cleanly
make clean && make
# Should show: "Instrumented X locations with no collisions"

# 2. Test execution
echo "test input" > test.txt
./harness test.txt
# Should execute without errors

# 3. Verify AFL++ integration
mkdir -p inputs outputs
echo "seed" > inputs/seed1
timeout 10s afl-fuzz -i inputs -o outputs -d ./harness @@
# Should initialize fuzzer and process seeds
```

### **Cross-Platform Compatibility**

#### **Windows Subsystem for Linux (WSL)**
```bash
# Tested on Ubuntu 24.04 in WSL2
wsl -d Ubuntu-24.04
cd /mnt/c/your-project/fuzzing-harness
make clean && make
./harness test_input.txt
```

#### **Native Linux**
```bash
# Tested on Ubuntu 24.04 with AFL++ 4.34a
sudo apt install afl++
make clean && make
./harness test_input.txt
```

### **Common Issues and Solutions**

#### **Issue 1: config.h not found**
```
Error: fatal error: 'config.h' file not found
Solution: Remove #include "config.h" - not needed for basic AFL++ fuzzing
```

#### **Issue 2: C++ compiler warnings**
```
Warning: treating 'c' input as 'c++' when in C++ mode
Solution: Use afl-clang-fast instead of afl-clang-fast++ for .c files
```

#### **Issue 3: Function redefinition**
```
Error: redefinition of 'target_function'
Solution: Implement function deduplication in harness generator
```

#### **Issue 4: Variable scope errors**
```
Error: use of undeclared identifier 'input_data'
Solution: Declare variables outside AFL++ loops for proper scoping
```

---

## 📋 **Complete Workflow Example**

### **End-to-End Fuzzing with ShadowSeek**

```bash
# 1. Upload binary to ShadowSeek
curl -X POST -F "file=@target.exe" http://localhost:5000/api/binaries/upload

# 2. Run security analysis
curl -X POST http://localhost:5000/api/binaries/123/analyze-security

# 3. Generate fuzzing harness
curl -X POST -H "Content-Type: application/json" \
  -d '{"harness_types":["AFL++"],"min_risk_score":30.0}' \
  http://localhost:5000/api/binaries/123/generate-fuzzing-harness

# 4. Download and extract harness
curl -o harness.zip http://localhost:5000/api/fuzzing-harnesses/456/download/package
unzip harness.zip && cd fuzzing-harness/

# 5. Compile and test
make clean && make
echo "test" > test_input.txt
./afl++_harness test_input.txt

# 6. Start fuzzing campaign
make seeds
afl-fuzz -i inputs -o outputs -d ./afl++_harness @@

# 7. Monitor results
afl-whatsup outputs/
ls outputs/default/crashes/
```

This comprehensive guide covers all aspects of fuzzing with ShadowSeek, from basic setup to advanced techniques and analysis. Use these examples as starting points for your own fuzzing campaigns and customize them based on your specific needs and targets. 