"""
Fuzzing Harness Generator for ShadowSeek - Advanced Binary Security Analysis Platform
Generates AFL/AFL++ compatible fuzzing harnesses based on security analysis results
"""

import json
import logging
import os
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from .models import (
    Binary, Function, UnifiedSecurityFinding, 
    FuzzingHarness, FuzzingTarget, db
)
from .ai_service import AIService

# Configure logger
logger = logging.getLogger(__name__)

@dataclass
class FuzzingCandidate:
    """Represents a function candidate for fuzzing"""
    function: Function
    security_finding: Optional[UnifiedSecurityFinding]
    risk_score: float
    severity: str
    rationale: str
    input_strategy: str
    priority: int


class FuzzingHarnessGenerator:
    """Generates intelligent fuzzing harnesses for multiple fuzzers based on security analysis"""
    
    def __init__(self, ai_service: AIService = None):
        self.ai_service = ai_service or AIService()
        
        # Supported fuzzers and their characteristics
        self.supported_fuzzers = {
            'AFL++': {
                'description': 'Enhanced AFL with improved features, mutations, and performance',
                'default': True,
                'file_based': True,
                'persistent_mode': True,
                'compile_flags': ['-fsanitize=address', '-g'],
                'runtime_args': ['-i', 'inputs', '-o', 'outputs', '-d']
            },
            'AFL': {
                'description': 'Classic American Fuzzy Lop fuzzer',
                'default': False,
                'file_based': True,
                'persistent_mode': True,
                'compile_flags': ['-fsanitize=address', '-g'],
                'runtime_args': ['-i', 'inputs', '-o', 'outputs']
            },
            'LibFuzzer': {
                'description': 'In-process, coverage-guided fuzzing engine (part of LLVM)',
                'default': False,
                'file_based': False,
                'persistent_mode': False,
                'compile_flags': ['-fsanitize=fuzzer,address', '-g'],
                'runtime_args': ['-max_len=1024', '-timeout=60']
            },
            'Honggfuzz': {
                'description': 'Security oriented fuzzer with powerful analysis options',
                'default': False,
                'file_based': True,
                'persistent_mode': False,
                'compile_flags': ['-fsanitize=address', '-g'],
                'runtime_args': ['-i', 'inputs', '-W', 'outputs']
            },
            'WinAFL': {
                'description': 'Windows-specific AFL fork for fuzzing Windows binaries',
                'default': False,
                'file_based': True,
                'persistent_mode': True,
                'compile_flags': ['/Od', '/Zi', '/RTC1'],
                'runtime_args': ['-i', 'inputs', '-o', 'outputs', '-D', 'DynamoRIO\\bin64', '-t', '20000']
            }
        }
        
        # Vulnerability patterns that are good fuzzing targets
        self.fuzzing_patterns = {
            'buffer_overflow': {
                'functions': ['strcpy', 'strcat', 'sprintf', 'gets', 'memcpy'],
                'strategy': 'boundary_testing',
                'priority': 1
            },
            'format_string': {
                'functions': ['printf', 'sprintf', 'fprintf', 'snprintf'],
                'strategy': 'format_injection',
                'priority': 1
            },
            'input_validation': {
                'functions': ['scanf', 'fscanf', 'sscanf', 'fgets'],
                'strategy': 'malformed_input',
                'priority': 2
            },
            'memory_corruption': {
                'functions': ['malloc', 'free', 'realloc', 'calloc'],
                'strategy': 'heap_manipulation',
                'priority': 2
            },
            'integer_overflow': {
                'functions': ['atoi', 'strtol', 'strtoul'],
                'strategy': 'boundary_values',
                'priority': 3
            }
        }
    
    def generate_harness_for_binary(
        self, 
        binary_id: int, 
        min_risk_score: float = 40.0,
        target_severities: List[str] = None,
        harness_types: List[str] = None,
        ai_enabled: bool = True,
        include_seeds: bool = True
    ) -> List[FuzzingHarness]:
        """Generate fuzzing harnesses for multiple fuzzers for a binary"""
        
        if target_severities is None:
            target_severities = ['HIGH', 'MEDIUM']
        
        if harness_types is None:
            harness_types = ['AFL++']  # Default to AFL++
        
        binary = Binary.query.get(binary_id)
        if not binary:
            raise ValueError(f"Binary {binary_id} not found")
        
        # Find fuzzing candidates
        candidates = self._find_fuzzing_candidates(
            binary, min_risk_score, target_severities
        )
        
        if not candidates:
            raise ValueError("No suitable fuzzing targets found")
        
        generated_harnesses = []
        
        # Generate harness for each requested fuzzer type
        for harness_type in harness_types:
            if harness_type not in self.supported_fuzzers:
                raise ValueError(f"Unsupported fuzzer type: {harness_type}")
            
            harness = self._generate_single_harness(
                binary, candidates, harness_type, min_risk_score, 
                target_severities, ai_enabled, include_seeds
            )
            generated_harnesses.append(harness)
        
        return generated_harnesses
    
    def _generate_single_harness(
        self,
        binary: Binary,
        candidates: List[FuzzingCandidate],
        harness_type: str,
        min_risk_score: float,
        target_severities: List[str],
        ai_enabled: bool,
        include_seeds: bool
    ) -> FuzzingHarness:
        """Generate a single harness for a specific fuzzer type"""
        
        fuzzer_config = self.supported_fuzzers[harness_type]
        
        # Create harness record
        harness = FuzzingHarness(
            binary_id=binary.id,
            name=f"{harness_type} Fuzzing Harness - {binary.filename}",
            description=f"Auto-generated {harness_type} fuzzing harness for {len(candidates)} high-risk functions",
            harness_type=harness_type,
            min_risk_score=min_risk_score,
            target_severities=json.dumps(target_severities),
            target_count=len(candidates),
            generation_strategy="security_analysis_based",
            input_type="file" if fuzzer_config['file_based'] else "in_memory"
        )
        
        db.session.add(harness)
        db.session.flush()  # Get harness ID
        
        # Create target records
        for candidate in candidates:
            target = FuzzingTarget(
                harness_id=harness.id,
                function_id=candidate.function.id,
                security_finding_id=candidate.security_finding.id if candidate.security_finding else None,
                priority=candidate.priority,
                rationale=candidate.rationale,
                risk_score=candidate.risk_score,
                severity=candidate.severity,
                input_strategy=candidate.input_strategy
            )
            db.session.add(target)
        
        # Generate fuzzer-specific code
        harness_code = self._generate_fuzzer_specific_code(binary, candidates, harness_type)
        makefile = self._generate_fuzzer_makefile(binary, harness, harness_type)
        readme = self._generate_fuzzer_readme(binary, harness, candidates, harness_type)
        fuzzer_config_data = self._generate_fuzzer_config(harness, candidates, harness_type)
        
        harness.harness_code = harness_code
        harness.makefile_content = makefile
        harness.readme_content = readme
        harness.afl_config = json.dumps(fuzzer_config_data)
        harness.confidence_score = self._calculate_harness_confidence(candidates)
        
        db.session.commit()
        return harness
    
    def _generate_fuzzer_specific_code(self, binary: Binary, candidates: List[FuzzingCandidate], fuzzer_type: str) -> str:
        """Generate fuzzer-specific harness code"""
        
        if fuzzer_type == 'LibFuzzer':
            return self._generate_libfuzzer_code(binary, candidates)
        elif fuzzer_type == 'Honggfuzz':
            return self._generate_honggfuzz_code(binary, candidates)
        elif fuzzer_type in ['AFL', 'AFL++']:
            return self._generate_afl_code(binary, candidates, fuzzer_type)
        elif fuzzer_type == 'WinAFL':
            return self._generate_winafl_code(binary, candidates)
        else:
            raise ValueError(f"Unsupported fuzzer type: {fuzzer_type}")
    
    def _generate_libfuzzer_code(self, binary: Binary, candidates: List[FuzzingCandidate]) -> str:
        """Generate LibFuzzer-specific harness code"""
        
        template = '''/*
 * LibFuzzer Harness for {binary_name}
 * Auto-generated by ShadowSeek
 * 
 * Targets {target_count} high-risk functions based on security analysis
 * Generation date: {generation_date}
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Target function declarations
{function_declarations}

// LibFuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Limit input size to prevent excessive memory usage
    if (size == 0 || size > 4096) {{
        return 0;
    }}
    
    // Create null-terminated string for string-based functions
    char *input_str = (char*)malloc(size + 1);
    if (!input_str) {{
        return 0;
    }}
    memcpy(input_str, data, size);
    input_str[size] = '\\0';
    
    // Execute fuzzing targets
{target_calls}
    
    free(input_str);
    return 0;
}}
'''
        
        # Generate function declarations - using stub functions for demonstration
        declarations = []
        for candidate in candidates:
            func = candidate.function
            # Create stub function declarations that simulate the target functions
            declarations.append(f"// Stub function for {func.name} - replace with actual function call")
            declarations.append(f"void target_{func.name}(const char *input, size_t len);")
        
        # Generate target calls
        calls = []
        for i, candidate in enumerate(candidates):
            calls.append(f"    // Target {i+1}: {candidate.function.name} - {candidate.rationale}")
            calls.append(f"    target_{candidate.function.name}(input_str, size);")
            calls.append("")
        
        return template.format(
            binary_name=binary.filename,
            target_count=len(candidates),
            generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            function_declarations="\n".join(declarations),
            target_calls="\n".join(calls)
        )
    
    def _generate_honggfuzz_code(self, binary: Binary, candidates: List[FuzzingCandidate]) -> str:
        """Generate Honggfuzz-specific harness code"""
        
        template = '''/*
 * Honggfuzz Harness for {binary_name}
 * Auto-generated by ShadowSeek
 * 
 * Targets {target_count} high-risk functions based on security analysis
 * Generation date: {generation_date}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// Target function declarations
{function_declarations}

// Fuzzing target wrapper functions
{wrapper_functions}

// Honggfuzz main harness
int main(int argc, char **argv) {{
    // Read input file
    if (argc != 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {{
        perror("fopen");
        return 1;
    }}
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // Limit input size to prevent excessive memory usage
    if (file_size > 1024 * 1024) {{
        fprintf(stderr, "Input file too large (max 1MB)\\n");
        fclose(fp);
        return 1;
    }}
    
    // Read input data
    unsigned char *input_data = malloc(file_size + 1);
    if (!input_data) {{
        perror("malloc");
        fclose(fp);
        return 1;
    }}
    
    size_t bytes_read = fread(input_data, 1, file_size, fp);
    fclose(fp);
    input_data[bytes_read] = '\\0';
    
    // Execute fuzzing targets
{target_calls}
    
    free(input_data);
    return 0;
}}
'''
        
        # Generate function declarations - using stub functions for demonstration
        declarations = []
        for candidate in candidates:
            func = candidate.function
            # Create stub function declarations that simulate the target functions
            declarations.append(f"// Stub function for {func.name} - replace with actual function call")
            declarations.append(f"void target_{func.name}(const char *input, size_t len);")
        
        # Generate wrapper functions
        wrappers = []
        for i, candidate in enumerate(candidates):
            wrapper = self._generate_wrapper_function(candidate, i)
            wrappers.append(wrapper)
        
        # Generate target calls
        calls = []
        for i, candidate in enumerate(candidates):
            calls.append(f"    // Target {i+1}: {candidate.function.name} - {candidate.rationale}")
            calls.append(f"    fuzz_target_{i}(input_data, bytes_read);")
            calls.append("")
        
        return template.format(
            binary_name=binary.filename,
            target_count=len(candidates),
            generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            function_declarations="\n".join(declarations),
            wrapper_functions="\n".join(wrappers),
            target_calls="\n".join(calls)
        )
    
    def _generate_afl_code(self, binary: Binary, candidates: List[FuzzingCandidate], fuzzer_type: str) -> str:
        """Generate AFL/AFL++ specific harness code"""
        
        template = '''/*
 * {fuzzer_type} Fuzzing Harness for {binary_name}
 * Auto-generated by ShadowSeek
 * 
 * Targets {target_count} high-risk functions based on security analysis
 * Generation date: {generation_date}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

{afl_includes}

// Target function declarations
{function_declarations}

// Stub function implementations - replace with actual binary function calls
{stub_functions}

// Fuzzing target wrapper functions
{wrapper_functions}

// Main {fuzzer_type} harness
int main(int argc, char **argv) {{
    // {fuzzer_type} setup
    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif
    
    // Read input file (outside AFL++ loop for proper scoping)
    if (argc != 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}
    
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {{
        perror("fopen");
        return 1;
    }}
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // Limit input size to prevent excessive memory usage
    if (file_size > 1024 * 1024) {{
        fprintf(stderr, "Input file too large (max 1MB)\\n");
        fclose(fp);
        return 1;
    }}
    
    // Read input data
    unsigned char *input_data = malloc(file_size + 1);
    if (!input_data) {{
        perror("malloc");
        fclose(fp);
        return 1;
    }}
    
    size_t bytes_read = fread(input_data, 1, file_size, fp);
    fclose(fp);
    input_data[bytes_read] = '\\0';
    
    // AFL++ loop start
{afl_loop_start}
    
    // Execute fuzzing targets
{target_calls}
    
    // AFL++ loop closing
{afl_loop_close}
    
    free(input_data);
    return 0;
}}
'''
        
        # AFL-specific includes and loop setup
        afl_includes = ""
        afl_loop_start = ""
        
        if fuzzer_type == 'AFL++':
            afl_includes = '''
// AFL++ specific includes - no config.h needed for basic fuzzing
'''
            afl_loop_start = '''    #ifdef __AFL_LOOP
        while (__AFL_LOOP(1000)) {
    #endif'''
        else:  # AFL
            afl_includes = '''
// AFL specific includes - no config.h needed for basic fuzzing
'''
            afl_loop_start = ''
        
        # Generate function declarations - using stub functions for demonstration (avoid duplicates)
        declarations = []
        seen_declarations = set()
        for candidate in candidates:
            func = candidate.function
            if func.name not in seen_declarations:
                seen_declarations.add(func.name)
                # Create stub function declarations that simulate the target functions
                declarations.append(f"// Stub function for {func.name} - replace with actual function call")
                declarations.append(f"void target_{func.name}(const char *input, size_t len);")
        
        # Generate stub function implementations (avoid duplicates)
        stubs = []
        seen_functions = set()
        for candidate in candidates:
            func = candidate.function
            if func.name not in seen_functions:
                seen_functions.add(func.name)
                stub = f'''
void target_{func.name}(const char *input, size_t len) {{
    // STUB: Replace this with actual function call to {func.name}
    // For demonstration purposes, this stub just validates input
    if (input && len > 0) {{
        // Simulate some processing - replace with actual binary function call
        volatile char temp = input[0];  // Prevent optimization
        (void)temp;  // Suppress unused variable warning
    }}
    // TODO: Link against original binary and call actual {func.name} function
}}'''
                stubs.append(stub)
        
        # Generate wrapper functions
        wrappers = []
        for i, candidate in enumerate(candidates):
            wrapper = self._generate_wrapper_function(candidate, i)
            wrappers.append(wrapper)
        
        # Generate target calls
        calls = []
        for i, candidate in enumerate(candidates):
            calls.append(f"    // Target {i+1}: {candidate.function.name} - {candidate.rationale}")
            calls.append(f"    fuzz_target_{i}(input_data, bytes_read);")
            calls.append("")
        
        # Generate AFL++ loop closing separately
        afl_loop_close = ""
        if fuzzer_type == 'AFL++':
            afl_loop_close = '''    #ifdef __AFL_LOOP
        }
    #endif'''
        
        return template.format(
            fuzzer_type=fuzzer_type,
            binary_name=binary.filename,
            target_count=len(candidates),
            generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            afl_includes=afl_includes,
            afl_loop_start=afl_loop_start,
            function_declarations="\n".join(declarations),
            stub_functions="\n".join(stubs),
            wrapper_functions="\n".join(wrappers),
            target_calls="\n".join(calls),
            afl_loop_close=afl_loop_close
        )
    
    def _generate_fuzzer_makefile(self, binary: Binary, harness: FuzzingHarness, fuzzer_type: str) -> str:
        """Generate fuzzer-specific Makefile"""
        
        fuzzer_config = self.supported_fuzzers[fuzzer_type]
        
        if fuzzer_type == 'LibFuzzer':
            return self._generate_libfuzzer_makefile(binary, harness)
        elif fuzzer_type == 'Honggfuzz':
            return self._generate_honggfuzz_makefile(binary, harness)
        elif fuzzer_type in ['AFL', 'AFL++']:
            return self._generate_afl_makefile(binary, harness, fuzzer_type)
        elif fuzzer_type == 'WinAFL':
            return self._generate_winafl_makefile(binary, harness)
        else:
            raise ValueError(f"Unsupported fuzzer type: {fuzzer_type}")
    
    def _generate_libfuzzer_makefile(self, binary: Binary, harness: FuzzingHarness) -> str:
        """Generate LibFuzzer-specific Makefile"""
        
        # Create target name from binary filename (remove extension and add fuzzer prefix)
        binary_name = binary.filename.rsplit('.', 1)[0] if '.' in binary.filename else binary.filename
        target_name = f"{binary_name}_libfuzzer_harness"
        
        return f'''# LibFuzzer Makefile for {binary.filename}
# Auto-generated by ShadowSeek

# Compiler settings
CXX = clang++
CC = clang
CFLAGS = -fsanitize=fuzzer,address -g -O1 -fno-omit-frame-pointer
CXXFLAGS = $(CFLAGS)
TARGET = {target_name}

# Build targets
all: $(TARGET)

$(TARGET): harness.cpp
\t$(CXX) $(CXXFLAGS) -o $(TARGET) harness.cpp

# LibFuzzer specific targets
run: $(TARGET)
\t./$(TARGET) -timeout=60 -max_len=1024 -workers=4 corpus/

run-single: $(TARGET)
\t./$(TARGET) -runs=1000 -max_len=1024

# Create corpus directory
corpus:
\tmkdir -p corpus

# Seed generation
seeds: corpus
\techo "AAAA" > corpus/seed1
\techo "BBBBBBBB" > corpus/seed2
\techo "\\x00\\x01\\x02\\x03" > corpus/seed3

# Analysis targets
minimize: $(TARGET)
\t./$(TARGET) -minimize_crash=1 crash-input

merge: $(TARGET) corpus
\t./$(TARGET) -merge=1 corpus/ new_corpus/

# Cleanup
clean:
\trm -f $(TARGET)
\trm -rf corpus/ crash-* leak-* timeout-*

.PHONY: all run run-single corpus seeds minimize merge clean
'''
    
    def _generate_honggfuzz_makefile(self, binary: Binary, harness: FuzzingHarness) -> str:
        """Generate Honggfuzz-specific Makefile"""
        
        # Create target name from binary filename (remove extension and add fuzzer prefix)
        binary_name = binary.filename.rsplit('.', 1)[0] if '.' in binary.filename else binary.filename
        target_name = f"{binary_name}_honggfuzz_harness"
        
        return f'''# Honggfuzz Makefile for {binary.filename}
# Auto-generated by ShadowSeek

# Compiler settings
CC = hfuzz-clang
CFLAGS = -fsanitize=address -g -O1 -fno-omit-frame-pointer
TARGET = {target_name}

# Build targets
all: $(TARGET)

$(TARGET): harness.c
\t$(CC) $(CFLAGS) -o $(TARGET) harness.c

# Honggfuzz specific targets
run: $(TARGET) inputs
\thonggfuzz -i inputs/ -W outputs/ -- ./$(TARGET) ___FILE___

run-persistent: $(TARGET) inputs
\thonggfuzz -i inputs/ -W outputs/ -n 4 -t 60 -- ./$(TARGET) ___FILE___

run-coverage: $(TARGET) inputs
\thonggfuzz -i inputs/ -W outputs/ -C -n 4 -- ./$(TARGET) ___FILE___

# Create directories
inputs:
\tmkdir -p inputs

outputs:
\tmkdir -p outputs

# Seed generation
seeds: inputs
\techo "AAAA" > inputs/seed1
\techo "BBBBBBBB" > inputs/seed2
\techo "\\x00\\x01\\x02\\x03" > inputs/seed3

# Cleanup
clean:
\trm -f $(TARGET)
\trm -rf inputs/ outputs/ HONGGFUZZ.REPORT

.PHONY: all run run-persistent run-coverage inputs outputs seeds clean
'''
    
    def _generate_afl_makefile(self, binary: Binary, harness: FuzzingHarness, fuzzer_type: str) -> str:
        """Generate AFL/AFL++ specific Makefile"""
        
        # Use C compiler for C source files to avoid C++ warnings
        compiler = 'afl-clang-fast' if fuzzer_type == 'AFL++' else 'afl-gcc'
        
        # Create target name from binary filename (remove extension and add fuzzer prefix)
        binary_name = binary.filename.rsplit('.', 1)[0] if '.' in binary.filename else binary.filename
        target_name = f"{binary_name}_{fuzzer_type.lower()}_harness"
        
        return f'''# {fuzzer_type} Makefile for {binary.filename}
# Auto-generated by ShadowSeek

# Compiler settings
CC = {compiler}
CFLAGS = -fsanitize=address -g -O1 -fno-omit-frame-pointer
TARGET = {target_name}

# Build targets
all: $(TARGET)

$(TARGET): harness.c
\t$(CC) $(CFLAGS) -o $(TARGET) harness.c

# {fuzzer_type} specific targets
run: $(TARGET) inputs outputs
\t{fuzzer_type.lower()} -i inputs/ -o outputs/ -d ./$(TARGET) @@

run-parallel: $(TARGET) inputs outputs
\t{fuzzer_type.lower()} -i inputs/ -o outputs/ -M master ./$(TARGET) @@ &
\t{fuzzer_type.lower()} -i inputs/ -o outputs/ -S slave1 ./$(TARGET) @@ &
\t{fuzzer_type.lower()} -i inputs/ -o outputs/ -S slave2 ./$(TARGET) @@ &

run-fast: $(TARGET) inputs outputs
\t{fuzzer_type.lower()} -i inputs/ -o outputs/ -f -x dict.txt ./$(TARGET) @@

# Create directories
inputs:
\tmkdir -p inputs

outputs:
\tmkdir -p outputs

# Seed generation
seeds: inputs
\techo "AAAA" > inputs/seed1
\techo "BBBBBBBB" > inputs/seed2
\techo "\\x00\\x01\\x02\\x03" > inputs/seed3

# Dictionary for mutation
dict.txt:
\techo 'keyword_"admin"' > dict.txt
\techo 'keyword_"user"' >> dict.txt
\techo 'keyword_"password"' >> dict.txt

# Analysis targets
analyze: outputs
\t{fuzzer_type.lower()}-analyze -i outputs/

minimize: $(TARGET)
\t{fuzzer_type.lower()}-tmin -i crash_input -o minimized_crash -- ./$(TARGET) @@

# Cleanup
clean:
\trm -f $(TARGET)
\trm -rf inputs/ outputs/ dict.txt

.PHONY: all run run-parallel run-fast inputs outputs seeds dict.txt analyze minimize clean
'''
    
    def _generate_winafl_code(self, binary: Binary, candidates: List[FuzzingCandidate]) -> str:
        """Generate WinAFL-specific harness code"""
        
        template = '''/*
 * WinAFL Fuzzing Harness for {binary_name}
 * Auto-generated by ShadowSeek
 * 
 * Targets {target_count} high-risk functions based on security analysis
 * Generation date: {generation_date}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// WinAFL specific includes
#include "winafl.h"

// Target function declarations
{function_declarations}

// Stub function implementations - replace with actual binary function calls
{stub_functions}

// Fuzzing target wrapper functions
{wrapper_functions}

// WinAFL target function
int fuzz_target(char *input_data, size_t input_size) {{
    // Input validation
    if (!input_data || input_size == 0) {{
        return 0;
    }}
    
    // Limit input size to prevent excessive memory usage
    if (input_size > 1024 * 1024) {{
        return 0;
    }}
    
    // Execute fuzzing targets
{target_calls}
    
    return 0;
}}

// Main WinAFL harness
int main(int argc, char **argv) {{
    char *input_data;
    size_t input_size;
    
    // WinAFL initialization
    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}
    
    // Read input file
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {{
        perror("fopen");
        return 1;
    }}
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 1024 * 1024) {{
        fprintf(stderr, "Invalid file size\\n");
        fclose(fp);
        return 1;
    }}
    
    // Allocate and read input data
    input_data = (char*)malloc(file_size);
    if (!input_data) {{
        perror("malloc");
        fclose(fp);
        return 1;
    }}
    
    input_size = fread(input_data, 1, file_size, fp);
    fclose(fp);
    
    // Call the target function
    int result = fuzz_target(input_data, input_size);
    
    free(input_data);
    return result;
}}
'''
        
        # Generate function declarations - using stub functions for demonstration (avoid duplicates)
        declarations = []
        seen_declarations = set()
        for candidate in candidates:
            func = candidate.function
            if func.name not in seen_declarations:
                seen_declarations.add(func.name)
                declarations.append(f"// Stub function for {func.name} - replace with actual function call")
                declarations.append(f"void target_{func.name}(const char *input, size_t len);")
        
        # Generate stub function implementations (avoid duplicates)
        stubs = []
        seen_functions = set()
        for candidate in candidates:
            func = candidate.function
            if func.name not in seen_functions:
                seen_functions.add(func.name)
                stub = f'''
void target_{func.name}(const char *input, size_t len) {{
    // STUB: Replace this with actual function call to {func.name}
    // For demonstration purposes, this stub just validates input
    if (input && len > 0) {{
        // Simulate some processing - replace with actual binary function call
        volatile char temp = input[0];  // Prevent optimization
        (void)temp;  // Suppress unused variable warning
    }}
    // TODO: Link against original binary and call actual {func.name} function
}}'''
                stubs.append(stub)
        
        # Generate wrapper functions
        wrappers = []
        for i, candidate in enumerate(candidates):
            wrapper = self._generate_wrapper_function(candidate, i)
            wrappers.append(wrapper)
        
        # Generate target calls
        calls = []
        for i, candidate in enumerate(candidates):
            calls.append(f"    // Target {i+1}: {candidate.function.name} - {candidate.rationale}")
            calls.append(f"    fuzz_target_{i}((unsigned char*)input_data, input_size);")
            calls.append("")
        
        return template.format(
            binary_name=binary.filename,
            target_count=len(candidates),
            generation_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            function_declarations="\\n".join(declarations),
            stub_functions="\\n".join(stubs),
            wrapper_functions="\\n".join(wrappers),
            target_calls="\\n".join(calls)
        )
    
    def _generate_winafl_makefile(self, binary: Binary, harness: FuzzingHarness) -> str:
        """Generate WinAFL-specific Makefile"""
        
        # Create target name from binary filename (remove extension and add fuzzer prefix)
        binary_name = binary.filename.rsplit('.', 1)[0] if '.' in binary.filename else binary.filename
        target_name = f"{binary_name}_winafl_harness"
        
        return f'''# WinAFL Makefile for {binary.filename}
# Auto-generated by ShadowSeek

# Compiler settings
CC = cl.exe
CFLAGS = /Od /Zi /RTC1 /MTd
LDFLAGS = /DEBUG
TARGET = {target_name}.exe
WINAFL_DIR = C:\\\\winafl
DYNAMORIO_DIR = C:\\\\DynamoRIO

# Build targets
all: $(TARGET)

$(TARGET): harness.c
\t$(CC) $(CFLAGS) harness.c /Fe:$(TARGET) /link $(LDFLAGS)

# WinAFL specific targets
run: $(TARGET) inputs
\t$(WINAFL_DIR)\\\\afl-fuzz.exe -i inputs -o outputs -D $(DYNAMORIO_DIR)\\\\bin64 -t 20000 -- $(TARGET) @@

run-debug: $(TARGET) inputs  
\t$(WINAFL_DIR)\\\\afl-fuzz.exe -i inputs -o outputs -D $(DYNAMORIO_DIR)\\\\bin64 -t 20000 -debug -- $(TARGET) @@

run-coverage: $(TARGET) inputs
\t$(WINAFL_DIR)\\\\afl-fuzz.exe -i inputs -o outputs -D $(DYNAMORIO_DIR)\\\\bin64 -t 20000 -coverage_module $(TARGET) -- $(TARGET) @@

# Create directories
inputs:
\tif not exist inputs mkdir inputs

outputs:
\tif not exist outputs mkdir outputs

# Seed generation for Windows binaries
seeds: inputs
\techo admin > inputs\\\\seed1.txt
\techo password123 > inputs\\\\seed2.txt
\techo 192.168.1.1 > inputs\\\\seed3.txt
\techo DeviceName > inputs\\\\seed4.txt
\techo GET /api/device HTTP/1.1 > inputs\\\\seed5.txt

# Analysis targets
analyze: outputs
\t$(WINAFL_DIR)\\\\afl-analyze.exe -i outputs

minimize: $(TARGET)
\t$(WINAFL_DIR)\\\\afl-tmin.exe -i crash_input -o minimized_crash -- $(TARGET) @@

# Cleanup
clean:
\tif exist $(TARGET) del $(TARGET)
\tif exist *.pdb del *.pdb
\tif exist *.ilk del *.ilk
\tif exist *.obj del *.obj
\tif exist inputs rmdir /s /q inputs
\tif exist outputs rmdir /s /q outputs

.PHONY: all run run-debug run-coverage inputs outputs seeds analyze minimize clean
'''
    
    def _find_fuzzing_candidates(
        self, 
        binary: Binary, 
        min_risk_score: float, 
        target_severities: List[str]
    ) -> List[FuzzingCandidate]:
        """Find the best fuzzing candidates based on security analysis or AI analysis"""
        
        candidates = []
        
        # First, try to get security findings matching criteria
        findings = UnifiedSecurityFinding.query.filter(
            UnifiedSecurityFinding.binary_id == binary.id,
            UnifiedSecurityFinding.confidence >= min_risk_score,
            UnifiedSecurityFinding.severity.in_(target_severities)
        ).all()
        
        if findings:
            # Use security findings if available
            for finding in findings:
                function = finding.function_relationship
                if not function:
                    continue
                
                # Determine fuzzing strategy based on function analysis
                input_strategy = self._determine_input_strategy(function)
                priority = self._calculate_priority(finding, function)
                
                rationale = self._generate_rationale(finding, function, input_strategy)
                
                candidate = FuzzingCandidate(
                    function=function,
                    security_finding=finding,
                    risk_score=finding.confidence,
                    severity=finding.severity,
                    rationale=rationale,
                    input_strategy=input_strategy,
                    priority=priority
                )
                candidates.append(candidate)
        
        else:
            # Fallback: Use AI analyzed functions with risk scores
            logger.info(f"No security findings found for binary {binary.id}, using AI analyzed functions")
            
            # Get AI analyzed functions with risk scores above threshold
            functions = Function.query.filter(
                Function.binary_id == binary.id,
                Function.ai_analyzed == True,
                Function.risk_score != None,
                Function.risk_score >= min_risk_score,
                Function.is_external == False
            ).order_by(Function.risk_score.desc()).all()
            
            logger.info(f"Found {len(functions)} AI analyzed functions with risk_score >= {min_risk_score}")
            
            for function in functions:
                # Map AI risk score to severity
                if function.risk_score >= 80:
                    severity = 'CRITICAL'
                elif function.risk_score >= 60:
                    severity = 'HIGH' 
                elif function.risk_score >= 40:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                
                # Only include functions matching target severities
                if severity not in target_severities:
                    continue
                
                # Determine fuzzing strategy based on function analysis
                input_strategy = self._determine_input_strategy(function)
                priority = self._calculate_ai_priority(function)
                
                rationale = self._generate_ai_rationale(function, input_strategy)
                
                candidate = FuzzingCandidate(
                    function=function,
                    security_finding=None,  # No security finding, using AI analysis
                    risk_score=function.risk_score,
                    severity=severity,
                    rationale=rationale,
                    input_strategy=input_strategy,
                    priority=priority
                )
                candidates.append(candidate)
        
        # Sort by priority and risk score
        candidates.sort(key=lambda x: (x.priority, -x.risk_score))
        
        logger.info(f"Selected {len(candidates)} fuzzing candidates for binary {binary.id}")
        
        # Return all candidates that match severity criteria
        return candidates
    
    def _determine_input_strategy(self, function: Function) -> str:
        """Determine the best fuzzing input strategy for a function"""
        
        function_name = function.name.lower()
        
        # Check for dangerous function patterns
        for pattern_name, pattern_info in self.fuzzing_patterns.items():
            for dangerous_func in pattern_info['functions']:
                if dangerous_func in function_name:
                    return pattern_info['strategy']
        
        # Check decompiled code for clues
        if function.decompiled_code:
            code_lower = function.decompiled_code.lower()
            
            if any(func in code_lower for func in ['strcpy', 'strcat', 'sprintf']):
                return 'boundary_testing'
            elif any(func in code_lower for func in ['printf', 'fprintf']):
                return 'format_injection'
            elif any(func in code_lower for func in ['scanf', 'fgets']):
                return 'malformed_input'
            elif any(func in code_lower for func in ['malloc', 'free']):
                return 'heap_manipulation'
        
        # Default strategy
        return 'general_fuzzing'
    
    def _calculate_priority(self, finding: UnifiedSecurityFinding, function: Function) -> int:
        """Calculate fuzzing priority (1=highest, 5=lowest)"""
        
        priority = 3  # Default
        
        # High severity gets higher priority
        if finding.severity == 'HIGH':
            priority -= 1
        elif finding.severity == 'CRITICAL':
            priority -= 2
        
        # High confidence gets higher priority
        if finding.confidence > 80:
            priority -= 1
        
        # Known dangerous functions get higher priority
        function_name = function.name.lower()
        for pattern_info in self.fuzzing_patterns.values():
            if any(func in function_name for func in pattern_info['functions']):
                priority = min(priority, pattern_info['priority'])
                break
        
        return max(1, min(5, priority))
    
    def _calculate_ai_priority(self, function: Function) -> int:
        """Calculate fuzzing priority for AI-analyzed functions (1=highest, 5=lowest)"""
        
        priority = 3  # Default
        
        # High risk score gets higher priority
        if function.risk_score and function.risk_score >= 80:
            priority -= 2  # Critical risk
        elif function.risk_score and function.risk_score >= 60:
            priority -= 1  # High risk
        
        # Known dangerous functions get higher priority
        if function.name:
            function_name = function.name.lower()
            for pattern_info in self.fuzzing_patterns.values():
                if any(func in function_name for func in pattern_info['functions']):
                    priority = min(priority, pattern_info['priority'])
                    break
        
        return max(1, min(5, priority))
    
    def _generate_rationale(self, finding: UnifiedSecurityFinding, function: Function, input_strategy: str) -> str:
        """Generate a rationale explaining why this function was selected for fuzzing"""
        
        rationale_parts = []
        
        # Security finding information
        if finding:
            rationale_parts.append(f"Security finding: {finding.severity} severity {finding.title}")
            if finding.confidence >= 80:
                rationale_parts.append(f"High confidence ({finding.confidence}%)")
            elif finding.confidence >= 60:
                rationale_parts.append(f"Medium confidence ({finding.confidence}%)")
            else:
                rationale_parts.append(f"Low confidence ({finding.confidence}%)")
        
        # Function analysis
        function_name = function.name.lower() if function.name else 'unknown'
        
        # Check for dangerous function patterns
        dangerous_patterns = []
        for pattern_name, pattern_info in self.fuzzing_patterns.items():
            for dangerous_func in pattern_info['functions']:
                if dangerous_func in function_name:
                    dangerous_patterns.append(dangerous_func)
        
        if dangerous_patterns:
            rationale_parts.append(f"Contains dangerous functions: {', '.join(dangerous_patterns)}")
        
        # Strategy-specific rationale
        strategy_reasons = {
            'boundary_testing': 'Function appears to handle string/buffer operations',
            'format_injection': 'Function may be vulnerable to format string attacks',
            'malformed_input': 'Function processes user input and may be vulnerable to malformed data',
            'heap_manipulation': 'Function performs memory allocation operations',
            'general_fuzzing': 'Function selected for general fuzzing based on analysis'
        }
        
        if input_strategy in strategy_reasons:
            rationale_parts.append(strategy_reasons[input_strategy])
        
        # Additional analysis from decompiled code
        if function.decompiled_code:
            code_lower = function.decompiled_code.lower()
            code_concerns = []
            
            if 'strcpy' in code_lower or 'strcat' in code_lower:
                code_concerns.append('unsafe string operations')
            if 'malloc' in code_lower or 'free' in code_lower:
                code_concerns.append('memory management')
            if 'printf' in code_lower or 'sprintf' in code_lower:
                code_concerns.append('format string usage')
            if 'scanf' in code_lower or 'gets' in code_lower:
                code_concerns.append('input processing')
            
            if code_concerns:
                rationale_parts.append(f"Code analysis reveals: {', '.join(code_concerns)}")
        
        # Risk assessment
        if finding and finding.risk_score:
            if finding.risk_score >= 70:
                rationale_parts.append("High risk score indicates significant security impact")
            elif finding.risk_score >= 50:
                rationale_parts.append("Medium risk score suggests potential security issues")
        
        # Combine all rationale parts
        if rationale_parts:
            return '. '.join(rationale_parts) + '.'
        else:
            return f"Function {function.name} selected for fuzzing based on security analysis."
    
    def _generate_ai_rationale(self, function: Function, input_strategy: str) -> str:
        """Generate a rationale for AI-analyzed functions without security findings"""
        
        rationale_parts = []
        
        # AI analysis information
        if function.risk_score:
            rationale_parts.append(f"AI analysis identified {function.risk_score:.1f}% risk score")
            if function.risk_score >= 80:
                rationale_parts.append("Critical risk level indicates high vulnerability potential")
            elif function.risk_score >= 60:
                rationale_parts.append("High risk level suggests significant security concerns")
            elif function.risk_score >= 40:
                rationale_parts.append("Medium risk level indicates potential security issues")
        
        # Function analysis
        function_name = function.name.lower() if function.name else 'unknown'
        
        # Check for dangerous function patterns
        dangerous_patterns = []
        for pattern_name, pattern_info in self.fuzzing_patterns.items():
            for dangerous_func in pattern_info['functions']:
                if dangerous_func in function_name:
                    dangerous_patterns.append(dangerous_func)
        
        if dangerous_patterns:
            rationale_parts.append(f"Contains dangerous functions: {', '.join(dangerous_patterns)}")
        
        # Strategy-specific rationale
        strategy_reasons = {
            'boundary_testing': 'Function appears to handle string/buffer operations',
            'format_injection': 'Function may be vulnerable to format string attacks', 
            'malformed_input': 'Function processes user input and may be vulnerable to malformed data',
            'heap_manipulation': 'Function performs memory allocation operations',
            'general_fuzzing': 'Function selected for general fuzzing based on AI analysis'
        }
        
        if input_strategy in strategy_reasons:
            rationale_parts.append(strategy_reasons[input_strategy])
        
        # Additional analysis from decompiled code
        if function.decompiled_code:
            code_lower = function.decompiled_code.lower()
            code_concerns = []
            
            if 'strcpy' in code_lower or 'strcat' in code_lower:
                code_concerns.append('unsafe string operations')
            if 'malloc' in code_lower or 'free' in code_lower:
                code_concerns.append('memory management')
            if 'printf' in code_lower or 'sprintf' in code_lower:
                code_concerns.append('format string usage')
            if 'scanf' in code_lower or 'gets' in code_lower:
                code_concerns.append('input processing')
            
            if code_concerns:
                rationale_parts.append(f"Code analysis reveals: {', '.join(code_concerns)}")
        
        # AI summary information
        if function.ai_summary:
            summary_lower = function.ai_summary.lower()
            if any(term in summary_lower for term in ['buffer', 'overflow', 'vulnerable', 'unsafe']):
                rationale_parts.append("AI summary indicates potential security vulnerabilities")
        
        # Combine all rationale parts
        if rationale_parts:
            return '. '.join(rationale_parts) + '.'
        else:
            return f"Function {function.name} selected for fuzzing based on AI risk analysis."
    
    def _generate_wrapper_function(self, candidate: FuzzingCandidate, index: int) -> str:
        """Generate a wrapper function for a fuzzing target"""
        
        strategy_templates = {
            'boundary_testing': '''
void fuzz_target_{index}(const unsigned char *input, size_t len) {{
    // Boundary testing for {func_name}
    if (len == 0) return;
    
    // Create various buffer sizes to test boundaries
    char buffer[256];
    char *dynamic_buffer = malloc(len + 1);
    
    if (dynamic_buffer) {{
        memcpy(dynamic_buffer, input, len);
        dynamic_buffer[len] = '\\0';
        
        // Test with original input
        target_{func_name}(dynamic_buffer, len);
        
        // Test with truncated input
        if (len > 1) {{
            dynamic_buffer[len/2] = '\\0';
            target_{func_name}(dynamic_buffer, len/2);
        }}
        
        free(dynamic_buffer);
    }}
    
    // Test with stack buffer
    size_t copy_len = len < sizeof(buffer) - 1 ? len : sizeof(buffer) - 1;
    memcpy(buffer, input, copy_len);
    buffer[copy_len] = '\\0';
    target_{func_name}(buffer, copy_len);
}}''',
            
            'format_injection': '''
void fuzz_target_{index}(const unsigned char *input, size_t len) {{
    // Format string testing for {func_name}
    if (len == 0) return;
    
    char *safe_input = malloc(len + 1);
    if (!safe_input) return;
    
    memcpy(safe_input, input, len);
    safe_input[len] = '\\0';
    
    // Test format string injection
    target_{func_name}(safe_input, len);
    
    free(safe_input);
}}''',
            
            'malformed_input': '''
void fuzz_target_{index}(const unsigned char *input, size_t len) {{
    // Malformed input testing for {func_name}
    if (len == 0) return;
    
    char *test_input = malloc(len + 1);
    if (!test_input) return;
    
    memcpy(test_input, input, len);
    test_input[len] = '\\0';
    
    // Test with various input formats
    target_{func_name}(test_input, len);
    
    free(test_input);
}}''',

            'heap_manipulation': '''
void fuzz_target_{index}(const unsigned char *input, size_t len) {{
    // Heap manipulation testing for {func_name}
    if (len == 0) return;
    
    // Test with various allocation sizes
    size_t alloc_sizes[] = {{8, 16, 32, 64, 128, 256, 512, 1024}};
    size_t num_sizes = sizeof(alloc_sizes) / sizeof(alloc_sizes[0]);
    
    for (size_t i = 0; i < num_sizes && i < len; i++) {{
        char *heap_buffer = malloc(alloc_sizes[i]);
        if (heap_buffer) {{
            size_t copy_len = len < alloc_sizes[i] - 1 ? len : alloc_sizes[i] - 1;
            memcpy(heap_buffer, input, copy_len);
            heap_buffer[copy_len] = '\\0';
            
            target_{func_name}(heap_buffer, copy_len);
            free(heap_buffer);
        }}
    }}
}}''',
            
            'general_fuzzing': '''
void fuzz_target_{index}(const unsigned char *input, size_t len) {{
    // General fuzzing for {func_name}
    if (len == 0) return;
    
    char *safe_input = malloc(len + 1);
    if (!safe_input) return;
    
    memcpy(safe_input, input, len);
    safe_input[len] = '\\0';
    
    target_{func_name}(safe_input, len);
    
    free(safe_input);
}}'''
        }
        
        template = strategy_templates.get(
            candidate.input_strategy, 
            strategy_templates['general_fuzzing']
        )
        
        return template.format(
            index=index,
            func_name=candidate.function.name
        )
    
    def _generate_fuzzer_readme(
        self, 
        binary: Binary, 
        harness: FuzzingHarness, 
        candidates: List[FuzzingCandidate],
        fuzzer_type: str
    ) -> str:
        """Generate comprehensive README for the fuzzing harness"""
        
        targets_info = []
        for i, candidate in enumerate(candidates):
            targets_info.append(f"{i+1}. **{candidate.function.name}**")
            targets_info.append(f"   - Risk Score: {candidate.risk_score:.1f}%")
            targets_info.append(f"   - Severity: {candidate.severity}")
            targets_info.append(f"   - Strategy: {candidate.input_strategy}")
            targets_info.append(f"   - Rationale: {candidate.rationale}")
            targets_info.append("")

        if fuzzer_type == 'LibFuzzer':
            return self._generate_libfuzzer_readme(binary, harness, candidates, targets_info)
        elif fuzzer_type == 'Honggfuzz':
            return self._generate_honggfuzz_readme(binary, harness, candidates, targets_info)
        elif fuzzer_type in ['AFL', 'AFL++']:
            return self._generate_afl_readme(binary, harness, candidates, targets_info, fuzzer_type)
        else:
            return self._generate_generic_readme(binary, harness, candidates, targets_info, fuzzer_type)

    def _generate_libfuzzer_readme(self, binary, harness, candidates, targets_info):
        """Generate LibFuzzer-specific README"""
        return f'''# LibFuzzer Harness

## Target Information
- **Binary**: {binary.filename}
- **File Size**: {getattr(binary, 'size', 'Unknown')} bytes
- **Harness Type**: LibFuzzer
- **Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Target Functions**: {len(candidates)}

## Fuzzing Targets

{chr(10).join(targets_info)}

## Quick Start

### 1. Install Clang/LLVM
```bash
# Ubuntu/Debian
sudo apt-get install clang llvm

# macOS
brew install llvm
```

### 2. Build the Harness
```bash
# Build with LibFuzzer
make

# Or manually:
clang++ -fsanitize=fuzzer,address -g -O1 -o libfuzzer_harness harness.cpp
```

### 3. Run Fuzzing
```bash
# Create corpus directory
mkdir corpus

# Basic fuzzing
./libfuzzer_harness corpus/

# Advanced fuzzing with options
./libfuzzer_harness -timeout=60 -max_len=1024 -workers=4 corpus/
```

### 4. Monitor Results
LibFuzzer provides real-time feedback:
- `NEW` indicates new coverage found
- `REDUCE` shows corpus minimization
- Crashes are automatically saved

## Advanced Usage

### Custom Options
```bash
# Limit execution time
./libfuzzer_harness -timeout=30 corpus/

# Set maximum input length
./libfuzzer_harness -max_len=2048 corpus/

# Use multiple workers
./libfuzzer_harness -workers=8 corpus/

# Merge corpora
./libfuzzer_harness -merge=1 corpus/ new_inputs/
```

### Reproduce Crashes
```bash
# Run with specific input
./libfuzzer_harness crash-input

# Debug with GDB
gdb --args ./libfuzzer_harness crash-input
```

## Performance Tips
- Use AddressSanitizer for memory error detection
- Start with small `-max_len` values
- Use `-workers` for parallel fuzzing
- Monitor coverage growth rate

---

Generated by ShadowSeek - Advanced Binary Security Analysis Platform
'''

    def _generate_honggfuzz_readme(self, binary, harness, candidates, targets_info):
        """Generate Honggfuzz-specific README"""
        return f'''# Honggfuzz Harness

## Target Information
- **Binary**: {binary.filename}
- **File Size**: {getattr(binary, 'size', 'Unknown')} bytes
- **Harness Type**: Honggfuzz
- **Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Target Functions**: {len(candidates)}

## Fuzzing Targets

{chr(10).join(targets_info)}

## Quick Start

### 1. Install Honggfuzz
```bash
# Ubuntu/Debian
sudo apt-get install honggfuzz

# Build from source
git clone https://github.com/google/honggfuzz
cd honggfuzz
make
sudo make install
```

### 2. Build the Harness
```bash
# Build with Honggfuzz
make

# Or manually:
hfuzz-clang -fsanitize=address -g -O1 -o honggfuzz_harness harness.c
```

### 3. Setup and Run Fuzzing
```bash
# Create directories
mkdir inputs outputs

# Add seed files
echo "test" > inputs/seed1
echo "sample" > inputs/seed2

# Start fuzzing
honggfuzz -i inputs/ -W outputs/ -- ./honggfuzz_harness ___FILE___
```

### 4. Monitor Results
Honggfuzz provides detailed statistics:
- `Crashes` shows found crashes
- `Coverage` indicates code coverage
- `Mutations/sec` shows fuzzing speed

## Advanced Usage

### Coverage-Guided Fuzzing
```bash
# Enable coverage feedback
honggfuzz -i inputs/ -W outputs/ -C -- ./honggfuzz_harness ___FILE___
```

### Persistent Mode
```bash
# Use persistent mode for performance
honggfuzz -i inputs/ -W outputs/ -P -- ./honggfuzz_harness
```

### Parallel Fuzzing
```bash
# Run multiple instances
honggfuzz -i inputs/ -W outputs/ -n 4 -- ./honggfuzz_harness ___FILE___
```

### Custom Options
```bash
# Set timeout and memory limit
honggfuzz -i inputs/ -W outputs/ -t 60 -m 200 -- ./honggfuzz_harness ___FILE___

# Enable sanitizers
honggfuzz -i inputs/ -W outputs/ -S -- ./honggfuzz_harness ___FILE___
```

## Crash Analysis
```bash
# Crashes are saved in outputs/
ls outputs/

# Reproduce crashes
./honggfuzz_harness outputs/SIGABRT.PC.7ffff7a05000.STACK.18d2c9d6.CODE.-6.ADDR.0.INSTR.mov.fuzz
```

---

Generated by ShadowSeek - Advanced Binary Security Analysis Platform
'''

    def _generate_afl_readme(self, binary, harness, candidates, targets_info, fuzzer_type):
        """Generate AFL/AFL++ specific README"""
        return f'''# {fuzzer_type} Fuzzing Harness

## Target Information
- **Binary**: {binary.filename}
- **File Size**: {getattr(binary, 'size', 'Unknown')} bytes
- **Harness Type**: {fuzzer_type}
- **Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Target Functions**: {len(candidates)}

## Fuzzing Targets

{chr(10).join(targets_info)}

## Quick Start

### 1. Install {fuzzer_type}
```bash
# Ubuntu/Debian
sudo apt-get install afl++

# Build from source
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make all
sudo make install
```

### 2. Build the Harness
```bash
# Build with {fuzzer_type}
make

# Or manually:
{'afl-clang-fast' if fuzzer_type == 'AFL++' else 'afl-gcc'} -fsanitize=address -g -O1 -o {fuzzer_type.lower()}_harness harness.c
```

### 3. Setup and Run Fuzzing
```bash
# Create directories and seeds
make seeds

# Start fuzzing
{fuzzer_type.lower()} -i inputs/ -o outputs/ ./afl_harness @@
```

### 4. Monitor Results
```bash
# Check fuzzing status
afl-whatsup outputs/

# Analyze crashes
ls outputs/crashes/
```

## Advanced Usage

### Parallel Fuzzing
```bash
# Master fuzzer
{fuzzer_type.lower()} -i inputs/ -o outputs/ -M master ./afl_harness @@

# Slave fuzzers
{fuzzer_type.lower()} -i inputs/ -o outputs/ -S slave1 ./afl_harness @@
{fuzzer_type.lower()} -i inputs/ -o outputs/ -S slave2 ./afl_harness @@
```

### Performance Optimization
```bash
# Use fast mode
{fuzzer_type.lower()} -i inputs/ -o outputs/ -f ./afl_harness @@

# Custom dictionary
{fuzzer_type.lower()} -i inputs/ -o outputs/ -x dict.txt ./afl_harness @@
```

### Crash Analysis
```bash
# Reproduce a crash
./afl_harness outputs/crashes/id:000000,sig:11,src:000000,op:havoc,rep:2

# Minimize crash
{fuzzer_type.lower()}-tmin -i crash_input -o minimized_crash -- ./afl_harness @@

# Debug with GDB
gdb --args ./afl_harness outputs/crashes/id:000000,sig:11,src:000000,op:havoc,rep:2
```

## IMPORTANT: Binary Integration

⚠️ **This harness contains stub functions that need to be replaced with actual function calls
from the target binary '{binary.filename}'. The current implementation will compile but won't
find real vulnerabilities.**

### Option 1: Link Against Binary Object Files (Recommended)
```bash
# If you have access to object files or static library
{fuzzer_type.lower()}-clang-fast -fsanitize=address -g -O1 -o harness harness.c target_binary.o

# Or link against shared library
{fuzzer_type.lower()}-clang-fast -fsanitize=address -g -O1 -o harness harness.c -L. -ltarget_binary
```

### Option 2: Dynamic Loading
Replace stub functions in harness.c with dynamic loading:
```c
#include <dlfcn.h>

void target_function_name(const char *input, size_t len) {{
    static void *handle = NULL;
    static void (*real_func)(const char*, size_t) = NULL;
    
    if (!handle) {{
        handle = dlopen("./{binary.filename}", RTLD_LAZY);
        if (handle) {{
            real_func = dlsym(handle, "function_name");
        }}
    }}
    
    if (real_func) {{
        real_func(input, len);
    }}
}}
```

### Option 3: Process Injection (Advanced)
For closed-source binaries, consider process injection or binary instrumentation.

## Environment Variables
```bash
export AFL_SKIP_CPUFREQ=1
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_AUTORESUME=1
```

## Recommended {fuzzer_type} Options
- `-P exploration`: Use exploration power schedule
- `-L 0`: Disable MOpt mutator  
- `-D`: Use deterministic mutations
- `-c program`: Use CmpLog for better mutations

---

Generated by ShadowSeek - Advanced Binary Security Analysis Platform
'''

    def _generate_generic_readme(self, binary, harness, candidates, targets_info, fuzzer_type):
        """Generate generic README for unknown fuzzer types"""
        return f'''# {fuzzer_type} Fuzzing Harness

## Target Information
- **Binary**: {binary.filename}
- **File Size**: {getattr(binary, 'size', 'Unknown')} bytes
- **Harness Type**: {fuzzer_type}
- **Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Target Functions**: {len(candidates)}

## Fuzzing Targets

{chr(10).join(targets_info)}

## Build Instructions
```bash
# Compile the harness
make

# Or use your preferred compiler
gcc -g -O1 -fsanitize=address -o harness harness.c
```

## Usage
Refer to your fuzzer's documentation for specific usage instructions.

---

Generated by ShadowSeek - Advanced Binary Security Analysis Platform
'''
    
    def _generate_fuzzer_config(
        self, 
        harness: FuzzingHarness, 
        candidates: List[FuzzingCandidate],
        fuzzer_type: str
    ) -> Dict[str, Any]:
        """Generate fuzzer-specific configuration"""
        
        config = {
            "fuzzer_type": fuzzer_type,
            "input_type": harness.input_type,
            "timeout": "1000+",  # 1 second timeout
            "memory_limit": "200",  # 200MB memory limit
            "recommended_args": [
                "-P", "exploration",  # Exploration power schedule
                "-D",  # Deterministic mutations
            ],
            "environment": {
                "AFL_SKIP_CPUFREQ": "1",
                "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"
            },
            "seed_strategy": "varied_sizes",
            "target_priorities": []
        }
        
        # Add target-specific configuration
        for candidate in candidates:
            priority_config = {
                "function": candidate.function.name,
                "strategy": candidate.input_strategy,
                "priority": candidate.priority,
                "timeout_multiplier": 1.0
            }
            
            # Adjust timeout for complex functions
            if candidate.input_strategy in ['heap_manipulation', 'boundary_testing']:
                priority_config["timeout_multiplier"] = 2.0
            
            config["target_priorities"].append(priority_config)
        
        return config
    
    def _calculate_harness_confidence(self, candidates: List[FuzzingCandidate]) -> float:
        """Calculate overall confidence score for the harness"""
        
        if not candidates:
            return 0.0
        
        # Base confidence on average risk scores
        avg_risk = sum(c.risk_score for c in candidates) / len(candidates)
        
        # Boost confidence for high-priority targets
        priority_boost = sum(1 for c in candidates if c.priority <= 2) * 5
        
        # Boost confidence for known dangerous functions
        strategy_boost = sum(1 for c in candidates if c.input_strategy != 'general_fuzzing') * 3
        
        total_confidence = avg_risk + priority_boost + strategy_boost
        return min(100.0, total_confidence)
    
    def _extract_function_signature(self, function: Function) -> Optional[str]:
        """Extract function signature from decompiled code"""
        
        if not function.decompiled_code:
            return None
        
        # Simple pattern matching for function signatures
        lines = function.decompiled_code.split('\n')
        for line in lines:
            line = line.strip()
            if function.name in line and '(' in line and ')' in line:
                # Clean up the line
                if line.endswith('{'):
                    line = line[:-1].strip()
                return line
        
        return None


def get_fuzzing_harness_generator() -> FuzzingHarnessGenerator:
    """Factory function to get a fuzzing harness generator instance"""
    return FuzzingHarnessGenerator() 