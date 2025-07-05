# Simple analysis script for Ghidra
# @category Analysis

import os

# Create temp directory if it doesn't exist
temp_dir = os.path.join(os.path.expanduser("~"), "ghidra_temp")
if not os.path.exists(temp_dir):
    os.makedirs(temp_dir)

# Define output file path
output_path = os.path.join(temp_dir, "ghidra_analysis.json")

# Get function manager
function_manager = currentProgram.getFunctionManager()

# Get all functions
functions = function_manager.getFunctions(True)  # True = forward order

# Create output file
output_file = open(output_path, "w")
output_file.write("{\n")
output_file.write('  "program_name": "' + currentProgram.getName() + '",\n')
output_file.write('  "architecture": "' + str(currentProgram.getLanguage().getProcessor()) + '",\n')
output_file.write('  "functions": [\n')

# Process functions
function_count = 0
for function in functions:
    if function_count > 0:
        output_file.write(",\n")
    
    entry_point = function.getEntryPoint()
    function_address = "0x" + entry_point.toString()
    function_name = function.getName()
    function_size = function.getBody().getNumAddresses()
    is_library = str(function.isLibrary()).lower()
    is_thunk = str(function.isThunk()).lower()
    calling_convention = function.getCallingConventionName() or "unknown"
    
    output_file.write('    {\n')
    output_file.write('      "name": "' + function_name + '",\n')
    output_file.write('      "address": "' + function_address + '",\n')
    output_file.write('      "size": ' + str(function_size) + ',\n')
    output_file.write('      "is_library": ' + is_library + ',\n')
    output_file.write('      "is_thunk": ' + is_thunk + ',\n')
    output_file.write('      "calling_convention": "' + calling_convention + '"\n')
    output_file.write('    }')
    
    function_count += 1

# Close JSON structure
output_file.write('\n  ],\n')
output_file.write('  "function_count": ' + str(function_count) + '\n')
output_file.write('}\n')
output_file.close()

# Print summary
print("Analysis complete")
print("Analyzed " + str(function_count) + " functions")
print("Results saved to " + output_path) 