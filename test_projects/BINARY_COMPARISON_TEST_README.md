# Binary Comparison Test Files

This directory contains test files for evaluating the binary comparison feature of the ShadowSeek platform.

## Test Files

1. `binary_compare_v1.c` - Source code for version 1 of the test program
2. `binary_compare_v2.c` - Source code for version 2 of the test program with intentional differences
3. `build_test_binaries.bat` - Windows batch script to compile both versions

## Expected Differences

The two versions have the following differences that should be detected by the binary comparison feature:

1. **Version Number**: Changed from v1.0 to v2.0
2. **Function Implementation**: `process_data()` multiplies by 2 in v1, by 3 in v2
3. **New Function**: v2 adds a new `log_operation()` function
4. **Additional Code**: v2 adds even/odd result analysis
5. **Additional Header**: v2 includes the `time.h` header
6. **Function Calls**: v2 calls the new `log_operation()` function in several places
7. **Additional Output**: v2 has extra cleanup steps

## How to Build

1. Ensure you have GCC installed (MinGW on Windows)
2. Run the build script:
   ```
   build_test_binaries.bat
   ```
3. This will create two executable files:
   - `binary_compare_v1.exe`
   - `binary_compare_v2.exe`

## Testing the Binary Comparison Feature

1. Navigate to the Binary Comparison page in the ShadowSeek UI (http://localhost:3000/comparison)
2. Select the "Upload & Compare New Binaries" tab
3. Upload `binary_compare_v1.exe` as Binary 1
4. Upload `binary_compare_v2.exe` as Binary 2
5. Select "All Differences" as the comparison type
6. Click "Upload & Compare"

## Expected Results

The binary comparison should detect:

1. **Function Differences**: The new `log_operation()` function in v2
2. **Instruction Differences**: Different implementation of `process_data()`
3. **Data Differences**: Different string literals (v1.0 vs v2.0)

## Alternative Testing Method

You can also:

1. Upload both binaries separately using the main upload feature
2. Go to the "Compare Existing Binaries" tab
3. Select the two binaries from the dropdown menus
4. Click "Compare Binaries"

This tests both the binary upload feature and the comparison of existing binaries.

## Troubleshooting

If you encounter any issues:

1. Check that GCC is properly installed and in your PATH
2. Verify that both executables were created successfully
3. Make sure the ShadowSeek platform is running (both frontend and backend)
4. Check the browser console and server logs for any errors 