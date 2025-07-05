# Binary Comparison Feature Test Workflow

This document provides a step-by-step workflow for testing the binary comparison feature of the ShadowSeek platform.

## Prerequisites

- ShadowSeek platform running (both frontend and backend)
- Test binaries (either compiled or using the pre-compiled versions)

## Test Workflow 1: Direct Upload and Compare

This workflow tests the direct upload and comparison functionality.

1. **Access the Binary Comparison Page**
   - Navigate to http://localhost:3000/comparison
   - Verify that the page loads correctly with two tabs: "Compare Existing Binaries" and "Upload & Compare New Binaries"

2. **Select Upload Tab**
   - Click on the "Upload & Compare New Binaries" tab
   - Verify that the file upload interface appears

3. **Upload Test Binaries**
   - Click "Select File" for Binary 1 and choose `binary_compare_v1.exe`
   - Click "Select File" for Binary 2 and choose `binary_compare_v2.exe`
   - Select "All Differences" from the Comparison Type dropdown
   - Click "Upload & Compare"

4. **Monitor Upload Progress**
   - Verify that progress indicators appear during upload
   - Wait for the uploads to complete

5. **Monitor Comparison Progress**
   - Verify that a progress indicator appears during comparison
   - Wait for the comparison to complete

6. **Review Comparison Results**
   - Verify that a summary appears showing:
     - Similarity score
     - Total differences count
     - Counts for instruction, data, and function differences
   - Verify that a detailed table of differences appears
   - Check that the differences include:
     - The new `log_operation()` function in v2
     - Different implementation of `process_data()`
     - Different string literals (v1.0 vs v2.0)

7. **Export Results**
   - Click "Export Results"
   - Verify that a JSON file is downloaded
   - Open the JSON file and check that it contains the comparison data

## Test Workflow 2: Upload Separately and Compare

This workflow tests uploading binaries separately and then comparing them.

1. **Upload Binaries Separately**
   - Navigate to the main upload page (http://localhost:3000/upload or similar)
   - Upload `binary_compare_v1.exe` and wait for processing to complete
   - Upload `binary_compare_v2.exe` and wait for processing to complete

2. **Access Binary Comparison**
   - Navigate to http://localhost:3000/comparison
   - Verify that the "Compare Existing Binaries" tab is selected by default

3. **Select Binaries**
   - From the Binary 1 dropdown, select `binary_compare_v1.exe`
   - From the Binary 2 dropdown, select `binary_compare_v2.exe`
   - Select "All Differences" from the Comparison Type dropdown
   - Click "Compare Binaries"

4. **Monitor Comparison Progress**
   - Verify that a progress indicator appears during comparison
   - Wait for the comparison to complete

5. **Review Comparison Results**
   - Verify that the same comparison results appear as in Workflow 1

## Test Workflow 3: Different Comparison Types

This workflow tests the different comparison types.

1. **Instructions Comparison**
   - Upload both binaries or select them from existing binaries
   - Select "Instructions" from the Comparison Type dropdown
   - Click "Compare Binaries" or "Upload & Compare"
   - Verify that only instruction differences are shown

2. **Functions Comparison**
   - Select "Functions" from the Comparison Type dropdown
   - Click "Compare Binaries"
   - Verify that only function differences are shown

3. **Data Comparison**
   - Select "Data Sections" from the Comparison Type dropdown
   - Click "Compare Binaries"
   - Verify that only data differences are shown

## Expected Results

After completing these workflows, you should have verified:

1. **Functionality**:
   - Direct upload and comparison works
   - Comparison of existing binaries works
   - Different comparison types work correctly

2. **UI/UX**:
   - Progress indicators work correctly
   - Results are displayed clearly
   - Export functionality works

3. **Technical Accuracy**:
   - The system correctly identifies the differences between the two binaries
   - The similarity score reasonably reflects the differences

## Troubleshooting

If you encounter issues:

1. **Upload Failures**:
   - Check browser console for errors
   - Verify that the backend server is running
   - Check server logs for errors

2. **Comparison Failures**:
   - Check if the binaries were uploaded successfully
   - Verify that the backend task processing is working
   - Check server logs for task errors

3. **Display Issues**:
   - Try refreshing the page
   - Check browser console for React errors
   - Verify that the API responses contain the expected data 