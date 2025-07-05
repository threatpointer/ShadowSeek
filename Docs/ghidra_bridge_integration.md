# Ghidra Bridge Integration

This document describes how the Ghidra Bridge integration works in this application.

## Overview

The application uses Ghidra's headless analyzer to perform binary analysis. The integration consists of several components:

1. **GhidraBridgeManager**: Manages the Ghidra Bridge connection and provides methods for running headless analysis.
2. **TaskManager**: Manages analysis tasks and executes them in the background.
3. **Analysis Scripts**: Python scripts that run within Ghidra to extract information from binaries.

## Components

### GhidraBridgeManager

The `GhidraBridgeManager` class in `flask_app/ghidra_bridge_manager.py` handles the connection to Ghidra Bridge and provides methods for running headless analysis:

- `start_bridge()`: Starts the Ghidra Bridge server.
- `stop_bridge()`: Stops the Ghidra Bridge server.
- `is_connected()`: Checks if the Ghidra Bridge server is running.
- `run_headless_analysis()`: Runs headless analysis on a binary file.

### TaskManager

The `TaskManager` class in `flask_app/task_manager.py` manages analysis tasks:

- `submit_task()`: Submits a task for execution.
- `_run_task()`: Executes the task in the background.
- `cancel_task()`: Cancels a running task.

### Analysis Scripts

The application uses Python scripts in the `analysis_scripts` directory to extract information from binaries:

- `simple_analysis.py`: Extracts basic information from a binary, including functions, architecture, etc.

## Workflow

1. User uploads a binary file through the API.
2. User submits the binary for analysis.
3. The application creates an analysis task and submits it to the task manager.
4. The task manager runs the Ghidra headless analyzer with the appropriate analysis script.
5. The analysis script extracts information from the binary and saves it as JSON.
6. The task manager reads the JSON and stores the results in the database.
7. The user can view the analysis results through the API.

## Troubleshooting

If the Ghidra Bridge integration is not working, check the following:

1. Make sure Ghidra is installed and the path is correctly set in the configuration.
2. Check if the Ghidra Bridge server is running.
3. Check the logs for any errors.
4. Try running the `direct_analysis.py` script to test the headless analyzer directly.

## Future Improvements

1. Add support for more analysis types.
2. Improve error handling and reporting.
3. Add support for custom analysis scripts.
4. Add support for multiple Ghidra versions. 