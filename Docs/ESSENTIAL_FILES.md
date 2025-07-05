# Essential Files

This document lists the essential files for the ShadowSeek project, explaining their purpose and how they work together.

## Core Application Files

- **run.py**: Main entry point for the Flask application.
- **direct_analysis.py**: Standalone script to analyze binaries using Ghidra's headless analyzer.
- **reset_db.py**: Script to reset the database.
- **start_all.bat**: Script to start the application (starts Ghidra Bridge, Flask backend, and React frontend).
- **stop.bat**: Script to stop the application.
- **start_ghidra_bridge.py**: Script to start the Ghidra Bridge server.

## Configuration Files

- **env_template.txt**: Template for the .env file containing environment variables.
- **.env**: Environment variables for the application.
- **pyproject.toml**: Python project configuration.
- **requirements.txt**: Python package dependencies.
- **setup.py**: Python package setup script.

## Documentation Files

- **README.md**: Main documentation for the project.
- **MIGRATION_SUMMARY.md**: Summary of the migration process.
- **ghidra_bridge_integration.md**: Documentation for the Ghidra Bridge integration.

## Directory Structure

- **flask_app/**: Flask application code.
  - **app.py**: Flask application factory.
  - **routes.py**: API routes.
  - **models.py**: Database models.
  - **ghidra_bridge_manager.py**: Ghidra Bridge connection manager.
  - **task_manager.py**: Task management for analysis jobs.

- **analysis_scripts/**: Python scripts that run within Ghidra.
  - **simple_analysis.py**: Script to extract basic information from binaries.

- **frontend/**: React frontend code.

- **uploads/**: Directory for uploaded binary files.

- **ghidra_projects/**: Directory for Ghidra projects.

- **temp/**: Directory for temporary files.

## Archived Files

Non-essential files have been archived in the following directories:

- **archive/testing/**: Test scripts and files.
- **archive/utilities/**: Utility scripts.
- **archive/batch_scripts/**: Batch scripts for various tasks.

See the respective README files in those directories for more information. 