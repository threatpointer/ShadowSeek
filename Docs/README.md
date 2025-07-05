# Documentation Directory

This directory contains comprehensive documentation for the ShadowSeek project, with special focus on bridge connection troubleshooting and system management.

## Documentation Files

### Core Reference Documents

#### [QUICK_REFERENCE.md](./QUICK_REFERENCE.md)
- **Purpose**: Fast reference guide for common operations
- **Contents**: 
  - Quick commands for bridge management
  - System status checks
  - Common troubleshooting steps
  - Port and process management
- **When to use**: Day-to-day operations and quick fixes

#### [JFX_BRIDGE_FIX_DOCUMENTATION.md](./JFX_BRIDGE_FIX_DOCUMENTATION.md)
- **Purpose**: Comprehensive troubleshooting guide for Ghidra bridge issues
- **Contents**:
  - Complete problem diagnosis workflow
  - Ghidrathon interference solutions
  - Frontend compilation fixes
  - Bridge server restoration procedures
  - System recovery steps
- **When to use**: When experiencing bridge connection problems or system failures

## Documentation Structure

```
Docs/
├── README.md                           # This file - documentation overview
├── QUICK_REFERENCE.md                  # Quick commands and operations
└── JFX_BRIDGE_FIX_DOCUMENTATION.md    # Comprehensive troubleshooting guide
```

## Usage Guidelines

### For Quick Operations
Start with `QUICK_REFERENCE.md` for:
- Daily system management
- Status checks
- Simple troubleshooting
- Port management

### For Complex Issues
Use `JFX_BRIDGE_FIX_DOCUMENTATION.md` for:
- Bridge connection failures
- Ghidrathon interference problems
- Frontend compilation errors
- System restoration after crashes
- Component replacement procedures

## Related Files

### Project Root Documentation
- `README.md` - Main project overview
- `API_DOCUMENTATION.md` - API endpoint documentation
- `ESSENTIAL_FILES.md` - Critical project files listing

### Memory Bank Documentation
- `memory-bank/` - Project context and progress tracking
- `memory-bank/activeContext.md` - Current work status
- `memory-bank/progress.md` - System functionality status

### Archive Documentation
- `archive/SOLUTION_SUMMARY.md` - Historical problem solutions
- `archive/PROGRESS.md` - Development timeline
- `VULNERABILITY_DETECTION_COMPLETED.md` - Feature completion status

## Maintenance

Keep documentation updated when:
- New troubleshooting procedures are discovered
- System architecture changes
- New tools or scripts are added
- Critical fixes are implemented

## Quick Access Commands

From project root:
```bash
# View quick reference
cat Docs/QUICK_REFERENCE.md

# View comprehensive troubleshooting
cat Docs/JFX_BRIDGE_FIX_DOCUMENTATION.md

# Check current system status
python check_status.py

# Test bridge connection
python test_bridge_connection.py
``` 