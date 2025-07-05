# Ghidra Web Analyzer - Custom MCP + Headless Architecture

## 🏗️ Project Overview

A Flask-based web application that integrates with Ghidra in headless mode using a custom Model Context Protocol (MCP) layer. This provides automated binary analysis with a modern React frontend featuring control flow graph visualization.

## 🎯 Key Features

- **Fully Automated**: No manual Ghidra launching required
- **MCP Protocol**: Clean, standardized JSON-RPC 2.0 interface
- **Headless Scalability**: Multiple concurrent binary analyses
- **Process Isolation**: Each analysis runs in separate Ghidra instance
- **Resource Management**: Auto cleanup and process pooling
- **Real-time Updates**: WebSocket progress tracking
- **CFG Visualization**: Interactive control flow graphs with Cytoscape.js
- **File Upload**: Support for binaries up to 1GB with progress tracking

## 🏛️ Architecture

### High-Level Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   React Frontend│◄──►│   Flask Backend  │◄──►│   Custom MCP Server │◄──►│ Ghidra Headless Pool│
│   (CFG + UI)    │    │   (MCP Client)   │    │  (Process Manager)  │    │  (Auto-managed)     │
└─────────────────┘    └──────────────────┘    └─────────────────────┘    └─────────────────────┘
                              │                           │                          │
                              ▼                           ▼                          ▼
                       ┌──────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
                       │ RabbitMQ + Celery│    │   MCP Protocol      │    │ Headless Instance 1 │
                       │   (Task Queue)   │    │   (JSON-RPC 2.0)    │    │ Headless Instance 2 │
                       └──────────────────┘    └─────────────────────┘    │ Headless Instance N │
                                                                          └─────────────────────┘
```

### Component Breakdown

#### 1. React Frontend
- Modern UI with responsive design
- File upload interface with drag-and-drop
- Real-time analysis progress tracking
- Interactive CFG visualization using Cytoscape.js
- Analysis results dashboard
- Basic blocks view with instruction-level drill-down toggle

#### 2. Flask Backend (MCP Client)
- REST API endpoints for all operations
- WebSocket support for real-time updates
- MCP client for communication with Ghidra
- Async task queuing with Celery
- SQLite database for persistence
- File storage and management

#### 3. Custom MCP Server
- JSON-RPC 2.0 protocol implementation
- Ghidra headless process pool management
- Auto-scaling based on workload
- Process isolation and resource cleanup
- Error handling and recovery

#### 4. Ghidra Headless Pool
- Multiple concurrent Ghidra instances
- Custom analysis scripts (Python/Java)
- Automatic project creation and cleanup
- Binary import and analysis pipeline

## 🔧 Core Analysis Functions

The system implements 9 core analysis functions via MCP protocol:

1. **decompileFunction**: Returns high-level pseudo-code of a function
2. **getXrefs**: Provides cross-references to or from a function
3. **getStackFrame**: Retrieves local variable and parameter layout
4. **getMemoryRegions**: Returns mapped memory segments
5. **getDiffs**: Identifies instruction-level differences for patch analysis
6. **getCFG**: Extracts full control flow graph for a function
7. **executeSymbolically**: Leverages symbolic execution engines
8. **searchPatterns**: Detects dangerous instructions, crypto signatures, etc.
9. **runVulnChecks**: Executes vulnerability detection plugins

## 📁 Project Structure

```
ghidra-web-analyzer/
├── mcp_server/                           # Custom MCP Server
│   ├── __init__.py
│   ├── ghidra_mcp_server.py             # Main MCP server implementation
│   ├── ghidra_manager.py                # Headless process manager
│   ├── protocol.py                      # MCP JSON-RPC 2.0 protocol
│   ├── ghidra_scripts/                  # Custom Ghidra analysis scripts
│   │   ├── comprehensive_analysis.py    # Main analysis script
│   │   ├── decompile_function.py        # Function decompilation
│   │   ├── get_xrefs.py                 # Cross-reference analysis
│   │   ├── get_stack_frame.py           # Stack frame analysis
│   │   ├── get_memory_regions.py        # Memory mapping
│   │   ├── get_cfg.py                   # Control flow graph
│   │   ├── search_patterns.py           # Pattern detection
│   │   └── vuln_checks.py               # Vulnerability scanning
│   └── utils/
│       ├── process_pool.py              # Process pool management
│       └── cleanup.py                   # Resource cleanup utilities
├── flask_app/                           # Flask Web Application
│   ├── __init__.py
│   ├── app.py                           # Main Flask application
│   ├── config.py                        # Configuration management
│   ├── models.py                        # SQLite database models
│   ├── mcp_client.py                    # MCP client implementation
│   ├── tasks.py                         # Celery background tasks
│   ├── api/                             # REST API blueprints
│   │   ├── __init__.py
│   │   ├── binaries.py                  # Binary upload/management
│   │   ├── analysis.py                  # Analysis operations
│   │   └── config.py                    # Configuration endpoints
│   ├── services/                        # Business logic
│   │   ├── __init__.py
│   │   ├── file_service.py              # File handling
│   │   └── analysis_service.py          # Analysis orchestration
│   └── utils/
│       ├── __init__.py
│       └── websockets.py                # Real-time updates
├── frontend/                            # React Frontend
│   ├── package.json
│   ├── src/
│   │   ├── components/                  # React components
│   │   │   ├── FileUpload.jsx          # File upload interface
│   │   │   ├── ProgressTracker.jsx     # Real-time progress
│   │   │   ├── CFGVisualization.jsx    # Control flow graphs
│   │   │   ├── AnalysisResults.jsx     # Results dashboard
│   │   │   └── Configuration.jsx       # Settings management
│   │   ├── utils/                       # Utilities
│   │   │   ├── api.js                  # API client
│   │   │   └── websocket.js            # WebSocket client
│   │   ├── styles/                      # CSS/styling
│   │   └── App.jsx                      # Main React app
│   └── public/
├── tests/                               # Test suite
│   ├── test_mcp_server.py
│   ├── test_flask_app.py
│   └── test_integration.py
├── docker/                              # Docker configuration
│   ├── Dockerfile
│   └── docker-compose.yml
├── docs/                                # Documentation
├── requirements.txt                     # Python dependencies
├── .env.example                         # Environment variables template
└── README.md                            # Setup and usage guide
```

## 🚀 Implementation Plan

### Phase 1: Custom MCP Server for Headless Ghidra (Days 1-3)
- Create MCP server that spawns/manages Ghidra headless processes
- Implement JSON-RPC 2.0 protocol for all 9 analysis functions
- Process pool management with auto-scaling
- Custom Ghidra scripts for headless analysis

### Phase 2: Flask MCP Client (Days 4-5)
- Flask backend acting as MCP client
- Async task queuing with Celery
- File upload and management (1GB limit)
- Real-time progress tracking via WebSockets

### Phase 3: React Frontend + CFG Visualization (Days 6-7)
- Modern React UI with Cytoscape.js for CFG visualization
- Basic blocks view with instruction-level drill-down
- Progress tracking and real-time updates
- Analysis results dashboard

### Phase 4: Advanced Features (Days 8-9)
- All 9 analysis functions integrated
- Binary comparison interface
- Vulnerability scanning dashboard
- Pattern search visualization

### Phase 5: Production Ready (Day 10)
- Configuration management
- Error handling and logging
- Performance optimization
- Documentation

## ⚙️ Configuration

### Environment Variables
```bash
# Ghidra Configuration
GHIDRA_INSTALL_DIR=D:\1132-Ghidra\ghidra_11.3.2
GHIDRA_MAX_PROCESSES=4
GHIDRA_TIMEOUT=3600

# MCP Server Configuration
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=8080

# Flask Configuration
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_ENV=development

# Database Configuration
DATABASE_URL=sqlite:///ghidra_analyzer.db

# RabbitMQ Configuration
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USER=guest
RABBITMQ_PASSWORD=guest
RABBITMQ_VHOST=/

# File Upload Configuration
MAX_FILE_SIZE=1073741824  # 1GB in bytes
UPLOAD_FOLDER=./uploads
TEMP_FOLDER=./temp
```

## 🔒 Security Considerations

- **File Upload Validation**: Basic file type checking (configurable)
- **Process Isolation**: Each analysis runs in separate process
- **Resource Limits**: Memory and CPU limits for Ghidra processes
- **Cleanup**: Automatic temporary file cleanup
- **Error Handling**: Comprehensive error recovery

## 📊 Performance Features

- **Process Pool**: Multiple concurrent Ghidra instances
- **Caching**: Analysis result caching
- **Progress Tracking**: Real-time analysis progress
- **Auto-scaling**: Dynamic process pool sizing
- **Resource Management**: Memory and disk usage monitoring

## 🎨 UI/UX Features

### CFG Visualization
- Interactive graph navigation
- Zoom and pan functionality
- Basic block highlighting
- Instruction-level drill-down
- Export capabilities (PNG, SVG)

### Analysis Dashboard
- Real-time progress indicators
- Analysis history
- Results comparison
- Export functionality
- Search and filtering

### File Management
- Drag-and-drop upload
- Progress tracking
- File size validation
- Binary information display
- Upload history

## 🧪 Testing Strategy

- **Unit Tests**: Individual component testing
- **Integration Tests**: MCP protocol testing
- **End-to-End Tests**: Full workflow testing
- **Performance Tests**: Load and stress testing
- **UI Tests**: Frontend interaction testing

## 📈 Future Enhancements

- **Multi-Architecture Support**: ARM, MIPS, etc.
- **Plugin System**: Custom analysis plugins
- **Collaboration Features**: Shared analysis sessions
- **Cloud Deployment**: AWS/Azure deployment
- **Advanced Visualization**: 3D graphs, heatmaps
- **Machine Learning**: Automated pattern recognition

## 🛠️ Development Tools

- **Backend**: Flask, SQLAlchemy, Celery, RabbitMQ
- **Frontend**: React, Cytoscape.js, Material-UI
- **Protocol**: JSON-RPC 2.0 for MCP communication
- **Database**: SQLite (development), PostgreSQL (production)
- **Testing**: pytest, Jest, Selenium
- **Deployment**: Docker, Docker Compose

## 📝 Notes

- Ghidra path is configurable via web UI and stored in .env
- Analysis functions are implemented as MCP tools
- Process pool size is configurable based on system resources
- All temporary files are automatically cleaned up
- WebSocket connections provide real-time updates
- CFG visualization supports both basic blocks and instruction-level views 