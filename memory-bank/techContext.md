# Technical Context - Development Environment & Technologies

## Technology Stack

### Frontend Technologies
- **React 18.2.x**: Modern React with hooks and functional components
- **TypeScript 5.x**: Type-safe JavaScript with strict compiler settings
- **Material-UI 5.x**: Professional UI component library with consistent theming
- **Recharts 2.x**: Professional data visualization library for interactive charts and metrics
- **D3.js 7.x**: Interactive data visualization (removed from active use)
- **Cytoscape.js**: Graph visualization library (removed from active use)
- **React Router 6.x**: Client-side routing with nested routes for dual-dashboard navigation
- **Axios**: HTTP client for API communication with interceptors

### Backend Technologies  
- **Python 3.8+**: Core backend language with async/await support
- **Flask 2.3.x**: Lightweight web framework with blueprints
- **SQLAlchemy 2.x**: Modern ORM with async support and type hints
- **SQLite**: Embedded database for development and small deployments
- **Ghidra Bridge**: Real-time communication with Ghidra headless analyzer
- **Threading**: Background task processing with proper Flask context

### Analysis Technologies
- **Ghidra 10.4+**: NSA's reverse engineering platform
- **Ghidra Headless Analyzer**: Automated binary analysis without GUI
- **Ghidrathon**: Python scripting integration for Ghidra
- **Custom Analysis Scripts**: Specialized Python scripts for different analysis types

### AI/ML Integration
- **OpenAI API**: GPT-4 integration for function explanation and security analysis
- **Google Gemini**: Alternative LLM provider for analysis
- **Anthropic Claude**: Claude API for security-focused analysis
- **Ollama**: Local LLM support for offline analysis
- **Multi-Provider Support**: Configurable AI provider selection

### UI/UX Technologies
- **Professional Dashboard Design**: Dual-dashboard architecture with Security Hub + Fuzzing
- **Gradient Card System**: Enterprise-grade visual hierarchy and professional presentation
- **Interactive Data Visualization**: Recharts integration for performance metrics and status tracking
- **Dark Theme Integration**: VS Code Dark+ theme for code display and professional aesthetics
- **Responsive Design**: Mobile-friendly layouts with adaptive dashboard interfaces

### Development Tools
- **Git**: Version control with branching strategy
- **VS Code**: Primary development environment with extensions
- **Cursor**: AI-powered code editor for enhanced development
- **Python Black**: Code formatting with consistent style
- **ESLint**: JavaScript/TypeScript linting with security rules
- **Prettier**: Code formatting for frontend consistency

## Development Environment Setup

### Prerequisites
```bash
# System Requirements
- Python 3.8+ with pip and venv
- Node.js 16+ with npm
- Ghidra 10.4+ installation
- Git for version control
- 8GB+ RAM for binary analysis
- 20GB+ disk space for projects and binaries
```

### Backend Setup
```bash
# Virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Dependencies
pip install -r requirements.txt

# Environment configuration
cp env_template.txt .env
# Edit .env with appropriate values

# Database initialization
python migrate_database.py
python add_vulnerability_tables.py

# Ghidra Bridge setup
python setup_ghidra_bridge.py
```

### Frontend Setup
```bash
cd frontend
npm install
npm start  # Development server on port 3000
```

### Ghidra Configuration
```bash
# Ghidrathon installation
python install_ghidrathon_extension.py

# Bridge configuration
python ghidrathon/ghidrathon_configure.py

# Test installation
python test_ghidrathon_integration.py
```

## Environment Configuration

### Backend Configuration (.env)
```ini
# Database
DATABASE_URL=sqlite:///instance/shadowseek.db

# Ghidra
GHIDRA_PATH=C:\ghidra_10.4_PUBLIC
GHIDRA_PROJECT_PATH=./ghidra_projects
GHIDRA_BRIDGE_PORT=6777

# AI Services
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
GOOGLE_API_KEY=your_google_key
OLLAMA_URL=http://localhost:11434

# Application
FLASK_ENV=development
FLASK_DEBUG=true
SECRET_KEY=your_secret_key
UPLOAD_FOLDER=./uploads
TEMP_FOLDER=./temp
```

### Frontend Configuration
```json
{
  "proxy": "http://localhost:5000",
  "homepage": "http://localhost:3000",
  "scripts": {
    "start": "react-scripts start",
    "build": "react-scripts build",
    "test": "react-scripts test"
  }
}
```

## Development Workflow

### Git Workflow
```bash
# Feature development
git checkout -b feature/binary-cfg-progress
git add .
git commit -m "Add CFG progress indicator with real-time updates"
git push origin feature/binary-cfg-progress

# Code review and merge
git checkout main
git pull origin main
git merge feature/binary-cfg-progress
```

### Testing Workflow
```bash
# Backend testing
python -m pytest tests/
python test_bridge_connection.py
python test_comprehensive_system.py

# Frontend testing
cd frontend
npm test
npm run build  # Production build test
```

### Deployment Workflow
```bash
# Local development
python run.py  # Backend on port 5000
cd frontend && npm start  # Frontend on port 3000

# Production build
cd frontend && npm run build
python run.py --production
```

## Technical Constraints

### Performance Constraints
- **Memory Usage**: Large binaries (>100MB) require careful memory management
- **Processing Time**: Complex analysis can take 10-30 minutes for large binaries
- **Concurrent Users**: Single Ghidra instance limits concurrent analysis
- **Database Size**: SQLite performance degrades with large datasets (>10GB)

### Security Constraints
- **File Upload**: Limited to known binary formats with size restrictions
- **Analysis Isolation**: Ghidra runs in same process as web server
- **Data Storage**: Sensitive binary data stored in local filesystem
- **Network Security**: No built-in authentication or encryption

### Platform Constraints
- **Windows Dependencies**: Ghidra Bridge requires Windows-specific paths
- **Python Version**: Ghidrathon requires Python 3.8+ with specific dependencies
- **Ghidra Version**: Compatible with Ghidra 10.4+, may break with newer versions
- **Browser Support**: Modern browsers required for D3.js visualizations

### Resource Constraints
- **CPU Intensive**: Binary analysis is CPU-bound operation
- **Disk Space**: Binary storage and analysis results require significant space
- **Network Bandwidth**: Large binary uploads require high-speed connections
- **RAM Requirements**: Minimum 8GB RAM for medium-sized binary analysis

## Dependencies

### Backend Dependencies (requirements.txt)
```txt
Flask==2.3.3
SQLAlchemy==2.0.21
Flask-SQLAlchemy==3.0.5
ghidra-bridge==0.21.0
requests==2.31.0
python-dotenv==1.0.0
openai==1.3.7
anthropic==0.7.4
google-generativeai==0.3.1
```

### Frontend Dependencies (package.json)
```json
{
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.8.0",
    "@mui/material": "^5.11.10",
    "@mui/icons-material": "^5.11.9",
    "@emotion/react": "^11.10.5",
    "@emotion/styled": "^11.10.5",
    "recharts": "^2.8.0",
    "axios": "^1.3.4",
    "typescript": "^5.0.0"
  }
}
```

### Analysis Dependencies
```txt
# Ghidra Installation
ghidra_10.4_PUBLIC/
├── Ghidra/
├── Extensions/
└── support/

# Ghidrathon Extension
ghidrathon/
├── Ghidrathon-v4.0.0.zip
├── requirements.txt
└── ghidrathon_configure.py
```

## Development Setup Issues & Solutions

### Common Issues

#### 1. **Ghidra Bridge Connection Failures**
```python
# Symptoms: "Connection refused" or "Bridge not responding"
# Solution: Ensure Ghidra headless is running
python start_ghidra_bridge.py
python test_bridge_connection.py
```

#### 2. **Python Path Issues**
```python
# Symptoms: "Module not found" errors
# Solution: Verify Python path and virtual environment
import sys
print(sys.path)
pip list  # Verify installed packages
```

#### 3. **Database Migration Errors**
```python
# Symptoms: "Table already exists" or "Column not found"
# Solution: Reset database and re-run migrations
python reset_db.py
python migrate_database.py
python add_vulnerability_tables.py
```

#### 4. **Frontend Build Failures**
```bash
# Symptoms: TypeScript compilation errors
# Solution: Clear cache and reinstall dependencies
cd frontend
rm -rf node_modules package-lock.json
npm install
npm start
```

### Memory Bank Integration

#### File Structure
```
memory-bank/
├── projectbrief.md      # Project overview and goals
├── productContext.md    # Why project exists, problems solved
├── systemPatterns.md    # Architecture and design patterns
├── techContext.md       # This file - technical setup
├── activeContext.md     # Current work and recent changes
└── progress.md          # Implementation status and achievements
```

#### Development Tools Integration
```python
# VS Code Extensions
- Python
- React
- TypeScript
- GitLens
- Material-UI Snippets

# Cursor AI Integration
- Code completion
- Documentation generation
- Error resolution
- Refactoring assistance
```

## Performance Optimization

### Backend Optimization
```python
# Database optimization
- Proper indexing on frequently queried columns
- Connection pooling for concurrent requests
- Lazy loading for large datasets
- Pagination for API responses

# Memory management
- Explicit cleanup of analysis resources
- Garbage collection after large operations
- Streaming for large file operations
```

### Frontend Optimization
```typescript
// React optimization
- React.memo for expensive components
- useMemo for expensive calculations
- useCallback for stable function references
- Code splitting for large bundles

// D3.js optimization
- Virtualization for large graphs
- Debounced updates for interactive elements
- Efficient SVG manipulation
```

### Analysis Optimization
```python
# Ghidra optimization
- Headless analyzer settings for performance
- Selective analysis to avoid unnecessary processing
- Caching of analysis results
- Parallel processing where possible
```

## Monitoring & Debugging

### Backend Monitoring
```python
# Logging configuration
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/app.log'),
        logging.StreamHandler()
    ]
)

# Performance monitoring
import time
def timed_operation(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        logging.info(f"{func.__name__} took {end - start:.2f} seconds")
        return result
    return wrapper
```

### Frontend Monitoring
```typescript
// Error boundary for React components
class ErrorBoundary extends React.Component {
  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Component error:', error, errorInfo);
    // Send to error reporting service
  }
}

// Performance monitoring
const performanceObserver = new PerformanceObserver((list) => {
  list.getEntries().forEach((entry) => {
    console.log(`${entry.name}: ${entry.duration}ms`);
  });
});
```

## Security Considerations

### Input Validation
```python
# File upload validation
ALLOWED_EXTENSIONS = {'.exe', '.dll', '.so', '.dylib', '.bin'}
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB

def validate_upload(file):
    if not file.filename:
        raise ValueError("No filename provided")
    
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid file type: {ext}")
    
    if len(file.read()) > MAX_FILE_SIZE:
        raise ValueError("File too large")
```

### API Security
```python
# Rate limiting (future implementation)
from flask_limiter import Limiter
limiter = Limiter(
    app,
    key_func=lambda: request.remote_addr,
    default_limits=["200 per day", "50 per hour"]
)

# Input sanitization
import bleach
def sanitize_input(data):
    if isinstance(data, str):
        return bleach.clean(data, tags=[], strip=True)
    return data
```

## Future Technical Considerations

### Scalability Improvements
- **Database**: PostgreSQL migration for better performance
- **Caching**: Redis for distributed caching
- **Queue System**: Celery for background task processing
- **Load Balancing**: nginx for frontend serving and API load balancing

### Security Enhancements
- **Authentication**: JWT-based authentication system
- **Authorization**: Role-based access control
- **Encryption**: TLS/SSL for data in transit, encryption at rest
- **Audit Logging**: Comprehensive security event logging

### Performance Enhancements
- **Containerization**: Docker for consistent deployment
- **Orchestration**: Kubernetes for auto-scaling
- **CDN**: Content delivery network for static assets
- **Database Sharding**: Horizontal database scaling

### Integration Enhancements
- **API Gateway**: Centralized API management
- **Message Queue**: Asynchronous processing
- **Webhook Support**: Event-driven integration
- **Plugin System**: Extensible architecture for custom analysis 

## Bridge System Status Update (Latest)

### **Ghidra Bridge Integration** ✅ **FULLY OPERATIONAL**

**Connection Status**: 
- **Active**: `ghidra.app.script.GhidraState@fe7667c` on port 4768
- **Communication**: Real-time Python script execution in Ghidra's Jython environment
- **Analysis Pipeline**: Binary upload → Bridge analysis → Database storage → Status update

### **Recent Infrastructure Restoration**

**Issue Resolved**: Bridge execution was previously disabled with hardcoded failure
**Root Cause**: `execute_script()` method in `ghidra_bridge_manager.py` was hardcoded to return failure
**Resolution**: Restored proper script execution with Python code evaluation via bridge

**Files Modified**:
- ✅ `flask_app/ghidra_bridge_manager.py` - Restored script execution functionality
- ✅ `analysis_scripts/comprehensive_analysis_direct.py` - Created missing analysis script (7.9KB)
- ✅ `flask_app/models.py` - Enhanced binary status logic for 0-function detection

### **Validated Analysis Workflow**

**Working Examples**:
- **cacls.exe**: 77/78 functions decompiled (98.7%), Status: Decompiled ✅
- **OOBEFodSetup.exe**: 94/94 functions decompiled (100.0%), Status: Decompiled ✅
- **security.dll**: 0 functions found, Status: Failed (correct behavior) ✅

**Bridge Communication**:
```python
# Confirmed working script execution
def execute_script(self, project_name, script_path, args=None, binary_path=None):
    script_path = os.path.abspath(script_path)
    self.bridge.remote_eval(f"import sys; sys.path.append(r'{script_dir}')")
    import_cmd = f"exec(open(r'{script_path}').read())"
    result = self.bridge.remote_eval(import_cmd)
    return {"success": True, "result": result}
```

**Analysis Script**:
```python
# comprehensive_analysis_direct.py - Full binary analysis
def comprehensive_analysis(program=None, binary_id=None, database_url=None):
    # Function decompilation with DecompInterface
    # Extract functions, strings, symbols, memory blocks
    # Store results in temporary JSON for Flask database integration
    # Return comprehensive analysis data
```

### **Enhanced Error Handling**

**Status Management**:
- **Resource Files**: Files with 0 functions (like security.dll) correctly marked as "Failed"
- **Working Binaries**: Files with functions progress through normal analysis pipeline
- **Bridge Failures**: Graceful fallback to headless mode when bridge execution fails

**User Experience**:
- ✅ Clear distinction between system failure and file-specific limitations
- ✅ Proper feedback for "No suitable fuzzing targets" (expected for resource-only files)
- ✅ Accurate status reporting throughout binary lifecycle

### **Platform Integration**

**Complete Architecture**:
- **Flask Backend**: Task management, API endpoints, database operations
- **Ghidra Bridge**: Real-time communication with Ghidra headless analyzer
- **Analysis Scripts**: Python scripts executed in Ghidra's Jython environment
- **Database Storage**: Direct storage of analysis results from bridge execution
- **Status Management**: Intelligent binary lifecycle with accurate progress reporting

**Production Readiness**: System now operates exactly as designed in memory bank documentation with full bridge integration. 

## Documentation & Frontend Technical Context (Latest)

- Frontend documentation navigation now features persistent "Overview" links (sidebar, breadcrumbs, footer, floating button) for easy access from any section.
- Navigation consistently uses "Overview" for clarity and professionalism.
- "System Requirements" section removed from Getting Started and navigation.
- Added a detailed, step-by-step "Basic Workflow" section with a comprehensive Mermaid diagram and workflow steps.
- Analysis Workflow Overview diagram (color-coded) included in both Overview and Platform Capabilities sections.
- Platform Capabilities section simplified for clarity and professionalism.
- All diagrams use a consistent color scheme and no HTML in Mermaid labels.
- All Mermaid diagrams and Markdown code blocks in template literals are escaped (triple backticks) to prevent linter/build errors.
- All diagrams and Markdown blocks are properly escaped and rendered.
- Build and dev server now run without errors related to documentation content. 