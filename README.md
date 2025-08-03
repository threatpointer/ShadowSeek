# ShadowSeek - Advanced Binary Security Analysis Platform

🔍 **Enterprise-grade binary security analysis with AI-powered vulnerability detection and intelligent fuzzing harness generation**

> **Author**: [Mohammed Tanveer (@threatpointer)](https://github.com/threatpointer) - Security Researcher & Architect
 
> 🚀 **One-Command Setup**: Run `python setup-shadowseek.py` to automatically install dependencies, configure environment, and start all components!
> 
> ✨ **Enhanced Features**: Automatic dependency installation, corporate network support, environment refresh, and intelligent error recovery.
> 
> 📚 **Documentation**: See [Docs/SETUP_SCRIPTS_README.md](Docs/SETUP_SCRIPTS_README.md) for setup guide and [Docs/ENVIRONMENT_VARIABLES.md](Docs/ENVIRONMENT_VARIABLES.md) for manual configuration.

## 🌟 Platform Overview

ShadowSeek is a revolutionary binary security analysis platform that transforms traditional reverse engineering into an intelligent, automated, and AI-enhanced workflow. Built on NSA's Ghidra framework, ShadowSeek provides enterprise-grade security analysis capabilities suitable for security professionals, vulnerability researchers, and enterprise security teams.

## ✨ Key Features

- 🧠 **AI-Powered Security Analysis** - LLM-enhanced vulnerability detection with evidence-based confidence scoring
- 🎯 **Intelligent Fuzzing** - AI-driven fuzzing harness generation for AFL/AFL++/HongFuzz/LibFuzzer with target selection automation
- 🛡️ **Comprehensive Vulnerability Detection** - 75+ dangerous function patterns with CWE/CVE classification
- 🔄 **Binary Differential Analysis** - Advanced BinDiff capabilities using ghidriff for comparing binary versions and tracking changes
- 🎨 **Professional User Experience** - Modern React UI with syntax highlighting and seamless navigation
- 📊 **Unified Security Dashboard** - Single-pane-of-glass for complete security analysis workflow
- ⚡ **Production-Ready Output** - Enterprise-quality harnesses and professional security reports

## 🚀 Advanced Capabilities

### **Unified Security Analysis**
- **AI + Pattern Correlation**: Intelligent validation combining LLM insights with static analysis
- **Evidence-Based Confidence**: Mathematical scoring with 93.1% average confidence
- **Industry Standards**: Consistent CWE/CVE classification across all findings
- **Professional Reporting**: Executive summaries with technical implementation details

### **AI-Powered Fuzzing System**
- **Intelligent Target Selection**: AI analyzes security findings to identify optimal fuzzing targets
- **Production-Ready Harnesses**: Complete AFL/AFL++ infrastructure with professional documentation
- **Multiple Fuzzing Strategies**: Boundary testing, format injection, malformed input, heap manipulation
- **Evidence-Based Rationale**: Clear explanations for every function selected for fuzzing

### **Professional User Experience**
- **One-Click Operations**: Simplified workflow with intelligent automation
- **Beautiful Code Display**: VS Code-style syntax highlighting with dark theme integration
- **Hyperlink Navigation**: Direct links from security findings to function details
- **Complete Integration**: Seamless workflow from binary analysis to vulnerability hunting

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    React Frontend (3000)                       │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │   Dashboard     │ │  Security       │ │  Fuzzing        │   │
│  │   Management    │ │   Analysis      │ │   Dashboard     │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ REST API
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Flask Backend (5000)                        │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │ Unified Security│ │ AI-Powered      │ │ Fuzzing Harness │   │
│  │   Analyzer      │ │   Intelligence  │ │   Generator     │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ Bridge Connection
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Ghidra Headless (6777)                       │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │  Binary Analysis│ │ Function        │ │   Advanced      │   │
│  │     Engine      │ │ Decompilation   │ │   Analysis      │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 📋 Requirements

### **System Requirements**
- **Python 3.8+** (required - install from [python.org](https://python.org))
- **8GB+ RAM** for binary analysis
- **20GB+ disk space** for projects and analysis results
- **Windows, macOS, or Linux** (Windows recommended for full compatibility)

### **Auto-Installed by Setup Script**
- **Ghidra 10.4+** (detected automatically or prompted for path)
- **Node.js 16+** with npm (installed from [nodejs.org](https://nodejs.org))
- **Java JDK 11+** (installed from [Eclipse Adoptium](https://adoptium.net))
- **Git** (installed from [git-scm.com](https://git-scm.com)) - optional but recommended
- **Python packages** (Flask, React dependencies, AI libraries, etc.)

> 💡 **Note**: The `setup-shadowseek.py` script automatically installs missing dependencies from official sources, handles corporate network restrictions, and configures everything for you!

## ⚡ Quick Start

### 1. Clone and Auto-Setup (Recommended)
```bash
git clone https://github.com/threatpointer/ShadowSeek.git
cd ShadowSeek

# 🚀 One-command setup - installs everything automatically!
python setup-shadowseek.py
```

**✨ The enhanced setup script automatically:**
- ✅ Installs Node.js, Java JDK, Git from official sources
- ✅ Creates optimized virtual environment (with `uv` if available)
- ✅ Installs all Python and frontend dependencies
- ✅ **Installs official Ghidra Bridge server scripts** (enables Python-Ghidra integration)
- ✅ Configures Ghidra Bridge integration
- ✅ Sets up environment variables and directories
- ✅ Starts all components and tests connectivity
- ✅ Handles corporate networks and SSL issues
- ✅ Refreshes environment variables automatically

### 2. Manual Setup (Advanced Users)
```bash
# Create virtual environment with uv (faster) or venv
uv venv .venv  # or: python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies  
uv pip install -r requirements.txt  # or: pip install -r requirements.txt

# Install Ghidra Bridge server scripts (REQUIRED for bridge functionality)
python -m ghidra_bridge.install_server ghidra_scripts

# Install frontend dependencies
cd frontend && npm install

# Configure environment
python setup-shadowseek.py --skip-install
```

### 3. Access Platform
After setup completes:
- **Main Interface**: http://localhost:3000
- **API Documentation**: http://localhost:5000/api/docs
- **System Status**: http://localhost:5000/api/status

### 4. Setup Options
```bash
# Common setup options
python setup-shadowseek.py --auto              # Non-interactive mode
python setup-shadowseek.py --refresh-env       # Refresh environment variables
python setup-shadowseek.py --skip-system-check # Skip dependency checks
python setup-shadowseek.py --force-continue    # Continue with missing deps
```

## 🛠️ Enhanced Setup Features

The `setup-shadowseek.py` script provides enterprise-grade installation automation:

### **⚡ Fast Package Management**
- **uv Integration**: Uses `uv` for 3-5x faster Python package installation when available
- **Intelligent Fallbacks**: Gracefully falls back to `pip` when needed
- **Virtual Environment Management**: Creates and manages optimized Python environments

### **🔄 Environment Refresh**
- **Real-time PATH Updates**: Refreshes environment variables without restarting terminal
- **Command Verification**: Tests newly installed software immediately
- **Registry Integration**: Updates Windows PATH from registry for instant availability

### **🤖 Intelligent Installation**
- **Official Sources**: Downloads from official repositories (nodejs.org, adoptium.net, etc.)
- **Version Compatibility**: Ensures compatible versions for all dependencies
- **Error Recovery**: Attempts multiple installation methods with detailed feedback

## 🎯 Usage Workflow

### **Complete Security Analysis Pipeline**
```
Binary Upload → AI Security Analysis → Security Findings → 
Function Navigation → Fuzzing Generation → Code Viewing → 
Download & Deploy → Vulnerability Hunting
```

## 📊 API Reference

### **Core Endpoints**
- `GET /api/status` - System status and capabilities
- `POST /api/binaries` - Upload binary for analysis
- `GET /api/binaries/{id}` - Binary details and analysis results

### **Security Analysis**
- `POST /api/binaries/{id}/security-analysis` - Unified security analysis
- `GET /api/binaries/{id}/security-findings` - Security findings with pagination

### **Fuzzing System**
- `POST /api/binaries/{id}/generate-fuzzing-harness` - AI-powered harness generation
- `GET /api/fuzzing-harnesses/{id}/download/package` - Complete fuzzing package

## 🔧 Development

### **Project Structure**
```
ShadowSeek/
├── flask_app/                 # Backend API and services
│   ├── models.py             # Database models
│   ├── routes.py             # API endpoints
│   ├── unified_security_analyzer.py  # Core security engine
│   └── fuzzing_harness_generator.py  # Fuzzing system
├── frontend/                  # React frontend
│   └── src/components/       # Professional UI components
├── Docs/                     # Technical documentation
├── user-docs/                # User documentation and guides
├── analysis_scripts/         # Ghidra analysis scripts
├── uploads/                  # Binary upload directory
├── temp/                     # Temporary analysis files
└── logs/                     # Application logs
```

## 📚 Documentation

- **[Complete Documentation](Docs/)** - Full technical documentation
- **[User Guides](user-docs/)** - Step-by-step user documentation
- **[API Reference](Docs/API_DOCUMENTATION.md)** - Complete REST API reference
- **[Setup Guide](Docs/SETUP_SCRIPTS_README.md)** - Automated setup documentation
- **[Environment Variables](Docs/ENVIRONMENT_VARIABLES.md)** - Configuration reference

## 👨‍💻 About the Author

**[Mohammed Tanveer (@threatpointer)](https://github.com/threatpointer)** - Security Researcher & Architect  
**Links**: [GitHub](https://github.com/threatpointer) | [Twitter](https://twitter.com/threatpointer) | [LinkedIn](https://linkedin.com/in/mdtanveer)

## 🏆 Acknowledgments

### **Binary Differential Analysis**

ShadowSeek's binary comparison and differential analysis capabilities are powered by **[ghidriff](https://github.com/clearbluejar/ghidriff)**, an exceptional Python command-line Ghidra binary diffing engine.

**Special thanks to:**
- **[@clearbluejar](https://github.com/clearbluejar)** - Creator and maintainer of ghidriff
- **Project**: [ghidriff - Python Command-Line Ghidra Binary Diffing Engine](https://github.com/clearbluejar/ghidriff)
- **Connect**: [GitHub](https://github.com/clearbluejar) | [Twitter/X](https://x.com/clearbluejar)

ghidriff enables ShadowSeek to perform sophisticated binary comparisons with professional-grade accuracy and detailed reporting.

### **Open Source Foundation**

ShadowSeek builds upon excellent open-source projects:
- **[Ghidra](https://ghidra-sre.org/)** - NSA's Software Reverse Engineering Framework
- **[AFL/AFL++](https://github.com/AFLplusplus/AFLplusplus)** - Advanced fuzzing frameworks
- **[React](https://reactjs.org/)** & **[Flask](https://flask.palletsprojects.com/)** - Frontend and backend frameworks

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines and code of conduct.

**Security Contributions**: Given the security focus of this platform, we especially welcome contributions from security researchers and practitioners.

## 📞 Support

- **Documentation**: [Docs/](Docs/) and [user-docs/](user-docs/)
- **Issues**: [GitHub Issues](https://github.com/threatpointer/ShadowSeek/issues)
- **Security Issues**: Please report security vulnerabilities privately to [@threatpointer](https://github.com/threatpointer)

---

**ShadowSeek** - Transforming binary security analysis through AI-powered intelligence and professional automation.

*Developed with ❤️ by [@threatpointer](https://github.com/threatpointer) for the global cybersecurity community* 🔍✨ 