# Quick Start Guide

## 🚀 Get Started with ShadowSeek in 5 Minutes

Welcome to ShadowSeek! This guide will get you analyzing binaries and hunting vulnerabilities in just a few minutes.

---

## 📋 Prerequisites

Before you begin, ensure you have:

- **Python 3.8+** with pip and virtual environment support
- **Node.js 16+** with npm
- **Ghidra 10.4+** installation
- **8GB+ RAM** for binary analysis
- **Modern web browser** (Chrome, Firefox, Safari, Edge)

---

## ⚡ Quick Installation

### 1. Clone and Setup Backend

```bash
# Clone repository
git clone https://github.com/shadowseek/shadowseek.git
cd shadowseek

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp env_template.txt .env
# Edit .env with your Ghidra path and API keys
```

### 2. Setup Frontend

```bash
# Install frontend dependencies
cd frontend
npm install
```

### 3. Initialize Database

```bash
# Return to root directory
cd ..

# Initialize database
python -c "from flask_app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"
```

---

## 🎯 First Binary Analysis

### 1. Start ShadowSeek

```bash
# Terminal 1: Start backend
python run.py

# Terminal 2: Start frontend
cd frontend
npm start
```

**Access:** Open `http://localhost:3000` in your browser

### 2. Upload Your First Binary

1. **Click "Upload"** in the navigation bar
2. **Drag and drop** a binary file (`.exe`, `.dll`, `.so`, etc.)
3. **Watch automatic analysis** begin immediately
4. **Wait for completion** (typically 2-5 minutes)

### 3. Explore Analysis Results

1. **Navigate to Dashboard** - View your uploaded binary
2. **Click binary name** - Open detailed analysis
3. **Explore Functions tab** - See decompiled functions
4. **Try Security Analysis** - One-click vulnerability detection

---

## 🔍 Your First Security Analysis

### 1. Perform Security Analysis

1. **Open your binary** from the dashboard
2. **Click "Security Analysis" tab**
3. **Click "Analyze Security"** button
4. **Review findings** with confidence scores

### 2. Navigate Security Findings

1. **Click function hyperlinks** in security findings
2. **Auto-navigate** to Functions tab
3. **View expanded function details** with AI analysis
4. **Review decompiled code** and security implications

---

## 🎯 Your First Fuzzing Harness

### 1. Generate Fuzzing Harness

1. **Complete security analysis** (previous step)
2. **Click "Fuzzing" tab** or fuzzing button
3. **Review AI-selected targets** with rationales
4. **Click "Generate Harness"** for AFL/AFL++

### 2. View Generated Code

1. **Click "View Code"** on generated harness
2. **Explore syntax-highlighted code** (C, Makefile, README)
3. **Copy code snippets** to clipboard
4. **Download complete package** as ZIP

### 3. Deploy Fuzzing Campaign

```bash
# Extract downloaded harness
unzip fuzzing_harness.zip
cd fuzzing_harness

# Install AFL++ (if not already installed)
# Ubuntu/Debian: sudo apt install afl++
# macOS: brew install afl++

# Build harness
make

# Setup inputs
make setup

# Start fuzzing
make fuzz
```

---

## 📊 Understanding the Interface

### Navigation Overview

- **🏠 Dashboard** - View all uploaded binaries and their status
- **📤 Upload** - Upload new binaries for analysis
- **⚖️ Compare** - Compare multiple binaries side-by-side
- **🛡️ Security Hub** - Advanced security analysis dashboard
- **🎯 Fuzzing** - Fuzzing harness generation and management
- **⚙️ Config** - Configure AI providers and system settings
- **🔧 System** - System management and diagnostics

### Binary Analysis Tabs

- **📊 Overview** - Binary metadata and analysis status
- **🔧 Functions** - Function listing with decompilation and AI analysis
- **🔍 Results** - Comprehensive analysis data (imports, exports, strings)
- **🛡️ Security Analysis** - Unified security findings with evidence
- **🎯 Fuzzing** - AI-powered fuzzing harness generation

---

## 🎛️ Essential Configuration

### 1. Configure AI Provider

1. **Navigate to Config**
2. **Select AI Provider** (OpenAI, Anthropic, Google, Ollama)
3. **Add API Key** for your chosen provider
4. **Test Connection** to verify setup

### 2. Adjust Analysis Settings

```bash
# Edit .env file
GHIDRA_PATH=/path/to/ghidra
OPENAI_API_KEY=your_key_here
ANALYSIS_TIMEOUT=300
MAX_FUNCTIONS_PER_BINARY=1000
```

### 3. Verify Ghidra Bridge

1. **Check System tab** for bridge status
2. **Ensure "Connected"** status
3. **Test bridge connection** if needed

---

## 🏆 Best Practices

### Analysis Workflow

1. **Upload binaries** during low-activity periods (analysis is CPU-intensive)
2. **Start with smaller binaries** to familiarize yourself with the interface
3. **Use AI analysis selectively** to conserve API credits
4. **Review security findings** before generating fuzzing harnesses

### Security Analysis

1. **Trust high-confidence findings** (>90%) for immediate investigation
2. **Review medium-confidence findings** (70-90%) manually
3. **Use evidence trails** to understand detection rationale
4. **Mark false positives** to improve future analysis

### Fuzzing Best Practices

1. **Review AI target selection** rationale before proceeding
2. **Test harnesses locally** before large-scale campaigns
3. **Monitor resource usage** during fuzzing campaigns
4. **Document vulnerability discoveries** systematically

---

## 🚨 Common Issues & Solutions

### Binary Upload Issues

**Problem:** File type not supported
**Solution:** Ensure file has supported extension (`.exe`, `.dll`, `.so`, `.bin`, etc.)

**Problem:** Analysis stuck in "analyzing" status
**Solution:** Click "Restart Analysis" button or reset analysis status

### Ghidra Bridge Issues

**Problem:** Bridge shows "disconnected"
**Solution:** Restart ShadowSeek backend and check Ghidra installation path

**Problem:** Analysis fails with bridge error
**Solution:** Verify Ghidra Bridge dependencies and Python path

### Performance Issues

**Problem:** Analysis takes too long
**Solution:** Reduce analysis scope or increase timeout in configuration

**Problem:** UI becomes unresponsive
**Solution:** Close other browser tabs and refresh the application

---

## 🎯 Next Steps

### Explore Advanced Features

1. **[Security Hub](../user-guide/security-hub.md)** - Advanced vulnerability detection
2. **[Fuzzing Dashboard](../user-guide/fuzzing-dashboard.md)** - Comprehensive fuzzing management
3. **[API Integration](../api-reference/rest-api.md)** - Automate workflows with REST API
4. **[System Administration](../administration/system-management.md)** - Advanced configuration

### Learning Resources

1. **[Complete Workflow Examples](../examples/complete-workflow.md)** - Detailed analysis scenarios
2. **[Architecture Overview](../architecture/system-architecture.md)** - Technical deep dive
3. **[Troubleshooting Guide](../administration/troubleshooting.md)** - Common issues and solutions

---

## 📞 Getting Help

If you encounter issues:

1. **Check [Troubleshooting Guide](../administration/troubleshooting.md)**
2. **Review [FAQ](../administration/troubleshooting.md#faq)**
3. **Contact support:** dev@shadowseek.security

---

## 🎉 Congratulations!

You've successfully:
- ✅ Set up ShadowSeek
- ✅ Analyzed your first binary
- ✅ Performed security analysis
- ✅ Generated a fuzzing harness
- ✅ Explored the interface

You're now ready to leverage ShadowSeek's enterprise-grade security analysis capabilities for your vulnerability research and security assessment needs.

**Next:** Explore the [User Guide](../user-guide/README.md) for detailed feature documentation. 