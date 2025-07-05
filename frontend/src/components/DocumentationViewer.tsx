import React, { useState, useEffect } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Box,
  Container,
  Grid,
  Paper,
  Typography,
  List,
  ListItem,
  ListItemText,
  ListItemButton,
  Collapse,
  Breadcrumbs,
  Link,
  CircularProgress,
  Alert,
  Divider,
  Chip,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  ExpandLess,
  ExpandMore,
  Description,
  Code,
  Architecture,
  Security,
  Settings,
  Help,
  Home,
  NavigateNext,
  Download,
  GitHub
} from '@mui/icons-material';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import rehypeRaw from 'rehype-raw';
import axios from 'axios';
import mermaid from 'mermaid';
// @ts-ignore
import SyntaxHighlighter from 'react-syntax-highlighter';

interface DocSection {
  title: string;
  icon: React.ReactNode;
  items: DocItem[];
  expanded?: boolean;
}

interface DocItem {
  title: string;
  path: string;
  description?: string;
}

// Mermaid Diagram Component
const MermaidDiagram: React.FC<{ chart: string }> = ({ chart }) => {
  const [svg, setSvg] = useState<string>('');
  const [error, setError] = useState<string>('');

  useEffect(() => {
    const renderMermaid = async () => {
      try {
        // Initialize mermaid with dark theme
        mermaid.initialize({
          startOnLoad: false,
          theme: 'dark',
          themeVariables: {
            primaryColor: '#00bcd4',
            primaryTextColor: '#ffffff',
            primaryBorderColor: '#00bcd4',
            lineColor: '#ffffff',
            secondaryColor: '#1e1e1e',
            tertiaryColor: '#2d2d2d',
            background: '#1e1e1e',
            mainBkg: '#2d2d2d',
            secondBkg: '#1e1e1e',
            tertiaryBkg: '#1e1e1e'
          },
          flowchart: {
            useMaxWidth: true,
            htmlLabels: true
          }
        });

        // Generate unique ID for this diagram
        const id = `mermaid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        // Render the diagram
        const { svg: renderedSvg } = await mermaid.render(id, chart);
        setSvg(renderedSvg);
        setError('');
      } catch (err) {
        console.error('Mermaid rendering error:', err);
        setError(err instanceof Error ? err.message : 'Failed to render diagram');
        setSvg('');
      }
    };

    if (chart) {
      renderMermaid();
    }
  }, [chart]);

  if (error) {
    return (
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="error" sx={{ display: 'block', mb: 1 }}>
          ⚠️ Mermaid Diagram Rendering Error
        </Typography>
        <Paper sx={{ p: 2, backgroundColor: '#ffebee', border: '1px solid #e57373' }}>
          <Typography variant="body2" color="error" gutterBottom>
            {error}
          </Typography>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
            Raw diagram code:
          </Typography>
          <Typography
            component="pre"
            sx={{ 
              fontFamily: 'monospace', 
              whiteSpace: 'pre-wrap',
              margin: 0,
              fontSize: '0.75rem',
              backgroundColor: '#f5f5f5',
              p: 1,
              mt: 1,
              borderRadius: 1
            }}
          >
            {chart}
          </Typography>
        </Paper>
      </Box>
    );
  }

  if (!svg) {
    return (
      <Box sx={{ mb: 2, textAlign: 'center', py: 2 }}>
        <CircularProgress size={24} />
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
          Rendering diagram...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="caption" color="primary" sx={{ display: 'block', mb: 1 }}>
        📊 Interactive Mermaid Diagram
      </Typography>
      <Paper 
        sx={{ 
          p: 2, 
          backgroundColor: '#1e1e1e', 
          border: '1px solid #00bcd4',
          borderRadius: 2,
          overflow: 'auto',
          '& svg': {
            maxWidth: '100%',
            height: 'auto'
          }
        }}
      >
        <Box dangerouslySetInnerHTML={{ __html: svg }} />
      </Paper>
    </Box>
  );
};

const DocumentationViewer: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [markdownContent, setMarkdownContent] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string>('');
  const [showBackToTop, setShowBackToTop] = useState<boolean>(false);
  const [expandedSections, setExpandedSections] = useState<{ [key: string]: boolean }>({
    'getting-started': true,
    'user-guide': false,
    'api-reference': false,
    'architecture': false,
    'security-features': false,
    'administration': false,
    'examples': false
  });

  // Handle scroll for back to top button
  useEffect(() => {
    const handleScroll = () => {
      setShowBackToTop(window.pageYOffset > 300);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Documentation structure
  const docSections: DocSection[] = [
    {
      title: 'Getting Started',
      icon: <Home />,
      items: [
        { title: 'Installation Guide', path: '/docs/getting-started/installation', description: 'Step-by-step installation instructions' },
        { title: 'Quick Start Tutorial', path: '/docs/getting-started/quick-start', description: 'Get started in 5 minutes' },
        { title: 'Basic Workflow', path: '/docs/getting-started/basic-workflow', description: 'Understanding the analysis workflow' }
      ]
    },
    {
      title: 'User Guide',
      icon: <Description />,
      items: [
        { title: 'Dashboard Overview', path: '/docs/user-guide/dashboard', description: 'Navigate the main dashboard' },
        { title: 'Binary Analysis', path: '/docs/user-guide/binary-analysis', description: 'Analyzing binary files' },
        { title: 'Function Analysis', path: '/docs/user-guide/function-analysis', description: 'Function decompilation and AI analysis' },
        { title: 'Security Hub', path: '/docs/user-guide/security-hub', description: 'Advanced vulnerability detection' },
        { title: 'Fuzzing Dashboard', path: '/docs/user-guide/fuzzing-dashboard', description: 'Generating fuzzing harnesses' },
        { title: 'Configuration', path: '/docs/user-guide/configuration', description: 'System and AI configuration' }
      ]
    },
    {
      title: 'API Reference',
      icon: <Code />,
      items: [
        { title: 'REST API Overview', path: '/docs/api-reference/rest-api', description: 'Complete API documentation' },
        { title: 'Binary Management', path: '/docs/api-reference/binary-management', description: 'Binary upload and management APIs' },
        { title: 'Function Analysis', path: '/docs/api-reference/function-analysis', description: 'Function decompilation APIs' },
        { title: 'Security Analysis', path: '/docs/api-reference/security-analysis', description: 'Security scanning APIs' },
        { title: 'Fuzzing APIs', path: '/docs/api-reference/fuzzing-apis', description: 'Fuzzing harness generation APIs' },
        { title: 'Task Management', path: '/docs/api-reference/task-management', description: 'Analysis task APIs' }
      ]
    },
    {
      title: 'Architecture',
      icon: <Architecture />,
      items: [
        { title: 'System Architecture', path: '/docs/architecture/system-architecture', description: 'Overall system design' },
        { title: 'Component Overview', path: '/docs/architecture/components', description: 'System components and services' },
        { title: 'Data Flow', path: '/docs/architecture/data-flow', description: 'Data processing pipelines' },
        { title: 'Workflow Diagrams', path: '/docs/architecture/workflow-diagrams', description: 'Visual workflow documentation' },
        { title: 'Database Schema', path: '/docs/architecture/database-schema', description: 'Database design and relationships' }
      ]
    },
    {
      title: 'Security Features',
      icon: <Security />,
      items: [
        { title: 'AI-Powered Analysis', path: '/docs/security-features/ai-analysis', description: 'AI-enhanced security analysis' },
        { title: 'Vulnerability Detection', path: '/docs/security-features/vulnerability-detection', description: 'Automated vulnerability detection' },
        { title: 'Pattern Recognition', path: '/docs/security-features/pattern-recognition', description: 'Security pattern matching' },
        { title: 'Fuzzing Capabilities', path: '/docs/security-features/fuzzing', description: 'Intelligent fuzzing features' }
      ]
    },
    {
      title: 'Administration',
      icon: <Settings />,
      items: [
        { title: 'System Management', path: '/docs/administration/system-management', description: 'System administration guide' },
        { title: 'Database Administration', path: '/docs/administration/database', description: 'Database management' },
        { title: 'Performance Tuning', path: '/docs/administration/performance', description: 'Optimization and tuning' },
        { title: 'Troubleshooting', path: '/docs/administration/troubleshooting', description: 'Common issues and solutions' }
      ]
    },
    {
      title: 'Examples',
      icon: <Help />,
      items: [
        { title: 'Complete Analysis Workflow', path: '/docs/examples/complete-workflow', description: 'End-to-end analysis example' },
        { title: 'API Usage Examples', path: '/docs/examples/api-examples', description: 'Practical API usage' },
        { title: 'Fuzzing Campaign Setup', path: '/docs/examples/fuzzing-examples', description: 'Setting up fuzzing campaigns' },
        { title: 'Security Analysis Examples', path: '/docs/examples/security-examples', description: 'Security analysis workflows' }
      ]
    }
  ];

  // Load markdown content from API
  useEffect(() => {
    const loadMarkdown = async () => {
      setLoading(true);
      setError('');

      try {
        let docPath = location.pathname;
        
        // Default to overview if just /docs
        if (docPath === '/docs' || docPath === '/docs/') {
          docPath = 'README.md';
        } else {
          // Convert route path to file path
          docPath = docPath.replace('/docs/', '').replace(/\//g, '/');
        }

        try {
          // Try to fetch from API first
          const response = await axios.get(`/api/docs/${docPath}`);
          setMarkdownContent(response.data.content);
        } catch (apiError) {
          // Fallback to mock content if API fails
          console.warn('API failed, using fallback content:', apiError);
          const content = await getFallbackContent(docPath);
          setMarkdownContent(content);
        }
      } catch (err) {
        setError('Failed to load documentation content');
        console.error('Error loading markdown:', err);
      } finally {
        setLoading(false);
      }
    };

    loadMarkdown();
  }, [location.pathname]);

  // Fallback content for when API is not available
  const getFallbackContent = async (filePath: string): Promise<string> => {
    if (filePath.includes('README.md') || filePath === '') {
      return `# ShadowSeek Documentation Overview

## 🔍 Advanced Binary Security Analysis Platform

Welcome to the comprehensive documentation for ShadowSeek, an enterprise-grade AI-powered binary security analysis platform that transforms complex reverse engineering into accessible security insights.

---

## 🚀 **Quick Start**

New to ShadowSeek? Get up and running in minutes:

1. **[Installation Guide](/docs/getting-started/installation)** - Complete setup instructions
2. **[Quick Start Tutorial](/docs/getting-started/quick-start)** - Get started in 5 minutes
3. **[Basic Workflow](/docs/getting-started/basic-workflow)** - Complete 7-step analysis process

### 🔄 **Analysis Workflow Overview**

\`\`\`mermaid
flowchart TD
    A[Target Binary] --> B[Binary Analysis]
    B --> C[Function Decompilation]
    C --> D[AI Security Analysis]
    D --> E[Vulnerability Detection]
    E --> F[Fuzzing Harness Generation]
    style A fill:#00bcd4,stroke:#fff,color:#fff
    style B fill:#2196f3,stroke:#fff,color:#fff
    style C fill:#2196f3,stroke:#fff,color:#fff
    style D fill:#ff9800,stroke:#fff,color:#fff
    style E fill:#f44336,stroke:#fff,color:#fff
    style F fill:#81c784,stroke:#fff,color:#fff
\`\`\`

**[➤ See Complete Workflow Guide](/docs/getting-started/basic-workflow)** with detailed step-by-step instructions, examples, and pro tips.

### 🏗️ **ShadowSeek Platform Overview**

\`\`\`mermaid
flowchart TD
    BIN[Binary File] --> GHIDRA[Ghidra Decompilation]
    GHIDRA --> AI[AI Analysis]
    AI --> VULN[Vulnerability Detection]
    VULN --> HARNESS[Fuzzing Harness Generation]
    HARNESS --> EXT[External Fuzzing]
    VULN --> REPORT[Security Report]
    REPORT --> API[REST API]
    style BIN fill:#00bcd4,stroke:#fff,color:#fff
    style GHIDRA fill:#2196f3,stroke:#fff,color:#fff
    style AI fill:#ff9800,stroke:#fff,color:#fff
    style VULN fill:#f44336,stroke:#fff,color:#fff
    style HARNESS fill:#9c27b0,stroke:#fff,color:#fff
    style EXT fill:#81c784,stroke:#fff,color:#fff
    style REPORT fill:#607d8b,stroke:#fff,color:#fff
    style API fill:#ff9800,stroke:#fff,color:#fff
\`\`\`

---

## 📚 **Documentation Sections**

### 🏠 Getting Started
Essential guides to get you up and running:
- **[Installation Guide](/docs/getting-started/installation)** - Step-by-step installation
- **[Quick Start Tutorial](/docs/getting-started/quick-start)** - 5-minute getting started guide
- **[Basic Workflow](/docs/getting-started/basic-workflow)** - Understanding the analysis workflow

### 👤 User Guide
Comprehensive feature documentation:
- **[Dashboard Overview](/docs/user-guide/dashboard)** - Navigate the main dashboard
- **[Binary Analysis](/docs/user-guide/binary-analysis)** - Analyzing binary files
- **[Function Analysis](/docs/user-guide/function-analysis)** - Function decompilation and AI analysis
- **[Security Hub](/docs/user-guide/security-hub)** - Advanced vulnerability detection
- **[Fuzzing Dashboard](/docs/user-guide/fuzzing-dashboard)** - Generating fuzzing harnesses
- **[Configuration](/docs/user-guide/configuration)** - System and AI configuration

### 🔧 API Reference
Complete API documentation:
- **[REST API Overview](/docs/api-reference/rest-api)** - Complete API documentation
- **[Binary Management](/docs/api-reference/binary-management)** - Binary upload and management APIs
- **[Function Analysis](/docs/api-reference/function-analysis)** - Function decompilation APIs
- **[Security Analysis](/docs/api-reference/security-analysis)** - Security scanning APIs
- **[Fuzzing APIs](/docs/api-reference/fuzzing-apis)** - Fuzzing harness generation APIs
- **[Task Management](/docs/api-reference/task-management)** - Analysis task APIs

### 🏗️ Architecture
Technical system documentation:
- **[System Architecture](/docs/architecture/system-architecture)** - Overall system design
- **[Component Overview](/docs/architecture/components)** - System components and services
- **[Data Flow](/docs/architecture/data-flow)** - Data processing pipelines
- **[Workflow Diagrams](/docs/architecture/workflow-diagrams)** - Visual workflow documentation
- **[Database Schema](/docs/architecture/database-schema)** - Database design and relationships

### 🔐 Security Features
Advanced security capabilities:
- **[AI-Powered Analysis](/docs/security-features/ai-analysis)** - AI-enhanced security analysis
- **[Vulnerability Detection](/docs/security-features/vulnerability-detection)** - Automated vulnerability detection
- **[Pattern Recognition](/docs/security-features/pattern-recognition)** - Security pattern matching
- **[Fuzzing Capabilities](/docs/security-features/fuzzing)** - Intelligent fuzzing features

### ⚙️ Administration
System management guides:
- **[System Management](/docs/administration/system-management)** - System administration guide
- **[Database Administration](/docs/administration/database)** - Database management
- **[Performance Tuning](/docs/administration/performance)** - Optimization and tuning
- **[Troubleshooting](/docs/administration/troubleshooting)** - Common issues and solutions

### 📋 Examples
Practical usage examples:
- **[Complete Analysis Workflow](/docs/examples/complete-workflow)** - End-to-end analysis example
- **[API Usage Examples](/docs/examples/api-examples)** - Practical API usage
- **[Fuzzing Campaign Setup](/docs/examples/fuzzing-examples)** - Setting up fuzzing campaigns
- **[Security Analysis Examples](/docs/examples/security-examples)** - Security analysis workflows

---

## 🎯 **Platform Overview**

ShadowSeek is a production-ready enterprise security platform that transforms complex binary analysis into accessible security insights through AI-powered automation.

### **What ShadowSeek Does**
- **🧠 AI-Enhanced Analysis** - Intelligent function analysis with 93% confidence scoring
- **🔍 Vulnerability Detection** - Automated discovery of 75+ dangerous patterns  
- **🎯 Fuzzing Harness Generation** - Creates ready-to-use harnesses for external fuzzing tools
- **📊 Security Intelligence** - Comprehensive vulnerability reports and risk assessments

### **Why Choose ShadowSeek**
- **⚡ Fast Setup** - Get analyzing in under 5 minutes
- **🔧 Multi-Platform** - Support for PE, ELF, Mach-O, and more
- **🤖 AI-Powered** - Integration with leading AI providers (OpenAI, Claude, Local LLMs)
- **🔌 API-First** - Complete REST API for automation and integration

---

## 📖 **Documentation Features**

This documentation includes interactive examples, visual diagrams, professional syntax highlighting, and comprehensive cross-references. Explore detailed capabilities in each section:

- **[🔐 Security Features](/docs/security-features/ai-analysis)** - Advanced AI analysis and vulnerability detection
- **🔧 [API Reference](/docs/api-reference/rest-api)** - Complete REST API with 50+ endpoints
- **🏗️ [System Architecture](/docs/architecture/system-architecture)** - Technical design and components
- **🎯 [Fuzzing Capabilities](/docs/security-features/fuzzing)** - Multi-engine fuzzing support

---

## 🚀 **Popular Pages**

- **[Quick Start Tutorial](/docs/getting-started/quick-start)** - Get started in 5 minutes
- **[REST API Overview](/docs/api-reference/rest-api)** - Complete API documentation
- **[Security Analysis Examples](/docs/examples/security-examples)** - Security analysis workflows
- **[System Architecture](/docs/architecture/system-architecture)** - Technical architecture
- **[Troubleshooting Guide](/docs/administration/troubleshooting)** - Common issues and solutions

---

## 📞 **Getting Help**

Need assistance? We're here to help:

- **📧 Email**: [dev@shadowseek.security](mailto:dev@shadowseek.security)
- **👥 Team**: ShadowSeek Development Team
- **📚 Documentation**: Browse the complete guides above
- **🐛 Issues**: Report bugs and request features

---

**Ready to get started?** Begin with our **[Quick Start Tutorial](/docs/getting-started/quick-start)** and start analyzing binaries in just 5 minutes!`;
    }

    if (filePath.includes('quick-start')) {
      return `# Quick Start Guide

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

\`\`\`bash
# Clone repository
git clone https://github.com/shadowseek/shadowseek.git
cd shadowseek

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp env_template.txt .env
# Edit .env with your Ghidra path and API keys
\`\`\`

### 2. Setup Frontend

\`\`\`bash
# Install frontend dependencies
cd frontend
npm install
\`\`\`

### 3. Initialize Database

\`\`\`python
# Initialize database
from flask_app import create_app, db
app = create_app()
app.app_context().push()
db.create_all()
\`\`\`

---

## 🎯 First Binary Analysis

### 1. Start ShadowSeek

\`\`\`bash
# Terminal 1: Start backend
python run.py

# Terminal 2: Start frontend
cd frontend
npm start
\`\`\`

> **Access:** Open \`http://localhost:3000\` in your browser

### 2. Upload Your First Binary

1. **Click "Upload"** in the navigation bar
2. **Drag and drop** a binary file (exe, dll, so, etc.)
3. **Watch automatic analysis** begin immediately
4. **Wait for completion** (typically 2-5 minutes)

### 3. Explore Analysis Results

#### Sample API Response
\`\`\`json
{
  "success": true,
  "data": {
    "message": "AI analysis completed successfully",
    "function": {
      "id": 123,
      "name": "main",
      "address": "0x401000",
      "ai_summary": "This function serves as the main entry point...",
      "risk_score": 92.5,
      "is_analyzed": true,
      "ai_analyzed_at": "2024-01-15T10:20:00Z"
    }
  }
}
\`\`\`

#### Analysis Steps
1. **Navigate to Dashboard** - View your uploaded binary
2. **Click binary name** - Open detailed analysis
3. **Explore Functions tab** - See decompiled functions
4. **Try Security Analysis** - One-click vulnerability detection

---

## 🎉 Congratulations!

You've successfully set up ShadowSeek and are ready to start analyzing binaries!

### Next Steps
- Explore the **[Security Hub](/docs/user-guide/security-hub)** for vulnerability detection
- Check out **[API Examples](/docs/examples/api-examples)** for programmatic access
- Learn about **[Fuzzing Capabilities](/docs/security-features/fuzzing)** for advanced testing

---

*Ready to dive deeper? Continue with our comprehensive **[User Guide](/docs/user-guide/dashboard)** to explore all features.*`;
    }

    // Handle basic-workflow specifically
    if (filePath.includes('basic-workflow')) {
      return `# Basic Workflow Guide

## 🔄 Complete ShadowSeek Analysis Workflow

This guide walks you through the complete binary analysis workflow in ShadowSeek, from upload to vulnerability discovery and fuzzing harness generation.

---

## 📋 **Workflow Overview**

ShadowSeek provides a comprehensive analysis pipeline that transforms raw binaries into actionable security insights:

\`\`\`mermaid
flowchart TD
    A[Upload Binary] --> B[View Binary Details]
    B --> C[Decompile All Functions]
    C --> D[AI Explain All Functions]
    D --> E[AI Binary Analysis]
    E --> F[Security Analysis]
    F --> G[Fuzzing Harness Generation]
    
    style A fill:#00bcd4,stroke:#fff,color:#fff
    style G fill:#81c784,stroke:#fff,color:#fff
\`\`\`

---

## 🚀 **Step-by-Step Workflow**

### **Step 1: Upload Binary** 📤

1. Navigate to **Upload** in the main navigation
2. **Drag and drop** your binary file (PE, ELF, Mach-O, etc.)
3. **Wait for upload** completion and automatic processing to begin
4. **Monitor progress** in the task dashboard

\`\`\`bash
# Supported binary formats
- Windows PE (.exe, .dll)
- Linux ELF binaries
- macOS Mach-O binaries
- Additional formats via Ghidra
\`\`\`

### **Step 2: View Binary Details** 🔍

1. **Navigate to Dashboard** to see your uploaded binaries
2. **Click on the binary name** to open the Binary Details section
3. **Explore basic information**:
   - File metadata and properties
   - Architecture and platform details
   - Import/export tables
   - Section analysis

### **Step 3: Decompile All Functions** ⚙️

1. In the **Binary Details** page, navigate to the **Functions** tab
2. **Click "Decompile All"** to start comprehensive function analysis
3. **Monitor decompilation progress** in real-time
4. **Review decompiled functions** as they become available

\`\`\`json
{
  "status": "decompiling",
  "functions_total": 1247,
  "functions_completed": 856,
  "progress_percentage": 68.7
}
\`\`\`

### **Step 4: AI Explain All Functions** 🤖

1. Once decompilation completes, **click "AI Explain All"**
2. **Watch AI analysis progress** for each function
3. **Review AI-generated summaries** for function behavior
4. **Examine risk scores** and security assessments

#### Sample AI Function Analysis:
\`\`\`json
{
  "function_name": "validate_input",
  "ai_summary": "This function validates user input but contains a buffer overflow vulnerability. It copies user data without bounds checking, potentially allowing arbitrary code execution.",
  "risk_score": 92.5,
  "vulnerability_types": ["buffer_overflow", "input_validation"],
  "confidence": 94.2
}
\`\`\`

### **Step 5: AI Binary Analysis** 📊

1. **Click "AI Binary Analysis"** for comprehensive binary overview
2. **Review complete binary summary** including:
   - Overall security posture
   - Critical vulnerability summary
   - Attack surface analysis
   - Recommended security measures

#### Sample Binary Analysis Report:
\`\`\`json
{
  "binary_summary": "Network service daemon with multiple security vulnerabilities",
  "overall_risk_score": 87.3,
  "critical_vulnerabilities": 5,
  "high_vulnerabilities": 12,
  "attack_vectors": ["network", "file_system", "memory_corruption"],
  "recommendations": [
    "Implement input validation",
    "Add bounds checking",
    "Enable stack protection"
  ]
}
\`\`\`

### **Step 6: Security Analysis** 🔐

1. **Navigate to Security Analysis** section
2. **Review vulnerability findings**:
   - Dangerous function usage
   - Memory corruption risks
   - Input validation issues
   - Cryptographic weaknesses
3. **Examine evidence and recommendations**
4. **Export security reports** for further analysis

#### Security Analysis Results:
- **🔴 Critical**: Buffer overflows, arbitrary code execution
- **🟡 High**: Input validation, memory leaks
- **🟢 Medium**: Code quality, performance issues
- **📊 Metrics**: Risk scoring, confidence levels

### **Step 7: Fuzzing Harness Generation** 🎯

1. **Click on Fuzzing** in the main navigation
2. **Select target functions** for fuzzing
3. **Choose fuzzing engine**:
   - AFL++ (recommended)
   - LibFuzzer
   - Honggfuzz
   - AFL (classic)
4. **Generate harness code** automatically
5. **Download and execute** fuzzing campaigns

#### Sample Fuzzing Harness:
\`\`\`c
// Generated AFL++ harness for function: process_packet
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    
    // Call target function with fuzzed input
    process_packet((char*)data, size);
    return 0;
}
\`\`\`

---

## 🎯 **Complete Analysis Example**

Here's what a complete analysis workflow looks like:

### **Binary: network_service.exe**
1. **Upload**: 2.3MB Windows PE executable
2. **Analysis**: 1,247 functions identified
3. **Decompilation**: 100% complete in 3.2 minutes
4. **AI Analysis**: 94.2% confidence, 15 critical findings
5. **Security Scan**: 5 critical vulnerabilities discovered
6. **Fuzzing**: 3 harnesses generated for high-risk functions

### **Key Findings**:
- **Buffer overflow** in packet processing function
- **SQL injection** vulnerability in database interface
- **Path traversal** in file handling routines
- **Memory corruption** in string processing

### **Next Steps**:
- **Patch vulnerabilities** using provided recommendations
- **Run fuzzing campaigns** to discover additional issues
- **Monitor results** and iterate on security improvements

---

## 🚀 **Pro Tips**

### **Efficient Analysis**
- **Start with critical functions** identified by AI analysis
- **Focus on high-risk scores** (>80) for immediate attention
- **Use parallel processing** for large binaries

### **Security Focus**
- **Prioritize network-facing functions** for security analysis
- **Pay attention to user input handling** routines
- **Review cryptographic implementations** carefully

### **Fuzzing Strategy**
- **Target functions with complex input parsing**
- **Focus on network protocol handlers**
- **Generate multiple harnesses** for comprehensive coverage

---

## 🚀 Platform Capabilities

### 🔄 Analysis Workflow Overview

\`\`\`mermaid
flowchart TD
    A[Target Binary] --> B[Binary Analysis]
    B --> C[Function Decompilation]
    C --> D[AI Security Analysis]
    D --> E[Vulnerability Detection]
    E --> F[Fuzzing Harness Generation]
    style A fill:#00bcd4,stroke:#fff,color:#fff
    style B fill:#2196f3,stroke:#fff,color:#fff
    style C fill:#2196f3,stroke:#fff,color:#fff
    style D fill:#ff9800,stroke:#fff,color:#fff
    style E fill:#f44336,stroke:#fff,color:#fff
    style F fill:#81c784,stroke:#fff,color:#fff
\`\`\`

### Binary Analysis Engine

---

## 📞 **Need Help?**

- **📧 Support**: [dev@shadowseek.security](mailto:dev@shadowseek.security)
- **📚 Detailed Guides**: Check the User Guide section
- **🔧 API Documentation**: See API Reference for automation
- **💬 Community**: Join our security researcher community

---

**Ready to start analyzing?** Upload your first binary and follow this workflow to discover security vulnerabilities and generate comprehensive fuzzing harnesses! 🎉`;
    }

    // Default content for pages that don't have specific content yet
    return `# ${filePath.replace('.md', '').replace(/\//g, ' > ')}

This documentation page is being developed. Please check back soon for complete content.

## 📋 Available Documentation

Navigate through the sidebar to explore:

- **Getting Started** - Installation and quick start guides
- **User Guide** - Comprehensive feature documentation
- **API Reference** - Complete REST API documentation
- **Architecture** - Technical system architecture
- **Security Features** - AI-powered security capabilities
- **Administration** - System management guides
- **Examples** - Practical usage examples

## 📞 Support

For technical support:
- Email: dev@shadowseek.security
- Team: ShadowSeek Development Team`;
  };

  const handleSectionToggle = (sectionKey: string) => {
    setExpandedSections(prev => ({
      ...prev,
      [sectionKey]: !prev[sectionKey]
    }));
  };

  const handleNavigate = (path: string) => {
    navigate(path);
  };

  const getCurrentPageInfo = () => {
    const path = location.pathname;
    for (const section of docSections) {
      for (const item of section.items) {
        if (item.path === path) {
          return { section: section.title, item };
        }
      }
    }
    return { section: 'Getting Started', item: { title: 'Overview', path: '/docs', description: 'ShadowSeek Documentation Overview' } };
  };

  const { section, item } = getCurrentPageInfo();

  return (
    <Container maxWidth="xl" sx={{ mt: 3, mb: 6 }}>
      <Grid container spacing={3}>
        {/* Sidebar Navigation */}
        <Grid item xs={12} md={3}>
          <Paper sx={{ p: 2, position: 'sticky', top: 16 }}>
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Description />
                Documentation
              </Typography>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <Chip 
                  label="v1.0.0" 
                  size="small" 
                  color="primary" 
                  sx={{ mr: 1 }}
                />
                <Tooltip title="Download Documentation">
                  <IconButton size="small">
                    <Download />
                  </IconButton>
                </Tooltip>
                <Tooltip title="View on GitHub">
                  <IconButton size="small">
                    <GitHub />
                  </IconButton>
                </Tooltip>
              </Box>
              
              {/* Quick Overview Link */}
              <Box sx={{ 
                p: 2, 
                backgroundColor: '#2a2a2a', 
                borderRadius: '8px',
                border: '1px solid #00bcd4',
                mb: 2
              }}>
                                 <Link
                   href="/docs"
                   onClick={(e) => {
                     e.preventDefault();
                     handleNavigate('/docs');
                   }}
                   sx={{
                     display: 'flex',
                     alignItems: 'center',
                     gap: 1,
                     color: '#00bcd4',
                     textDecoration: 'none',
                     fontWeight: 600,
                     fontSize: '0.9rem',
                     '&:hover': {
                       color: '#00acc1',
                       textDecoration: 'underline'
                     }
                   }}
                 >
                   <Home fontSize="small" />
                   📖 Overview
                 </Link>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.5 }}>
                  Start here for complete platform overview
                </Typography>
              </Box>
            </Box>

            <List dense>
              {docSections.map((section, sectionIndex) => {
                const sectionKey = section.title.toLowerCase().replace(/\s+/g, '-');
                const isExpanded = expandedSections[sectionKey];

                return (
                  <React.Fragment key={sectionIndex}>
                    <ListItem disablePadding>
                      <ListItemButton onClick={() => handleSectionToggle(sectionKey)}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mr: 1 }}>
                          {section.icon}
                        </Box>
                        <ListItemText 
                          primary={section.title}
                          primaryTypographyProps={{ variant: 'subtitle2', fontWeight: 600 }}
                        />
                        {isExpanded ? <ExpandLess /> : <ExpandMore />}
                      </ListItemButton>
                    </ListItem>
                    <Collapse in={isExpanded} timeout="auto" unmountOnExit>
                      <List component="div" dense>
                        {section.items.map((docItem, itemIndex) => (
                          <ListItem key={itemIndex} disablePadding>
                            <ListItemButton 
                              sx={{ pl: 4 }}
                              selected={location.pathname === docItem.path}
                              onClick={() => handleNavigate(docItem.path)}
                            >
                              <ListItemText 
                                primary={docItem.title}
                                primaryTypographyProps={{ variant: 'body2' }}
                              />
                            </ListItemButton>
                          </ListItem>
                        ))}
                      </List>
                    </Collapse>
                    {sectionIndex < docSections.length - 1 && <Divider sx={{ my: 1 }} />}
                  </React.Fragment>
                );
              })}
            </List>
          </Paper>
        </Grid>

        {/* Main Content */}
        <Grid item xs={12} md={9}>
          <Paper sx={{ p: 4 }}>
            {/* Breadcrumbs */}
            <Breadcrumbs separator={<NavigateNext fontSize="small" />} sx={{ mb: 3 }}>
              <Link
                color="inherit"
                href="/docs"
                onClick={(e) => {
                  e.preventDefault();
                  handleNavigate('/docs');
                }}
                sx={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  cursor: 'pointer',
                  textDecoration: 'none',
                  '&:hover': {
                    color: '#00bcd4',
                    textDecoration: 'underline'
                  }
                }}
              >
                <Home sx={{ mr: 0.5 }} fontSize="inherit" />
                Overview
              </Link>
              {section !== 'Getting Started' && (
                <Typography color="text.primary">{section}</Typography>
              )}
              {item.title !== 'Overview' && (
                <Typography color="text.primary">{item.title}</Typography>
              )}
            </Breadcrumbs>

            {/* Page Header */}
            <Box sx={{ mb: 4 }}>
              <Typography variant="h4" gutterBottom>
                {item.title}
              </Typography>
              {item.description && (
                <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
                  {item.description}
                </Typography>
              )}
            </Box>

            {/* Content */}
            {loading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
                <CircularProgress />
              </Box>
            ) : error ? (
              <Alert severity="error" sx={{ mb: 3 }}>
                {error}
              </Alert>
            ) : (
              <Box
                sx={{
                  '& h1': { 
                    mt: 4, 
                    mb: 3, 
                    fontSize: '2rem', 
                    fontWeight: 700,
                    color: '#00bcd4',
                    borderBottom: '3px solid #00bcd4',
                    paddingBottom: '8px'
                  },
                  '& h2': { 
                    mt: 3, 
                    mb: 2, 
                    fontSize: '1.5rem', 
                    fontWeight: 700,
                    color: '#00bcd4',
                    borderBottom: '2px solid #444',
                    paddingBottom: '6px'
                  },
                  '& h3': { 
                    mt: 2, 
                    mb: 1, 
                    fontSize: '1.25rem', 
                    fontWeight: 600,
                    color: '#81c784'
                  },
                  '& h4': { 
                    mt: 2, 
                    mb: 1, 
                    fontSize: '1.1rem', 
                    fontWeight: 600,
                    color: '#ffb74d'
                  },
                  '& p': { mb: 2, lineHeight: 1.7 },
                  '& ul, & ol': { mb: 2, pl: 3 },
                  '& li': { mb: 0.5 },
                  '& pre': {
                    backgroundColor: '#1a1a1a',
                    padding: 2,
                    borderRadius: 2,
                    overflow: 'auto',
                    mb: 3,
                    border: '1px solid #333',
                    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
                  },
                  '& code': {
                    backgroundColor: '#2a2a2a',
                    color: '#00bcd4',
                    padding: '3px 8px',
                    borderRadius: '6px',
                    fontSize: '0.9em',
                    fontFamily: 'Consolas, Monaco, "Courier New", monospace',
                    fontWeight: 500,
                    border: '1px solid #444',
                    boxShadow: '0 1px 3px rgba(0, 0, 0, 0.2)'
                  },
                  '& pre code': {
                    backgroundColor: 'transparent',
                    padding: 0,
                    border: 'none',
                    boxShadow: 'none',
                    color: 'inherit'
                  },
                  '& blockquote': {
                    borderLeft: '4px solid #00bcd4',
                    pl: 3,
                    ml: 0,
                    fontStyle: 'italic',
                    backgroundColor: 'rgba(0, 188, 212, 0.08)',
                    py: 2,
                    pr: 2,
                    borderRadius: '0 8px 8px 0',
                    boxShadow: '0 2px 8px rgba(0, 188, 212, 0.1)',
                    mb: 3
                  },
                  '& table': {
                    width: '100%',
                    borderCollapse: 'collapse',
                    mb: 3,
                    backgroundColor: '#1a1a1a',
                    border: '1px solid #333',
                    borderRadius: '8px',
                    overflow: 'hidden',
                    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
                  },
                  '& th, & td': {
                    border: '1px solid #333',
                    padding: '12px 16px',
                    textAlign: 'left'
                  },
                  '& th': {
                    backgroundColor: '#2a2a2a',
                    fontWeight: 700,
                    color: '#00bcd4',
                    borderBottom: '2px solid #00bcd4'
                  },
                  '& td': {
                    backgroundColor: '#1a1a1a'
                  },
                  '& tr:nth-of-type(even) td': {
                    backgroundColor: '#222'
                  }
                }}
              >
                <ReactMarkdown
                  remarkPlugins={[remarkGfm, remarkBreaks]}
                  rehypePlugins={[rehypeRaw]}
                  components={{
                    code({node, inline, className, children, ...props}) {
                      const match = /language-(\w+)/.exec(className || '');
                      const language = match?.[1];
                      
                      // Handle mermaid blocks specially - render actual diagrams
                      if (language === 'mermaid') {
                        return <MermaidDiagram chart={String(children).replace(/\n$/, '')} />;
                      }
                      
                      // Handle other code blocks with proper syntax highlighting
                      if (!inline && language) {
                        return (
                          <Paper sx={{ 
                            mb: 3, 
                            backgroundColor: '#1a1a1a', 
                            overflow: 'hidden',
                            border: '1px solid #333',
                            borderRadius: '8px',
                            boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)'
                          }}>
                            <Box sx={{ 
                              px: 2, 
                              py: 1, 
                              backgroundColor: '#2a2a2a', 
                              borderBottom: '1px solid #444',
                              display: 'flex',
                              alignItems: 'center',
                              gap: 1
                            }}>
                              <Box sx={{ 
                                display: 'flex', 
                                gap: 0.5,
                                mr: 1
                              }}>
                                <Box sx={{ 
                                  width: 8, 
                                  height: 8, 
                                  borderRadius: '50%', 
                                  backgroundColor: '#ff5f57' 
                                }} />
                                <Box sx={{ 
                                  width: 8, 
                                  height: 8, 
                                  borderRadius: '50%', 
                                  backgroundColor: '#ffbd2e' 
                                }} />
                                <Box sx={{ 
                                  width: 8, 
                                  height: 8, 
                                  borderRadius: '50%', 
                                  backgroundColor: '#28ca42' 
                                }} />
                              </Box>
                              <Typography variant="caption" sx={{ 
                                color: '#00bcd4', 
                                textTransform: 'uppercase', 
                                fontWeight: 700,
                                letterSpacing: '0.5px'
                              }}>
                                {language}
                              </Typography>
                            </Box>
                            <Box sx={{ 
                              position: 'relative',
                              '& pre': { 
                                margin: 0, 
                                padding: '16px !important', 
                                backgroundColor: '#1a1a1a !important' 
                              }
                            }}>
                              <SyntaxHighlighter
                                language={language}
                                style={{
                                  'hljs': {
                                    background: '#1a1a1a',
                                    color: '#e6e6e6',
                                    fontSize: '0.875rem',
                                    padding: '16px',
                                    borderRadius: '4px'
                                  },
                                  'hljs-keyword': { color: '#00bcd4', fontWeight: 'bold' },
                                  'hljs-string': { color: '#81c784' },
                                  'hljs-number': { color: '#ffb74d' },
                                  'hljs-literal': { color: '#ff8a65' },
                                  'hljs-built_in': { color: '#64b5f6' },
                                  'hljs-function': { color: '#ba68c8' },
                                  'hljs-variable': { color: '#fff176' },
                                  'hljs-comment': { color: '#757575', fontStyle: 'italic' },
                                  'hljs-attr': { color: '#4fc3f7' },
                                  'hljs-title': { color: '#00bcd4', fontWeight: 'bold' },
                                  'hljs-type': { color: '#81c784' },
                                  'hljs-meta': { color: '#ff8a65' },
                                  'hljs-tag': { color: '#ff8a65' },
                                  'hljs-name': { color: '#ff8a65' },
                                  'hljs-selector-id': { color: '#00bcd4' },
                                  'hljs-selector-class': { color: '#81c784' },
                                  'hljs-regexp': { color: '#ffb74d' },
                                  'hljs-deletion': { color: '#f48fb1' },
                                  'hljs-addition': { color: '#81c784' },
                                  'hljs-quote': { color: '#81c784', fontStyle: 'italic' },
                                  'hljs-doctag': { color: '#00bcd4' },
                                  'hljs-section': { color: '#00bcd4', fontWeight: 'bold' },
                                  'hljs-link': { color: '#4fc3f7' },
                                  'hljs-subst': { color: '#e6e6e6' },
                                  'hljs-formula': { color: '#ffb74d' },
                                  'hljs-emphasis': { fontStyle: 'italic' },
                                  'hljs-strong': { fontWeight: 'bold' }
                                }}
                                customStyle={{
                                  backgroundColor: '#1a1a1a',
                                  padding: '16px',
                                  margin: 0,
                                  fontSize: '0.875rem',
                                  lineHeight: 1.6,
                                  borderRadius: '4px',
                                  border: '1px solid #333',
                                  overflow: 'auto'
                                }}
                                wrapLines={true}
                                wrapLongLines={true}
                              >
                                {String(children).replace(/\n$/, '')}
                              </SyntaxHighlighter>
                            </Box>
                          </Paper>
                        );
                      }
                      
                      // Inline code
                      return (
                        <Box
                          component="code"
                          sx={{
                            backgroundColor: '#2a2a2a',
                            color: '#00bcd4',
                            padding: '3px 8px',
                            borderRadius: '6px',
                            fontSize: '0.9em',
                            fontFamily: 'Consolas, Monaco, "Courier New", monospace',
                            fontWeight: 500,
                            border: '1px solid #444',
                            boxShadow: '0 1px 3px rgba(0, 0, 0, 0.2)'
                          }}
                          {...props}
                        >
                          {children}
                        </Box>
                      );
                    }
                  }}
                >
                  {markdownContent}
                </ReactMarkdown>
                
                {/* Back to Overview Navigation */}
                {location.pathname !== '/docs' && (
                  <Box sx={{ 
                    mt: 6, 
                    pt: 3, 
                    borderTop: '2px solid #333',
                    textAlign: 'center'
                  }}>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Need help with something else?
                    </Typography>
                    <Link
                      href="/docs"
                      onClick={(e) => {
                        e.preventDefault();
                        handleNavigate('/docs');
                      }}
                      sx={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: 1,
                        px: 3,
                        py: 1.5,
                        backgroundColor: '#00bcd4',
                        color: '#fff',
                        borderRadius: '8px',
                        textDecoration: 'none',
                        fontWeight: 600,
                        transition: 'all 0.2s ease',
                        '&:hover': {
                          backgroundColor: '#00acc1',
                          transform: 'translateY(-2px)',
                          boxShadow: '0 4px 12px rgba(0, 188, 212, 0.3)'
                        }
                      }}
                                         >
                       <Home fontSize="small" />
                       Back to Overview
                     </Link>
                  </Box>
                )}
              </Box>
            )}
          </Paper>
        </Grid>
      </Grid>
      
      {/* Floating Back to Top Button */}
      {showBackToTop && (
        <Box
          sx={{
            position: 'fixed',
            bottom: 24,
            right: 24,
            zIndex: 1000,
            display: 'flex',
            flexDirection: 'column',
            gap: 1
          }}
        >
          {/* Back to Overview */}
          <Link
            href="/docs"
            onClick={(e) => {
              e.preventDefault();
              handleNavigate('/docs');
            }}
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: 56,
              height: 56,
              backgroundColor: '#00bcd4',
              color: '#fff',
              borderRadius: '50%',
              textDecoration: 'none',
              boxShadow: '0 4px 12px rgba(0, 188, 212, 0.3)',
              transition: 'all 0.2s ease',
              '&:hover': {
                backgroundColor: '#00acc1',
                transform: 'scale(1.1)',
                boxShadow: '0 6px 20px rgba(0, 188, 212, 0.4)'
              }
            }}
          >
            <Home />
          </Link>
          
          {/* Back to Top */}
          <IconButton
            onClick={scrollToTop}
            sx={{
              width: 48,
              height: 48,
              backgroundColor: '#2a2a2a',
              color: '#00bcd4',
              border: '1px solid #00bcd4',
              boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
              transition: 'all 0.2s ease',
              '&:hover': {
                backgroundColor: '#00bcd4',
                color: '#fff',
                transform: 'scale(1.1)',
                boxShadow: '0 6px 20px rgba(0, 188, 212, 0.4)'
              }
            }}
          >
            <NavigateNext sx={{ transform: 'rotate(-90deg)' }} />
          </IconButton>
        </Box>
      )}
    </Container>
  );
};

export default DocumentationViewer; 