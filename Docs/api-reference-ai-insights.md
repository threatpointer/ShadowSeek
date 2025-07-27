# AI-Powered Insights APIs

## 🤖 **AI-Powered Insights**

### **Get AI Insights for Binary Comparison**
```http
POST /api/ai/insights
```

**Request Body:**
```json
{
  "context": {
    "binary1": "program_v1.exe",
    "binary2": "program_v2.exe",
    "functionStats": {
      "total_funcs_len": 245,
      "total_changes": 25
    },
    "addedFunctions": 12,
    "deletedFunctions": 5,
    "modifiedFunctions": 8
  },
  "includeWebSearch": true,
  "searchQueries": [
    "program_v1.exe security vulnerabilities CVE",
    "program_v2.exe security vulnerabilities CVE", 
    "program_v1.exe program_v2.exe changelog release notes"
  ]
}
```

**Parameters:**
- `context` (required): Binary comparison context data
  - `binary1` (string): First binary name
  - `binary2` (string): Second binary name  
  - `functionStats` (object): Function statistics from comparison
  - `addedFunctions` (number): Number of functions added
  - `deletedFunctions` (number): Number of functions deleted
  - `modifiedFunctions` (number): Number of functions modified
- `includeWebSearch` (boolean): Enable web search for external intelligence
- `searchQueries` (array): Custom search queries for web research

**Response:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "binaryNames": {
    "binary1": "program_v1.exe",
    "binary2": "program_v2.exe"
  },
  "securityFindings": [
    {
      "title": "CVE-2024-1234 - Buffer Overflow in program_v1.exe",
      "description": "Critical buffer overflow vulnerability found in version 1.0",
      "severity": "high",
      "cveId": "CVE-2024-1234",
      "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    }
  ],
  "versionAnalysis": {
    "summary": "The transition shows expansion with 12 new functions added and 5 removed, suggesting feature enhancements.",
    "releaseNotes": [
      "Modified 8 existing functions for improvements or bug fixes",
      "Added 12 new functions for enhanced functionality", 
      "Removed 5 deprecated or unnecessary functions"
    ]
  },
  "researchLinks": [
    {
      "title": "Security Analysis of Program Updates",
      "description": "Research paper analyzing security improvements in program updates",
      "url": "https://example.com/research-paper"
    }
  ],
  "recommendations": [
    "🧪 TESTING FOCUS: With 12 new functions, conduct comprehensive integration testing",
    "🔄 REGRESSION TESTING: 8 functions modified. Perform thorough regression testing",
    "📚 DOCUMENTATION: Update user documentation to reflect functional changes"
  ]
}
```

## **Web Search Integration**

### **CVE Database Queries**
The AI insights service automatically searches:
- National Vulnerability Database (NVD)
- CVE databases
- Security advisories
- Vulnerability reports

### **Security Research**
Searches for:
- Academic research papers
- Security analysis reports
- Industry security studies
- Community vulnerability discussions

### **Version Intelligence**
Analyzes:
- Release notes and changelogs
- Version comparison reports
- Update documentation
- Migration guides

## **AI Analysis Features**

### **Security Intelligence**
- **CVE Detection**: Automatic identification of known vulnerabilities
- **Severity Assessment**: Risk classification (Critical, High, Medium, Low)
- **Impact Analysis**: Assessment of vulnerability impact on your environment

### **Version Analysis**
- **Change Summarization**: AI-generated summaries of binary changes
- **Release Notes Generation**: Automatic creation of version change documentation
- **Compatibility Assessment**: Analysis of breaking changes and compatibility impact

### **Smart Recommendations**
- **Testing Strategies**: Targeted testing recommendations based on changes
- **Security Actions**: Specific security measures for identified risks
- **Deployment Guidance**: Rollout strategies based on change analysis

## **Usage Examples**

### **Basic AI Insights**
```bash
curl -X POST "http://localhost:5000/api/ai/insights" \
     -H "Content-Type: application/json" \
     -d '{
       "context": {
         "binary1": "app_v1.exe",
         "binary2": "app_v2.exe",
         "addedFunctions": 5,
         "deletedFunctions": 2,
         "modifiedFunctions": 3
       },
       "includeWebSearch": false
     }'
```

### **AI Insights with Web Search**
```bash
curl -X POST "http://localhost:5000/api/ai/insights" \
     -H "Content-Type: application/json" \
     -d '{
       "context": {
         "binary1": "secure_app_v1.exe",
         "binary2": "secure_app_v2.exe",
         "functionStats": {
           "total_funcs_len": 156,
           "total_changes": 18
         },
         "addedFunctions": 8,
         "deletedFunctions": 3,
         "modifiedFunctions": 7
       },
       "includeWebSearch": true,
       "searchQueries": [
         "secure_app_v1.exe security vulnerabilities CVE",
         "secure_app_v2.exe changelog security fixes",
         "secure_app vulnerability reports 2024"
       ]
     }'
```

### **Custom Search Queries**
```python
import requests

# Targeted security research
response = requests.post("http://localhost:5000/api/ai/insights", json={
    "context": {
        "binary1": "crypto_lib_v2.1.dll",
        "binary2": "crypto_lib_v2.2.dll",
        "modifiedFunctions": 15
    },
    "includeWebSearch": True,
    "searchQueries": [
        "crypto_lib_v2.1 cryptographic vulnerabilities",
        "crypto_lib_v2.2 security improvements",
        "crypto_lib CVE database entries",
        "crypto_lib_v2 side-channel attacks"
    ]
})

insights = response.json()
```

## **Response Structure**

### **Security Findings**
Each security finding includes:
- **title**: Descriptive title of the security issue
- **description**: Detailed description of the vulnerability
- **severity**: Risk level (critical, high, medium, low)
- **cveId**: CVE identifier if available
- **source**: URL to original security advisory

### **Version Analysis**
- **summary**: AI-generated overview of changes between versions
- **releaseNotes**: Structured list of changes and improvements

### **Research Links**
- **title**: Title of the research resource
- **description**: Brief description of the content
- **url**: Link to the full resource

### **Recommendations**
Array of actionable recommendations including:
- Testing strategies
- Security measures
- Documentation updates
- Deployment considerations

## **Best Practices**

### **Query Optimization**
- Use specific binary names in search queries
- Include version numbers when available
- Target security-related keywords
- Limit to 3-5 focused queries for best performance

### **Context Enrichment**
- Provide detailed function statistics
- Include binary metadata when available
- Specify analysis scope and objectives

### **Result Interpretation**
- Prioritize high-severity security findings
- Review AI-generated recommendations carefully
- Validate external research links
- Consider context-specific factors in your environment 