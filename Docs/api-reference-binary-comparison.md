# Binary Comparison APIs

## 🔄 **Binary Comparison**

### **Compare Two Binaries**
```http
POST /api/analysis/diff
```

**Request Body:**
```json
{
  "binary_id1": "uuid-of-first-binary",
  "binary_id2": "uuid-of-second-binary", 
  "diff_type": "simple",
  "performance_mode": "balanced"
}
```

**Parameters:**
- `binary_id1` (required): UUID of the first binary to compare
- `binary_id2` (required): UUID of the second binary to compare  
- `diff_type` (optional): Analysis type - `"simple"`, `"version_tracking"`, or `"structural_graph"` (default: `"simple"`)
- `performance_mode` (optional): Performance mode - `"speed"`, `"balanced"`, or `"accuracy"` (default: `"balanced"`)

**Response:**
```json
{
  "success": true,
  "task_id": "comparison-task-uuid",
  "binary_id1": "uuid-of-first-binary",
  "binary_id2": "uuid-of-second-binary",
  "diff_type": "simple",
  "performance_mode": "balanced",
  "status": "running",
  "message": "Binary comparison started successfully"
}
```

### **Get Comparison Results**
```http
GET /api/analysis/diff/{task_id}
```

**Response:**
```json
{
  "success": true,
  "task_id": "comparison-task-uuid",
  "status": "completed",
  "binary_names": {
    "binary1": "program_v1.exe",
    "binary2": "program_v2.exe"
  },
  "summary": {
    "functions_added": 12,
    "functions_deleted": 5,
    "functions_modified": 8,
    "match_percentage": 87.3
  },
  "markdown_report": "# Binary Comparison Report...",
  "execution_time": 145.7,
  "completed_at": "2024-01-15T10:30:00Z"
}
```

### **List Past Comparison Results**
```http
GET /api/analysis/results
```

**Query Parameters:**
- `limit` (optional): Maximum number of results (default: 50)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
  "results": [
    {
      "id": "result-uuid",
      "task_id": "comparison-task-uuid",
      "binary_names": {
        "binary1": "program_v1.exe", 
        "binary2": "program_v2.exe"
      },
      "success": true,
      "functions_added": 12,
      "functions_deleted": 5,
      "functions_modified": 8,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 25,
  "limit": 50,
  "offset": 0
}
```

### **Delete Comparison Result**
```http
DELETE /api/analysis/results/{result_id}
```

**Response:**
```json
{
  "success": true,
  "message": "Analysis result deleted successfully"
}
```

## **Performance Modes**

### **Speed Mode**
- Optimized for fast comparison (~5-15 minutes)
- Uses conservative analysis settings
- Lower memory usage
- Basic function matching

### **Balanced Mode** (Default)
- Good balance of speed and accuracy (~15-45 minutes)
- Standard analysis depth
- Recommended for most use cases

### **Accuracy Mode**
- Maximum analysis depth (~30-120 minutes)
- Comprehensive function analysis
- Higher memory usage
- Most detailed results

## **Diff Types**

### **Simple Diff**
- Basic function-level comparison
- Shows added, deleted, and modified functions
- Fast execution
- Good for version comparisons

### **Version Tracking Diff**
- Advanced version tracking
- Tracks function movements and renaming
- Better handling of refactored code

### **Structural Graph Diff**
- Deep structural analysis
- Call graph comparison
- Most comprehensive but slowest

## **Usage Examples**

### **Basic Comparison**
```bash
curl -X POST "http://localhost:5000/api/analysis/diff" \
     -H "Content-Type: application/json" \
     -d '{
       "binary_id1": "uuid1",
       "binary_id2": "uuid2",
       "performance_mode": "balanced"
     }'
```

### **Speed Comparison**
```bash
curl -X POST "http://localhost:5000/api/analysis/diff" \
     -H "Content-Type: application/json" \
     -d '{
       "binary_id1": "uuid1", 
       "binary_id2": "uuid2",
       "performance_mode": "speed",
       "diff_type": "simple"
     }'
```

### **Monitor Comparison Progress**
```bash
# Get task status
curl "http://localhost:5000/api/analysis/diff/{task_id}"

# List all past results  
curl "http://localhost:5000/api/analysis/results?limit=10"
``` 