# Data Management APIs

## 📥 **Data Management**

### **Import Existing Results**
```http
POST /api/import-results
```

**Description:** Import previously generated analysis results from the filesystem into the database. This endpoint scans the `uploads/diff_results` directory for existing ghidriff comparison results and imports them into the database so they appear in the "Past Results" section of the UI.

**Request Body:** None required

**Response:**
```json
{
  "success": true,
  "imported_count": 15,
  "failed_count": 2,
  "total_processed": 17,
  "results": [
    "✅ Imported: task-uuid-1",
    "✅ Imported: task-uuid-2", 
    "❌ Failed: task-uuid-3 - Invalid JSON format",
    "⚠️  Skipped: task-uuid-4 (already exists)"
  ]
}
```

**Response Fields:**
- `success` (boolean): Whether the import operation completed
- `imported_count` (number): Number of results successfully imported
- `failed_count` (number): Number of results that failed to import
- `total_processed` (number): Total number of items processed
- `results` (array): Detailed status for each processed item

## **Import Process**

### **Directory Structure**
The import process scans for results in two formats:

#### **Task-based Directories**
```
uploads/diff_results/
├── task-uuid-1/
│   ├── binary1-binary2.ghidriff.md
│   ├── ghidriff.log
│   └── json/
└── task-uuid-2/
    ├── binary1-binary2.ghidriff.md
    └── ghidriff.log
```

#### **Standalone JSON Files**
```
uploads/diff_results/
├── result1.json
├── result2.json
└── comparison_data.json
```

### **Data Extraction**
The import process extracts:
- **Binary Names**: From log files and markdown titles
- **Analysis Results**: From JSON files and markdown reports
- **Task Metadata**: Creation timestamps, execution times
- **Summary Data**: Function counts, match percentages

### **Database Integration**
Imported data is stored in:
- **AnalysisTask**: Task metadata and status
- **AnalysisResult**: Comparison results and reports
- **Binary**: Binary information (if not already present)

## **Usage Examples**

### **Basic Import**
```bash
# Import all existing results
curl -X POST "http://localhost:5000/api/import-results"
```

### **Check Import Status**
```python
import requests

# Trigger import
response = requests.post("http://localhost:5000/api/import-results")
result = response.json()

print(f"Imported: {result['imported_count']}")
print(f"Failed: {result['failed_count']}")
print(f"Total: {result['total_processed']}")

# Print detailed results
for item in result['results']:
    print(item)
```

### **Monitor Import Results**
```bash
# Run import and check specific results
curl -X POST "http://localhost:5000/api/import-results" | jq '
{
  summary: {
    imported: .imported_count,
    failed: .failed_count,
    total: .total_processed
  },
  successes: [.results[] | select(startswith("✅"))],
  failures: [.results[] | select(startswith("❌"))]
}'
```

## **Error Handling**

### **Common Import Errors**

#### **Invalid JSON Format**
```json
{
  "error": "❌ Failed: task-uuid-3 - Invalid JSON format",
  "description": "JSON file contains malformed data"
}
```

#### **Missing Binary Information**
```json
{
  "error": "❌ Failed: task-uuid-4 - Binary information not found",
  "description": "Could not extract binary names from logs or metadata"
}
```

#### **Database Conflicts**
```json
{
  "warning": "⚠️  Skipped: task-uuid-5 (already exists)",
  "description": "Result already exists in database"
}
```

### **Troubleshooting**

#### **Check File Permissions**
```bash
# Ensure the import directory is readable
ls -la uploads/diff_results/
```

#### **Validate JSON Files**
```bash
# Check JSON syntax
jq . uploads/diff_results/result.json
```

#### **Review Import Logs**
```bash
# Check Flask logs for detailed error messages
tail -f logs/flask_startup.log
```

## **Data Migration**

### **Bulk Data Import**
For large-scale data migration:

1. **Prepare Data Structure**
   ```bash
   # Organize files in expected structure
   mkdir -p uploads/diff_results
   ```

2. **Run Import**
   ```python
   import requests
   import time
   
   # Run import
   response = requests.post("http://localhost:5000/api/import-results")
   
   # Monitor progress
   while response.status_code == 202:  # Processing
       time.sleep(5)
       response = requests.get("http://localhost:5000/api/import-status")
   ```

3. **Verify Results**
   ```bash
   # Check database entries
   curl "http://localhost:5000/api/analysis/results?limit=100"
   ```

### **Data Validation**
After import, validate data integrity:

```python
import requests

# Get imported results
results = requests.get("http://localhost:5000/api/analysis/results")
data = results.json()

print(f"Total results in database: {data['total']}")

# Validate specific entries
for result in data['results'][:5]:
    print(f"✓ {result['binary_names']['binary1']} vs {result['binary_names']['binary2']}")
    print(f"  Functions: +{result['functions_added']} -{result['functions_deleted']} ~{result['functions_modified']}")
```

## **Performance Considerations**

### **Import Speed**
- **Small datasets** (< 100 results): ~30 seconds
- **Medium datasets** (100-500 results): ~2-5 minutes  
- **Large datasets** (> 500 results): ~5-15 minutes

### **Memory Usage**
- Each result consumes ~1-5MB memory during import
- Large markdown reports may require additional memory
- Consider running imports during low-usage periods

### **Disk Space**
- Original files are preserved during import
- Database entries add minimal additional space
- Consider archiving original files after successful import

## **Best Practices**

### **Before Import**
1. **Backup Database**: Create database backup before large imports
2. **Check Disk Space**: Ensure sufficient space for processing
3. **Review File Structure**: Verify files are in expected format

### **During Import**
1. **Monitor Progress**: Check import status and logs
2. **Handle Errors**: Address failures promptly
3. **Avoid Interruption**: Don't stop process mid-import

### **After Import**
1. **Validate Results**: Verify data integrity
2. **Update UI**: Refresh frontend to see new results
3. **Clean Up**: Archive or remove processed files if desired

### **Regular Maintenance**
```bash
# Periodic import of new results
curl -X POST "http://localhost:5000/api/import-results"

# Check for orphaned files
find uploads/diff_results -name "*.json" -mtime +30

# Database cleanup if needed
curl -X POST "http://localhost:5000/api/cleanup/orphaned-results"
``` 