# Task Management API

## ⚙️ Asynchronous Task Management & Monitoring API

The Task Management API provides comprehensive control over ShadowSeek's asynchronous operations including binary analysis, decompilation, AI analysis, security scanning, and fuzzing campaigns.

---

## 🌐 **Base Configuration**

**Base URL**: `http://localhost:5000/api`
**Content-Type**: `application/json`

---

## 📋 **Task Operations**

### **Get All Tasks**
```http
GET /api/tasks?status=running&task_type=decompile&page=1&per_page=20
```

Retrieve all tasks with filtering and pagination capabilities.

**Query Parameters:**
- `status` (string) - Filter by task status: queued, running, completed, failed, cancelled
- `task_type` (string) - Filter by task type: analyze, decompile, ai_explain, security_scan, fuzzing
- `binary_id` (string) - Filter by specific binary UUID
- `page` (integer) - Page number (default: 1)
- `per_page` (integer) - Items per page (default: 20, max: 100)
- `sort_by` (string) - Sort field: created_at, updated_at, priority (default: created_at)
- `sort_order` (string) - Sort order: asc, desc (default: desc)

**Response:**
```json
{
  "success": true,
  "data": {
    "tasks": [
      {
        "id": "task_decompile_456",
        "task_type": "bulk_decompile",
        "status": "running",
        "progress": 65.5,
        "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "binary_name": "example.exe",
        "created_at": "2024-01-15T10:30:00Z",
        "started_at": "2024-01-15T10:31:00Z",
        "estimated_completion": "2024-01-15T10:40:00Z",
        "priority": 3,
        "assigned_worker": "worker_node_2",
        "current_step": "Decompiling function parse_input",
        "total_steps": 42,
        "completed_steps": 28,
        "metadata": {
          "functions_total": 42,
          "functions_completed": 28,
          "functions_failed": 1,
          "average_time_per_function": 2.3
        }
      },
      {
        "id": "task_ai_explain_789",
        "task_type": "ai_explain",
        "status": "queued",
        "progress": 0.0,
        "binary_id": "b2c3d4e5-f6g7-8901-bcde-f234567890ab",
        "binary_name": "another.exe",
        "created_at": "2024-01-15T10:35:00Z",
        "started_at": null,
        "estimated_completion": "2024-01-15T10:45:00Z",
        "priority": 2,
        "assigned_worker": null,
        "queue_position": 3,
        "metadata": {
          "function_count": 15,
          "ai_provider": "openai",
          "analysis_focus": "security"
        }
      }
    ],
    "pagination": {
      "page": 1,
      "per_page": 20,
      "total": 8,
      "pages": 1,
      "has_next": false,
      "has_prev": false
    },
    "summary": {
      "total_tasks": 8,
      "by_status": {
        "queued": 2,
        "running": 3,
        "completed": 2,
        "failed": 1,
        "cancelled": 0
      },
      "by_type": {
        "analyze": 1,
        "decompile": 2,
        "ai_explain": 3,
        "security_scan": 1,
        "fuzzing": 1
      },
      "active_workers": 3,
      "queue_length": 2,
      "average_completion_time": "8.5 minutes"
    }
  },
  "message": "Tasks retrieved successfully",
  "timestamp": "2024-01-15T10:40:00Z"
}
```

### **Get Task Status**
```http
GET /api/tasks/{task_id}/status
```

Get detailed status information for a specific task.

**Path Parameters:**
- `task_id` (string) - Unique task identifier

**Response:**
```json
{
  "success": true,
  "data": {
    "task": {
      "id": "task_decompile_456",
      "task_type": "bulk_decompile",
      "status": "running",
      "progress": 72.5,
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "binary_name": "example.exe",
      "created_at": "2024-01-15T10:30:00Z",
      "started_at": "2024-01-15T10:31:00Z",
      "updated_at": "2024-01-15T10:42:00Z",
      "estimated_completion": "2024-01-15T10:40:00Z",
      "actual_completion": null,
      "priority": 3,
      "assigned_worker": "worker_node_2",
      "current_step": "Decompiling function process_data",
      "total_steps": 42,
      "completed_steps": 30,
      "failed_steps": 1,
      "duration": "00:11:30",
      "estimated_remaining": "00:03:15"
    },
    "progress_details": {
      "phase": "decompilation",
      "phase_progress": 72.5,
      "current_operation": "Analyzing function process_data",
      "operations_completed": 30,
      "operations_total": 42,
      "operations_failed": 1,
      "failure_details": [
        {
          "step": "decompile_corrupted_function",
          "error": "Decompilation timeout after 60 seconds",
          "function_name": "corrupted_function",
          "timestamp": "2024-01-15T10:38:00Z"
        }
      ]
    },
    "performance_metrics": {
      "cpu_usage": 85.2,
      "memory_usage": "1.2GB",
      "average_processing_time": 2.1,
      "throughput": "28 functions/minute",
      "efficiency_score": 8.5
    },
    "resource_usage": {
      "worker_node": "worker_node_2",
      "cpu_cores": 4,
      "memory_allocated": "4GB",
      "disk_usage": "150MB",
      "network_usage": "minimal"
    }
  },
  "message": "Task status retrieved",
  "timestamp": "2024-01-15T10:42:00Z"
}
```

### **Get Task Details**
```http
GET /api/tasks/{task_id}
```

Get comprehensive information about a task including logs and results.

**Response:**
```json
{
  "success": true,
  "data": {
    "task": {
      "id": "task_decompile_456",
      "task_type": "bulk_decompile",
      "status": "completed",
      "progress": 100.0,
      "binary_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      "binary_name": "example.exe",
      "created_at": "2024-01-15T10:30:00Z",
      "started_at": "2024-01-15T10:31:00Z",
      "completed_at": "2024-01-15T10:45:00Z",
      "duration": "00:14:30",
      "priority": 3,
      "assigned_worker": "worker_node_2",
      "total_steps": 42,
      "completed_steps": 41,
      "failed_steps": 1,
      "success_rate": 97.6
    },
    "results": {
      "functions_decompiled": 41,
      "functions_failed": 1,
      "average_decompilation_time": 2.1,
      "total_processing_time": "14.5 minutes",
      "decompilation_quality": {
        "high": 35,
        "medium": 5,
        "low": 1
      },
      "failed_functions": [
        {
          "function_name": "corrupted_function",
          "address": "0x405000",
          "error": "Decompilation timeout",
          "retry_count": 3
        }
      ]
    },
    "logs": [
      {
        "timestamp": "2024-01-15T10:31:00Z",
        "level": "INFO",
        "message": "Starting bulk decompilation for binary example.exe",
        "details": {
          "total_functions": 42,
          "worker_assigned": "worker_node_2"
        }
      },
      {
        "timestamp": "2024-01-15T10:31:15Z",
        "level": "INFO",
        "message": "Decompiled function main successfully",
        "details": {
          "function_address": "0x401000",
          "decompilation_time": 1.8,
          "quality": "high"
        }
      },
      {
        "timestamp": "2024-01-15T10:38:00Z",
        "level": "WARNING",
        "message": "Decompilation timeout for function corrupted_function",
        "details": {
          "function_address": "0x405000",
          "timeout": 60,
          "retry_count": 3
        }
      },
      {
        "timestamp": "2024-01-15T10:45:00Z",
        "level": "INFO",
        "message": "Bulk decompilation completed",
        "details": {
          "success_count": 41,
          "failure_count": 1,
          "total_duration": "14.5 minutes"
        }
      }
    ],
    "configuration": {
      "decompiler_timeout": 60,
      "max_retries": 3,
      "parallel_processing": true,
      "quality_threshold": "medium"
    }
  },
  "message": "Task details retrieved",
  "timestamp": "2024-01-15T10:50:00Z"
}
```

---

## 🎮 **Task Control Operations**

### **Cancel Task**
```http
POST /api/tasks/{task_id}/cancel
```

Cancel a running or queued task.

**Path Parameters:**
- `task_id` (string) - Unique task identifier

**Request Body (Optional):**
```json
{
  "reason": "User requested cancellation",
  "force": false,
  "cleanup": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "task": {
      "id": "task_decompile_456",
      "status": "cancelled",
      "cancelled_at": "2024-01-15T10:35:00Z",
      "cancellation_reason": "User requested cancellation"
    },
    "cleanup_actions": [
      "Stopped worker process",
      "Cleaned up temporary files",
      "Released allocated resources"
    ],
    "partial_results": {
      "functions_completed": 15,
      "functions_remaining": 27,
      "progress_saved": true
    }
  },
  "message": "Task cancelled successfully",
  "timestamp": "2024-01-15T10:35:00Z"
}
```

### **Retry Failed Task**
```http
POST /api/tasks/{task_id}/retry
```

Retry a failed task with optional configuration changes.

**Request Body (Optional):**
```json
{
  "retry_failed_steps_only": true,
  "increase_timeout": true,
  "change_priority": 4,
  "use_different_worker": true
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "original_task": {
      "id": "task_decompile_456",
      "status": "failed",
      "failed_at": "2024-01-15T10:30:00Z"
    },
    "new_task": {
      "id": "task_decompile_789",
      "status": "queued",
      "created_at": "2024-01-15T10:35:00Z",
      "priority": 4,
      "retry_of": "task_decompile_456"
    },
    "retry_configuration": {
      "retry_failed_steps_only": true,
      "timeout_increased": "60s -> 120s",
      "priority_changed": "3 -> 4",
      "steps_to_retry": 3
    }
  },
  "message": "Task retry queued",
  "timestamp": "2024-01-15T10:35:00Z"
}
```

### **Update Task Priority**
```http
PUT /api/tasks/{task_id}/priority
```

Update the priority of a queued task.

**Request Body:**
```json
{
  "priority": 5,
  "reason": "Critical security analysis required"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "task": {
      "id": "task_ai_explain_789",
      "old_priority": 2,
      "new_priority": 5,
      "old_queue_position": 8,
      "new_queue_position": 2,
      "updated_at": "2024-01-15T10:40:00Z"
    },
    "impact": {
      "queue_position_change": 6,
      "estimated_delay_reduction": "15 minutes"
    }
  },
  "message": "Task priority updated",
  "timestamp": "2024-01-15T10:40:00Z"
}
```

---

## 📊 **Task Analytics & Monitoring**

### **Get Task Statistics**
```http
GET /api/tasks/statistics?timeframe=24h&group_by=type
```

Get comprehensive task execution statistics.

**Query Parameters:**
- `timeframe` (string) - Time period: 1h, 24h, 7d, 30d (default: 24h)
- `group_by` (string) - Group results by: type, status, worker, binary (default: type)
- `include_failed` (boolean) - Include failed tasks in statistics (default: true)

**Response:**
```json
{
  "success": true,
  "data": {
    "timeframe": "24h",
    "summary": {
      "total_tasks": 156,
      "completed_tasks": 132,
      "failed_tasks": 8,
      "cancelled_tasks": 2,
      "active_tasks": 14,
      "success_rate": 89.7,
      "average_completion_time": "12.5 minutes",
      "total_processing_time": "32.5 hours"
    },
    "by_type": {
      "analyze": {
        "total": 45,
        "completed": 42,
        "failed": 2,
        "cancelled": 1,
        "success_rate": 93.3,
        "average_time": "8.2 minutes"
      },
      "decompile": {
        "total": 38,
        "completed": 35,
        "failed": 2,
        "cancelled": 1,
        "success_rate": 92.1,
        "average_time": "15.7 minutes"
      },
      "ai_explain": {
        "total": 42,
        "completed": 35,
        "failed": 3,
        "cancelled": 0,
        "success_rate": 90.5,
        "average_time": "5.3 minutes"
      },
      "security_scan": {
        "total": 18,
        "completed": 15,
        "failed": 1,
        "cancelled": 0,
        "success_rate": 94.4,
        "average_time": "18.2 minutes"
      },
      "fuzzing": {
        "total": 13,
        "completed": 5,
        "failed": 0,
        "cancelled": 0,
        "success_rate": 100.0,
        "average_time": "45.8 minutes"
      }
    },
    "performance_trends": {
      "completion_time_trend": "decreasing",
      "success_rate_trend": "stable",
      "queue_length_trend": "increasing",
      "worker_utilization": 78.5
    },
    "resource_usage": {
      "average_cpu_usage": 72.3,
      "average_memory_usage": "2.1GB",
      "peak_memory_usage": "3.8GB",
      "total_disk_usage": "15.6GB"
    }
  },
  "message": "Task statistics retrieved",
  "timestamp": "2024-01-15T10:45:00Z"
}
```

### **Get Worker Status**
```http
GET /api/workers/status
```

Get status of all worker nodes and their current tasks.

**Response:**
```json
{
  "success": true,
  "data": {
    "workers": [
      {
        "id": "worker_node_1",
        "status": "active",
        "last_heartbeat": "2024-01-15T10:44:30Z",
        "current_task": {
          "id": "task_ai_explain_123",
          "type": "ai_explain",
          "progress": 35.2,
          "started_at": "2024-01-15T10:30:00Z"
        },
        "capabilities": ["analyze", "decompile", "ai_explain"],
        "performance": {
          "cpu_usage": 82.5,
          "memory_usage": "2.8GB",
          "tasks_completed": 23,
          "average_task_time": "8.5 minutes",
          "success_rate": 95.7
        },
        "configuration": {
          "max_concurrent_tasks": 1,
          "supported_types": ["analyze", "decompile", "ai_explain"],
          "memory_limit": "4GB",
          "timeout_default": 300
        }
      },
      {
        "id": "worker_node_2",
        "status": "active",
        "last_heartbeat": "2024-01-15T10:44:45Z",
        "current_task": {
          "id": "task_security_scan_456",
          "type": "security_scan",
          "progress": 78.3,
          "started_at": "2024-01-15T10:25:00Z"
        },
        "capabilities": ["security_scan", "fuzzing"],
        "performance": {
          "cpu_usage": 91.2,
          "memory_usage": "3.2GB",
          "tasks_completed": 18,
          "average_task_time": "15.2 minutes",
          "success_rate": 94.4
        }
      },
      {
        "id": "worker_node_3",
        "status": "idle",
        "last_heartbeat": "2024-01-15T10:44:50Z",
        "current_task": null,
        "capabilities": ["analyze", "decompile", "ai_explain", "security_scan"],
        "performance": {
          "cpu_usage": 15.3,
          "memory_usage": "0.8GB",
          "tasks_completed": 31,
          "average_task_time": "9.8 minutes",
          "success_rate": 96.8
        }
      }
    ],
    "cluster_summary": {
      "total_workers": 3,
      "active_workers": 3,
      "idle_workers": 1,
      "offline_workers": 0,
      "total_capacity": 3,
      "current_utilization": 2,
      "utilization_percentage": 66.7
    }
  },
  "message": "Worker status retrieved",
  "timestamp": "2024-01-15T10:45:00Z"
}
```

---

## 🎯 **Queue Management**

### **Get Task Queue**
```http
GET /api/queue?priority_order=desc&limit=50
```

Get current task queue with priority ordering.

**Query Parameters:**
- `priority_order` (string) - Order by priority: asc, desc (default: desc)
- `limit` (integer) - Maximum tasks to return (default: 50)
- `task_type` (string) - Filter by task type
- `estimated_time` (boolean) - Include estimated completion times (default: true)

**Response:**
```json
{
  "success": true,
  "data": {
    "queue": [
      {
        "id": "task_security_scan_789",
        "task_type": "security_scan",
        "priority": 5,
        "queue_position": 1,
        "binary_name": "critical_app.exe",
        "created_at": "2024-01-15T10:40:00Z",
        "estimated_start": "2024-01-15T10:47:00Z",
        "estimated_completion": "2024-01-15T11:05:00Z",
        "estimated_duration": "18 minutes",
        "required_worker_type": "security_scan"
      },
      {
        "id": "task_ai_explain_101",
        "task_type": "ai_explain",
        "priority": 4,
        "queue_position": 2,
        "binary_name": "analyze_me.exe",
        "created_at": "2024-01-15T10:35:00Z",
        "estimated_start": "2024-01-15T10:50:00Z",
        "estimated_completion": "2024-01-15T10:55:00Z",
        "estimated_duration": "5 minutes",
        "required_worker_type": "ai_explain"
      }
    ],
    "queue_summary": {
      "total_queued": 8,
      "by_priority": {
        "5": 2,
        "4": 1,
        "3": 3,
        "2": 1,
        "1": 1
      },
      "by_type": {
        "security_scan": 2,
        "ai_explain": 3,
        "decompile": 2,
        "fuzzing": 1
      },
      "estimated_queue_duration": "1 hour 25 minutes",
      "next_available_slot": "2024-01-15T10:47:00Z"
    }
  },
  "message": "Task queue retrieved",
  "timestamp": "2024-01-15T10:45:00Z"
}
```

### **Clear Task Queue**
```http
POST /api/queue/clear
```

Clear all queued tasks (running tasks are not affected).

**Request Body (Optional):**
```json
{
  "task_types": ["ai_explain", "decompile"],
  "priority_threshold": 3,
  "older_than": "2024-01-15T09:00:00Z",
  "reason": "System maintenance"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "cleared_tasks": 5,
    "affected_task_types": ["ai_explain", "decompile"],
    "running_tasks_preserved": 3,
    "cleared_task_ids": [
      "task_ai_explain_101",
      "task_decompile_202",
      "task_ai_explain_303"
    ]
  },
  "message": "Task queue cleared",
  "timestamp": "2024-01-15T10:50:00Z"
}
```

---

## 🔧 **Advanced Task Operations**

### **Bulk Task Operations**
```http
POST /api/tasks/bulk-action
```

Perform bulk operations on multiple tasks.

**Request Body:**
```json
{
  "action": "cancel",
  "task_ids": [
    "task_ai_explain_101",
    "task_decompile_202",
    "task_security_scan_303"
  ],
  "reason": "System maintenance scheduled",
  "force": false
}
```

**Actions Available:**
- `cancel` - Cancel multiple tasks
- `retry` - Retry multiple failed tasks
- `priority` - Update priority for multiple tasks
- `delete` - Delete completed/failed tasks

**Response:**
```json
{
  "success": true,
  "data": {
    "action": "cancel",
    "total_tasks": 3,
    "successful_actions": 2,
    "failed_actions": 1,
    "results": [
      {
        "task_id": "task_ai_explain_101",
        "status": "cancelled",
        "success": true
      },
      {
        "task_id": "task_decompile_202",
        "status": "cancelled",
        "success": true
      },
      {
        "task_id": "task_security_scan_303",
        "status": "running",
        "success": false,
        "error": "Cannot cancel running task without force flag"
      }
    ]
  },
  "message": "Bulk action completed",
  "timestamp": "2024-01-15T10:55:00Z"
}
```

### **Task Templates**
```http
GET /api/tasks/templates
```

Get available task templates for common operations.

**Response:**
```json
{
  "success": true,
  "data": {
    "templates": [
      {
        "id": "comprehensive_analysis",
        "name": "Comprehensive Binary Analysis",
        "description": "Complete analysis workflow including decompilation, AI analysis, and security scanning",
        "task_sequence": [
          {
            "type": "analyze",
            "priority": 3,
            "config": {"deep_analysis": true}
          },
          {
            "type": "decompile",
            "priority": 3,
            "config": {"exclude_external": true},
            "depends_on": ["analyze"]
          },
          {
            "type": "ai_explain",
            "priority": 2,
            "config": {"analysis_focus": "security"},
            "depends_on": ["decompile"]
          },
          {
            "type": "security_scan",
            "priority": 4,
            "config": {"ai_enabled": true},
            "depends_on": ["ai_explain"]
          }
        ],
        "estimated_duration": "25-35 minutes"
      },
      {
        "id": "quick_security_scan",
        "name": "Quick Security Assessment",
        "description": "Fast security scanning for immediate threat assessment",
        "task_sequence": [
          {
            "type": "analyze",
            "priority": 4,
            "config": {"quick_mode": true}
          },
          {
            "type": "security_scan",
            "priority": 5,
            "config": {"pattern_only": true},
            "depends_on": ["analyze"]
          }
        ],
        "estimated_duration": "5-8 minutes"
      }
    ]
  },
  "message": "Task templates retrieved",
  "timestamp": "2024-01-15T11:00:00Z"
}
```

---

## 💡 **Task Management Examples**

### **Complete Task Monitoring Script**
```python
import requests
import time
import json

class TaskMonitor:
    def __init__(self, api_base="http://localhost:5000/api"):
        self.api_base = api_base
    
    def create_analysis_workflow(self, binary_id):
        """Create comprehensive analysis workflow"""
        
        # Step 1: Start binary analysis
        analyze_response = requests.post(
            f"{self.api_base}/binaries/{binary_id}/analyze"
        )
        
        if analyze_response.status_code == 200:
            analyze_task = analyze_response.json()['data']['task']
            
            # Step 2: Wait for analysis completion
            if self.wait_for_completion(analyze_task['id']):
                
                # Step 3: Start decompilation
                decompile_response = requests.post(
                    f"{self.api_base}/binaries/{binary_id}/decompile-all"
                )
                
                if decompile_response.status_code == 200:
                    decompile_task = decompile_response.json()['data']['task']
                    
                    # Step 4: Wait for decompilation
                    if self.wait_for_completion(decompile_task['id']):
                        
                        # Step 5: Start AI analysis
                        ai_response = requests.post(
                            f"{self.api_base}/binaries/{binary_id}/ai-explain-all"
                        )
                        
                        if ai_response.status_code == 200:
                            ai_task = ai_response.json()['data']['task']
                            
                            # Step 6: Wait for AI analysis
                            if self.wait_for_completion(ai_task['id']):
                                
                                # Step 7: Start security scan
                                security_response = requests.post(
                                    f"{self.api_base}/binaries/{binary_id}/security-analysis"
                                )
                                
                                if security_response.status_code == 200:
                                    security_task = security_response.json()['data']['task']
                                    return self.wait_for_completion(security_task['id'])
        
        return False
    
    def wait_for_completion(self, task_id, timeout=3600):
        """Wait for task completion with progress monitoring"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            response = requests.get(f"{self.api_base}/tasks/{task_id}/status")
            
            if response.status_code == 200:
                task_data = response.json()['data']['task']
                
                print(f"Task {task_id}: {task_data['status']} - {task_data['progress']:.1f}%")
                
                if task_data['current_step']:
                    print(f"  Current: {task_data['current_step']}")
                
                if task_data['status'] == 'completed':
                    print(f"✓ Task {task_id} completed successfully")
                    return True
                elif task_data['status'] == 'failed':
                    print(f"✗ Task {task_id} failed")
                    return False
                elif task_data['status'] == 'cancelled':
                    print(f"⚠ Task {task_id} was cancelled")
                    return False
            
            time.sleep(30)
        
        print(f"⏱ Task {task_id} timed out after {timeout} seconds")
        return False
    
    def get_task_summary(self):
        """Get summary of all tasks"""
        response = requests.get(f"{self.api_base}/tasks/statistics")
        
        if response.status_code == 200:
            stats = response.json()['data']
            
            print("Task Summary:")
            print(f"  Total Tasks: {stats['summary']['total_tasks']}")
            print(f"  Completed: {stats['summary']['completed_tasks']}")
            print(f"  Failed: {stats['summary']['failed_tasks']}")
            print(f"  Success Rate: {stats['summary']['success_rate']:.1f}%")
            print(f"  Average Time: {stats['summary']['average_completion_time']}")
            
            return stats
        return None
    
    def monitor_queue(self):
        """Monitor task queue status"""
        response = requests.get(f"{self.api_base}/queue")
        
        if response.status_code == 200:
            queue_data = response.json()['data']
            
            print("Queue Status:")
            print(f"  Queued Tasks: {queue_data['queue_summary']['total_queued']}")
            print(f"  Estimated Duration: {queue_data['queue_summary']['estimated_queue_duration']}")
            
            if queue_data['queue']:
                print("  Next Tasks:")
                for task in queue_data['queue'][:5]:
                    print(f"    {task['task_type']} - Priority {task['priority']} - {task['binary_name']}")
            
            return queue_data
        return None
    
    def cleanup_completed_tasks(self, older_than_hours=24):
        """Clean up old completed tasks"""
        from datetime import datetime, timedelta
        
        cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
        
        # Get all completed tasks
        response = requests.get(
            f"{self.api_base}/tasks",
            params={"status": "completed,failed", "per_page": 100}
        )
        
        if response.status_code == 200:
            tasks = response.json()['data']['tasks']
            
            old_tasks = []
            for task in tasks:
                task_time = datetime.fromisoformat(task['created_at'].replace('Z', '+00:00'))
                if task_time < cutoff_time:
                    old_tasks.append(task['id'])
            
            if old_tasks:
                # Bulk delete old tasks
                delete_response = requests.post(
                    f"{self.api_base}/tasks/bulk-action",
                    json={
                        "action": "delete",
                        "task_ids": old_tasks,
                        "reason": "Automated cleanup"
                    }
                )
                
                if delete_response.status_code == 200:
                    print(f"Cleaned up {len(old_tasks)} old tasks")
                    return True
        
        return False

# Usage example
if __name__ == "__main__":
    monitor = TaskMonitor()
    
    # Monitor current queue
    monitor.monitor_queue()
    
    # Get task summary
    monitor.get_task_summary()
    
    # Create comprehensive analysis workflow
    binary_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    if monitor.create_analysis_workflow(binary_id):
        print("Analysis workflow completed successfully!")
    else:
        print("Analysis workflow failed")
    
    # Clean up old tasks
    monitor.cleanup_completed_tasks(older_than_hours=48)
```

---

## 🎯 **Best Practices**

### **Task Management Strategy**
1. **Priority Management**: Use priorities to ensure critical tasks run first
2. **Resource Monitoring**: Monitor worker utilization and adjust workload
3. **Queue Management**: Regularly clean up completed tasks to maintain performance
4. **Error Handling**: Implement retry logic for failed tasks

### **Performance Optimization**
1. **Batch Operations**: Use bulk operations for multiple tasks
2. **Worker Allocation**: Distribute tasks across available workers
3. **Timeout Management**: Set appropriate timeouts for different task types
4. **Resource Limits**: Configure memory and CPU limits appropriately

### **Monitoring & Maintenance**
1. **Regular Monitoring**: Check task statistics and worker health
2. **Automated Cleanup**: Implement automated cleanup of old tasks
3. **Performance Tracking**: Monitor trends in completion times and success rates
4. **Alert System**: Set up alerts for task failures or queue congestion

The Task Management API provides comprehensive control over ShadowSeek's asynchronous operations, enabling efficient orchestration of complex analysis workflows with real-time monitoring and robust error handling. 