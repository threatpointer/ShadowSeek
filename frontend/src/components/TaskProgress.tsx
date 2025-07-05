import React, { useState, useEffect } from 'react';
import {
  Box,
  LinearProgress,
  Typography,
  Paper,
  Chip,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemText,
  Collapse,
  CardContent,
  Alert,
  Divider,
  Pagination,
  Stack
} from '@mui/material';
import { 
  CheckCircle, 
  Error as ErrorIcon, 
  Pending, 
  HourglassEmpty,
  Cancel as CancelIcon,
  Refresh as RefreshIcon,
  ExpandMore,
  ExpandLess,
  Schedule,
  PlayArrow,
  Stop,
  Analytics,
  Memory,
  Security
} from '@mui/icons-material';
import { apiClient, AnalysisTask, getStatusColor } from '../utils/api';

interface TaskWithProgress extends AnalysisTask {
  expanded?: boolean;
}

interface TaskProgressProps {
  binaryId?: string;
  taskId?: string;
  showAll?: boolean;
  autoRefresh?: boolean;
  refreshIntervalMs?: number;
  onComplete?: (result: any) => void;
  showControls?: boolean;
  maxHeight?: number;
  compact?: boolean;
}

const TaskProgress: React.FC<TaskProgressProps> = ({
  binaryId,
  taskId,
  showAll = false,
  autoRefresh = true,
  refreshIntervalMs = 3000,
  onComplete,
  showControls = true,
  maxHeight = 500,
  compact = false
}) => {
  const [allTasks, setAllTasks] = useState<TaskWithProgress[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<{ [key: string]: boolean }>({});
  const [intervalId, setIntervalId] = useState<NodeJS.Timeout | null>(null);
  const [cancelDialogOpen, setCancelDialogOpen] = useState<boolean>(false);
  const [cancellingTaskId, setCancellingTaskId] = useState<string | null>(null);
  const [systemStatus, setSystemStatus] = useState<any>(null);
  
  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 15;

  const fetchTasks = async () => {
    try {
      setLoading(true);
      let fetchedTasks: AnalysisTask[] = [];

      // Fetch system status for overview
      try {
        const status = await apiClient.getSystemStatus();
        setSystemStatus(status);
      } catch (statusError) {
        console.warn('Could not fetch system status:', statusError);
      }

      if (taskId) {
        const task = await apiClient.getTaskStatus(taskId);
        fetchedTasks = [task];
        
        // If task is completed, call onComplete callback
        if (task.status === 'completed' && onComplete) {
          onComplete(task);
        }
      } else if (binaryId) {
        fetchedTasks = await apiClient.getBinaryTasks(binaryId);
      } else if (showAll) {
        fetchedTasks = await apiClient.getAllTasks();
      }

      // Sort tasks to show running/queued first, then by creation time (latest first)
      fetchedTasks.sort((a, b) => {
        const statusPriority = { 'running': 1, 'queued': 2, 'completed': 3, 'failed': 4, 'cancelled': 5 };
        const aPriority = statusPriority[a.status as keyof typeof statusPriority] || 6;
        const bPriority = statusPriority[b.status as keyof typeof statusPriority] || 6;
        
        if (aPriority !== bPriority) {
          return aPriority - bPriority;
        }
        
        // If same priority, sort by creation time (newest first)
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      });

      // Check if any tasks are still running
      const hasRunningTasks = fetchedTasks.some(
        task => task.status === 'running' || task.status === 'queued'
      );

      // If no running tasks and autoRefresh is enabled, clear the interval
      if (!hasRunningTasks && autoRefresh && intervalId) {
        clearInterval(intervalId);
        setIntervalId(null);
      }

      setAllTasks(fetchedTasks);
      
      // Reset to page 1 if current page is out of bounds
      const totalPages = Math.ceil(fetchedTasks.length / itemsPerPage);
      if (currentPage > totalPages && totalPages > 0) {
        setCurrentPage(1);
      }
      
      setError(null);
    } catch (err) {
      console.error('Error fetching tasks:', err);
      setError('Failed to fetch task status');
    } finally {
      setLoading(false);
    }
  };

  const handleToggleExpand = (taskId: string) => {
    setExpanded(prev => ({
      ...prev,
      [taskId]: !prev[taskId]
    }));
  };

  const handleCancelTask = async (taskIdToCancel: string) => {
    try {
      setCancellingTaskId(taskIdToCancel);
      await apiClient.cancelTask(taskIdToCancel);
      setCancelDialogOpen(false);
      // Refresh task status after cancellation
      fetchTasks();
    } catch (err) {
      console.error('Error cancelling task:', err);
      setError('Failed to cancel task');
    } finally {
      setCancellingTaskId(null);
    }
  };

  const handleCancelAllTasks = async () => {
    try {
      await apiClient.cancelAllTasks();
      fetchTasks();
    } catch (err) {
      console.error('Error cancelling all tasks:', err);
      setError('Failed to cancel all tasks');
    }
  };

  const handleRefresh = () => {
    fetchTasks();
  };

  const handlePageChange = (event: React.ChangeEvent<unknown>, value: number) => {
    setCurrentPage(value);
  };

  useEffect(() => {
    fetchTasks();

    if (autoRefresh) {
      const interval = setInterval(fetchTasks, refreshIntervalMs);
      setIntervalId(interval);
      return () => clearInterval(interval);
    }
  }, [binaryId, taskId, showAll, autoRefresh, refreshIntervalMs]);

  const getTaskTypeDescription = (taskType: string) => {
    const descriptions: { [key: string]: string } = {
      'basic': 'Basic Analysis',
      'process_binary': 'Initial Processing',
      'run_auto_analysis': 'Auto Analysis',
      'get_functions': 'Function Analysis',
      'get_memory_regions': 'Memory Layout Analysis',
      'search_patterns': 'Pattern Search',
      'run_vuln_checks': 'Vulnerability Scanning',
      'comprehensive_analysis': 'Comprehensive Analysis',
      'decompile_function': 'Function Decompilation',
      'bulk_decompile': 'Bulk Decompilation',
      'explain_function': 'AI Function Analysis',
      'binary_ai_summary': 'Binary AI Summary',
      'generate_cfg': 'Control Flow Graph Generation'
    };
    
    return descriptions[taskType] || taskType.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  const getTaskTypeIcon = (taskType: string) => {
    const icons: { [key: string]: React.ReactNode } = {
      'basic': <Analytics color="primary" />,
      'comprehensive_analysis': <Memory color="secondary" />,
      'decompile_function': <PlayArrow color="info" />,
      'bulk_decompile': <PlayArrow color="info" />,
      'explain_function': <Security color="warning" />,
      'binary_ai_summary': <Security color="warning" />,
      'generate_cfg': <Analytics color="success" />,
      'run_vuln_checks': <Security color="error" />
    };
    
    return icons[taskType] || <Analytics color="primary" />;
  };

  // Calculate estimated time remaining
  const calculateETA = (task: AnalysisTask): string => {
    if (!task || !task.started_at || task.progress < 5) {
      return 'Calculating...';
    }
    
    const startTime = new Date(task.started_at).getTime();
    const now = Date.now();
    const elapsedMs = now - startTime;
    
    if (task.progress <= 0) return 'Unknown';
    
    const totalEstimatedMs = (elapsedMs / task.progress) * 100;
    const remainingMs = totalEstimatedMs - elapsedMs;
    
    if (remainingMs <= 0) return 'Almost done...';
    
    // Convert to minutes and seconds
    const remainingMinutes = Math.floor(remainingMs / 60000);
    const remainingSeconds = Math.floor((remainingMs % 60000) / 1000);
    
    if (remainingMinutes > 60) {
      const hours = Math.floor(remainingMinutes / 60);
      const mins = remainingMinutes % 60;
      return `${hours}h ${mins}m remaining`;
    }
    
    return `${remainingMinutes}m ${remainingSeconds}s remaining`;
  };

  const getStatusIcon = (status: string) => {
    const size = compact ? 16 : 20;
    switch (status) {
      case 'completed':
        return <CheckCircle color="success" sx={{ fontSize: size }} />;
      case 'failed':
        return <ErrorIcon color="error" sx={{ fontSize: size }} />;
      case 'running':
        return <HourglassEmpty color="primary" sx={{ fontSize: size }} />;
      case 'queued':
        return <Pending color="warning" sx={{ fontSize: size }} />;
      case 'cancelled':
        return <Stop color="disabled" sx={{ fontSize: size }} />;
      default:
        return null;
    }
  };

  if (loading && allTasks.length === 0) {
    return (
      <Box sx={{ width: '100%' }}>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Loading tasks...
        </Typography>
        <LinearProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Paper sx={{ p: 2, mb: 2, bgcolor: 'error.light' }}>
        <Typography color="error">{error}</Typography>
      </Paper>
    );
  }

  // Note: Specific task matching is handled by the tasks array filtering

  // Count tasks by status
  const runningTasks = allTasks.filter(t => t.status === 'running').length;
  const queuedTasks = allTasks.filter(t => t.status === 'queued').length;
  const completedTasks = allTasks.filter(t => t.status === 'completed').length;
  const failedTasks = allTasks.filter(t => t.status === 'failed').length;

  // Calculate pagination
  const totalPages = Math.ceil(allTasks.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentTasks = allTasks.slice(startIndex, endIndex);

  return (
    <Paper sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" p={2}>
        <Typography variant="h6">
          Tasks ({allTasks.length})
        </Typography>
        <Box display="flex" gap={1}>
          {showControls && (runningTasks > 0 || queuedTasks > 0) && (
            <Tooltip title="Cancel All Tasks">
              <Button
                size="small"
                color="error"
                variant="outlined"
                startIcon={<CancelIcon />}
                onClick={handleCancelAllTasks}
              >
                Cancel All
              </Button>
            </Tooltip>
          )}
          <Tooltip title="Refresh">
            <IconButton size="small" onClick={handleRefresh} disabled={loading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* System Status Summary */}
      {systemStatus && !compact && (
        <Box px={2} pb={1}>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            <Chip
              label={`Running: ${runningTasks}`}
              color={runningTasks > 0 ? "warning" : "default"}
              size="small"
              icon={<HourglassEmpty />}
            />
            <Chip
              label={`Queued: ${queuedTasks}`}
              color={queuedTasks > 0 ? "info" : "default"}
              size="small"
              icon={<Pending />}
            />
            <Chip
              label={`Completed: ${completedTasks}`}
              color={completedTasks > 0 ? "success" : "default"}
              size="small"
              icon={<CheckCircle />}
            />
            {failedTasks > 0 && (
              <Chip
                label={`Failed: ${failedTasks}`}
                color="error"
                size="small"
                icon={<ErrorIcon />}
              />
            )}
            <Chip
              label={`Ghidra: ${systemStatus.ghidra_bridge_connected ? 'Connected' : 'Disconnected'}`}
              color={systemStatus.ghidra_bridge_connected ? "success" : "error"}
              size="small"
            />
          </Stack>
        </Box>
      )}

      <Divider />

      {/* Task List */}
      <Box sx={{ flexGrow: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {currentTasks.length === 0 ? (
          <Box p={3} textAlign="center">
            <Typography variant="body2" color="text.secondary">
              No tasks found
            </Typography>
          </Box>
        ) : (
          <Box sx={{ flexGrow: 1, overflow: 'auto', maxHeight: maxHeight - 140 }}>
            <List dense={compact}>
              {currentTasks.map((task, index) => (
                <React.Fragment key={task.id}>
                  <ListItem
                    button
                    onClick={() => handleToggleExpand(task.id)}
                    secondaryAction={
                      showControls && (task.status === 'running' || task.status === 'queued') ? (
                        <Tooltip title="Cancel task">
                          <IconButton 
                            edge="end" 
                            size="small" 
                            color="error"
                            onClick={(e) => {
                              e.stopPropagation();
                              setCancelDialogOpen(true);
                              setCancellingTaskId(task.id);
                            }}
                            disabled={cancellingTaskId === task.id}
                          >
                            <CancelIcon fontSize={compact ? "small" : "medium"} />
                          </IconButton>
                        </Tooltip>
                      ) : null
                    }
                    sx={{ py: compact ? 0.5 : 1 }}
                  >
                    <ListItemText
                      primary={
                        <Box display="flex" alignItems="center" gap={1}>
                          {!compact && getTaskTypeIcon(task.task_type)}
                          {getStatusIcon(task.status)}
                          <Typography variant={compact ? "body2" : "body1"} sx={{ fontSize: compact ? '0.875rem' : undefined }}>
                            {getTaskTypeDescription(task.task_type)}
                          </Typography>
                          <Chip
                            label={task.status}
                            color={getStatusColor(task.status) as any}
                            size="small"
                            sx={{ fontSize: compact ? '0.7rem' : undefined }}
                          />
                          {index < 3 && (task.status === 'running' || task.status === 'queued') && (
                            <Chip
                              label="Priority"
                              color="warning"
                              size="small"
                              variant="outlined"
                            />
                          )}
                        </Box>
                      }
                      secondary={
                        task.status === 'running' ? (
                          <Box sx={{ mt: 1 }}>
                            <Box display="flex" justifyContent="space-between">
                              <Typography variant="body2" color="text.secondary">
                                {task.progress}% complete
                              </Typography>
                              {!compact && (
                                <Typography variant="body2" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                  <Schedule fontSize="small" />
                                  {calculateETA(task)}
                                </Typography>
                              )}
                            </Box>
                            <LinearProgress
                              variant="determinate"
                              value={Math.max(task.progress, 5)}
                              sx={{ mt: 0.5, height: compact ? 3 : 4 }}
                            />
                          </Box>
                        ) : task.status === 'queued' ? (
                          <Typography variant="body2" color="warning.main">
                            Waiting for execution...
                          </Typography>
                        ) : (
                          <Typography variant="caption" color="text.secondary">
                            {task.created_at ? new Date(task.created_at).toLocaleString() : 'Unknown time'}
                          </Typography>
                        )
                      }
                    />
                    {!compact && (expanded[task.id] ? <ExpandLess /> : <ExpandMore />)}
                  </ListItem>

                  {!compact && (
                    <Collapse in={expanded[task.id]} timeout="auto" unmountOnExit>
                      <CardContent sx={{ py: 1, px: 2, bgcolor: 'background.default' }}>
                        <Typography variant="body2">
                          <strong>Task ID:</strong> {task.id}
                        </Typography>
                        <Typography variant="body2">
                          <strong>Binary ID:</strong> {task.binary_id}
                        </Typography>
                        <Typography variant="body2">
                          <strong>Created:</strong> {task.created_at ? new Date(task.created_at).toLocaleString() : 'Unknown'}
                        </Typography>
                        {task.started_at && (
                          <Typography variant="body2">
                            <strong>Started:</strong> {new Date(task.started_at).toLocaleString()}
                          </Typography>
                        )}
                        {task.completed_at && (
                          <Typography variant="body2">
                            <strong>Completed:</strong> {new Date(task.completed_at).toLocaleString()}
                          </Typography>
                        )}
                        {task.error_message && (
                          <Alert severity="error" sx={{ mt: 1 }}>
                            <Typography variant="body2">
                              <strong>Error:</strong> {task.error_message}
                            </Typography>
                          </Alert>
                        )}
                      </CardContent>
                    </Collapse>
                  )}
                  
                  {index < currentTasks.length - 1 && <Divider />}
                </React.Fragment>
              ))}
            </List>
          </Box>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <Box sx={{ p: 2, borderTop: '1px solid', borderColor: 'divider' }}>
            <Box display="flex" justifyContent="center">
              <Pagination
                count={totalPages}
                page={currentPage}
                onChange={handlePageChange}
                color="primary"
                size="small"
                showFirstButton
                showLastButton
              />
            </Box>
            <Typography variant="caption" color="text.secondary" textAlign="center" sx={{ display: 'block', mt: 1 }}>
              Showing {startIndex + 1}-{Math.min(endIndex, allTasks.length)} of {allTasks.length} tasks
            </Typography>
          </Box>
        )}
      </Box>

      {/* Cancel Task Confirmation Dialog */}
      <Dialog open={cancelDialogOpen} onClose={() => setCancelDialogOpen(false)}>
        <DialogTitle>Cancel Task</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to cancel this task? This action cannot be undone.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCancelDialogOpen(false)} disabled={!!cancellingTaskId}>
            No, Keep Running
          </Button>
          <Button 
            onClick={() => cancellingTaskId && handleCancelTask(cancellingTaskId)} 
            color="error" 
            variant="contained" 
            disabled={!cancellingTaskId}
            startIcon={<CancelIcon />}
          >
            {cancellingTaskId ? 'Cancelling...' : 'Yes, Cancel Task'}
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
};

export default TaskProgress; 