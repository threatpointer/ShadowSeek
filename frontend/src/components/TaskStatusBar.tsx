import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  LinearProgress,
  Chip,
  IconButton,
  Collapse,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Button,
  Divider
} from '@mui/material';
import {
  ExpandMore,
  ExpandLess,
  Close,
  Visibility,
  CheckCircle,
  Error,
  Schedule
} from '@mui/icons-material';
import { taskManager, TaskInfo, TaskProgress } from '../utils/taskManager';
import { toast } from 'react-toastify';
import { debugTaskManager } from '../utils/taskManagerDebug';

interface TaskStatusBarProps {
  onTaskComplete?: (taskId: string, results: any) => void;
  onViewResults?: (taskId: string) => void;
}

const TaskStatusBar: React.FC<TaskStatusBarProps> = ({ onTaskComplete, onViewResults }) => {
  const [activeTasks, setActiveTasks] = useState<TaskInfo[]>([]);
  const [taskProgress, setTaskProgress] = useState<Map<string, TaskProgress>>(new Map());
  const [isExpanded, setIsExpanded] = useState(false);
  const [isVisible, setIsVisible] = useState(false);

  // Format time duration
  const formatDuration = (milliseconds: number): string => {
    const seconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  };

  // Format estimated time remaining
  const formatETA = (milliseconds: number): string => {
    if (milliseconds < 60000) return 'Less than 1 minute';
    
    const minutes = Math.floor(milliseconds / 60000);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `About ${hours}h ${minutes % 60}m remaining`;
    } else {
      return `About ${minutes} minutes remaining`;
    }
  };

  // Update active tasks
  const updateActiveTasks = () => {
    const active = taskManager.getActiveTasks();
    console.log('TaskStatusBar - Active tasks updated:', active);
    setActiveTasks(active);
    setIsVisible(active.length > 0);
    
    if (active.length === 0) {
      setIsExpanded(false);
    }
  };

  // Handle task progress updates
  const handleTaskProgress = (taskId: string) => (progress: TaskProgress) => {
    setTaskProgress(prev => new Map(prev.set(taskId, progress)));
    
    // Handle completion
    if (progress.status === 'completed' && progress.results) {
      toast.success(`Binary comparison completed!`);
      onTaskComplete?.(taskId, progress.results);
      
      // Remove from active tasks after a delay
      setTimeout(() => {
        updateActiveTasks();
      }, 2000);
    } else if (progress.status === 'failed') {
      toast.error(`Binary comparison failed: ${progress.error || 'Unknown error'}`);
      
      // Remove from active tasks after a delay
      setTimeout(() => {
        updateActiveTasks();
      }, 2000);
    }
  };

  // Initialize and monitor tasks
  useEffect(() => {
    console.log('TaskStatusBar - Initializing...');
    debugTaskManager();
    
    // Subscribe to task updates
    const unsubscribe = taskManager.onTasksUpdate((tasks) => {
      console.log('TaskStatusBar - Tasks updated from manager:', tasks);
      setActiveTasks(tasks);
      setIsVisible(tasks.length > 0);
      
      if (tasks.length === 0) {
        setIsExpanded(false);
      } else {
        console.log('TaskStatusBar - Setting visible with', tasks.length, 'tasks');
      }
      
      // Set up monitoring for any new tasks
      tasks.forEach(task => {
        if (!taskProgress.has(task.taskId)) {
          console.log('TaskStatusBar - Setting up monitoring for task:', task.taskId);
          taskManager.monitorTask(task.taskId, handleTaskProgress(task.taskId));
        }
      });
    });

    // Force visibility check on initialization
    const initialTasks = taskManager.getActiveTasks();
    console.log('TaskStatusBar - Initial tasks on mount:', initialTasks);
    if (initialTasks.length > 0) {
      setActiveTasks(initialTasks);
      setIsVisible(true);
    }

    return () => {
      unsubscribe();
      // Stop monitoring all tasks when component unmounts
      const active = taskManager.getActiveTasks();
      active.forEach(task => {
        taskManager.stopMonitoring(task.taskId);
      });
    };
  }, [taskProgress]);

  // Get task status icon
  const getStatusIcon = (task: TaskInfo, progress?: TaskProgress) => {
    const status = progress?.status || task.status;
    
    switch (status) {
      case 'completed':
        return <CheckCircle sx={{ color: '#4caf50' }} />;
      case 'failed':
        return <Error sx={{ color: '#f44336' }} />;
      case 'queued':
        return <Schedule sx={{ color: '#ff9800' }} />;
      default:
        return <Schedule sx={{ color: '#2196f3' }} />;
    }
  };

  // Get task status color
  const getStatusColor = (task: TaskInfo, progress?: TaskProgress) => {
    const status = progress?.status || task.status;
    
    switch (status) {
      case 'completed':
        return '#4caf50';
      case 'failed':
        return '#f44336';
      case 'queued':
        return '#ff9800';
      default:
        return '#2196f3';
    }
  };

  if (!isVisible) {
    return null;
  }

  return (
    <Paper 
      elevation={3} 
      sx={{ 
        position: 'fixed', 
        bottom: 0, 
        left: 0, 
        right: 0, 
        zIndex: 1300,
        backgroundColor: '#1e1e1e',
        borderTop: '1px solid #333'
      }}
    >
      {/* Main status bar */}
      <Box 
        sx={{ 
          px: 2, 
          py: 1, 
          display: 'flex', 
          alignItems: 'center', 
          cursor: 'pointer',
          '&:hover': { backgroundColor: 'rgba(255, 255, 255, 0.05)' }
        }}
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', flex: 1 }}>
          <Typography variant="body2" sx={{ color: 'white', mr: 2 }}>
            {activeTasks.length} active comparison{activeTasks.length !== 1 ? 's' : ''}
          </Typography>
          
          {activeTasks.map(task => {
            const progress = taskProgress.get(task.taskId);
            return (
              <Chip
                key={task.taskId}
                label={`${task.binary1Name || 'Binary 1'} vs ${task.binary2Name || 'Binary 2'}`}
                size="small"
                sx={{
                  mr: 1,
                  backgroundColor: getStatusColor(task, progress),
                  color: 'white',
                  maxWidth: 200
                }}
              />
            );
          })}
        </Box>

        <IconButton size="small" sx={{ color: 'white' }}>
          {isExpanded ? <ExpandLess /> : <ExpandMore />}
        </IconButton>
      </Box>

      {/* Expanded view */}
      <Collapse in={isExpanded}>
        <Divider sx={{ borderColor: '#333' }} />
        <List sx={{ maxHeight: 300, overflow: 'auto' }}>
          {activeTasks.map(task => {
            const progress = taskProgress.get(task.taskId);
            const elapsed = Date.now() - task.startTime;
            
            return (
              <ListItem key={task.taskId} sx={{ py: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mr: 2 }}>
                  {getStatusIcon(task, progress)}
                </Box>
                
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="body2" sx={{ color: 'white' }}>
                        {task.binary1Name || task.binary1Id} vs {task.binary2Name || task.binary2Id}
                      </Typography>
                      <Chip 
                        label={task.diffType} 
                        size="small" 
                        variant="outlined"
                        sx={{ color: 'white', borderColor: 'rgba(255,255,255,0.3)' }}
                      />
                    </Box>
                  }
                  secondary={
                    <Box sx={{ mt: 1 }}>
                      <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                        {progress?.message || `Running for ${formatDuration(elapsed)}`}
                      </Typography>
                      
                      {progress?.estimatedTimeRemaining && (
                        <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)', display: 'block' }}>
                          {formatETA(progress.estimatedTimeRemaining)}
                        </Typography>
                      )}
                      
                      {/* Progress bar */}
                      <LinearProgress
                        variant="determinate"
                        value={progress?.progress || 0}
                        sx={{
                          mt: 1,
                          height: 4,
                          backgroundColor: 'rgba(255,255,255,0.1)',
                          '& .MuiLinearProgress-bar': {
                            backgroundColor: getStatusColor(task, progress)
                          }
                        }}
                      />
                    </Box>
                  }
                />

                <ListItemSecondaryAction>
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    {progress?.status === 'completed' && progress.results && (
                      <Button
                        size="small"
                        startIcon={<Visibility />}
                        onClick={() => onViewResults?.(task.taskId)}
                        sx={{ color: 'white' }}
                      >
                        View Results
                      </Button>
                    )}
                    
                    <IconButton
                      size="small"
                      onClick={() => {
                        taskManager.removeTask(task.taskId);
                        updateActiveTasks();
                      }}
                      sx={{ color: 'rgba(255,255,255,0.5)' }}
                    >
                      <Close />
                    </IconButton>
                  </Box>
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
      </Collapse>
    </Paper>
  );
};

export default TaskStatusBar; 