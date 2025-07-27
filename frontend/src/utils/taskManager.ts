/**
 * Persistent Task Manager for Binary Comparisons
 * Tracks long-running tasks across page navigation and browser sessions
 */

export interface TaskInfo {
  taskId: string;
  type: 'binary_comparison';
  status: 'running' | 'completed' | 'failed' | 'queued';
  progress: number;
  startTime: number;
  binary1Id: string;
  binary2Id: string;
  binary1Name?: string;
  binary2Name?: string;
  diffType: string;
  estimatedDuration?: number;
  lastUpdate: number;
}

export interface TaskProgress {
  taskId: string;
  status: string;
  progress: number;
  message?: string;
  results?: any;
  error?: string;
  estimatedTimeRemaining?: number;
}

class PersistentTaskManager {
  private static instance: PersistentTaskManager;
  private tasks: Map<string, TaskInfo> = new Map();
  private listeners: Map<string, (progress: TaskProgress) => void> = new Map();
  private pollingIntervals: Map<string, NodeJS.Timeout> = new Map();
  private updateListeners: ((tasks: TaskInfo[]) => void)[] = [];
  private readonly STORAGE_KEY = 'shadowseek_active_tasks';
  private readonly POLL_INTERVAL = 3000; // 3 seconds
  private readonly MAX_TASK_AGE = 24 * 60 * 60 * 1000; // 24 hours

  private constructor() {
    this.loadTasksFromStorage();
    this.startCleanupInterval();
    
    // Sync with backend for any active tasks
    this.syncWithBackend();
    
    // Handle page unload - save tasks to storage
    window.addEventListener('beforeunload', () => {
      this.saveTasksToStorage();
    });

    // Handle page visibility change - resume polling when page becomes visible
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        console.log('TaskManager - Page became visible, resuming polling for', this.tasks.size, 'tasks');
        this.resumeAllPolling();
        // Sync with backend again when page becomes visible
        this.syncWithBackend();
        // Force notification to listeners after resuming
        setTimeout(() => {
          this.notifyUpdateListeners();
        }, 100);
      }
    });
  }

  public static getInstance(): PersistentTaskManager {
    if (!PersistentTaskManager.instance) {
      PersistentTaskManager.instance = new PersistentTaskManager();
    }
    return PersistentTaskManager.instance;
  }

  /**
   * Add a new task to track
   */
  public addTask(taskInfo: Omit<TaskInfo, 'startTime' | 'lastUpdate'>): void {
    const fullTaskInfo: TaskInfo = {
      ...taskInfo,
      startTime: Date.now(),
      lastUpdate: Date.now()
    };
    
    console.log('TaskManager - Adding task:', fullTaskInfo);
    this.tasks.set(taskInfo.taskId, fullTaskInfo);
    this.saveTasksToStorage();
    
    console.log('TaskManager - Active tasks after adding:', this.getActiveTasks());
    
    // Notify listeners immediately
    this.notifyUpdateListeners();
    
    // Start polling after notification
    this.startPolling(taskInfo.taskId);
  }

  /**
   * Start monitoring a task
   */
  public monitorTask(
    taskId: string, 
    onProgress: (progress: TaskProgress) => void
  ): void {
    this.listeners.set(taskId, onProgress);
    
    // If task exists, start polling immediately
    if (this.tasks.has(taskId)) {
      this.startPolling(taskId);
    }
  }

  /**
   * Stop monitoring a task
   */
  public stopMonitoring(taskId: string): void {
    this.listeners.delete(taskId);
    this.stopPolling(taskId);
  }

  /**
   * Get all active tasks
   */
  public getActiveTasks(): TaskInfo[] {
    return Array.from(this.tasks.values()).filter(
      task => task.status === 'running' || task.status === 'queued'
    );
  }

  /**
   * Get a specific task
   */
  public getTask(taskId: string): TaskInfo | undefined {
    return this.tasks.get(taskId);
  }

  /**
   * Remove a completed or failed task
   */
  public removeTask(taskId: string): void {
    this.tasks.delete(taskId);
    this.stopPolling(taskId);
    this.listeners.delete(taskId);
    this.saveTasksToStorage();
    this.notifyUpdateListeners();
  }

  /**
   * Calculate estimated time remaining for a task
   */
  private calculateEstimatedTime(task: TaskInfo): number | undefined {
    if (task.progress <= 0) return undefined;
    
    const elapsed = Date.now() - task.startTime;
    const estimatedTotal = elapsed / (task.progress / 100);
    const remaining = estimatedTotal - elapsed;
    
    return Math.max(0, remaining);
  }

  /**
   * Start polling for a specific task
   */
  private async startPolling(taskId: string): Promise<void> {
    if (this.pollingIntervals.has(taskId)) {
      return; // Already polling
    }

    const task = this.tasks.get(taskId);
    if (!task || (task.status !== 'running' && task.status !== 'queued')) {
      return;
    }

    const interval = setInterval(async () => {
      await this.pollTask(taskId);
    }, this.POLL_INTERVAL);

    this.pollingIntervals.set(taskId, interval);
    
    // Poll immediately
    await this.pollTask(taskId);
  }

  /**
   * Stop polling for a specific task
   */
  private stopPolling(taskId: string): void {
    const interval = this.pollingIntervals.get(taskId);
    if (interval) {
      clearInterval(interval);
      this.pollingIntervals.delete(taskId);
    }
  }

  /**
   * Poll a single task for updates
   */
  private async pollTask(taskId: string): Promise<void> {
    try {
      const task = this.tasks.get(taskId);
      if (!task) return;

      // Import apiClient dynamically to avoid circular dependencies
      const { apiClient } = await import('./api');
      
      const result = await apiClient.getBinaryComparisonResults(taskId);
      
      // Update task info
      task.lastUpdate = Date.now();
      task.status = result.status;
      task.progress = result.progress || (result.status === 'completed' ? 100 : task.progress);
      
      // Calculate estimated time remaining
      const estimatedTimeRemaining = this.calculateEstimatedTime(task);

      // Notify listeners
      const listener = this.listeners.get(taskId);
      if (listener) {
        const progress: TaskProgress = {
          taskId,
          status: result.status,
          progress: task.progress,
          message: this.getStatusMessage(task),
          estimatedTimeRemaining,
          results: result.status === 'completed' ? result.diff_result : undefined,
          error: result.status === 'failed' ? result.error : undefined
        };
        
        listener(progress);
      }

             // Handle completion
       if (result.status === 'completed' || result.status === 'failed') {
         this.stopPolling(taskId);
         
         // Notify listeners of task completion
         this.notifyUpdateListeners();
         
         // If it's a completed binary comparison, dispatch event to refresh past results
         if (result.status === 'completed' && task.type === 'binary_comparison') {
           console.log('Binary comparison completed - dispatching refresh event');
           window.dispatchEvent(new CustomEvent('binary_comparison_completed', {
             detail: { taskId, result }
           }));
         }
         
         // Keep completed tasks for a while, then remove them
         setTimeout(() => {
           this.removeTask(taskId);
         }, 5 * 60 * 1000); // 5 minutes
       }

       this.saveTasksToStorage();
      
    } catch (error) {
      console.error(`Error polling task ${taskId}:`, error);
      
      // If task is not found, remove it
      if (error instanceof Error && error.message.includes('404')) {
        this.removeTask(taskId);
      }
    }
  }

  /**
   * Resume polling for all active tasks
   */
  private resumeAllPolling(): void {
    console.log('TaskManager - Resuming polling for all active tasks...');
    for (const [taskId, task] of this.tasks.entries()) {
      if (task.status === 'running' || task.status === 'queued') {
        console.log(`TaskManager - Resuming polling for task ${taskId} (${task.status})`);
        this.startPolling(taskId);
      }
    }
    const activeTasks = this.getActiveTasks();
    console.log('TaskManager - Active tasks after resume:', activeTasks.length);
  }

  /**
   * Get a human-readable status message
   */
  private getStatusMessage(task: TaskInfo): string {
    const elapsed = Date.now() - task.startTime;
    const elapsedMinutes = Math.floor(elapsed / 60000);
    
    switch (task.status) {
      case 'queued':
        return 'Waiting in queue...';
      case 'running':
        if (task.progress > 0) {
          return `Analyzing binaries... ${task.progress}% complete (${elapsedMinutes}m elapsed)`;
        }
        return `Starting analysis... (${elapsedMinutes}m elapsed)`;
      case 'completed':
        return `Analysis completed in ${elapsedMinutes} minutes`;
      case 'failed':
        return 'Analysis failed';
      default:
        return 'Unknown status';
    }
  }

  /**
   * Load tasks from localStorage
   */
  private loadTasksFromStorage(): void {
    try {
      const stored = localStorage.getItem(this.STORAGE_KEY);
      if (stored) {
        const taskArray = JSON.parse(stored) as TaskInfo[];
        
        // Filter out old tasks
        const now = Date.now();
        const validTasks = taskArray.filter(
          task => (now - task.startTime) < this.MAX_TASK_AGE
        );
        
        this.tasks.clear();
        validTasks.forEach(task => {
          this.tasks.set(task.taskId, task);
        });
        
        console.log(`TaskManager - Loaded ${validTasks.length} tasks from storage`);
        
                 // Resume polling for active tasks and sync with backend
         setTimeout(() => {
           this.resumeAllPolling();
           this.syncWithBackend();
           this.notifyUpdateListeners();
         }, 500);
      }
    } catch (error) {
      console.error('Error loading tasks from storage:', error);
      this.tasks.clear();
    }
  }

  /**
   * Save tasks to localStorage
   */
  private saveTasksToStorage(): void {
    try {
      const taskArray = Array.from(this.tasks.values());
      localStorage.setItem(this.STORAGE_KEY, JSON.stringify(taskArray));
    } catch (error) {
      console.error('Error saving tasks to storage:', error);
    }
  }

  /**
   * Clean up old completed tasks periodically
   */
  private startCleanupInterval(): void {
    setInterval(() => {
      const now = Date.now();
      const tasksToRemove: string[] = [];
      
      for (const [taskId, task] of this.tasks.entries()) {
        // Remove completed/failed tasks older than 1 hour
        if (
          (task.status === 'completed' || task.status === 'failed') &&
          (now - task.lastUpdate) > 60 * 60 * 1000
        ) {
          tasksToRemove.push(taskId);
        }
        // Remove any tasks older than 24 hours
        else if ((now - task.startTime) > this.MAX_TASK_AGE) {
          tasksToRemove.push(taskId);
        }
      }
      
      tasksToRemove.forEach(taskId => this.removeTask(taskId));
      
    }, 10 * 60 * 1000); // Run every 10 minutes
  }

  /**
   * Get summary of all tasks for display
   */
  public getTasksSummary(): {
    active: number;
    completed: number;
    failed: number;
    oldestActiveTask?: TaskInfo;
  } {
    const tasks = Array.from(this.tasks.values());
    const active = tasks.filter(t => t.status === 'running' || t.status === 'queued');
    const completed = tasks.filter(t => t.status === 'completed');
    const failed = tasks.filter(t => t.status === 'failed');
    
    const oldestActiveTask = active.reduce((oldest, current) => {
      return !oldest || current.startTime < oldest.startTime ? current : oldest;
    }, undefined as TaskInfo | undefined);

    return {
      active: active.length,
      completed: completed.length,
      failed: failed.length,
      oldestActiveTask
    };
  }

  /**
   * Subscribe to task list updates
   */
  public onTasksUpdate(listener: (tasks: TaskInfo[]) => void): () => void {
    this.updateListeners.push(listener);
    
    // Immediately call with current tasks
    listener(this.getActiveTasks());
    
    // Return unsubscribe function
    return () => {
      const index = this.updateListeners.indexOf(listener);
      if (index > -1) {
        this.updateListeners.splice(index, 1);
      }
    };
  }

  /**
   * Sync with backend to discover any active binary_comparison tasks
   */
  private async syncWithBackend(): Promise<void> {
    try {
      console.log('TaskManager - Syncing with backend for active tasks...');
      
      // Import API dynamically to avoid circular dependency
      const apiModule = await import('./api');
      const response = await apiModule.apiClient.get('/tasks');
      const backendTasks = response.data.tasks || [];
      
      // Filter for active binary_comparison tasks
      const activeBinaryTasks = backendTasks.filter((task: any) => 
        task.task_type === 'binary_comparison' && 
        (task.status === 'running' || task.status === 'queued')
      );
      
      console.log(`TaskManager - Found ${activeBinaryTasks.length} active binary comparison tasks on backend`);
      
      // Add any backend tasks that we don't know about
      let addedTasks = 0;
      for (const backendTask of activeBinaryTasks) {
        if (!this.tasks.has(backendTask.id)) {
          const taskInfo: TaskInfo = {
            taskId: backendTask.id,
            type: 'binary_comparison',
            status: backendTask.status === 'running' ? 'running' : 'queued',
            progress: backendTask.progress || 0,
            startTime: new Date(backendTask.started_at || backendTask.created_at).getTime(),
            lastUpdate: Date.now(),
            binary1Id: backendTask.parameters?.binary_id1 || '',
            binary2Id: backendTask.parameters?.binary_id2 || '',
            binary1Name: `Binary ${backendTask.parameters?.binary_id1?.substring(0, 8)}`,
            binary2Name: `Binary ${backendTask.parameters?.binary_id2?.substring(0, 8)}`,
            diffType: backendTask.parameters?.diff_type || 'simple'
          };
          
          console.log('TaskManager - Adding backend task to frontend:', taskInfo);
          this.tasks.set(backendTask.id, taskInfo);
          this.startPolling(backendTask.id);
          addedTasks++;
        }
      }
      
      if (addedTasks > 0) {
        console.log(`TaskManager - Added ${addedTasks} backend tasks to frontend tracking`);
        this.saveTasksToStorage();
        this.notifyUpdateListeners();
      }
      
    } catch (error) {
      console.warn('TaskManager - Failed to sync with backend:', error);
    }
  }

  /**
   * Notify all update listeners
   */
  private notifyUpdateListeners(): void {
    const activeTasks = this.getActiveTasks();
    console.log('TaskManager - Notifying', this.updateListeners.length, 'listeners with', activeTasks.length, 'active tasks');
    
    this.updateListeners.forEach(listener => {
      try {
        listener(activeTasks);
      } catch (error) {
        console.error('Error in task update listener:', error);
      }
    });
  }
}

export const taskManager = PersistentTaskManager.getInstance(); 