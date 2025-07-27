import { taskManager } from './taskManager';

// Debug utility for task manager
export const debugTaskManager = () => {
  console.log('=== Task Manager Debug ===');
  console.log('Active tasks:', taskManager.getActiveTasks());
  console.log('Tasks summary:', taskManager.getTasksSummary());
  
  // Log localStorage content
  const stored = localStorage.getItem('shadowseek_active_tasks');
  console.log('Stored tasks:', stored ? JSON.parse(stored) : 'None');
  
  return {
    activeTasks: taskManager.getActiveTasks(),
    summary: taskManager.getTasksSummary(),
    stored: stored ? JSON.parse(stored) : null
  };
};

// Make it available globally for debugging
(window as any).debugTaskManager = debugTaskManager; 