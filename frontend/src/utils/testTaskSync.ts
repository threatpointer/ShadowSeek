import { taskManager } from './taskManager';
import { notificationManager } from '../components/NotificationCenter';

// Test function to manually trigger sync and show results
export const testTaskSync = async () => {
  console.log('=== Manual Task Sync Test ===');
  
  try {
    // Show current state
    const currentTasks = taskManager.getActiveTasks();
    console.log('Before sync - Frontend active tasks:', currentTasks.length);
    
    // Force sync by triggering visibilitychange event
    console.log('Triggering visibility change to force sync...');
    document.dispatchEvent(new Event('visibilitychange'));
    
    // Wait a bit for sync to complete
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Check results
    const afterTasks = taskManager.getActiveTasks();
    console.log('After sync - Frontend active tasks:', afterTasks.length);
    
    if (afterTasks.length > currentTasks.length) {
      console.log('✅ Sync worked! Found new tasks:', afterTasks);
      notificationManager.addNotification({
        type: 'success',
        title: 'Sync Test Results',
        message: `Found ${afterTasks.length} active tasks. Status bar should now be visible!`,
        persistent: true
      });
    } else {
      console.log('❌ No new tasks found. Sync may have failed.');
      notificationManager.addNotification({
        type: 'warning',
        title: 'Sync Test Results',
        message: `No active tasks found. Expected 2 binary comparisons from backend.`,
        persistent: true
      });
    }
    
    return {
      before: currentTasks.length,
      after: afterTasks.length,
      newTasks: afterTasks
    };
    
  } catch (error) {
    console.error('Manual sync test failed:', error);
    const errorMessage = error instanceof Error ? error.message : String(error);
    notificationManager.addNotification({
      type: 'error',
      title: 'Sync Test Failed',
      message: `Error: ${errorMessage}`,
      persistent: true
    });
    return { error: errorMessage };
  }
};

// Make it globally available
(window as any).testTaskSync = testTaskSync;

// Also export it
export default testTaskSync; 