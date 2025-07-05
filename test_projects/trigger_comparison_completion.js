// This script can be pasted into the browser console to help debug the binary comparison feature
// It will extract the task ID from the URL or local storage and manually trigger task completion

(async function() {
  // Function to extract task ID from various sources
  function extractTaskId() {
    // Try to get task ID from URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const taskId = urlParams.get('task_id');
    if (taskId) return taskId;
    
    // Try to get from localStorage
    const storedTaskId = localStorage.getItem('binary_comparison_task_id');
    if (storedTaskId) return storedTaskId;
    
    // Try to find in React component state (more complex)
    // This is a simplified approach and might not work in all cases
    return null;
  }
  
  // Function to manually trigger task completion
  async function triggerTaskCompletion(taskId) {
    if (!taskId) {
      console.error('No task ID found. Cannot trigger completion.');
      return;
    }
    
    try {
      console.log(`Attempting to trigger completion for task: ${taskId}`);
      
      // First, check current task status
      const statusResponse = await fetch(`/api/analysis/diff/${taskId}`);
      const statusData = await statusResponse.json();
      
      console.log('Current task status:', statusData);
      
      if (statusData.status === 'completed') {
        console.log('Task is already completed.');
        return;
      }
      
      // Trigger task completion
      const response = await fetch(`/api/analysis/diff/${taskId}/update-status`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({})
      });
      
      const data = await response.json();
      console.log('Task update response:', data);
      
      // Check status again after update
      const updatedStatusResponse = await fetch(`/api/analysis/diff/${taskId}`);
      const updatedStatus = await updatedStatusResponse.json();
      console.log('Updated task status:', updatedStatus);
      
      return data;
    } catch (error) {
      console.error('Error triggering task completion:', error);
    }
  }
  
  // Main execution
  const taskId = extractTaskId();
  if (!taskId) {
    // If we couldn't find the task ID automatically, ask the user
    const manualTaskId = prompt('Enter the task ID to complete:');
    if (manualTaskId) {
      await triggerTaskCompletion(manualTaskId);
    } else {
      console.log('No task ID provided. Cannot proceed.');
    }
  } else {
    await triggerTaskCompletion(taskId);
  }
})(); 