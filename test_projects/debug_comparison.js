// Simple debug script for binary comparison
// Paste this into browser console when on the comparison page

// 1. Extract task ID from React component state
function getTaskIdFromReact() {
  // Try to find React instance
  const reactRoot = document.querySelector('#root');
  if (!reactRoot || !reactRoot._reactRootContainer) {
    console.log("Can't access React root. Using alternative method.");
    return null;
  }
  
  // This is a hacky way to try to access React state
  // It might not work depending on React version and build
  try {
    const reactInstance = reactRoot._reactRootContainer._internalRoot.current.child;
    // Navigate through the fiber tree to find the component
    // This is very brittle and depends on the specific React structure
    return null; // Simplified to avoid complexity
  } catch (e) {
    console.log("Couldn't extract task ID from React:", e);
    return null;
  }
}

// 2. Check network requests to find task ID
function checkNetworkForTaskId() {
  console.log("To find the task ID, look in the Network tab for a request to /api/analysis/diff");
  console.log("The response will contain a task_id field");
  return null;
}

// 3. Manual task ID input
function promptForTaskId() {
  return prompt("Enter the task ID (check Network tab for /api/analysis/diff request):");
}

// 4. Check task status
async function checkTaskStatus(taskId) {
  if (!taskId) {
    console.error("No task ID provided");
    return;
  }
  
  try {
    console.log(`Checking status for task: ${taskId}`);
    const response = await fetch(`/api/analysis/diff/${taskId}`);
    const data = await response.json();
    console.log("Task status:", data);
    return data;
  } catch (e) {
    console.error("Error checking task status:", e);
  }
}

// 5. Force task completion
async function forceTaskCompletion(taskId) {
  if (!taskId) {
    console.error("No task ID provided");
    return;
  }
  
  try {
    console.log(`Forcing completion for task: ${taskId}`);
    const response = await fetch(`/api/analysis/diff/${taskId}/update-status`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({})
    });
    
    const data = await response.json();
    console.log("Force completion response:", data);
    return data;
  } catch (e) {
    console.error("Error forcing task completion:", e);
  }
}

// Main debug function
async function debugBinaryComparison() {
  console.log("=== Binary Comparison Debugger ===");
  
  // Try to get task ID
  let taskId = getTaskIdFromReact() || checkNetworkForTaskId() || promptForTaskId();
  
  if (!taskId) {
    console.error("Could not determine task ID");
    return;
  }
  
  // Check current status
  const status = await checkTaskStatus(taskId);
  
  if (status && status.status === 'completed') {
    console.log("Task is already completed. Try refreshing the page.");
    return;
  }
  
  // Ask if user wants to force completion
  if (confirm("Do you want to force task completion?")) {
    await forceTaskCompletion(taskId);
    
    // Check status again
    await checkTaskStatus(taskId);
    
    console.log("Try refreshing the page now to see if the comparison results appear.");
  }
}

// Run the debugger
debugBinaryComparison(); 