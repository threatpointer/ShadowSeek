import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Card,
  CardContent,
  LinearProgress,
  Alert,
  Chip,
  Grid,
  CircularProgress
} from '@mui/material';
import {
  PlayArrow,
  CheckCircle,
  Error,
  Refresh,
  AccountTree,
  Search,
  Code,
  Memory,
  Security
} from '@mui/icons-material';
import { toast } from 'react-toastify';
import { apiClient } from '../utils/api';

interface AnalysisStep {
  id: string;
  title: string;
  description: string;
  icon: React.ReactNode;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  startTime?: Date;
  endTime?: Date;
  results?: any;
  error?: string;
  substeps?: string[];
}

interface ComprehensiveAnalysisWorkflowProps {
  binaryId: string;
  onAnalysisComplete?: (results: any) => void;
}

const ComprehensiveAnalysisWorkflow: React.FC<ComprehensiveAnalysisWorkflowProps> = ({
  binaryId,
  onAnalysisComplete
}) => {
  const [isRunning, setIsRunning] = useState(false);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  const [overallProgress, setOverallProgress] = useState(0);
  
  const [steps, setSteps] = useState<AnalysisStep[]>([
    {
      id: 'metadata_extraction',
      title: 'Metadata Extraction',
      description: 'Extract program metadata, architecture, and compiler info',
      icon: <Memory color="primary" />,
      status: 'pending',
      progress: 0,
      substeps: ['Program metadata', 'Architecture detection', 'Memory map']
    },
    {
      id: 'function_analysis',
      title: 'Function Analysis',
      description: 'Discover and decompile all functions with full metadata',
      icon: <Code color="primary" />,
      status: 'pending',
      progress: 0,
      substeps: ['Function discovery', 'Decompilation', 'Parameters & variables']
    },
    {
      id: 'instruction_analysis',
      title: 'Instruction Analysis',
      description: 'Extract and analyze individual instructions and operands',
      icon: <AccountTree color="primary" />,
      status: 'pending',
      progress: 0,
      substeps: ['Instruction extraction', 'Operand analysis', 'Flow analysis']
    },
    {
      id: 'symbol_analysis',
      title: 'Symbol & String Analysis',
      description: 'Extract symbols, strings, imports, and exports',
      icon: <Search color="primary" />,
      status: 'pending',
      progress: 0,
      substeps: ['Symbol extraction', 'String analysis', 'Import/Export tables']
    },
    {
      id: 'cross_reference_analysis',
      title: 'Cross-Reference Analysis',
      description: 'Map cross-references and data relationships',
      icon: <Security color="primary" />,
      status: 'pending',
      progress: 0,
      substeps: ['XRef mapping', 'Data flow analysis', 'Call graph generation']
    }
  ]);

  const updateStepStatus = (stepId: string, updates: Partial<AnalysisStep>) => {
    setSteps(prevSteps => 
      prevSteps.map(step => 
        step.id === stepId ? { ...step, ...updates } : step
      )
    );
  };

  const calculateOverallProgress = () => {
    const totalSteps = steps.length;
    const completedSteps = steps.filter(step => step.status === 'completed').length;
    const runningStep = steps.find(step => step.status === 'running');
    
    let progress = (completedSteps / totalSteps) * 100;
    
    if (runningStep) {
      progress += (runningStep.progress / totalSteps);
    }
    
    return Math.round(progress);
  };

  useEffect(() => {
    setOverallProgress(calculateOverallProgress());
  }, [steps]);



  // All analysis steps are now handled by the comprehensive analysis task on the backend
  // No individual step functions needed since everything is processed in one comprehensive task

  const monitorComprehensiveAnalysis = async (taskId: string) => {
    const pollInterval = 3000;
    const maxPolls = 600; // 30 minutes max (increased from 200)
    let polls = 0;
    
    while (polls < maxPolls) {
      try {
        // Check comprehensive analysis progress instead of task status
        const analysisResponse = await apiClient.getComprehensiveAnalysis(binaryId);
        
        if (analysisResponse && analysisResponse.analysis) {
          const analysis = analysisResponse.analysis;
          
          // Check for error messages first
          if (analysis.error_message) {
            throw { message: analysis.error_message };
          }
          
          // Use improved progress tracking from metadata
          let currentProgress = 0;
          let currentStepName = 'Starting analysis...';
          
          if (analysis.program_metadata && typeof analysis.program_metadata === 'object') {
            const metadata = analysis.program_metadata;
            if (metadata.progress) {
              currentProgress = metadata.progress * 100;
            }
            if (metadata.current_step) {
              currentStepName = metadata.current_step;
            }
          }
          
          // Calculate progress based on extracted data flags
          const progressSteps = [
            analysis.memory_blocks_extracted || false,    // Step 1: Metadata/Memory
            analysis.functions_extracted || false,        // Step 2: Functions
            analysis.instructions_extracted || false,     // Step 3: Instructions
            (analysis.strings_extracted || false) &&      // Step 4: Strings & Symbols
            (analysis.symbols_extracted || false) &&
            (analysis.imports_extracted || false) &&
            (analysis.exports_extracted || false),
            (analysis.xrefs_extracted || false) &&        // Step 5: Cross-references
            (analysis.data_types_extracted || false)
          ];
          
          const completedSteps = progressSteps.filter(Boolean).length;
          const extractionProgress = (completedSteps / 5) * 100; // 5 main steps
          
          // Use the higher of the two progress values
          const overallProgress = Math.max(currentProgress, extractionProgress);
          
          // Update current step index based on what's running
          let currentStep = 0;
          if (!analysis.memory_blocks_extracted) {
            currentStep = 0; // Metadata extraction
          } else if (!analysis.functions_extracted) {
            currentStep = 1; // Function analysis
          } else if (!analysis.instructions_extracted) {
            currentStep = 2; // Instruction analysis
          } else if (!analysis.strings_extracted || !analysis.symbols_extracted || 
                     !analysis.imports_extracted || !analysis.exports_extracted) {
            currentStep = 3; // Symbol & String analysis
          } else if (!analysis.xrefs_extracted || !analysis.data_types_extracted) {
            currentStep = 4; // Cross-reference analysis
          } else {
            currentStep = 4; // All complete
          }
          setCurrentStepIndex(currentStep);
          
          // Update steps based on progress with more detailed status
          if (analysis.memory_blocks_extracted) {
            updateStepStatus('metadata_extraction', { status: 'completed', progress: 100 });
          } else {
            const progress = currentStep === 0 ? Math.max(currentProgress, 20) : 10;
            updateStepStatus('metadata_extraction', { 
              status: 'running', 
              progress: progress,
              substeps: [currentStepName || 'Extracting program metadata and memory map...']
            });
          }
          
          if (analysis.functions_extracted) {
            updateStepStatus('function_analysis', { status: 'completed', progress: 100 });
          } else if (analysis.memory_blocks_extracted) {
            const progress = currentStep === 1 ? Math.max(currentProgress, 40) : 0;
            updateStepStatus('function_analysis', { 
              status: currentStep === 1 ? 'running' : 'pending', 
              progress: progress,
              substeps: currentStep === 1 ? [currentStepName || 'Discovering and decompiling functions...'] : []
            });
          }
          
          if (analysis.instructions_extracted) {
            updateStepStatus('instruction_analysis', { status: 'completed', progress: 100 });
          } else if (analysis.functions_extracted) {
            const progress = currentStep === 2 ? Math.max(currentProgress, 50) : 0;
            updateStepStatus('instruction_analysis', { 
              status: currentStep === 2 ? 'running' : 'pending', 
              progress: progress,
              substeps: currentStep === 2 ? [currentStepName || 'Extracting instructions and operands...'] : []
            });
          }
          
          if (analysis.strings_extracted && analysis.symbols_extracted && 
              analysis.imports_extracted && analysis.exports_extracted) {
            updateStepStatus('symbol_analysis', { status: 'completed', progress: 100 });
          } else if (analysis.instructions_extracted) {
            const progress = currentStep === 3 ? Math.max(currentProgress, 60) : 0;
            updateStepStatus('symbol_analysis', { 
              status: currentStep === 3 ? 'running' : 'pending', 
              progress: progress,
              substeps: currentStep === 3 ? [currentStepName || 'Extracting symbols, strings, imports and exports...'] : []
            });
          }
          
          if (analysis.xrefs_extracted && analysis.data_types_extracted) {
            updateStepStatus('cross_reference_analysis', { status: 'completed', progress: 100 });
          } else if (analysis.strings_extracted) {
            const progress = currentStep === 4 ? Math.max(currentProgress, 80) : 0;
            updateStepStatus('cross_reference_analysis', { 
              status: currentStep === 4 ? 'running' : 'pending', 
              progress: progress,
              substeps: currentStep === 4 ? [currentStepName || 'Mapping cross-references and data relationships...'] : []
            });
          }
          
          // Check if analysis is complete
          if (analysis.is_complete) {
            // Mark all steps as completed
            steps.forEach(step => {
              updateStepStatus(step.id, { status: 'completed', progress: 100 });
            });
            break;
          }
          
        } else {
          // No analysis data yet, check task status for errors
          try {
            const taskStatus = await apiClient.getTaskStatus(taskId);
            
            if (taskStatus && (taskStatus.status === 'failed' || taskStatus.status === 'error')) {
              const errorMessage = taskStatus.error_message || 'Comprehensive analysis failed';
              throw { message: errorMessage };
            }
          } catch (taskError) {
            // Task status might not exist yet, continue waiting
            console.log('Task status not available yet, continuing...');
          }
          
          // Still waiting for analysis to start - be more patient
          const waitingProgress = Math.min(5 + (polls * 0.5), 15); // Gradually increase to 15%
          updateStepStatus('metadata_extraction', { 
            status: 'running', 
            progress: waitingProgress,
            substeps: polls < 5 ? ['Initializing analysis engine...'] : 
                     polls < 10 ? ['Loading binary into Ghidra...'] :
                     ['Starting comprehensive analysis...']
          });
        }
        
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        polls++;
        
      } catch (error: any) {
        // If we get 404 for comprehensive analysis, it means it hasn't started yet
        if (error.message?.includes('404') && polls < 20) {
          updateStepStatus('metadata_extraction', { 
            status: 'running', 
            progress: 5,
            substeps: ['Initializing analysis engine...']
          });
          await new Promise(resolve => setTimeout(resolve, pollInterval));
          polls++;
          continue;
        }
        
        // Handle network errors gracefully during startup
        if (polls < 40 && (error.message?.includes('NetworkError') || error.message?.includes('Failed to fetch'))) {
          updateStepStatus('metadata_extraction', { 
            status: 'running', 
            progress: Math.min(5 + polls, 15),
            substeps: ['Waiting for analysis to start...']
          });
          await new Promise(resolve => setTimeout(resolve, pollInterval));
          polls++;
          continue;
        }
        
        if (polls > 20) {
          throw error;
        }
        await new Promise(resolve => setTimeout(resolve, pollInterval));
        polls++;
      }
    }
    
    if (polls >= maxPolls) {
      throw { message: 'Analysis timed out after 30 minutes' };
    }
  };

  const startComprehensiveAnalysis = async () => {
    setIsRunning(true);
    setCurrentStepIndex(0);
    
    // Reset all steps
    setSteps(prevSteps => 
      prevSteps.map(step => ({ 
        ...step, 
        status: 'pending' as const, 
        progress: 0, 
        results: undefined, 
        error: undefined 
      }))
    );

    try {
      // Start the comprehensive analysis task on the backend
      toast.info('Starting comprehensive binary analysis...');
      const analysisResult = await apiClient.startComprehensiveAnalysis(binaryId);
      
      if (!analysisResult || !analysisResult.task_id) {
        throw { message: 'Failed to start comprehensive analysis - no task ID returned' };
      }
      
      toast.success('Comprehensive analysis started successfully!');
      
      // Monitor the comprehensive analysis task progress
      await monitorComprehensiveAnalysis(analysisResult.task_id);
      
      toast.success('Comprehensive analysis completed successfully!');
      
      if (onAnalysisComplete) {
        // Fetch the comprehensive analysis results
        try {
          const comprehensiveResults = await apiClient.getComprehensiveAnalysis(binaryId);
          if (comprehensiveResults && comprehensiveResults.analysis) {
            onAnalysisComplete(comprehensiveResults);
          } else {
            console.warn('Comprehensive analysis completed but no results available yet');
          }
        } catch (fetchError) {
          console.warn('Could not fetch comprehensive results for callback:', fetchError);
          // Continue anyway, the analysis completed successfully
        }
      }

    } catch (error: any) {
      toast.error(`Comprehensive analysis failed: ${error?.message || String(error)}`);
      console.error('Comprehensive analysis error:', error);
    } finally {
      setIsRunning(false);
    }
  };

  const resetAnalysis = () => {
    setSteps(prevSteps => 
      prevSteps.map(step => ({ 
        ...step, 
        status: 'pending' as const, 
        progress: 0, 
        results: undefined, 
        error: undefined
      }))
    );
    setIsRunning(false);
    setCurrentStepIndex(0);
    setOverallProgress(0);
  };

  const getStepStatusColor = (status: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
    switch (status) {
      case 'completed': return 'success';
      case 'running': return 'warning';
      case 'failed': return 'error';
      default: return 'default';
    }
  };

  const getStepStatusChipStyle = (status: string) => {
    switch (status) {
      case 'completed': 
        return { 
          bgcolor: 'rgba(76, 175, 80, 0.15)', 
          color: 'rgba(76, 175, 80, 0.9)',
          border: '1px solid rgba(76, 175, 80, 0.3)'
        };
      case 'running': 
        return { 
          bgcolor: 'rgba(255, 152, 0, 0.15)', 
          color: 'rgba(255, 152, 0, 0.9)',
          border: '1px solid rgba(255, 152, 0, 0.3)'
        };
      case 'failed': 
        return { 
          bgcolor: 'rgba(244, 67, 54, 0.15)', 
          color: 'rgba(244, 67, 54, 0.9)',
          border: '1px solid rgba(244, 67, 54, 0.3)'
        };
      default: 
        return { 
          bgcolor: 'rgba(158, 158, 158, 0.15)', 
          color: 'rgba(158, 158, 158, 0.9)',
          border: '1px solid rgba(158, 158, 158, 0.3)'
        };
    }
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h5">
          🔍 Comprehensive Binary Analysis
        </Typography>
        <Box display="flex" gap={2}>
          {!isRunning && (
            <Button
              variant="contained"
              onClick={startComprehensiveAnalysis}
              startIcon={<PlayArrow />}
              size="large"
            >
              Run Comprehensive Analysis
            </Button>
          )}
          {isRunning && (
            <Button
              variant="outlined"
              disabled
              startIcon={<Refresh />}
            >
              Analysis Running...
            </Button>
          )}
          <Button
            variant="outlined"
            onClick={resetAnalysis}
            startIcon={<Refresh />}
            disabled={isRunning}
          >
            Reset
          </Button>
        </Box>
      </Box>

      {/* Overall Progress */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
            <Typography variant="h6">Overall Progress</Typography>
            <Typography variant="h6" color="primary">
              {overallProgress}%
            </Typography>
          </Box>
          
          <LinearProgress
            variant="determinate"
            value={overallProgress}
            sx={{ height: 10, borderRadius: 5, mb: 2 }}
          />
          
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="body2" color="textSecondary">
                Steps Completed: {steps.filter(s => s.status === 'completed').length} / {steps.length}
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="body2" color="textSecondary">
                Currently Running: {steps[currentStepIndex]?.title || 'None'}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Horizontal Step Layout */}
      <Grid container spacing={2}>
        {steps.map((step, index) => (
          <Grid item xs={12} sm={6} md={2.4} key={step.id}>
            <Card 
              sx={{ 
                height: '100%',
                minHeight: 120,
                display: 'flex',
                flexDirection: 'column',
                                 border: step.status === 'running' ? '2px solid' : '1px solid',
                 borderColor: step.status === 'running' ? 'rgba(255, 152, 0, 0.3)' : 
                            step.status === 'completed' ? 'rgba(76, 175, 80, 0.3)' :
                            step.status === 'failed' ? 'rgba(244, 67, 54, 0.3)' : 'rgba(255, 255, 255, 0.1)',
                position: 'relative',
                transition: 'all 0.3s ease'
              }}
            >
              <CardContent sx={{ p: 2, flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
                {/* Step Icon and Status */}
                <Box display="flex" alignItems="center" justifyContent="space-between" mb={1}>
                  <Box>
                    {step.status === 'completed' ? (
                      <CheckCircle color="success" sx={{ fontSize: 20 }} />
                    ) : step.status === 'failed' ? (
                      <Error color="error" sx={{ fontSize: 20 }} />
                    ) : step.status === 'running' ? (
                      <CircularProgress size={20} />
                    ) : (
                      React.cloneElement(step.icon as React.ReactElement, { sx: { fontSize: 20 } })
                    )}
                  </Box>
                                     <Chip 
                     label={step.status}
                     size="small"
                     sx={{
                       ...getStepStatusChipStyle(step.status),
                       fontSize: '0.75rem',
                       height: 20
                     }}
                   />
                </Box>

                {/* Step Title */}
                <Typography 
                  variant="subtitle2" 
                  fontWeight="bold" 
                  sx={{ mb: 1, fontSize: '0.875rem', lineHeight: 1.2 }}
                >
                  {step.title}
                </Typography>

                {/* Progress for Running Step */}
                {step.status === 'running' && (
                  <Box sx={{ mt: 'auto' }}>
                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={0.5}>
                      <Typography variant="caption" color="textSecondary">
                        Progress
                      </Typography>
                      <Typography variant="caption" fontWeight="medium">
                        {step.progress}%
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={step.progress}
                      sx={{ height: 4, borderRadius: 2 }}
                    />
                  </Box>
                )}

                {/* Completion Time for Completed Steps */}
                {step.status === 'completed' && (
                  <Box sx={{ mt: 'auto' }}>
                                         <Typography variant="caption" sx={{ color: 'rgba(76, 175, 80, 0.9)' }} fontWeight="medium">
                       ✓ Completed
                     </Typography>
                  </Box>
                )}

                {/* Error for Failed Steps */}
                {step.status === 'failed' && (
                  <Box sx={{ mt: 'auto' }}>
                                         <Typography variant="caption" sx={{ color: 'rgba(244, 67, 54, 0.9)' }} fontWeight="medium">
                       ✗ Failed
                     </Typography>
                  </Box>
                )}

                {/* Pending State */}
                {step.status === 'pending' && (
                  <Box sx={{ mt: 'auto' }}>
                    <Typography variant="caption" color="textSecondary">
                      Waiting...
                    </Typography>
                  </Box>
                )}
              </CardContent>

              {/* Step Number Badge */}
              <Box
                sx={{
                  position: 'absolute',
                  top: -8,
                  left: -8,
                  width: 24,
                  height: 24,
                  borderRadius: '50%',
                                     bgcolor: step.status === 'completed' ? 'rgba(76, 175, 80, 0.8)' :
                            step.status === 'running' ? 'rgba(255, 152, 0, 0.8)' :
                            step.status === 'failed' ? 'rgba(244, 67, 54, 0.8)' : 'rgba(158, 158, 158, 0.6)',
                  color: 'white',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem',
                  fontWeight: 'bold'
                }}
              >
                {index + 1}
              </Box>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Current Step Details (Only when running) */}
      {steps.some(step => step.status === 'running') && (
                                   <Card sx={{ mt: 2, bgcolor: 'rgba(255, 152, 0, 0.05)', border: '1px solid rgba(255, 152, 0, 0.1)' }}>
          <CardContent sx={{ py: 2 }}>
            {steps.filter(step => step.status === 'running').map(step => (
              <Box key={step.id}>
                                 <Typography variant="body2" fontWeight="medium" sx={{ color: 'rgba(255, 152, 0, 0.9)' }}>
                   Currently Running: {step.title}
                 </Typography>
                <Typography variant="body2" color="textSecondary" sx={{ mt: 0.5 }}>
                  {step.description}
                </Typography>
                {step.substeps && step.substeps.length > 0 && (
                  <Typography variant="caption" color="textSecondary" sx={{ mt: 0.5, display: 'block' }}>
                    {step.substeps[step.substeps.length - 1]}
                  </Typography>
                )}
              </Box>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Error Details (Only when there are failures) */}
      {steps.some(step => step.status === 'failed') && (
        <Card sx={{ mt: 2 }}>
          <CardContent sx={{ py: 2 }}>
                         <Typography variant="subtitle2" sx={{ color: 'rgba(244, 67, 54, 0.9)' }} fontWeight="bold" gutterBottom>
               Failed Steps
             </Typography>
            {steps.filter(step => step.status === 'failed').map(step => (
              <Alert severity="error" key={step.id} sx={{ mt: 1, py: 1 }}>
                <Typography variant="body2" fontWeight="medium">
                  {step.title}: {step.error}
                </Typography>
              </Alert>
            ))}
          </CardContent>
        </Card>
      )}
    </Paper>
  );
};

export default ComprehensiveAnalysisWorkflow; 