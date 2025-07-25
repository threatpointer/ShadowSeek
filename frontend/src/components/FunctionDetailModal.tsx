import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Chip,
  LinearProgress,
  Alert,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableRow,
  IconButton,
  Tooltip,
  Paper,
  Divider,
  CircularProgress
} from '@mui/material';
import {
  Close,
  Code,
  Psychology,
  AccountTree,
  Security,
  Refresh,
  Download,
  BugReport
} from '@mui/icons-material';
import SyntaxHighlighter from 'react-syntax-highlighter';
// @ts-ignore - Type definitions missing for style imports
import tomorrow from 'react-syntax-highlighter/dist/styles/tomorrow';
import { toast } from 'react-toastify';
import { Function } from '../utils/api';
import type { OverridableStringUnion } from '@mui/types';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div hidden={value !== index}>
    {value === index && <Box sx={{ p: 2 }}>{children}</Box>}
  </div>
);

interface FunctionDetailModalProps {
  open: boolean;
  onClose: () => void;
  functionData: Function | null;
  binaryId: string;
}

const FunctionDetailModal: React.FC<FunctionDetailModalProps> = ({
  open,
  onClose,
  functionData,
  binaryId
}) => {
  const [tabValue, setTabValue] = useState(0);
  const [decompiling, setDecompiling] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [decompiled, setDecompiled] = useState<any>(null);
  const [aiExplanation, setAiExplanation] = useState<any>(null);
  const [functionDetails, setFunctionDetails] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (open && functionData) {
      fetchFunctionDetails();
    }
  }, [open, functionData]);

  const fetchFunctionDetails = async () => {
    if (!functionData) return;
    
    try {
      setLoading(true);
      const response = await fetch(`/api/functions/${functionData.id}`);
      if (response.ok) {
        const data = await response.json();
        setFunctionDetails(data.function);
        
        // If already decompiled, set the data
        if (data.function.is_decompiled && data.function.decompiled_code) {
          setDecompiled({
            success: true,
            decompiled_code: data.function.decompiled_code,
            cached: true
          });
        }
        
        // If already explained, set the data
        if (data.function.ai_analyzed && data.function.ai_summary) {
          setAiExplanation({
            success: true,
            ai_summary: data.function.ai_summary,
            risk_score: data.function.risk_score,
            cached: true
          });
        }
      }
    } catch (err) {
      console.error('Error fetching function details:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDecompile = async () => {
    if (!functionData) return;
    
    try {
      setDecompiling(true);
      const response = await fetch(`/api/functions/${functionData.id}/decompile`, {
        method: 'POST'
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.cached) {
          setDecompiled(data);
          toast.success('Decompiled code loaded from cache');
        } else {
          toast.success('Decompilation started. Please wait...');
          // Poll for completion
          pollDecompilationStatus();
        }
      } else {
        const errorData = await response.json();
        toast.error(`Decompilation failed: ${errorData.error}`);
      }
    } catch (err) {
      toast.error('Failed to start decompilation');
      console.error('Decompilation error:', err);
    } finally {
      setDecompiling(false);
    }
  };

  const handleExplain = async () => {
    if (!functionData) return;
    
    try {
      setExplaining(true);
      const response = await fetch(`/api/functions/${functionData.id}/explain`, {
        method: 'POST'
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.cached) {
          setAiExplanation(data);
          toast.success('AI explanation loaded from cache');
        } else {
          toast.success('AI explanation started. Please wait...');
          // Poll for completion
          pollExplanationStatus();
        }
      } else {
        const errorData = await response.json();
        toast.error(`AI explanation failed: ${errorData.error}`);
      }
    } catch (err) {
      toast.error('Failed to start AI explanation');
      console.error('AI explanation error:', err);
    } finally {
      setExplaining(false);
    }
  };

  const pollDecompilationStatus = () => {
    const interval = setInterval(async () => {
      try {
        const response = await fetch(`/api/functions/${functionData?.id}`);
        if (response.ok) {
          const data = await response.json();
          if (data.function.is_decompiled && data.function.decompiled_code) {
            setDecompiled({
              success: true,
              decompiled_code: data.function.decompiled_code,
              cached: false
            });
            setFunctionDetails(data.function);
            toast.success('Decompilation completed!');
            clearInterval(interval);
          }
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 3000);

    // Stop polling after 5 minutes
    setTimeout(() => clearInterval(interval), 300000);
  };

  const pollExplanationStatus = () => {
    const interval = setInterval(async () => {
      try {
        const response = await fetch(`/api/functions/${functionData?.id}`);
        if (response.ok) {
          const data = await response.json();
          if (data.function.ai_analyzed && data.function.ai_summary) {
            setAiExplanation({
              success: true,
              ai_summary: data.function.ai_summary,
              risk_score: data.function.risk_score,
              cached: false
            });
            setFunctionDetails(data.function);
            toast.success('AI explanation completed!');
            clearInterval(interval);
          }
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 3000);

    // Stop polling after 5 minutes
    setTimeout(() => clearInterval(interval), 300000);
  };

  // Utility for risk score mapping
  const getRiskLevelAndExplanation = (score: number) => {
    if (score >= 81) return { level: 'Critical', color: 'error', explanation: 'Critical risk - remote code execution, privilege escalation, or system compromise.' };
    if (score >= 61) return { level: 'High', color: 'warning', explanation: 'High risk - easily exploitable, significant impact potential.' };
    if (score >= 41) return { level: 'Medium', color: 'info', explanation: 'Medium risk - exploitable vulnerabilities with moderate impact.' };
    if (score >= 21) return { level: 'Low', color: 'success', explanation: 'Low risk - minor issues, hard to exploit, limited impact.' };
    return { level: 'Info', color: 'info', explanation: 'Minimal risk - well-bounded, validated inputs, safe operations.' }; // Use 'info' instead of 'default'
  };

  if (!functionData) return null;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="lg"
      fullWidth
      PaperProps={{
        sx: { height: '90vh' }
      }}
    >
      <DialogTitle>
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Typography variant="h6">
              {functionData.name || functionData.original_name || 'Unknown Function'}
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ fontFamily: 'monospace' }}>
              {functionData.address}
            </Typography>
          </Box>
          <Box display="flex" gap={1}>
            {aiExplanation?.risk_score !== undefined && (
              <Chip
                icon={<Security />}
                label={`Risk: ${getRiskLevelAndExplanation(aiExplanation.risk_score).level} (${aiExplanation.risk_score})`}
                color={getRiskLevelAndExplanation(aiExplanation.risk_score).color as OverridableStringUnion<'default' | 'error' | 'warning' | 'info' | 'success' | 'primary' | 'secondary', {}>}
                variant="outlined"
              />
            )}
            <IconButton onClick={onClose}>
              <Close />
            </IconButton>
          </Box>
        </Box>
      </DialogTitle>

      <DialogContent dividers>
        {loading ? (
          <Box display="flex" justifyContent="center" alignItems="center" height="400px">
            <CircularProgress />
          </Box>
        ) : (
          <>
            {/* Action Buttons */}
            <Box display="flex" gap={2} mb={3}>
              <Button
                variant={decompiled ? "outlined" : "contained"}
                startIcon={decompiling ? <CircularProgress size={16} /> : <Code />}
                onClick={handleDecompile}
                disabled={decompiling}
                color={decompiled ? "success" : "primary"}
              >
                {decompiling ? 'Decompiling...' : decompiled ? 'Decompiled ✓' : 'Decompile Function'}
              </Button>
              
              <Button
                variant={aiExplanation ? "outlined" : "contained"}
                startIcon={explaining ? <CircularProgress size={16} /> : <Psychology />}
                onClick={handleExplain}
                disabled={explaining || !decompiled}
                color={aiExplanation ? "success" : "secondary"}
              >
                {explaining ? 'Analyzing...' : aiExplanation ? 'Explained ✓' : 'AI Explanation'}
              </Button>
              
              <Button
                variant="outlined"
                startIcon={<AccountTree />}
                onClick={() => window.open(`/cfg/${binaryId}/${functionData.address}`, '_blank')}
              >
                View CFG
              </Button>
            </Box>

            {/* Tabs */}
            <Paper>
              <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
                <Tab label="Overview" />
                <Tab label="Decompiled Code" disabled={!decompiled} />
                <Tab label="AI Analysis" disabled={!aiExplanation} />
                <Tab label="Details" />
              </Tabs>

              <TabPanel value={tabValue} index={0}>
                <Grid container spacing={3}>
                  <Grid item xs={12} md={6}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          Function Information
                        </Typography>
                        <Table size="small">
                          <TableBody>
                            <TableRow>
                              <TableCell><strong>Name</strong></TableCell>
                              <TableCell>{functionData.name || 'Unknown'}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell><strong>Address</strong></TableCell>
                              <TableCell sx={{ fontFamily: 'monospace' }}>{functionData.address}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell><strong>Size</strong></TableCell>
                              <TableCell>{functionData.size ? `${functionData.size} bytes` : 'Unknown'}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell><strong>Parameters</strong></TableCell>
                              <TableCell>{functionData.parameter_count || 0}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell><strong>Calling Convention</strong></TableCell>
                              <TableCell>{functionData.calling_convention || 'Unknown'}</TableCell>
                            </TableRow>
                            <TableRow>
                              <TableCell><strong>Return Type</strong></TableCell>
                              <TableCell>{functionData.return_type || 'Unknown'}</TableCell>
                            </TableRow>
                          </TableBody>
                        </Table>
                      </CardContent>
                    </Card>
                  </Grid>

                  <Grid item xs={12} md={6}>
                    <Card>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          Analysis Status
                        </Typography>
                        <Box display="flex" flexWrap="wrap" gap={1} mb={2}>
                          {functionData.is_analyzed && (
                            <Chip label="Analyzed" color="success" size="small" />
                          )}
                          {functionData.is_decompiled && (
                            <Chip label="Decompiled" color="info" size="small" />
                          )}
                          {functionData.ai_analyzed && (
                            <Chip label="AI Analyzed" color="secondary" size="small" />
                          )}
                          {functionData.has_cfg && (
                            <Chip label="CFG Available" color="primary" size="small" />
                          )}
                          {functionData.is_thunk && (
                            <Chip label="Thunk" color="default" size="small" />
                          )}
                          {functionData.is_external && (
                            <Chip label="External" color="default" size="small" />
                          )}
                        </Box>

                        {aiExplanation?.risk_score !== undefined && (
                          <Box mt={2}>
                            <Typography variant="subtitle2" gutterBottom>
                              Security Risk Score
                            </Typography>
                            <Box display="flex" alignItems="center" gap={2}>
                              <LinearProgress
                                variant="determinate"
                                value={aiExplanation.risk_score}
                                color={getRiskLevelAndExplanation(aiExplanation.risk_score).color as OverridableStringUnion<'error' | 'success' | 'info' | 'warning' | 'primary' | 'secondary', {}>}
                                sx={{ flexGrow: 1, height: 8, borderRadius: 4 }}
                              />
                              <Typography variant="body2" fontWeight="bold">
                                {aiExplanation.risk_score}/100
                              </Typography>
                            </Box>
                            <Typography variant="caption" color="textSecondary">
                              Risk Level: {getRiskLevelAndExplanation(aiExplanation.risk_score).level}
                            </Typography>
                          </Box>
                        )}
                      </CardContent>
                    </Card>
                  </Grid>
                </Grid>
              </TabPanel>

              <TabPanel value={tabValue} index={1}>
                {decompiled ? (
                  <Box>
                    <Box display="flex" justifyContent="between" alignItems="center" mb={2}>
                      <Typography variant="h6">Decompiled C Code</Typography>
                      {decompiled.cached && (
                        <Chip label="Cached" size="small" color="info" />
                      )}
                    </Box>
                    <Paper sx={{ p: 0, maxHeight: '60vh', overflow: 'auto' }}>
                      <SyntaxHighlighter
                        language="c"
                        style={tomorrow}
                        showLineNumbers
                        customStyle={{
                          margin: 0,
                          borderRadius: 0,
                          fontSize: '14px'
                        }}
                      >
                        {decompiled.decompiled_code}
                      </SyntaxHighlighter>
                    </Paper>
                  </Box>
                ) : (
                  <Box textAlign="center" py={4}>
                    <BugReport sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                    <Typography variant="h6" color="textSecondary" gutterBottom>
                      Function Not Decompiled
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Click the "Decompile Function" button to view the decompiled C code.
                    </Typography>
                  </Box>
                )}
              </TabPanel>

              <TabPanel value={tabValue} index={2}>
                {aiExplanation ? (
                  <Box>
                    <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                      <Typography variant="h6">AI Analysis</Typography>
                      {aiExplanation.cached && (
                        <Chip label="Cached" size="small" color="info" sx={{ ml: 1 }} />
                      )}
                    </Box>
                    {/* Risk Score Card */}
                    {aiExplanation.risk_score !== undefined && (() => {
                      const { level, color, explanation } = getRiskLevelAndExplanation(aiExplanation.risk_score);
                      return (
                        <Card sx={{ mb: 3 }}>
                          <CardContent>
                            <Box display="flex" alignItems="center" gap={2} mb={2}>
                              <Security color={color as OverridableStringUnion<'error' | 'success' | 'info' | 'warning' | 'primary' | 'secondary', {}>} />
                              <Typography variant="h6">
                                Security Risk Assessment
                              </Typography>
                            </Box>
                            <Box display="flex" alignItems="center" gap={2} mb={2}>
                              <Box flexGrow={1}>
                                <LinearProgress
                                  variant="determinate"
                                  value={aiExplanation.risk_score}
                                  color={color as OverridableStringUnion<'error' | 'success' | 'info' | 'warning' | 'primary' | 'secondary', {}>}
                                  sx={{ height: 12, borderRadius: 6 }}
                                />
                              </Box>
                              <Chip
                                label={`${aiExplanation.risk_score}/100`}
                                color={color as OverridableStringUnion<'default' | 'error' | 'success' | 'info' | 'warning' | 'primary' | 'secondary', {}>}
                                variant="outlined"
                              />
                              <Chip
                                label={level}
                                color={color as OverridableStringUnion<'default' | 'error' | 'success' | 'info' | 'warning' | 'primary' | 'secondary', {}>}
                                size="small"
                              />
                            </Box>
                            <Typography variant="body2" color="textSecondary" sx={{ mb: 1 }}>
                              {explanation}
                            </Typography>
                            <Divider sx={{ my: 2 }} />
                          </CardContent>
                        </Card>
                      );
                    })()}
                    {/* AI Explanation */}
                    <Card>
                      <CardContent>
                        <Typography variant="h6" gutterBottom>
                          Function Explanation
                        </Typography>
                        <Typography variant="body1" sx={{ whiteSpace: 'pre-line', lineHeight: 1.6 }}>
                          {aiExplanation.ai_summary}
                        </Typography>
                      </CardContent>
                    </Card>
                  </Box>
                ) : (
                  <Box textAlign="center" py={4}>
                    <Psychology sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                    <Typography variant="h6" color="textSecondary" gutterBottom>
                      No AI Analysis Available
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Decompile the function first, then click "AI Explanation" for detailed analysis.
                    </Typography>
                  </Box>
                )}
              </TabPanel>

              <TabPanel value={tabValue} index={3}>
                {functionDetails && (
                  <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                      <Card>
                        <CardContent>
                          <Typography variant="h6" gutterBottom>
                            Parameters ({functionDetails.parameters?.length || 0})
                          </Typography>
                          {functionDetails.parameters?.length ? (
                            <Table size="small">
                              <TableBody>
                                {functionDetails.parameters.map((param: any, index: number) => (
                                  <TableRow key={index}>
                                    <TableCell><strong>{param.name}</strong></TableCell>
                                    <TableCell>{param.datatype}</TableCell>
                                    <TableCell>{param.size} bytes</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          ) : (
                            <Typography variant="body2" color="textSecondary">
                              No parameters found
                            </Typography>
                          )}
                        </CardContent>
                      </Card>
                    </Grid>

                    <Grid item xs={12} md={6}>
                      <Card>
                        <CardContent>
                          <Typography variant="h6" gutterBottom>
                            Local Variables ({functionDetails.local_variables?.length || 0})
                          </Typography>
                          {functionDetails.local_variables?.length ? (
                            <Table size="small">
                              <TableBody>
                                {functionDetails.local_variables.map((variable: any, index: number) => (
                                  <TableRow key={index}>
                                    <TableCell><strong>{variable.name}</strong></TableCell>
                                    <TableCell>{variable.datatype}</TableCell>
                                    <TableCell>{variable.storage}</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          ) : (
                            <Typography variant="body2" color="textSecondary">
                              No local variables found
                            </Typography>
                          )}
                        </CardContent>
                      </Card>
                    </Grid>

                    <Grid item xs={12}>
                      <Card>
                        <CardContent>
                          <Typography variant="h6" gutterBottom>
                            Function Calls ({functionDetails.function_calls?.length || 0})
                          </Typography>
                          {functionDetails.function_calls?.length ? (
                            <Table size="small">
                              <TableBody>
                                {functionDetails.function_calls.map((call: any, index: number) => (
                                  <TableRow key={index}>
                                    <TableCell sx={{ fontFamily: 'monospace' }}>{call.source_address}</TableCell>
                                    <TableCell>→</TableCell>
                                    <TableCell sx={{ fontFamily: 'monospace' }}>{call.target_address}</TableCell>
                                    <TableCell>{call.call_type}</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          ) : (
                            <Typography variant="body2" color="textSecondary">
                              No function calls found
                            </Typography>
                          )}
                        </CardContent>
                      </Card>
                    </Grid>
                  </Grid>
                )}
              </TabPanel>
            </Paper>
          </>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        <Button
          variant="outlined"
          startIcon={<Refresh />}
          onClick={fetchFunctionDetails}
          disabled={loading}
        >
          Refresh
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default FunctionDetailModal; 