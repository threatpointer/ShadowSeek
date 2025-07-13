import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Grid,
  Card,
  CardContent,
  Alert,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  Stack,
  CircularProgress,
  Pagination,
  Switch,
  FormControlLabel,
  OutlinedInput,
  Slider,
  Collapse,
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton
} from '@mui/material';
import {
  BugReport,
  PlayArrow,
  ExpandMore,
  ExpandLess,
  Download,
  Refresh,
  FilterList,
  Search,
  Code,
  Analytics,
  TrendingUp,
  Psychology,
  Pattern,
  Speed,
  Build,
  FlashOn,
  CheckCircle,
  Delete,
  ContentCopy,
  Close,
  Description
} from '@mui/icons-material';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, ResponsiveContainer } from 'recharts';
import { toast } from 'react-toastify';
import { apiClient } from '../utils/api';
// @ts-ignore - Type definitions missing for style imports
import atomOneDark from 'react-syntax-highlighter/dist/styles/atom-one-dark';
import SyntaxHighlighter from 'react-syntax-highlighter';

// Types for fuzzing system
interface Binary {
  id: string;
  filename: string;
  original_filename: string;
  analysis_status: string;
}

interface FuzzingHarness {
  id: string;
  binary_id: string;
  function_id?: string;
  target_function: string;
  harness_name: string;
  harness_type: 'AFL' | 'AFL++' | 'LibFuzzer' | 'Honggfuzz';
  generation_method: 'AI' | 'Template' | 'Manual';
  status: 'generated' | 'compiled' | 'tested' | 'ready' | 'error';
  ai_analysis?: {
    input_analysis: string;
    vulnerability_targets: string[];
    recommended_strategy: string;
  };
  technical_details: {
    target_address?: string;
    input_format?: string;
    seed_inputs?: string[];
    compilation_flags?: string[];
    runtime_options?: string[];
  };
  performance_metrics?: {
    generation_time: number;
    code_coverage: number;
    crashes_found: number;
    test_cases_generated: number;
  };
  created_at: string;
  updated_at: string;
}

interface FuzzingSummary {
  total: number;
  harness_distribution: {
    afl: number;
    aflplusplus: number;
    libfuzzer: number;
    honggfuzz: number;
  };
}

interface FuzzingDashboardProps {
  binaryId?: string;
}

const FuzzingDashboard: React.FC<FuzzingDashboardProps> = ({ binaryId }) => {
  const [binaries, setBinaries] = useState<Binary[]>([]);
  const [selectedBinary, setSelectedBinary] = useState<string | null>(binaryId || null);
  const [harnesses, setHarnesses] = useState<FuzzingHarness[]>([]);
  const [summary, setSummary] = useState<FuzzingSummary | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [generationRunning, setGenerationRunning] = useState(false);
  
  // Enhanced filtering and search state
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterHarnessType, setFilterHarnessType] = useState('');
  const [showOnlyAIGenerated, setShowOnlyAIGenerated] = useState(false);

  // Fuzzer selection and configuration state
  const [supportedFuzzers, setSupportedFuzzers] = useState<any[]>([]);
  const [selectedFuzzers, setSelectedFuzzers] = useState<string[]>(['AFL++']);
  const [minRiskScore, setMinRiskScore] = useState(40);
  const [targetSeverities, setTargetSeverities] = useState<string[]>(['HIGH', 'MEDIUM']);
  const [aiEnabled, setAiEnabled] = useState(true);
  const [includeSeeds, setIncludeSeeds] = useState(true);
  const [showAdvanced, setShowAdvanced] = useState(false);
  
  // Filter options
  const statusOptions = ['ready', 'tested', 'compiled', 'generated', 'error'];
  const harnessTypeOptions = ['AFL++', 'AFL', 'LibFuzzer', 'Honggfuzz'];

  // Code viewing state
  const [viewingHarness, setViewingHarness] = useState<any>(null);
  const [viewingContent, setViewingContent] = useState<{ type: string; content: string; language: string } | null>(null);
  const [codeLoading, setCodeLoading] = useState(false);

  const fetchBinaries = useCallback(async () => {
    try {
      setLoading(true);
      // Get all binaries instead of just fuzzing-ready ones
      const response = await apiClient.getBinaries(1, 100);
      setBinaries(response.binaries || []);
      setError(null);
    } catch (err: any) {
      const errorMessage = err.response?.data?.error || err.message || 'Failed to load binaries';
      setError(errorMessage);
      toast.error(errorMessage);
      console.error('Binaries loading error:', err);
      setBinaries([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadSupportedFuzzers = useCallback(async () => {
    try {
      const response = await apiClient.getSupportedFuzzers();
      setSupportedFuzzers(response.supported_fuzzers || []);
    } catch (err) {
      console.error('Error loading supported fuzzers:', err);
    }
  }, []);

  const clearFuzzingData = useCallback(() => {
    setHarnesses([]);
    setSummary(null);
    setError(null);
  }, []);

  const loadFuzzingData = useCallback(async () => {
    if (!selectedBinary) {
      clearFuzzingData();
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      console.log(`Loading fuzzing data for binary ${selectedBinary}`);
      
      const response = await apiClient.getFuzzingHarnesses(selectedBinary);
      
      if (!response.harnesses) {
        console.warn('No harnesses property in response:', response);
        setHarnesses([]);
        setSummary({
          total: 0,
          harness_distribution: { afl: 0, aflplusplus: 0, libfuzzer: 0, honggfuzz: 0 }
        });
        return;
      }

      // Apply filters
      let filteredHarnesses = response.harnesses;
      
      if (searchTerm) {
        filteredHarnesses = filteredHarnesses.filter((h: FuzzingHarness) => 
          h.harness_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          h.target_function?.toLowerCase().includes(searchTerm.toLowerCase())
        );
      }
      
      if (filterStatus) {
        filteredHarnesses = filteredHarnesses.filter((h: FuzzingHarness) => h.status === filterStatus);
      }
      
      if (filterHarnessType) {
        filteredHarnesses = filteredHarnesses.filter((h: FuzzingHarness) => h.harness_type === filterHarnessType);
      }
      
      if (showOnlyAIGenerated) {
        filteredHarnesses = filteredHarnesses.filter((h: FuzzingHarness) => h.generation_method === 'AI');
      }
      
      setHarnesses(filteredHarnesses);
      
             // Generate summary
       const summary: FuzzingSummary = {
         total: filteredHarnesses.length,
         harness_distribution: {
           afl: filteredHarnesses.filter((h: FuzzingHarness) => h.harness_type === 'AFL').length,
           aflplusplus: filteredHarnesses.filter((h: FuzzingHarness) => h.harness_type === 'AFL++').length,
           libfuzzer: filteredHarnesses.filter((h: FuzzingHarness) => h.harness_type === 'LibFuzzer').length,
           honggfuzz: filteredHarnesses.filter((h: FuzzingHarness) => h.harness_type === 'Honggfuzz').length
         }
       };
      setSummary(summary);
      
         } catch (err: any) {
       const errorMessage = err.response?.data?.error || err.message || 'Failed to load fuzzing data';
       setError(errorMessage);
       toast.error(errorMessage);
       console.error('Fuzzing data error:', err);
       
       // Set empty state on error
       setHarnesses([]);
       setSummary({
         total: 0,
         harness_distribution: { afl: 0, aflplusplus: 0, libfuzzer: 0, honggfuzz: 0 }
       });
     } finally {
       setLoading(false);
     }
  }, [selectedBinary, filterStatus, filterHarnessType, searchTerm, showOnlyAIGenerated]);

  useEffect(() => {
    fetchBinaries();
    loadSupportedFuzzers();
  }, [fetchBinaries, loadSupportedFuzzers]);

  useEffect(() => {
    if (binaryId && binaries.length > 0 && !selectedBinary) {
      // Auto-select binary if binaryId prop is provided
      const binary = binaries.find(b => b.id === binaryId);
      if (binary) {
        setSelectedBinary(binaryId);
      }
    }
  }, [binaryId, binaries, selectedBinary]);

  useEffect(() => {
    if (selectedBinary) {
      loadFuzzingData();
    } else {
      clearFuzzingData();
    }
  }, [selectedBinary, loadFuzzingData, clearFuzzingData]);

  const handleFuzzerToggle = (fuzzerName: string) => {
    setSelectedFuzzers(prev => 
      prev.includes(fuzzerName) 
        ? prev.filter(f => f !== fuzzerName)
        : [...prev, fuzzerName]
    );
  };

  const handleViewContent = async (harness: any, contentType: 'harness' | 'makefile' | 'readme') => {
    try {
      setCodeLoading(true);
      const response = await fetch(`/api/fuzzing-harnesses/${harness.id}`);
      const harnessDetails = await response.json();
      
      let content = '';
      let language = 'text';
      
      switch (contentType) {
        case 'harness':
          content = harnessDetails.harness_code || 'No harness code available';
          language = 'c';
          break;
        case 'makefile':
          content = harnessDetails.makefile_content || 'No Makefile available';
          language = 'makefile';
          break;
        case 'readme':
          content = harnessDetails.readme_content || 'No README available';
          language = 'markdown';
          break;
      }
      
      setViewingHarness(harness);
      setViewingContent({ type: contentType, content, language });
    } catch (err: any) {
      toast.error(`Failed to load ${contentType}: ${err.message}`);
    } finally {
      setCodeLoading(false);
    }
  };

  const handleDeleteHarness = async (harnessId: string, harnessName: string) => {
    if (!window.confirm(`Are you sure you want to delete "${harnessName}"?`)) {
      return;
    }
    
    try {
      await apiClient.deleteFuzzingHarness(harnessId);
      toast.success('Fuzzing harness deleted successfully');
      loadFuzzingData(); // Reload the list
    } catch (err: any) {
      toast.error(`Failed to delete harness: ${err.message}`);
    }
  };

  const handleCopyToClipboard = (content: string) => {
    navigator.clipboard.writeText(content);
    toast.success('Copied to clipboard');
  };

  const generateFuzzingHarness = async () => {
    if (!selectedBinary) {
      toast.error('Please select a binary for fuzzing harness generation');
      return;
    }

    if (selectedFuzzers.length === 0) {
      toast.error('Please select at least one fuzzer type');
      return;
    }

    // Check if the selected binary is ready for fuzzing
    const selectedBinaryData = binaries.find(b => b.id === selectedBinary);
    if (!selectedBinaryData) {
      toast.error('Selected binary not found');
      return;
    }

    // Provide helpful guidance based on binary status
    const status = selectedBinaryData.analysis_status.toLowerCase();
    switch (status) {
      case 'pending':
        toast.warning('This binary is still pending initial analysis. Please wait for basic analysis to complete before generating fuzzing harnesses.');
        return;
      case 'analyzing':
      case 'processing':
        toast.warning('This binary is currently being analyzed. Please wait for the current analysis to complete before generating fuzzing harnesses.');
        return;
      case 'failed':
      case 'error':
        toast.error('This binary failed analysis and cannot be used for fuzzing. Try re-uploading the binary.');
        return;
      case 'decompiled':
      case 'completed':
      case 'analyzed':
        // These are good to proceed with fuzzing
        break;
      default:
        // For any other status, allow the generation but warn the user
        toast.warning(`Binary status is '${selectedBinaryData.analysis_status}'. Fuzzing harness generation will proceed but results may be limited.`);
        break;
    }

    try {
      setGenerationRunning(true);
      setError(null);
      
      console.log(`Starting fuzzing harness generation for binary ${selectedBinary} with fuzzers: ${selectedFuzzers.join(', ')}`);
      
      const generationResponse = await apiClient.generateFuzzingHarness(selectedBinary, {
        harness_types: selectedFuzzers,
        min_risk_score: minRiskScore,
        target_severities: targetSeverities,
        ai_enabled: aiEnabled,
        include_seeds: includeSeeds
      });
      
      console.log('Fuzzing harness generation response:', generationResponse);
      
      const harnessCount = generationResponse.harnesses?.length || generationResponse.summary?.total_harnesses || 1;
      toast.success(`${harnessCount} fuzzing harness(es) generated successfully for ${selectedFuzzers.join(', ')}`);
      
      // Reload data after a short delay
      setTimeout(() => {
        loadFuzzingData();
      }, 2000);
      
    } catch (err: any) {
      const errorMessage = err.response?.data?.error || err.message || 'Failed to start fuzzing harness generation';
      setError(errorMessage);
      toast.error(errorMessage);
      console.error('Fuzzing harness generation error:', err);
    } finally {
      setGenerationRunning(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'ready': return '#4caf50';
      case 'tested': return '#2196f3';
      case 'compiled': return '#ff9800';
      case 'generated': return '#9c27b0';
      case 'error': return '#f44336';
      default: return '#757575';
    }
  };

  const getHarnessTypeColor = (type: string) => {
    switch (type) {
      case 'AFL++': return '#e91e63';
      case 'AFL': return '#f44336';
      case 'LibFuzzer': return '#3f51b5';
      case 'Honggfuzz': return '#ff9800';
      default: return '#757575';
    }
  };

  const exportHarnesses = () => {
    if (!harnesses || harnesses.length === 0) {
      toast.error('No fuzzing harnesses to export');
      return;
    }

    const exportData = {
      binary_id: selectedBinary,
      binary_name: binaries.find(b => b.id === selectedBinary)?.original_filename,
      summary,
      harnesses,
      exported_at: new Date().toISOString(),
      export_metadata: {
        total_harnesses: harnesses.length,
        filters_applied: {
          status: filterStatus,
          harness_type: filterHarnessType,
          search_term: searchTerm,
          ai_only: showOnlyAIGenerated
        }
      }
    };

    const dataStr = JSON.stringify(exportData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    
    const binary = binaries.find(b => b.id === selectedBinary);
    const filename = `shadowseek_fuzzing_harnesses_${binary?.original_filename || selectedBinary}_${new Date().toISOString().split('T')[0]}.json`;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
    
    toast.success('Fuzzing harnesses exported successfully');
  };

  const renderFuzzingMetrics = () => {
    if (!summary) return null;

    // Use harnesses array directly instead of summary for status distribution
    const statusCounts = {
      ready: harnesses.filter((h: FuzzingHarness) => h.status === 'ready').length,
      tested: harnesses.filter((h: FuzzingHarness) => h.status === 'tested').length,
      compiled: harnesses.filter((h: FuzzingHarness) => h.status === 'compiled').length,
      generated: harnesses.filter((h: FuzzingHarness) => h.status === 'generated').length,
      error: harnesses.filter((h: FuzzingHarness) => h.status === 'error').length
    };

    const statusData = [
      { name: 'Ready', value: statusCounts.ready, color: '#4caf50' },
      { name: 'Tested', value: statusCounts.tested, color: '#2196f3' },
      { name: 'Compiled', value: statusCounts.compiled, color: '#ff9800' },
      { name: 'Generated', value: statusCounts.generated, color: '#9c27b0' },
      { name: 'Error', value: statusCounts.error, color: '#f44336' }
    ].filter(item => item.value > 0);

    const harnessTypeData = [
      { name: 'AFL++', value: summary.harness_distribution.aflplusplus, color: '#e91e63' },
      { name: 'AFL', value: summary.harness_distribution.afl, color: '#f44336' },
      { name: 'LibFuzzer', value: summary.harness_distribution.libfuzzer, color: '#3f51b5' },
      { name: 'Honggfuzz', value: summary.harness_distribution.honggfuzz, color: '#ff9800' }
    ].filter(item => item.value > 0);

    return (
      <Box sx={{ mb: 4 }}>
        {/* Summary Cards */}
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={2}>
            <Card sx={{ 
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              color: 'white',
              boxShadow: '0 4px 20px rgba(102, 126, 234, 0.4)',
              borderRadius: '8px'
            }}>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h3" fontWeight="700" sx={{ textShadow: '0 1px 2px rgba(0,0,0,0.1)' }}>
                  {summary.total}
                </Typography>
                <Typography variant="body2" sx={{ opacity: 0.95, fontWeight: '500' }}>
                  Total Harnesses
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>

        {/* Charts */}
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                  <TrendingUp sx={{ mr: 1 }} />
                  Status Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={250}>
                  <PieChart>
                    <Pie
                      data={statusData}
                      cx="50%"
                      cy="50%"
                      outerRadius={80}
                      dataKey="value"
                      label={({ name, value }) => `${name}: ${value}`}
                    >
                      {statusData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <RechartsTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                  <Analytics sx={{ mr: 1 }} />
                  Fuzzer Distribution
                </Typography>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={harnessTypeData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <RechartsTooltip />
                    <Bar dataKey="value" fill="#8884d8" />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Box>
    );
  };

  const renderFilters = () => (
    <Card sx={{ mb: 3 }}>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
          <FilterList sx={{ mr: 1 }} />
          Advanced Filters & Search
        </Typography>
        
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={3}>
            <TextField
              fullWidth
              size="small"
              label="Search Harnesses"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              InputProps={{
                startAdornment: <Search sx={{ mr: 1, color: 'action.active' }} />
              }}
            />
          </Grid>
          
          <Grid item xs={12} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Status</InputLabel>
              <Select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                label="Status"
              >
                <MenuItem value="">All</MenuItem>
                {statusOptions.map((status) => (
                  <MenuItem key={status} value={status}>{status.toUpperCase()}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Harness Type</InputLabel>
              <Select
                value={filterHarnessType}
                onChange={(e) => setFilterHarnessType(e.target.value)}
                label="Harness Type"
              >
                <MenuItem value="">All</MenuItem>
                {harnessTypeOptions.map((type) => (
                  <MenuItem key={type} value={type}>{type}</MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={2}>
            <FormControlLabel
              control={
                <Switch
                  checked={showOnlyAIGenerated}
                  onChange={(e) => setShowOnlyAIGenerated(e.target.checked)}
                />
              }
              label="AI-Generated Only"
            />
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );

     const renderHarnessCard = (harness: FuzzingHarness) => {
     // Safety check to ensure harness has required properties
     if (!harness || !harness.id) {
       console.warn('Invalid harness data:', harness);
       return null;
     }

     return (
     <Accordion key={harness.id} sx={{ mb: 1, border: '1px solid', borderColor: 'divider' }}>
      <AccordionSummary 
        expandIcon={<ExpandMore />}
        sx={{ 
          backgroundColor: 'background.paper',
          '&:hover': { backgroundColor: 'action.hover' }
        }}
      >
        <Box display="flex" alignItems="center" gap={2} width="100%" pr={2}>
          <Build sx={{ color: getHarnessTypeColor(harness.harness_type) }} />
          
          <Box flexGrow={1}>
            <Typography variant="subtitle1" fontWeight="medium">
              {harness.harness_name}
            </Typography>
            
            <Box display="flex" gap={1} mt={0.5} flexWrap="wrap">
              <Chip 
                label={harness.status}
                size="small"
                sx={{ 
                  backgroundColor: getStatusColor(harness.status),
                  color: 'white',
                  fontWeight: 'bold'
                }}
              />
              
              <Chip 
                label={harness.harness_type}
                size="small"
                sx={{
                  backgroundColor: getHarnessTypeColor(harness.harness_type),
                  color: 'white'
                }}
              />
              
              <Chip 
                label={harness.target_function}
                size="small"
                variant="outlined"
                icon={<Code />}
              />
              
              {harness.generation_method === 'AI' && (
                <Chip 
                  label="AI-Generated"
                  size="small"
                  icon={<Psychology />}
                  sx={{ backgroundColor: '#9c27b0', color: 'white' }}
                />
              )}
              
              {harness.performance_metrics && (
                <Chip 
                  label={`Coverage: ${harness.performance_metrics.code_coverage}%`}
                  size="small"
                  icon={<Speed />}
                  variant="outlined"
                />
              )}
            </Box>
          </Box>
        </Box>
      </AccordionSummary>
      
      <AccordionDetails>
        <Grid container spacing={3}>
          <Grid item xs={12} md={8}>
            <Typography variant="body2" paragraph>
              <strong>Target Function:</strong> {harness.target_function}
            </Typography>
            
            {harness.ai_analysis?.input_analysis && (
              <Alert severity="info" sx={{ mb: 2 }}>
                <Typography variant="body2">
                  <strong>AI Analysis:</strong> {harness.ai_analysis.input_analysis}
                </Typography>
              </Alert>
            )}
            
            <Typography variant="body2" paragraph>
              <strong>Technical Details:</strong>
            </Typography>
            <Box sx={{ ml: 2, fontFamily: 'monospace', fontSize: '0.875rem', mb: 2 }}>
              {harness.technical_details?.target_address && <div>Address: {harness.technical_details.target_address}</div>}
              {harness.technical_details?.input_format && <div>Input Format: {harness.technical_details.input_format}</div>}
              {harness.technical_details?.compilation_flags && (
                <div>Compilation Flags: {harness.technical_details.compilation_flags.join(' ')}</div>
              )}
              {!harness.technical_details && (
                <Typography variant="body2" color="text.secondary">
                  No technical details available
                </Typography>
              )}
            </Box>
            
            {harness.ai_analysis?.recommended_strategy && (
              <Alert severity="success" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  <strong>Recommended Strategy:</strong> {harness.ai_analysis.recommended_strategy}
                </Typography>
              </Alert>
            )}

            {/* View Content Buttons */}
            <Box sx={{ mt: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                View Content:
              </Typography>
              <Box display="flex" flexWrap="wrap" gap={1} mb={2}>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<Code />}
                  onClick={() => handleViewContent(harness, 'harness')}
                >
                  View C Code
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<Build />}
                  onClick={() => handleViewContent(harness, 'makefile')}
                >
                  View Makefile
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<Description />}
                  onClick={() => handleViewContent(harness, 'readme')}
                >
                  View README
                </Button>
              </Box>
            </Box>

            {/* Download and Delete Actions */}
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                Actions:
              </Typography>
              <Box display="flex" flexWrap="wrap" gap={1}>
                <Button
                  size="small"
                  variant="contained"
                  startIcon={<Download />}
                  onClick={() => window.open(`/api/fuzzing-harnesses/${harness.id}/download/package`, '_blank')}
                  color="primary"
                >
                  Download ZIP
                </Button>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<Delete />}
                  onClick={() => handleDeleteHarness(harness.id, harness.harness_name)}
                  color="error"
                >
                  Delete
                </Button>
              </Box>
            </Box>
          </Grid>
          
          <Grid item xs={12} md={4}>
            <Stack spacing={2}>
              <Paper sx={{ p: 2, backgroundColor: 'background.default' }}>
                <Typography variant="subtitle2" gutterBottom>Performance Metrics</Typography>
                {harness.performance_metrics ? (
                  <>
                    <Box display="flex" justifyContent="space-between" mb={1}>
                      <Typography variant="body2">Coverage:</Typography>
                      <Chip 
                        label={`${harness.performance_metrics.code_coverage}%`}
                        size="small"
                        color="primary"
                      />
                    </Box>
                    <Box display="flex" justifyContent="space-between" mb={1}>
                      <Typography variant="body2">Crashes Found:</Typography>
                      <Chip 
                        label={harness.performance_metrics.crashes_found}
                        size="small"
                        color={harness.performance_metrics.crashes_found > 0 ? 'error' : 'success'}
                      />
                    </Box>
                    <Box display="flex" justifyContent="space-between">
                      <Typography variant="body2">Test Cases:</Typography>
                      <Chip 
                        label={harness.performance_metrics.test_cases_generated}
                        size="small"
                        variant="outlined"
                      />
                    </Box>
                  </>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    No performance data available
                  </Typography>
                )}
              </Paper>
              
              <Paper sx={{ p: 2, backgroundColor: 'background.default' }}>
                <Typography variant="subtitle2" gutterBottom>Generation Details</Typography>
                <Box display="flex" justifyContent="space-between" mb={1}>
                  <Typography variant="body2">Method:</Typography>
                  <Chip 
                    label={harness.generation_method}
                    size="small"
                    variant="outlined"
                  />
                </Box>
                <Box display="flex" justifyContent="space-between">
                  <Typography variant="body2">Created:</Typography>
                  <Typography variant="body2" fontWeight="medium">
                    {new Date(harness.created_at).toLocaleDateString()}
                  </Typography>
                </Box>
              </Paper>
            </Stack>
          </Grid>
        </Grid>
      </AccordionDetails>
    </Accordion>
    );
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Box>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
            <FlashOn sx={{ mr: 2, color: 'primary.main' }} />
            Fuzzing Dashboard
          </Typography>
          <Typography variant="body1" color="text.secondary">
            AI-Powered Fuzzing Harness Generation • Advanced Coverage Analysis • Automated Testing
          </Typography>
        </Box>
        
        <Stack direction="row" spacing={2}>
          <Button
            variant="outlined"
            startIcon={<Refresh />}
            onClick={loadFuzzingData}
            disabled={!selectedBinary || loading}
          >
            Refresh
          </Button>
          
          <Button
            variant="outlined"
            startIcon={<Download />}
            onClick={exportHarnesses}
            disabled={!harnesses || harnesses.length === 0}
          >
            Export
          </Button>
        </Stack>
      </Box>
      
      {/* Binary Selection and Generation Controls */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Fuzzing Configuration
          {binaryId && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              Pre-selected binary from binary details view
            </Typography>
          )}
        </Typography>
        
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <FormControl fullWidth>
              <InputLabel>Select Binary for Fuzzing</InputLabel>
              <Select
                value={selectedBinary || ''}
                onChange={(e) => setSelectedBinary(e.target.value)}
                label="Select Binary for Fuzzing"
              >
                {binaries.map((binary) => {
                  const isReady = ['decompiled', 'analyzed', 'completed'].includes(binary.analysis_status);
                  const getStatusColor = (status: string) => {
                    switch (status.toLowerCase()) {
                      case 'decompiled':
                      case 'completed':
                      case 'analyzed':
                        return 'success';
                      case 'analyzing':
                      case 'processing':
                        return 'warning';
                      case 'pending':
                        return 'info';
                      case 'failed':
                      case 'error':
                        return 'error';
                      default:
                        return 'default';
                    }
                  };
                  
                  return (
                    <MenuItem key={binary.id} value={binary.id}>
                      <Box display="flex" alignItems="center" justifyContent="space-between" width="100%">
                        <Box display="flex" alignItems="center" gap={1}>
                          <BugReport />
                          {binary.original_filename}
                        </Box>
                        <Chip 
                          size="small" 
                          label={binary.analysis_status}
                          color={getStatusColor(binary.analysis_status)}
                          sx={{ ml: 1 }}
                        />
                      </Box>
                    </MenuItem>
                  );
                })}
              </Select>
            </FormControl>
            {binaries.length > 0 && (
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                <strong>All Binaries Available:</strong> You can select any binary for fuzzing. 
                The system will provide appropriate guidance based on the binary's current analysis status.
              </Typography>
            )}
          </Grid>
          
          <Grid item xs={12} md={6}>
            {(() => {
              const selectedBinaryData = binaries.find(b => b.id === selectedBinary);
              const isDisabled = !selectedBinary || generationRunning || selectedFuzzers.length === 0;
              
              return (
                <Button
                  variant="contained"
                  startIcon={generationRunning ? <CircularProgress size={20} /> : <PlayArrow />}
                  onClick={generateFuzzingHarness}
                  disabled={isDisabled}
                  fullWidth
                  sx={{ 
                    background: isDisabled ? undefined : 'linear-gradient(45deg, #FF6B6B 30%, #FF8E53 90%)',
                    '&:hover': {
                      background: isDisabled ? undefined : 'linear-gradient(45deg, #E55555 30%, #E67E44 90%)'
                    },
                    height: 56 // Match the select height
                  }}
                >
                  {generationRunning 
                    ? 'Generating Harness...' 
                    : !selectedBinary 
                      ? 'Select Binary First' 
                      : selectedFuzzers.length === 0
                        ? 'Select Fuzzer(s) First'
                        : `Generate ${selectedFuzzers.length} Fuzzing Harness(es)`}
                </Button>
              );
            })()}
          </Grid>
        </Grid>

        {/* Fuzzer Selection */}
        {selectedBinary && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle1" gutterBottom>
              Select Fuzzers:
            </Typography>
            <Box display="flex" flexWrap="wrap" gap={1} mb={2}>
              {supportedFuzzers.map((fuzzer) => (
                <Chip
                  key={fuzzer.name}
                  label={fuzzer.name}
                  onClick={() => handleFuzzerToggle(fuzzer.name)}
                  color={selectedFuzzers.includes(fuzzer.name) ? 'primary' : 'default'}
                  variant={selectedFuzzers.includes(fuzzer.name) ? 'filled' : 'outlined'}
                  icon={selectedFuzzers.includes(fuzzer.name) ? <CheckCircle /> : undefined}
                  sx={{ 
                    '&:hover': { backgroundColor: 'action.hover' },
                    cursor: 'pointer'
                  }}
                />
              ))}
            </Box>

            {selectedFuzzers.length > 0 && (
              <Alert severity="info" sx={{ mb: 2 }}>
                <Typography variant="body2">
                  <strong>Selected Fuzzers:</strong> {selectedFuzzers.join(', ')}
                </Typography>
                {supportedFuzzers
                  .filter(f => selectedFuzzers.includes(f.name))
                  .map(f => (
                    <Typography key={f.name} variant="caption" display="block">
                      <strong>{f.name}:</strong> {f.description}
                    </Typography>
                  ))
                }
              </Alert>
            )}

            {/* Advanced Options */}
            <Button
              variant="text"
              size="small"
              onClick={() => setShowAdvanced(!showAdvanced)}
              startIcon={showAdvanced ? <ExpandLess /> : <ExpandMore />}
              sx={{ mb: 2 }}
            >
              Advanced Options
            </Button>

            <Collapse in={showAdvanced}>
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="body2" gutterBottom>
                    Minimum Risk Score: {minRiskScore}%
                  </Typography>
                  <Slider
                    value={minRiskScore}
                    onChange={(_, value) => setMinRiskScore(value as number)}
                    min={0}
                    max={100}
                    step={5}
                    marks={[
                      { value: 0, label: '0%' },
                      { value: 40, label: '40%' },
                      { value: 80, label: '80%' },
                      { value: 100, label: '100%' }
                    ]}
                    size="small"
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Target Severities</InputLabel>
                    <Select
                      multiple
                      value={targetSeverities}
                      onChange={(e) => setTargetSeverities(e.target.value as string[])}
                      input={<OutlinedInput label="Target Severities" />}
                      renderValue={(selected) => (
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {selected.map((value) => (
                            <Chip key={value} label={value} size="small" />
                          ))}
                        </Box>
                      )}
                    >
                      {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((severity) => (
                        <MenuItem key={severity} value={severity}>
                          {severity}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={aiEnabled}
                        onChange={(e) => setAiEnabled(e.target.checked)}
                      />
                    }
                    label="AI-Enhanced Analysis"
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={includeSeeds}
                        onChange={(e) => setIncludeSeeds(e.target.checked)}
                      />
                    }
                    label="Include Seed Inputs"
                    sx={{ ml: 2 }}
                  />
                </Grid>
              </Grid>
            </Collapse>
          </Box>
        )}
      </Paper>

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Code Viewer Modal */}
      <Dialog
        open={!!viewingContent}
        onClose={() => setViewingContent(null)}
        maxWidth="lg"
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box display="flex" alignItems="center">
            <Code sx={{ mr: 1 }} />
            {viewingHarness?.harness_name || viewingHarness?.name} - {viewingContent?.type.toUpperCase()}
          </Box>
          <Box>
            <IconButton onClick={() => handleCopyToClipboard(viewingContent?.content || '')}>
              <ContentCopy />
            </IconButton>
            <IconButton onClick={() => setViewingContent(null)}>
              <Close />
            </IconButton>
          </Box>
        </DialogTitle>
        <DialogContent sx={{ p: 0 }}>
          {codeLoading ? (
            <Box display="flex" justifyContent="center" p={3}>
              <CircularProgress />
            </Box>
          ) : (
            <SyntaxHighlighter
              language={viewingContent?.language || 'text'}
              style={atomOneDark}
              showLineNumbers
              customStyle={{
                margin: 0,
                borderRadius: 0,
                fontSize: '14px',
                backgroundColor: '#181818'
              }}
            >
              {viewingContent?.content || ''}
            </SyntaxHighlighter>
          )}
        </DialogContent>
      </Dialog>

      {/* Loading Indicator */}
      {loading && (
        <Box display="flex" justifyContent="center" my={3}>
          <CircularProgress />
        </Box>
      )}

      {/* Fuzzing Metrics */}
      {summary && renderFuzzingMetrics()}

      {/* Filters */}
      {selectedBinary && renderFilters()}

      {/* Fuzzing Harnesses */}
      {harnesses && harnesses.length > 0 ? (
        <Box>
          <Typography variant="h6" mb={2}>
            Fuzzing Harnesses ({harnesses.length} found)
          </Typography>
          
          {harnesses.map(renderHarnessCard)}
        </Box>
      ) : selectedBinary && !loading && (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <BugReport sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
          <Typography variant="h6" color="text.secondary" gutterBottom>
            No Fuzzing Harnesses Available
          </Typography>
          <Typography variant="body2" color="text.secondary" mb={3}>
            Generate AI-powered fuzzing harnesses to start automated testing and vulnerability discovery.
          </Typography>
          <Button
            variant="contained"
            startIcon={<PlayArrow />}
            onClick={generateFuzzingHarness}
            disabled={generationRunning}
          >
            Generate Fuzzing Harness
          </Button>
        </Paper>
      )}
    </Box>
  );
};

export default FuzzingDashboard; 