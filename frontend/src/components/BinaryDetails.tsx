import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  LinearProgress,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  ListItemSecondaryAction,
  IconButton,
  Divider,
  Container,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Collapse,
  Tooltip,
  TextField,
  InputAdornment,
  Stack,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
  FormControl,
  InputLabel,
  Select,
  OutlinedInput,
  MenuItem,
  FormControlLabel,
  Switch,
  Slider
} from '@mui/material';
import {
  PlayArrow,
  Visibility,
  Download,
  Code,
  BugReport,
  Refresh,
  ExpandMore,
  ExpandLess,
  Psychology,
  Security,
  Search,
  FilterList,
  GetApp,
  Info,
  Analytics,
  Assignment,
  TrendingUp,
  Warning,
  Chat,
  Send,
  Clear,
  ArrowUpward,
  ArrowDownward,
  Speed,
  FlashOn,
  CheckCircle,
  Build,
  Description,
  Delete,
  ContentCopy,
  Close,
  Storage,        // For Strings tab
  AccountTree,    // For Symbols tab  
  Memory,         // For Memory Blocks tab
  ImportExport,   // For Imports/Exports tab
  DataObject      // For data display
} from '@mui/icons-material';
import { useParams, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import { apiClient, formatFileSize, formatDate, getStatusColor, BinaryDetails as BinaryDetailsType, Function } from '../utils/api';
import SyntaxHighlighter from 'react-syntax-highlighter';
// @ts-ignore - Type definitions missing for style imports
import tomorrow from 'react-syntax-highlighter/dist/styles/tomorrow';
// @ts-ignore - Type definitions missing for style imports
import atomOneDark from 'react-syntax-highlighter/dist/styles/atom-one-dark';
import TaskProgress from './TaskProgress';
import UnifiedSecurityDashboard from './UnifiedSecurityDashboard';
import FuzzingDashboard from './FuzzingDashboard';


interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div hidden={value !== index}>
    {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
  </div>
);

interface ExpandedFunctionData {
  decompiled?: any;
  aiExplanation?: any;
  details?: any;
  loading?: {
    decompiling?: boolean;
    explaining?: boolean;
    fetchingDetails?: boolean;
  };
}

// Simple Fuzzing Interface Component for Binary Details
const SimpleFuzzingInterface: React.FC<{ 
  binaryId: string; 
  functions: Function[]; 
  onRefresh: () => void 
}> = ({ binaryId, functions, onRefresh }) => {
  const [fuzzingHarnesses, setFuzzingHarnesses] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  
  // Enhanced state for tabbed code viewer
  const [viewingHarness, setViewingHarness] = useState<any>(null);
  const [codeLoading, setCodeLoading] = useState(false);
  const [activeTab, setActiveTab] = useState(0);
  const [harnessContents, setHarnessContents] = useState<{
    harness_code: string;
    makefile_content: string;
    readme_content: string;
  } | null>(null);
  
  // Configuration state
  const [selectedFuzzers, setSelectedFuzzers] = useState<string[]>(['LibFuzzer']);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [minRiskScore, setMinRiskScore] = useState(40);
  const [targetSeverities, setTargetSeverities] = useState<string[]>(['CRITICAL', 'HIGH']);
  const [aiEnabled, setAiEnabled] = useState(true);
  const [includeSeeds, setIncludeSeeds] = useState(true);

  const supportedFuzzers = [
    { name: 'AFL++', description: 'Advanced American Fuzzy Lop with additional features' },
    { name: 'AFL', description: 'Classic American Fuzzy Lop fuzzer' },
    { name: 'LibFuzzer', description: 'In-process, coverage-guided fuzzing engine (part of LLVM)' },
    { name: 'Honggfuzz', description: 'Security oriented fuzzer with powerful analysis options' }
  ];

  const loadFuzzingHarnesses = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/binaries/${binaryId}/fuzzing-harnesses`);
      const data = await response.json();
      setFuzzingHarnesses(data.harnesses || []);
    } catch (err) {
      console.error('Error loading fuzzing harnesses:', err);
      setFuzzingHarnesses([]);
    } finally {
      setLoading(false);
    }
  }, [binaryId]);

  useEffect(() => {
    loadFuzzingHarnesses();
  }, [loadFuzzingHarnesses]);

  const handleGenerateFuzzingHarness = async () => {
    if (!binaryId || selectedFuzzers.length === 0) return;
    
    try {
      setGenerating(true);
      
      // Use the same API format as FuzzingDashboard (correct format)
      const response = await fetch(`/api/binaries/${binaryId}/generate-fuzzing-harness`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          harness_types: selectedFuzzers,  // ✅ Fixed! Use correct parameter name
          min_risk_score: minRiskScore,
          target_severities: targetSeverities,
          ai_enabled: aiEnabled,
          include_seeds: includeSeeds
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || `Failed to generate fuzzing harnesses`);
      }

      const result = await response.json();
      const harnessCount = result.harnesses?.length || result.summary?.total_harnesses || selectedFuzzers.length;
      
      toast.success(`Generated ${harnessCount} fuzzing harness(es) successfully for ${selectedFuzzers.join(', ')}!`);
      loadFuzzingHarnesses();
      onRefresh();
    } catch (err: any) {
      toast.error(`Fuzzing harness generation failed: ${err.message}`);
    } finally {
      setGenerating(false);
    }
  };

  // Enhanced code viewer - loads all content at once and shows in tabs
  const handleViewAllCode = async (harness: any) => {
    try {
      setCodeLoading(true);
      setViewingHarness(harness);
      setActiveTab(0); // Start with first tab
      
      // Load full harness details with all content
      const response = await fetch(`/api/fuzzing-harnesses/${harness.id}`);
      if (!response.ok) {
        throw new Error(`Failed to load harness details: ${response.statusText}`);
      }
      
      const harnessDetails = await response.json();
      console.log('Loaded harness details:', harnessDetails); // Debug log
      
      setHarnessContents({
        harness_code: harnessDetails.harness_code || '// No harness code available\n// The harness may still be generating or there was an error.',
        makefile_content: harnessDetails.makefile_content || '# No Makefile available\n# The Makefile may still be generating or there was an error.',
        readme_content: harnessDetails.readme_content || '# No README available\n\nThe README may still be generating or there was an error.'
      });
      
    } catch (err: any) {
      console.error('Error loading harness code:', err);
      toast.error(`Failed to load code: ${err.message}`);
      // Set fallback content on error
      setHarnessContents({
        harness_code: `// Failed to load harness code\n// Error: ${err.message}\n// Please try downloading the ZIP package instead.`,
        makefile_content: `# Failed to load Makefile\n# Error: ${err.message}\n# Please try downloading the ZIP package instead.`,
        readme_content: `# Failed to load README\n\nError: ${err.message}\n\nPlease try downloading the ZIP package instead.`
      });
    } finally {
      setCodeLoading(false);
    }
  };

  const handleDeleteHarness = async (harnessId: string, harnessName: string) => {
    if (!window.confirm(`Are you sure you want to delete "${harnessName}"?`)) {
      return;
    }
    
    try {
      const response = await fetch(`/api/fuzzing-harnesses/${harnessId}`, {
        method: 'DELETE'
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Delete failed');
      }
      
      toast.success('Fuzzing harness deleted successfully');
      loadFuzzingHarnesses();
    } catch (err: any) {
      toast.error(`Failed to delete harness: ${err.message}`);
    }
  };

  const handleDownloadFile = async (harnessId: string, fileType: 'package') => {
    try {
      const response = await fetch(`/api/fuzzing-harnesses/${harnessId}/download/${fileType}`);
      if (!response.ok) throw new Error('Download failed');
      
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `fuzzing-harness-${harnessId}.zip`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      toast.success('ZIP package downloaded successfully');
    } catch (err: any) {
      toast.error(`Failed to download: ${err.message}`);
    }
  };

  const handleFuzzerToggle = (fuzzerName: string) => {
    setSelectedFuzzers(prev => 
      prev.includes(fuzzerName) 
        ? prev.filter(f => f !== fuzzerName)
        : [...prev, fuzzerName]
    );
  };

  const handleCopyToClipboard = (content: string) => {
    navigator.clipboard.writeText(content);
    toast.success('Copied to clipboard');
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const decompiledFunctions = functions.filter(f => f.is_decompiled);
  const canGenerate = decompiledFunctions.length > 0 && selectedFuzzers.length > 0;

  const getTabContent = () => {
    if (!harnessContents) return '';
    switch (activeTab) {
      case 0: return harnessContents.harness_code;
      case 1: return harnessContents.makefile_content;
      case 2: return harnessContents.readme_content;
      default: return '';
    }
  };

  const getTabLanguage = () => {
    switch (activeTab) {
      case 0: return 'c';
      case 1: return 'makefile';
      case 2: return 'markdown';
      default: return 'text';
    }
  };

  // Enhanced syntax highlighting function
  const applySyntaxHighlighting = (code: string, language: string): JSX.Element[] => {
    const lines = code.split('\n');
    
    return lines.map((line, index) => {
      let highlightedLine = line;
      
      if (language === 'c') {
        // C/C++ syntax highlighting
        highlightedLine = line
          // Keywords
          .replace(/\b(if|else|for|while|do|switch|case|break|continue|return|int|char|void|const|extern|static|struct|typedef|enum|union|sizeof|include|define|ifdef|ifndef|endif|pragma)\b/g, 
            '<span class="syntax-keyword">$1</span>')
          // Strings
          .replace(/"([^"\\]|\\.)*"/g, '<span class="syntax-string">"$1"</span>')
          .replace(/'([^'\\]|\\.)*'/g, '<span class="syntax-string">\'$1\'</span>')
          // Comments
          .replace(/(\/\/.*$)/g, '<span class="syntax-comment">$1</span>')
          .replace(/(\/\*[\s\S]*?\*\/)/g, '<span class="syntax-comment">$1</span>')
          // Numbers
          .replace(/\b(\d+\.?\d*)\b/g, '<span class="syntax-number">$1</span>')
          // Function calls
          .replace(/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(/g, '<span class="syntax-function">$1</span>(')
          // Preprocessor
          .replace(/^(\s*#.*)$/g, '<span class="syntax-preprocessor">$1</span>');
          
      } else if (language === 'makefile') {
        // Makefile syntax highlighting
        highlightedLine = line
          // Targets
          .replace(/^([^:\s]+):/g, '<span class="syntax-target">$1</span>:')
          // Variables
          .replace(/\$\(([^)]+)\)/g, '<span class="syntax-variable">$(</span><span class="syntax-variable-name">$1</span><span class="syntax-variable">)</span>')
          .replace(/\$\{([^}]+)\}/g, '<span class="syntax-variable">${</span><span class="syntax-variable-name">$1</span><span class="syntax-variable">}</span>')
          // Comments
          .replace(/(#.*$)/g, '<span class="syntax-comment">$1</span>')
          // Commands (lines starting with tab)
          .replace(/^(\t.*)$/g, '<span class="syntax-command">$1</span>')
          // Assignments
          .replace(/^([A-Z_][A-Z0-9_]*)\s*=/g, '<span class="syntax-variable-def">$1</span> =');
          
      } else if (language === 'markdown') {
        // Markdown syntax highlighting
        highlightedLine = line
          // Headers
          .replace(/^(#{1,6})\s+(.*)$/g, '<span class="syntax-header">$1</span> <span class="syntax-header-text">$2</span>')
          // Bold
          .replace(/\*\*(.*?)\*\*/g, '<span class="syntax-bold">**$1**</span>')
          .replace(/__(.*?)__/g, '<span class="syntax-bold">__$1__</span>')
          // Italic
          .replace(/\*(.*?)\*/g, '<span class="syntax-italic">*$1*</span>')
          .replace(/_(.*?)_/g, '<span class="syntax-italic">_$1_</span>')
          // Code
          .replace(/`([^`]+)`/g, '<span class="syntax-code">`$1`</span>')
          // Links
          .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<span class="syntax-link">[</span><span class="syntax-link-text">$1</span><span class="syntax-link">](</span><span class="syntax-url">$2</span><span class="syntax-link">)</span>')
          // Lists
          .replace(/^(\s*[-*+]\s+)/g, '<span class="syntax-list">$1</span>');
      }
      
      return (
        <div key={index} className="code-line" data-line={index + 1}>
          <span dangerouslySetInnerHTML={{ __html: highlightedLine }} />
        </div>
      );
    });
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
          <FlashOn sx={{ mr: 1, color: 'primary.main' }} />
          Fuzzing Harness Generation
        </Typography>
        <Button
          variant="outlined"
          startIcon={<Refresh />}
          onClick={loadFuzzingHarnesses}
          disabled={loading}
          size="small"
        >
          Refresh
        </Button>
      </Box>

      {/* Generation Configuration */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Grid container spacing={3}>
            <Grid item xs={12} md={8}>
              <Typography variant="body1" gutterBottom>
                <strong>Binary:</strong> {binaryId}
              </Typography>
              <Typography variant="body2" color="textSecondary" gutterBottom>
                <strong>Decompiled Functions:</strong> {decompiledFunctions.length} of {functions.length}
              </Typography>
              
              {/* Fuzzer Selection */}
              <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
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

              {/* Advanced Options Toggle */}
              <Button
                variant="text"
                size="small"
                onClick={() => setShowAdvanced(!showAdvanced)}
                startIcon={showAdvanced ? <ExpandLess /> : <ExpandMore />}
                sx={{ mb: 2 }}
              >
                Advanced Options
              </Button>

              {/* Advanced Configuration */}
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

              {!canGenerate && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  {decompiledFunctions.length === 0 
                    ? 'No decompiled functions available. Please decompile functions first to generate fuzzing harnesses.'
                    : 'Please select at least one fuzzer to generate harnesses.'
                  }
                </Alert>
              )}
            </Grid>
            
            <Grid item xs={12} md={4}>
              <Button
                variant="contained"
                fullWidth
                startIcon={generating ? <CircularProgress size={20} /> : <PlayArrow />}
                onClick={handleGenerateFuzzingHarness}
                disabled={generating || !canGenerate}
                sx={{ 
                  background: 'linear-gradient(45deg, #FF6B6B 30%, #FF8E53 90%)',
                  '&:hover': {
                    background: 'linear-gradient(45deg, #E55555 30%, #E67E44 90%)'
                  },
                  mb: 2
                }}
              >
                {generating ? 'Generating...' : 'Generate AI Fuzzing Harness'}
              </Button>
              
              {selectedFuzzers.length > 1 && (
                <Typography variant="caption" color="textSecondary" display="block" textAlign="center">
                  Will generate {selectedFuzzers.length} harnesses
                </Typography>
              )}
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Enhanced Professional Code Viewer Modal */}
      <Dialog
        open={!!viewingHarness}
        onClose={() => {
          setViewingHarness(null);
          setHarnessContents(null);
          setActiveTab(0);
        }}
        maxWidth="xl"
        fullWidth
        PaperProps={{
          sx: {
            minHeight: '92vh',
            maxHeight: '92vh',
            borderRadius: 3,
            overflow: 'hidden',
            background: 'linear-gradient(145deg, #1a1a1a 0%, #2d2d2d 100%)',
            boxShadow: '0 24px 48px rgba(0, 0, 0, 0.3), 0 8px 16px rgba(0, 0, 0, 0.2)'
          }
        }}
      >
        {/* Enhanced Header */}
        <DialogTitle sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'space-between',
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          color: 'white',
          py: 3,
          px: 4,
          borderBottom: '1px solid rgba(255, 255, 255, 0.1)'
        }}>
          <Box display="flex" alignItems="center">
            <Box
              sx={{
                background: 'rgba(255, 255, 255, 0.15)',
                borderRadius: 2,
                p: 1,
                mr: 2,
                backdropFilter: 'blur(10px)'
              }}
            >
              <Code sx={{ fontSize: 28 }} />
            </Box>
            <Box>
              <Typography variant="h5" component="div" fontWeight="600">
                {viewingHarness?.name || 'Fuzzing Harness'}
              </Typography>
              <Typography variant="body2" sx={{ opacity: 0.9, mt: 0.5 }}>
                {viewingHarness?.harness_type} • {viewingHarness?.target_count} targets • Generated {new Date().toLocaleDateString()}
              </Typography>
            </Box>
          </Box>
          <Box display="flex" gap={1}>
            <Tooltip title="Copy current tab to clipboard">
              <IconButton 
                onClick={() => handleCopyToClipboard(getTabContent())}
                sx={{ 
                  color: 'white',
                  background: 'rgba(255, 255, 255, 0.1)',
                  '&:hover': { 
                    background: 'rgba(255, 255, 255, 0.2)',
                    transform: 'scale(1.05)'
                  },
                  transition: 'all 0.2s ease'
                }}
              >
                <ContentCopy />
              </IconButton>
            </Tooltip>
            <Tooltip title="Close">
              <IconButton 
                onClick={() => {
                  setViewingHarness(null);
                  setHarnessContents(null);
                  setActiveTab(0);
                }}
                sx={{ 
                  color: 'white',
                  background: 'rgba(255, 255, 255, 0.1)',
                  '&:hover': { 
                    background: 'rgba(255, 255, 255, 0.2)',
                    transform: 'scale(1.05)'
                  },
                  transition: 'all 0.2s ease'
                }}
              >
                <Close />
              </IconButton>
            </Tooltip>
          </Box>
        </DialogTitle>
        
        {/* Enhanced Tabs */}
        <Box sx={{ 
          borderBottom: '1px solid rgba(255, 255, 255, 0.1)',
          background: 'linear-gradient(90deg, #2d2d2d 0%, #3a3a3a 100%)'
        }}>
          <Tabs 
            value={activeTab} 
            onChange={handleTabChange}
            sx={{
              '& .MuiTab-root': {
                color: 'rgba(255, 255, 255, 0.7)',
                fontWeight: 500,
                textTransform: 'none',
                fontSize: '1rem',
                minHeight: 60,
                px: 3,
                '&:hover': {
                  color: 'white',
                  background: 'rgba(255, 255, 255, 0.05)'
                },
                '&.Mui-selected': {
                  color: '#667eea',
                  background: 'rgba(102, 126, 234, 0.1)'
                }
              },
              '& .MuiTabs-indicator': {
                backgroundColor: '#667eea',
                height: 3,
                borderRadius: '3px 3px 0 0'
              }
            }}
          >
            <Tab 
              label="C Harness Code" 
              icon={<Code />} 
              iconPosition="start"
            />
            <Tab 
              label="Makefile" 
              icon={<Build />} 
              iconPosition="start"
            />
            <Tab 
              label="Documentation" 
              icon={<Description />} 
              iconPosition="start"
            />
          </Tabs>
        </Box>
        
        {/* Enhanced Code Content */}
        <DialogContent sx={{ 
          p: 0, 
          backgroundColor: '#1a1a1a', 
          overflow: 'hidden',
          position: 'relative'
        }}>
          {codeLoading ? (
            <Box 
              display="flex" 
              flexDirection="column"
              justifyContent="center" 
              alignItems="center" 
              py={8}
              sx={{
                background: 'linear-gradient(45deg, #1a1a1a 30%, #2d2d2d 90%)'
              }}
            >
              <CircularProgress 
                sx={{ 
                  color: '#667eea',
                  mb: 2
                }} 
                size={48}
              />
              <Typography variant="h6" sx={{ color: 'white', mb: 1 }}>
                Loading Code Content
              </Typography>
              <Typography variant="body2" sx={{ color: 'rgba(255, 255, 255, 0.7)' }}>
                Please wait while we fetch the harness files...
              </Typography>
            </Box>
          ) : (
            <Box sx={{ position: 'relative', height: '72vh' }}>
              {/* Professional Code Display with Syntax Highlighting */}
              <Box
                sx={{
                  height: '100%',
                  overflow: 'auto',
                  background: 'linear-gradient(145deg, #1a1a1a 0%, #0f0f0f 100%)',
                  fontFamily: '"JetBrains Mono", "Fira Code", "SF Mono", "Consolas", monospace',
                  fontSize: '14px',
                  lineHeight: 1.7,
                  
                  // Enhanced syntax highlighting styles
                  '& .code-line': {
                    position: 'relative',
                    paddingLeft: '4em',
                    paddingRight: '2em',
                    paddingTop: '2px',
                    paddingBottom: '2px',
                    minHeight: '24px',
                    display: 'flex',
                    alignItems: 'center',
                    
                    '&:hover': {
                      backgroundColor: 'rgba(102, 126, 234, 0.08)'
                    },
                    
                    '&::before': {
                      content: 'attr(data-line)',
                      position: 'absolute',
                      left: '1em',
                      color: 'rgba(255, 255, 255, 0.4)',
                      fontSize: '12px',
                      textAlign: 'right',
                      width: '2.5em',
                      userSelect: 'none',
                      fontWeight: 500
                    }
                  },
                  
                  // C/C++ syntax highlighting
                  '& .syntax-keyword': { 
                    color: '#ff7b72', 
                    fontWeight: 600 
                  },
                  '& .syntax-string': { 
                    color: '#a5d6ff' 
                  },
                  '& .syntax-comment': { 
                    color: '#8b949e',
                    fontStyle: 'italic' 
                  },
                  '& .syntax-function': { 
                    color: '#d2a8ff',
                    fontWeight: 500 
                  },
                  '& .syntax-number': { 
                    color: '#79c0ff' 
                  },
                  '& .syntax-preprocessor': {
                    color: '#ffa657',
                    fontWeight: 500
                  },
                  
                  // Makefile syntax highlighting
                  '& .syntax-target': {
                    color: '#7ee787',
                    fontWeight: 600
                  },
                  '& .syntax-variable': {
                    color: '#ffa657'
                  },
                  '& .syntax-variable-name': {
                    color: '#79c0ff'
                  },
                  '& .syntax-variable-def': {
                    color: '#ff7b72',
                    fontWeight: 600
                  },
                  '& .syntax-command': {
                    color: '#e6edf3'
                  },
                  
                  // Markdown syntax highlighting
                  '& .syntax-header': {
                    color: '#ff7b72',
                    fontWeight: 700
                  },
                  '& .syntax-header-text': {
                    color: '#f0f6fc',
                    fontWeight: 600
                  },
                  '& .syntax-bold': {
                    color: '#f0f6fc',
                    fontWeight: 700
                  },
                  '& .syntax-italic': {
                    color: '#f0f6fc',
                    fontStyle: 'italic'
                  },
                  '& .syntax-code': {
                    color: '#a5d6ff',
                    backgroundColor: 'rgba(110, 118, 129, 0.2)',
                    borderRadius: '3px',
                    padding: '2px 4px'
                  },
                  '& .syntax-link': {
                    color: '#58a6ff'
                  },
                  '& .syntax-link-text': {
                    color: '#79c0ff'
                  },
                  '& .syntax-url': {
                    color: '#a5d6ff'
                  },
                  '& .syntax-list': {
                    color: '#ffa657',
                    fontWeight: 600
                  },
                  
                  // Enhanced scrollbar
                  '&::-webkit-scrollbar': {
                    width: '14px',
                    height: '14px'
                  },
                  '&::-webkit-scrollbar-track': {
                    background: 'rgba(255, 255, 255, 0.05)',
                    borderRadius: '7px'
                  },
                  '&::-webkit-scrollbar-thumb': {
                    background: 'linear-gradient(145deg, #667eea 0%, #764ba2 100%)',
                    borderRadius: '7px',
                    border: '2px solid transparent',
                    backgroundClip: 'padding-box',
                    '&:hover': {
                      background: 'linear-gradient(145deg, #5a6fd8 0%, #6a4190 100%)'
                    }
                  },
                  '&::-webkit-scrollbar-corner': {
                    background: 'rgba(255, 255, 255, 0.05)'
                  }
                }}
              >
                <Box sx={{ p: 3, color: '#e6edf3' }}>
                  {applySyntaxHighlighting(getTabContent(), getTabLanguage())}
                </Box>
              </Box>
              
              {/* Enhanced Info Bar */}
              <Box
                sx={{
                  position: 'absolute',
                  bottom: 0,
                  left: 0,
                  right: 0,
                  background: 'linear-gradient(90deg, rgba(102, 126, 234, 0.9) 0%, rgba(118, 75, 162, 0.9) 100%)',
                  backdropFilter: 'blur(10px)',
                  color: 'white',
                  px: 3,
                  py: 1.5,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  fontSize: '13px',
                  fontWeight: 500,
                  borderTop: '1px solid rgba(255, 255, 255, 0.1)'
                }}
              >
                <Box display="flex" alignItems="center" gap={2}>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box sx={{ 
                      width: 8, 
                      height: 8, 
                      borderRadius: '50%', 
                      backgroundColor: '#7ee787' 
                    }} />
                    {getTabContent().split('\n').length} lines
                  </Box>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box sx={{ 
                      width: 8, 
                      height: 8, 
                      borderRadius: '50%', 
                      backgroundColor: '#79c0ff' 
                    }} />
                    {getTabLanguage().toUpperCase()}
                  </Box>
                  <Box display="flex" alignItems="center" gap={1}>
                    <Box sx={{ 
                      width: 8, 
                      height: 8, 
                      borderRadius: '50%', 
                      backgroundColor: '#ffa657' 
                    }} />
                    UTF-8
                  </Box>
                </Box>
                <Box display="flex" alignItems="center" gap={2}>
                  <Typography variant="caption" sx={{ opacity: 0.9 }}>
                    Generated by ShadowSeek
                  </Typography>
                  <Typography variant="caption" sx={{ opacity: 0.7 }}>
                    {new Date().toLocaleString()}
                  </Typography>
                </Box>
              </Box>
            </Box>
          )}
        </DialogContent>
      </Dialog>

      {/* Generated Harnesses - Full Width Stacked Layout */}
      {loading ? (
        <Box display="flex" justifyContent="center" py={3}>
          <CircularProgress />
        </Box>
      ) : fuzzingHarnesses.length > 0 ? (
        <Box>
          <Typography variant="h6" gutterBottom>
            Generated Harnesses ({fuzzingHarnesses.length})
          </Typography>
          
          {/* Full-width stacked harnesses */}
          <Stack spacing={2}>
            {fuzzingHarnesses.map((harness: any, index: number) => (
              <Card 
                key={harness.id || index}
                variant="outlined"
                sx={{ 
                  borderColor: 'divider',
                  '&:hover': { 
                    borderColor: 'primary.main',
                    boxShadow: 1
                  }
                }}
              >
                <CardContent>
                  <Grid container spacing={3} alignItems="center">
                    {/* Left: Harness Info */}
                    <Grid item xs={12} md={4}>
                      <Typography variant="h6" fontWeight="bold" gutterBottom>
                        {harness.name || `Harness ${index + 1}`}
                      </Typography>
                      <Box display="flex" flexWrap="wrap" gap={1} mb={1}>
                        <Chip 
                          label={harness.harness_type || 'AFL++'} 
                          size="small" 
                          color="primary"
                          variant="filled"
                        />
                        <Chip 
                          label={`${harness.target_count || 0} targets`} 
                          size="small" 
                          color="secondary"
                          variant="filled"
                        />
                        <Chip 
                          label={`${harness.confidence_score || 100}% confidence`} 
                          size="small" 
                          color="success"
                          variant="filled"
                        />
                      </Box>
                      <Typography variant="body2" color="textSecondary">
                        <strong>Strategy:</strong> {harness.generation_strategy || 'security_analysis_based'}
                      </Typography>
                    </Grid>

                    {/* Center: Actions */}
                    <Grid item xs={12} md={5}>
                      <Box display="flex" flexWrap="wrap" gap={1} justifyContent="center">
                        <Button
                          variant="contained"
                          startIcon={<Visibility />}
                          onClick={() => handleViewAllCode(harness)}
                          sx={{ 
                            background: 'linear-gradient(45deg, #2196F3 30%, #21CBF3 90%)',
                            border: 'none',
                            boxShadow: '0 2px 8px rgba(33, 150, 243, 0.3)',
                            '&:hover': {
                              background: 'linear-gradient(45deg, #1976D2 30%, #1BA3D3 90%)',
                              boxShadow: '0 4px 12px rgba(33, 150, 243, 0.4)'
                            },
                            '&:focus': {
                              outline: 'none',
                              boxShadow: '0 0 0 2px rgba(33, 150, 243, 0.2)'
                            }
                          }}
                        >
                          View Code
                        </Button>
                        <Button
                          variant="contained"
                          startIcon={<Download />}
                          onClick={() => handleDownloadFile(harness.id, 'package')}
                          sx={{ 
                            background: 'linear-gradient(45deg, #4CAF50 30%, #45a049 90%)',
                            border: 'none',
                            boxShadow: '0 2px 8px rgba(76, 175, 80, 0.3)',
                            '&:hover': {
                              background: 'linear-gradient(45deg, #45a049 30%, #3d8b40 90%)',
                              boxShadow: '0 4px 12px rgba(76, 175, 80, 0.4)'
                            },
                            '&:focus': {
                              outline: 'none',
                              boxShadow: '0 0 0 2px rgba(76, 175, 80, 0.2)'
                            }
                          }}
                        >
                          Download ZIP
                        </Button>
                      </Box>
                    </Grid>

                    {/* Right: Delete */}
                    <Grid item xs={12} md={3}>
                      <Box display="flex" justifyContent="flex-end" alignItems="center">
                        <Typography variant="caption" color="textSecondary" sx={{ mr: 2 }}>
                          Complete fuzzing setup
                        </Typography>
                        <IconButton
                          color="error"
                          onClick={() => handleDeleteHarness(harness.id, harness.name || 'harness')}
                          sx={{ 
                            '&:hover': { 
                              backgroundColor: 'error.main',
                              color: 'white'
                            }
                          }}
                        >
                          <Delete />
                        </IconButton>
                      </Box>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            ))}
          </Stack>
          
          <Box mt={3} textAlign="center">
            <Button
              variant="outlined"
              startIcon={<Speed />}
              onClick={() => {
                window.open(`/fuzzing`, '_blank');
              }}
            >
              Open Full Fuzzing Dashboard
            </Button>
          </Box>
        </Box>
      ) : (
        <Alert severity="info">
          No fuzzing harnesses generated yet. Click "Generate AI Fuzzing Harness" to create harnesses for this binary.
        </Alert>
      )}
    </Box>
  );
};

const BinaryDetails: React.FC = () => {
  const { binaryId } = useParams<{ binaryId: string }>();
  const navigate = useNavigate();
  const [binaryDetails, setBinaryDetails] = useState<BinaryDetailsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);
  
  // Enhanced state for function management
  const [expandedFunctions, setExpandedFunctions] = useState<Record<string, boolean>>({});
  const [functionData, setFunctionData] = useState<Record<string, ExpandedFunctionData>>({});
  const [bulkDecompiling, setBulkDecompiling] = useState(false);
  const [bulkDecompileProgress, setBulkDecompileProgress] = useState({ current: 0, total: 0 });
  const [bulkAIExplaining, setBulkAIExplaining] = useState(false);
  const [bulkAIProgress, setBulkAIProgress] = useState({ current: 0, total: 0 });
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  
  // Binary AI Summary state
  const [binaryAISummary, setBinaryAISummary] = useState<any>(null);
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false);
  const [showAISummary, setShowAISummary] = useState(false);
  
  // Vulnerability state
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [vulnerabilitiesLoading, setVulnerabilitiesLoading] = useState(false);
  const [vulnerabilityScanning, setVulnerabilityScanning] = useState(false);
  
  // Fuzzing state
  const [fuzzingGenerating, setFuzzingGenerating] = useState(false);
  
  // Sorting state
  const [sortBy, setSortBy] = useState<string>('address');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc');
  
  // Security analysis data
  const [securityFindings, setSecurityFindings] = useState<{ [key: string]: any[] }>({});
  const [securitySummary, setSecuritySummary] = useState<any>(null);
  
  // Comprehensive analysis data for new tabs
  const [stringsData, setStringsData] = useState<any[]>([]);
  const [symbolsData, setSymbolsData] = useState<any[]>([]);
  const [memoryBlocksData, setMemoryBlocksData] = useState<any[]>([]);
  const [importsData, setImportsData] = useState<any[]>([]);
  const [exportsData, setExportsData] = useState<any[]>([]);
  const [dataLoading, setDataLoading] = useState<Record<string, boolean>>({
    strings: false,
    symbols: false,
    memory: false,
    imports: false
  });


  useEffect(() => {
    if (binaryId) {
      fetchBinaryDetails();
      checkExistingAISummary();
      fetchVulnerabilities();
      fetchSecurityFindings();
    }
  }, [binaryId]);

  const fetchBinaryDetails = async () => {
    if (!binaryId) return;
    
    try {
      setLoading(true);
      const details = await apiClient.getBinaryDetails(binaryId);
      
      // Defensive programming: ensure all arrays exist and are properly formatted
      if (!Array.isArray(details.functions)) details.functions = [];
      if (!Array.isArray(details.results)) details.results = [];
      
      // Clean up any malformed function data
      details.functions = details.functions.filter(func => 
        func && typeof func === 'object' && func.id && func.address
      );
      
      // Clean up any malformed result data  
      details.results = details.results.filter(result => 
        result && typeof result === 'object' && result.id
      );
      
      setBinaryDetails(details);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch binary details');
      console.error('Error fetching binary details:', err);
    } finally {
      setLoading(false);
    }
  };

  const checkExistingAISummary = async () => {
    if (!binaryId) return;
    
    try {
      const summary = await apiClient.getBinaryAISummary(binaryId);
      if (summary.success) {
        setBinaryAISummary(summary);
        setShowAISummary(true);
      }
    } catch (err) {
      // No existing summary, that's fine
    }
  };

  const fetchVulnerabilities = async () => {
    if (!binaryId) return;
    
    try {
      setVulnerabilitiesLoading(true);
      const response = await apiClient.getVulnerabilities(binaryId, {
        page: 1,
        perPage: 100
      });
      setVulnerabilities(response.vulnerabilities || []);
    } catch (err) {
      console.error('Error fetching vulnerabilities:', err);
      // Don't show error for empty vulnerabilities
    } finally {
      setVulnerabilitiesLoading(false);
    }
  };

  const fetchSecurityFindings = async () => {
    if (!binaryId) return;
    try {
      const response = await fetch(`/api/binaries/${binaryId}/security-findings`);
      if (response.ok) {
        const data = await response.json();
        // Group findings by function_id
        const findingsByFunction: { [key: string]: any[] } = {};
        data.findings?.forEach((finding: any) => {
          if (finding.function_id) {
            if (!findingsByFunction[finding.function_id]) {
              findingsByFunction[finding.function_id] = [];
            }
            findingsByFunction[finding.function_id].push(finding);
          }
        });
        setSecurityFindings(findingsByFunction);
        setSecuritySummary(data.summary || null);
      }
    } catch (err) {
      console.error('Error fetching security findings:', err);
    }
  };

  const handleGenerateAISummary = async (forceFresh: boolean = false) => {
    if (!binaryId) return;
    
    try {
      setAiSummaryLoading(true);
      
      // If forcing fresh analysis or no existing summary, clear cache first
      if (forceFresh || !binaryAISummary) {
        toast.info('Clearing cache for fresh analysis...');
        try {
          // Clear binary AI summary cache
          await fetch('/api/clear-binary-ai-cache', {
            method: 'POST', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ binary_id: binaryId })
          });
          console.log('[AI] Cache cleared successfully');
          setBinaryAISummary(null); // Clear frontend cache too
        } catch (err) {
          console.warn('[AI] Cache clearing failed, proceeding anyway:', err);
        }
      }
      
      const result = await apiClient.generateBinaryAISummary(binaryId);
      
      if (result.cached && !forceFresh) {
        setBinaryAISummary(result);
        setShowAISummary(true);
        toast.success('AI summary loaded from cache');
      } else {
        toast.success('Fresh AI summary generation started. Please wait...');
        // Poll for completion
        pollAISummaryStatus();
      }
    } catch (err: any) {
      toast.error(`AI summary failed: ${err.response?.data?.error || err.message}`);
    } finally {
      setAiSummaryLoading(false);
    }
  };

  // Wrapper functions for button handlers
  const handleFreshAIAnalysis = () => handleGenerateAISummary(true);
  const handleUpdateAIAnalysis = () => handleGenerateAISummary(true);
  const handleStartAIAnalysis = () => handleGenerateAISummary(false);

  // Clear cache function
  const handleClearCache = async () => {
    if (!binaryId) return;
    
    try {
      // Clear binary AI summary cache
      await fetch('/api/clear-binary-ai-cache', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binary_id: binaryId })
      });
      
      // Clear frontend cache
      setBinaryAISummary(null);
      setShowAISummary(false);
      
      toast.success('AI analysis cache cleared successfully');
      
    } catch (err) {
      console.error('Cache clearing failed:', err);
      toast.error('Failed to clear cache');
    }
  };

  const pollAISummaryStatus = () => {
    const interval = setInterval(async () => {
      try {
        const summary = await apiClient.getBinaryAISummary(binaryId!);
        if (summary.success) {
          setBinaryAISummary(summary);
          setShowAISummary(true);
          toast.success('AI summary completed!');
          clearInterval(interval);
          setAiSummaryLoading(false);
        }
      } catch (err) {
        // Still processing
      }
    }, 3000);

    // Stop polling after 5 minutes
    setTimeout(() => {
      clearInterval(interval);
      setAiSummaryLoading(false);
    }, 300000);
  };

  const handleStartAnalysis = async () => {
    if (!binaryId) return;
    
    try {
      await apiClient.startAnalysis(binaryId);
      toast.success('Analysis started successfully');
      fetchBinaryDetails(); // Refresh details
    } catch (err: any) {
      toast.error('Failed to start analysis');
      console.error('Error starting analysis:', err);
    }
  };

  const handleRunVulnerabilityScan = async () => {
    if (!binaryId) return;
    
    try {
      setVulnerabilityScanning(true);
      await apiClient.scanVulnerabilities(binaryId);
      toast.success('Vulnerability scan started - refreshing results...');
      
      // Poll for new vulnerabilities
      setTimeout(() => {
        fetchVulnerabilities();
        setVulnerabilityScanning(false);
      }, 3000);
    } catch (err: any) {
      toast.error('Failed to start vulnerability scan');
      console.error('Error starting vulnerability scan:', err);
      setVulnerabilityScanning(false);
    }
  };

  const handleSearchPatterns = async () => {
    if (!binaryId) return;
    
    try {
      await apiClient.searchPatterns(binaryId);
      toast.success('Pattern search started');
      fetchBinaryDetails(); // Refresh to show new results
    } catch (err: any) {
      toast.error('Failed to start pattern search');
      console.error('Error starting pattern search:', err);
    }
  };

  const handleCompareBinary = () => {
    navigate('/comparison');
  };

  const handleDownload = () => {
    if (binaryId) {
      window.open(`/api/binaries/${binaryId}/download`);
    }
  };

  const handleGenerateFuzzingHarness = async () => {
    if (!binaryId) return;
    
    try {
      setFuzzingGenerating(true);
      
      const response = await fetch(`/api/binaries/${binaryId}/generate-fuzzing-harness`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          min_risk_score: 40,
          target_severities: ['HIGH', 'MEDIUM'],
          harness_types: ['AFL++']  // ✅ Fixed! Use correct parameter name
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || data.error || 'Failed to generate fuzzing harness');
      }

      toast.success('Fuzzing harness generated successfully!');
      
      // Switch to Fuzzing tab and scroll to it
              setTabValue(3); // Symbols tab updated index
      setTimeout(() => {
        const fuzzingTab = document.querySelector('[role="tabpanel"][hidden="false"]');
        if (fuzzingTab) {
          fuzzingTab.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }, 100);
      
    } catch (err: any) {
      toast.error(`Fuzzing harness generation failed: ${err.message}`);
      console.error('Error generating fuzzing harness:', err);
    } finally {
      setFuzzingGenerating(false);
    }
  };





  // Enhanced function handling
  const toggleFunctionExpanded = (functionId: string) => {
    setExpandedFunctions(prev => ({
      ...prev,
      [functionId]: !prev[functionId]
    }));

    // Load function details if expanding for the first time
    if (!expandedFunctions[functionId] && !functionData[functionId]) {
      loadFunctionDetails(functionId);
    }
  };

  const loadFunctionDetails = async (functionId: string) => {
    try {
      setFunctionData(prev => ({
        ...prev,
        [functionId]: {
          ...prev[functionId],
          loading: { ...prev[functionId]?.loading, fetchingDetails: true }
        }
      }));

      const details = await apiClient.getFunctionDetails(functionId);
      
      setFunctionData(prev => ({
        ...prev,
        [functionId]: {
          ...prev[functionId],
          details: details.function,
          decompiled: details.function.is_decompiled ? {
            success: true,
            decompiled_code: details.function.decompiled_code,
            cached: true
          } : null,
          aiExplanation: details.function.ai_analyzed ? {
            success: true,
            ai_summary: details.function.ai_summary,
            risk_score: details.function.risk_score,
            cached: true
          } : null,
          loading: { ...prev[functionId]?.loading, fetchingDetails: false }
        }
      }));
    } catch (err) {
      console.error('Error loading function details:', err);
      setFunctionData(prev => ({
        ...prev,
        [functionId]: {
          ...prev[functionId],
          loading: { ...prev[functionId]?.loading, fetchingDetails: false }
        }
      }));
    }
  };

  const handleDecompileFunction = async (functionId: string) => {
    try {
      setFunctionData(prev => ({
        ...prev,
        [functionId]: {
          ...prev[functionId],
          loading: { ...prev[functionId]?.loading, decompiling: true }
        }
      }));

      const result = await apiClient.decompileFunction(functionId);
      
      if (result.cached) {
        setFunctionData(prev => ({
          ...prev,
          [functionId]: {
            ...prev[functionId],
            decompiled: result,
            loading: { ...prev[functionId]?.loading, decompiling: false }
          }
        }));
        toast.success('Decompiled code loaded from cache');
      } else {
        toast.success('Decompilation started. Please wait...');
        // Poll for completion
        pollFunctionStatus(functionId, 'decompiling');
      }
    } catch (err: any) {
      toast.error(`Decompilation failed: ${err.response?.data?.error || err.message}`);
      setFunctionData(prev => ({
        ...prev,
        [functionId]: {
          ...prev[functionId],
          loading: { ...prev[functionId]?.loading, decompiling: false }
        }
      }));
    }
  };

  const handleExplainFunction = async (functionId: string) => {
    try {
      setFunctionData(prev => ({
        ...prev,
        [functionId]: {
          ...prev[functionId],
          loading: { ...prev[functionId]?.loading, explaining: true }
        }
      }));

      const result = await apiClient.explainFunction(functionId);
      
      if (result.cached) {
        setFunctionData(prev => ({
          ...prev,
          [functionId]: {
            ...prev[functionId],
            aiExplanation: result,
            loading: { ...prev[functionId]?.loading, explaining: false }
          }
        }));
        toast.success('AI explanation loaded from cache');
      } else {
        toast.success('AI explanation started. Please wait...');
        // Poll for completion
        pollFunctionStatus(functionId, 'explaining');
      }
    } catch (err: any) {
      toast.error(`AI explanation failed: ${err.response?.data?.error || err.message}`);
      setFunctionData(prev => ({
        ...prev,
        [functionId]: {
          ...prev[functionId],
          loading: { ...prev[functionId]?.loading, explaining: false }
        }
      }));
    }
  };

  const pollFunctionStatus = (functionId: string, type: 'decompiling' | 'explaining') => {
    const interval = setInterval(async () => {
      try {
        const details = await apiClient.getFunctionDetails(functionId);
        const func = details.function;
        
        if (type === 'decompiling' && func.is_decompiled && func.decompiled_code) {
          setFunctionData(prev => ({
            ...prev,
            [functionId]: {
              ...prev[functionId],
              decompiled: {
                success: true,
                decompiled_code: func.decompiled_code,
                cached: false
              },
              details: func,
              loading: { ...prev[functionId]?.loading, decompiling: false }
            }
          }));
          toast.success('Decompilation completed!');
          clearInterval(interval);
          fetchBinaryDetails(); // Refresh main view
        } else if (type === 'explaining' && func.ai_analyzed && func.ai_summary) {
          setFunctionData(prev => ({
            ...prev,
            [functionId]: {
              ...prev[functionId],
              aiExplanation: {
                success: true,
                ai_summary: func.ai_summary,
                risk_score: func.risk_score,
                cached: false
              },
              details: func,
              loading: { ...prev[functionId]?.loading, explaining: false }
            }
          }));
          toast.success('AI explanation completed!');
          clearInterval(interval);
          fetchBinaryDetails(); // Refresh main view
        }
      } catch (err) {
        console.error('Polling error:', err);
      }
    }, 3000);

    // Stop polling after 5 minutes
    setTimeout(() => {
      clearInterval(interval);
      setFunctionData(prev => ({
        ...prev,
        [functionId]: {
          ...prev[functionId],
          loading: { 
            ...prev[functionId]?.loading, 
            decompiling: false, 
            explaining: false 
          }
        }
      }));
    }, 300000);
  };

  const handleBulkDecompile = async () => {
    if (!binaryId) return;
    
    setBulkDecompiling(true);
    const initialDecompiledCount = functions.filter(f => f.is_decompiled).length;
    setBulkDecompileProgress({ current: initialDecompiledCount, total: functions.length });
    
    // Start progress tracking immediately
    let progressInterval: NodeJS.Timeout | null = null;
    let lastDecompiledCount = initialDecompiledCount;
    let stagnantCount = 0;
    
    const startProgressTracking = () => {
      progressInterval = setInterval(async () => {
        try {
          const details = await apiClient.getBinaryDetails(binaryId);
          if (details.functions) {
            const currentDecompiled = details.functions.filter((f: Function) => f.is_decompiled).length;
            setBulkDecompileProgress({ current: currentDecompiled, total: details.functions.length });
            
            // Update main state
            setBinaryDetails(details);
            
            // Check if progress is being made
            if (currentDecompiled === lastDecompiledCount) {
              stagnantCount++;
            } else {
              stagnantCount = 0;
              lastDecompiledCount = currentDecompiled;
            }
            
            // Stop if all functions are decompiled
            if (currentDecompiled >= details.functions.length) {
              if (progressInterval) clearInterval(progressInterval);
              setBulkDecompiling(false);
              toast.success(`Bulk decompilation completed! ${currentDecompiled - initialDecompiledCount} functions decompiled.`);
              return;
            }
            
            // Stop if no progress for 5 minutes (150 polls * 2 seconds)
            if (stagnantCount > 150) {
              if (progressInterval) clearInterval(progressInterval);
              setBulkDecompiling(false);
              if (currentDecompiled > initialDecompiledCount) {
                toast.success(`Bulk decompilation completed! ${currentDecompiled - initialDecompiledCount} functions decompiled.`);
              } else {
                toast.warning('Bulk decompilation appears to have stopped. Check the logs for details.');
              }
              return;
            }
          }
        } catch (err) {
          console.error('Error checking progress:', err);
          // Don't stop tracking on temporary errors
        }
      }, 2000);
    };
    
    // Start progress tracking
    startProgressTracking();
    
    // Attempt to start bulk decompilation
    try {
      const result = await apiClient.bulkDecompileFunctions(binaryId);
      
      if (result.success) {
        toast.success(`Bulk decompilation started for ${result.functions_to_decompile} functions!`);
      } else {
        toast.warning('Bulk decompilation may have started, but server response was unclear. Monitoring progress...');
      }
    } catch (err: any) {
      // Don't stop progress tracking even if API call fails
      console.error('Bulk decompilation API call failed:', err);
      if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
        toast.warning('Bulk decompilation API timed out, but the process may still be running. Monitoring progress...');
      } else {
        toast.error(`Bulk decompilation failed to start: ${err.response?.data?.error || err.message}`);
        // Only stop tracking if it's a clear failure to start
        if (progressInterval) clearInterval(progressInterval);
        setBulkDecompiling(false);
        setBulkDecompileProgress({ current: 0, total: 0 });
      }
    }
    
    // Safety timeout after 20 minutes
    setTimeout(() => {
      if (progressInterval) {
        clearInterval(progressInterval);
        setBulkDecompiling(false);
        toast.warning('Bulk decompilation monitoring stopped after 20 minutes. Process may still be running in background.');
      }
    }, 1200000);
  };

  const handleBulkAIExplain = async () => {
    if (!binaryId) return;
    
    setBulkAIExplaining(true);
    const decompiledFunctions = functions.filter(f => f.is_decompiled);
    
    console.log(`[BulkAI] Starting fresh AI analysis for ${decompiledFunctions.length} decompiled functions`);
    
    // Check prerequisites
    if (decompiledFunctions.length === 0) {
      toast.warning('No decompiled functions available for AI analysis. Please decompile functions first.');
      setBulkAIExplaining(false);
      return;
    }
    
    // Clear existing AI analysis cache and binary AI summary cache
    toast.info('Clearing existing AI analysis cache...');
    try {
      // Clear function AI analyses
      await fetch('/api/clear-function-ai-cache', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binary_id: binaryId })
      });
      
      // Clear binary AI summary cache
      await fetch('/api/clear-binary-ai-cache', {
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ binary_id: binaryId })
      });
      
      console.log('[BulkAI] Cache cleared successfully');
    } catch (err) {
      console.warn('[BulkAI] Cache clearing failed, proceeding anyway:', err);
    }
    
    // Initialize progress for ALL decompiled functions (re-analyzing everything)
    setBulkAIProgress({ current: 0, total: decompiledFunctions.length });
    
    // Progress tracking - count freshly analyzed functions
    const startTime = Date.now();
    let lastUpdatedTimestamp = Date.now();
    
    const progressInterval = setInterval(async () => {
      try {
        const details = await apiClient.getBinaryDetails(binaryId);
        if (details.functions) {
          // Count decompiled functions that have fresh AI analysis
          const recentlyAnalyzed = details.functions.filter((f: Function) => {
            if (!f.is_decompiled) return false;
            return f.ai_analyzed || f.ai_summary || (f.risk_score !== null && f.risk_score !== undefined);
          }).length;
          
          setBulkAIProgress({ current: recentlyAnalyzed, total: decompiledFunctions.length });
          setBinaryDetails(details); // Update main data
          
          console.log(`[BulkAI] Progress: ${recentlyAnalyzed}/${decompiledFunctions.length} functions analyzed`);
          
          // Clear local function data cache when we see updates
          if (recentlyAnalyzed > 0) {
            setFunctionData({}); // Clear cached function details to force fresh loads
          }
          
          // Check completion
          if (recentlyAnalyzed >= decompiledFunctions.length) {
            clearInterval(progressInterval);
            setBulkAIExplaining(false);
            setBulkAIProgress({ current: 0, total: 0 });
            toast.success(`Fresh AI analysis completed! ${recentlyAnalyzed} functions analyzed.`);
            
            // Refresh binary AI summary with fresh function data
            setTimeout(() => {
              setBinaryAISummary(null); // Clear cached summary
              handleGenerateAISummary();
            }, 2000);
            return;
          }
          
          // Timeout check (25 minutes for complete re-analysis)
          if (Date.now() - startTime > 1500000) {
            clearInterval(progressInterval);
            setBulkAIExplaining(false);
            setBulkAIProgress({ current: 0, total: 0 });
            toast.warning('AI analysis monitoring timed out after 25 minutes.');
            return;
          }
        }
      } catch (err) {
        console.error('[BulkAI] Progress check error:', err);
      }
    }, 3000);
    
    // Start fresh bulk analysis
    try {
      const result = await apiClient.bulkAIExplainFunctions(binaryId);
      if (result.success) {
        toast.success(`Fresh bulk AI analysis started for ${decompiledFunctions.length} functions!`);
      } else {
        toast.warning('AI analysis may have started. Monitoring progress...');
      }
    } catch (err: any) {
      console.error('[BulkAI] API error:', err);
      if (err.code === 'ECONNABORTED' || err.message.includes('timeout')) {
        toast.warning('AI analysis API timed out, but process may still be running. Monitoring progress...');
      } else {
        clearInterval(progressInterval);
        setBulkAIExplaining(false);
        setBulkAIProgress({ current: 0, total: 0 });
        toast.error(`AI analysis failed: ${err.response?.data?.error || err.message}`);
      }
    }
  };

  const getRiskColor = (score: number) => {
    if (score >= 80) return 'error';
    if (score >= 50) return 'warning';
    if (score >= 20) return 'info';
    return 'success';
  };

  const getRiskLevel = (score: number) => {
    if (score >= 80) return 'Critical';
    if (score >= 50) return 'High';
    if (score >= 20) return 'Medium';
    return 'Low';
  };

  // Helper function to get vulnerabilities for a specific function
  const getFunctionVulnerabilities = (functionId: string) => {
    return vulnerabilities.filter(vuln => vuln.function_id === functionId);
  };

  // Helper function to get highest severity for function vulnerabilities
  const getHighestVulnerabilitySeverity = (functionId: string) => {
    const funcVulns = getFunctionVulnerabilities(functionId);
    if (funcVulns.length === 0) return null;
    
    const severityOrder: { [key: string]: number } = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0 };
    return funcVulns.reduce((highest, vuln) => {
      const currentSeverity = severityOrder[vuln.severity] || 0;
      const highestSeverity = severityOrder[highest] || 0;
      return currentSeverity > highestSeverity ? vuln.severity : highest;
    }, 'info');
  };

  // New functions for unified security analysis
  const getFunctionSecurityFindings = (functionId: string) => {
    return securityFindings[functionId] || [];
  };

  const getSecurityAnalysisSummary = (functionId: string) => {
    const findings = getFunctionSecurityFindings(functionId);
    
    if (!findings.length) {
      return { text: 'None', severity: null, count: 0, confidence: null };
    }
    
    // Get highest severity and average confidence
    const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0 };
    const highestSeverity = findings.reduce((highest, finding) => {
      const currentScore = severityOrder[finding.severity as keyof typeof severityOrder] || 0;
      const highestScore = severityOrder[highest as keyof typeof severityOrder] || 0;
      return currentScore > highestScore ? finding.severity : highest;
    }, 'INFO');
    
    const avgConfidence = Math.round(
      findings.reduce((sum, finding) => sum + (finding.confidence || 0), 0) / findings.length
    );
    
    return {
      text: `${findings.length} ${highestSeverity.toLowerCase()}`,
      severity: highestSeverity.toLowerCase(),
      count: findings.length,
      confidence: avgConfidence
    };
  };

  // Sorting functions
  const handleSort = (column: string) => {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(column);
      setSortOrder('asc');
    }
  };

  const sortFunctions = (functions: Function[]) => {
    return [...functions].sort((a, b) => {
      let aValue: any, bValue: any;
      
      switch (sortBy) {
        case 'address':
          aValue = parseInt(a.address.replace('0x', ''), 16);
          bValue = parseInt(b.address.replace('0x', ''), 16);
          break;
        case 'name':
          aValue = (a.name || a.original_name || 'Unknown').toLowerCase();
          bValue = (b.name || b.original_name || 'Unknown').toLowerCase();
          break;
        case 'size':
          aValue = a.size || 0;
          bValue = b.size || 0;
          break;
        case 'security':
          const aSecurity = getSecurityAnalysisSummary(a.id);
          const bSecurity = getSecurityAnalysisSummary(b.id);
          const severityOrder = { 'critical': 4, 'high': 3, 'medium': 2, 'low': 1 };
          aValue = severityOrder[aSecurity.severity as keyof typeof severityOrder] || 0;
          bValue = severityOrder[bSecurity.severity as keyof typeof severityOrder] || 0;
          break;
        case 'risk':
          aValue = a.risk_score || 0;
          bValue = b.risk_score || 0;
          break;
        default:
          return 0;
      }
      
      if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
  };

  // Helper function to find function by name or address
  const findFunctionByNameOrAddress = (nameOrAddress: string) => {
    if (!binaryDetails?.functions) return null;
    
    return binaryDetails.functions.find(func => 
      func.name === nameOrAddress || 
      func.original_name === nameOrAddress ||
      func.address === nameOrAddress ||
      func.address.toLowerCase() === nameOrAddress.toLowerCase()
    );
  };

  // Helper function to navigate to a function
  const navigateToFunction = (functionName: string) => {
    const targetFunction = findFunctionByNameOrAddress(functionName);
    if (targetFunction) {
      setTabValue(0); // Switch to Functions tab
      // Expand the specific function
      setExpandedFunctions(prev => ({
        ...prev,
        [targetFunction.id]: true
      }));
      // Load function details if not already loaded
      if (!functionData[targetFunction.id]?.decompiled && !functionData[targetFunction.id]?.loading?.fetchingDetails) {
        loadFunctionDetails(targetFunction.id);
      }
      // Scroll to the function after a short delay
      setTimeout(() => {
        const functionElement = document.getElementById(`function-${targetFunction.id}`);
        if (functionElement) {
          functionElement.scrollIntoView({ 
            behavior: 'smooth', 
            block: 'center' 
          });
        }
      }, 300);
    }
  };

  // Helper function to render text with clickable function names
  const renderTextWithFunctionLinks = (text: string) => {
    // Pattern to match function names (FUN_xxxxxxxx, addresses, sub_ functions, etc.)
    const functionPattern = /(FUN_[0-9a-fA-F]{8,16}|0x[0-9a-fA-F]{8,16}|sub_[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*@0x[0-9a-fA-F]+)/g;
    const parts = text.split(functionPattern);
    
    return parts.map((part, index) => {
      if (part && /^(FUN_[0-9a-fA-F]{8,16}|0x[0-9a-fA-F]{8,16}|sub_[0-9a-fA-F]+|[a-zA-Z_][a-zA-Z0-9_]*@0x[0-9a-fA-F]+)$/.test(part)) {
        // This is a potential function name/address
        const targetFunction = findFunctionByNameOrAddress(part);
        if (targetFunction) {
          return (
            <Chip
              key={index}
              label={part}
              size="small"
              color="primary"
              variant="outlined"
              onClick={() => navigateToFunction(part)}
              clickable
              sx={{ 
                cursor: 'pointer', 
                mx: 0.5,
                '&:hover': {
                  backgroundColor: 'primary.main',
                  color: 'white'
                }
              }}
              title={`Click to jump to ${targetFunction.name || targetFunction.address} in Functions tab`}
            />
          );
        }
      }
      return part;
    });
  };

  // Filter and sort functions based on search and status with error handling
  const filteredFunctions = React.useMemo(() => {
    try {
      if (!binaryDetails?.functions || !Array.isArray(binaryDetails.functions)) {
        return [];
      }
      
      const filtered = binaryDetails.functions.filter(func => {
        if (!func || typeof func !== 'object') return false;
        
        const matchesSearch = searchTerm === '' || 
          (func.name && func.name.toLowerCase().includes(searchTerm.toLowerCase())) ||
          (func.address && func.address.toLowerCase().includes(searchTerm.toLowerCase()));
        
        const matchesStatus = statusFilter === 'all' || 
          (statusFilter === 'decompiled' && func.is_decompiled) ||
          (statusFilter === 'not_decompiled' && !func.is_decompiled) ||
          (statusFilter === 'ai_analyzed' && (func.ai_analyzed || func.ai_summary || func.risk_score)) ||
          (statusFilter === 'external' && func.is_external) ||
          (statusFilter === 'high_risk' && func.risk_score && func.risk_score >= 50);
          
        return matchesSearch && matchesStatus;
      });
      
      // Apply sorting
      return sortFunctions(filtered);
    } catch (error) {
      console.error('Error filtering functions:', error);
      return [];
    }
  }, [binaryDetails?.functions, searchTerm, statusFilter, sortBy, sortOrder, securityFindings]);

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <LinearProgress sx={{ width: '50%' }} />
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {error}
      </Alert>
    );
  }

  if (!binaryDetails) {
    return (
      <Alert severity="info" sx={{ m: 2 }}>
        Binary not found
      </Alert>
    );
  }

  const { binary, results } = binaryDetails;
  // Use fresh functions data from binaryDetails to ensure real-time updates
  const functions = binaryDetails.functions || [];

  // Vulnerabilities count: only CRITICAL, HIGH, MEDIUM, LOW from summary
  const vulnerabilitySeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const vulnerabilitiesCount = securitySummary
    ? vulnerabilitySeverities.reduce((sum, sev) => sum + (securitySummary.severity_counts?.[sev] || 0), 0)
    : 0;

  // Load comprehensive analysis data for different tabs
  const fetchComprehensiveData = async (dataType: string) => {
    if (!binaryId) return;
    
    setDataLoading(prev => ({ ...prev, [dataType]: true }));
    
    try {
      const response = await apiClient.getComprehensiveData(binaryId, dataType, 1, 100);
      
      switch (dataType) {
        case 'strings':
          setStringsData(response.data || []);
          break;
        case 'symbols':
          setSymbolsData(response.data || []);
          break;
        case 'memory_blocks':
          setMemoryBlocksData(response.data || []);
          break;
        case 'imports':
          setImportsData(response.data || []);
          break;
        case 'exports':
          setExportsData(response.data || []);
          break;
      }
    } catch (error) {
      console.error(`Error fetching ${dataType}:`, error);
      toast.error(`Failed to load ${dataType}`);
    } finally {
      setDataLoading(prev => ({ ...prev, [dataType]: false }));
    }
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">
          {binary.original_filename}
        </Typography>
        <Box>
          <Button
            variant="outlined"
            onClick={handleDownload}
            startIcon={<Download />}
            sx={{ mr: 1 }}
          >
            Download
          </Button>
          <Button
            variant="contained"
            color="primary"
            onClick={() => {
              // Always use comprehensive analysis - reset first if needed
              if (binary.analysis_status === 'analyzing') {
                // Reset analysis first, then start new one
                fetch(`/api/binaries/${binaryId}/reset-analysis`, { method: 'POST' })
                  .then(() => {
                    return apiClient.startComprehensiveAnalysis(binaryId!);
                  })
                  .then(() => {
                    toast.success('Comprehensive analysis restarted successfully');
                    fetchBinaryDetails();
                  })
                  .catch((err) => {
                    toast.error(`Failed to restart analysis: ${err.response?.data?.error || err.message}`);
                  });
              } else {
                apiClient.startComprehensiveAnalysis(binaryId!)
                  .then(() => {
                    toast.success('Comprehensive analysis started successfully');
                    fetchBinaryDetails();
                  })
                  .catch((err) => {
                    toast.error(`Failed to start comprehensive analysis: ${err.response?.data?.error || err.message}`);
                  });
              }
            }}
            startIcon={<PlayArrow />}
            sx={{ mr: 1 }}
          >
            {binary.analysis_status === 'analyzing' ? 'Restart Analysis' : 'Comprehensive Analysis'}
          </Button>
          <Button
            variant="contained"
            color="primary"
            onClick={() => {
              // Switch to Security Analysis tab and scroll to it
              setTabValue(2); // Strings tab updated index
              setTimeout(() => {
                const securityTab = document.querySelector('[role="tabpanel"][hidden="false"]');
                if (securityTab) {
                  securityTab.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
              }, 100);
            }}
            startIcon={<BugReport />}
            disabled={false} // Enhanced security analysis works with or without decompiled functions
            sx={{ mr: 1 }}
          >
            Security Analysis
          </Button>
          <Button
            variant="contained"
            color="primary"
            onClick={handleGenerateFuzzingHarness}
            startIcon={fuzzingGenerating ? <CircularProgress size={20} color="inherit" /> : <FlashOn />}
            disabled={fuzzingGenerating || functions.filter(f => f.is_decompiled).length === 0}
            sx={{ mr: 1 }}
          >
            {fuzzingGenerating ? 'Generating...' : 'Fuzzing'}
          </Button>
          <Button
            variant="outlined"
            onClick={handleCompareBinary}
            sx={{ mr: 1 }}
          >
            Compare Binary
          </Button>
        </Box>
      </Box>



      {/* Show analysis queued state */}
      {binary.analysis_status === 'queued' && (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="subtitle2">Analysis Queued</Typography>
          <Typography variant="body2">
            Your analysis request has been queued and will start shortly...
          </Typography>
        </Alert>
      )}

      {/* Main Content Layout */}
      <Grid container spacing={3} mb={3}>
        {/* Left Column: File Info + Analysis Data + Functions */}
        <Grid item xs={12} lg={8}>
          {/* File Information Section */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6" fontWeight="bold">
                  File Information
                </Typography>
                <Chip 
                  label={binary.analysis_status}
                  color={getStatusColor(binary.analysis_status)}
                  size="small"
                />
              </Box>
              
              <Grid container spacing={3}>
                <Grid item xs={12} md={8}>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={6}>
                      <Box>
                        <Typography variant="body2" color="textSecondary">Filename</Typography>
                        <Typography variant="body1" fontWeight="medium">{binary.original_filename}</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Box>
                        <Typography variant="body2" color="textSecondary">Size</Typography>
                        <Typography variant="body1" fontWeight="medium">{formatFileSize(binary.file_size)}</Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={12} sm={6}>
                      <Box>
                        <Typography variant="body2" color="textSecondary">Upload Time</Typography>
                        <Typography variant="body1" fontWeight="medium">{formatDate(binary.upload_time)}</Typography>
                      </Box>
                    </Grid>
                    {binary.architecture && (
                      <Grid item xs={12} sm={6}>
                        <Box>
                          <Typography variant="body2" color="textSecondary">Architecture</Typography>
                          <Typography variant="body1" fontWeight="medium">{binary.architecture}</Typography>
                        </Box>
                      </Grid>
                    )}
                    {binary.mime_type && (
                      <Grid item xs={12} sm={6}>
                        <Box>
                          <Typography variant="body2" color="textSecondary">MIME Type</Typography>
                          <Typography variant="body1" fontWeight="medium">{binary.mime_type}</Typography>
                        </Box>
                      </Grid>
                    )}
                    
                    {/* DLL Type Detection */}
                    {binary.original_filename?.toLowerCase().endsWith('.dll') && (
                      <Grid item xs={12} sm={6}>
                        <Box>
                          <Typography variant="body2" color="textSecondary">DLL Type</Typography>
                          {(() => {
                            const forwarderData = securitySummary?.forwarder_analysis;
                            const isForwarderDLL = forwarderData?.is_forwarder;
                            
                            if (isForwarderDLL) {
                              return (
                                <Chip
                                  label="🔄 API Forwarder DLL"
                                  color="warning"
                                  size="small"
                                  variant="outlined"
                                />
                              );
                            } else if (forwarderData) {
                              return (
                                <Chip
                                  label="⚙️ Implementation DLL"
                                  color="success"
                                  size="small"
                                  variant="outlined"
                                />
                              );
                            } else {
                              return (
                                <Chip
                                  label="🔍 Analysis Pending"
                                  color="info"
                                  size="small"
                                  variant="outlined"
                                />
                              );
                            }
                          })()}
                        </Box>
                      </Grid>
                    )}
                    
                    {binary.file_hash && (
                      <Grid item xs={12}>
                        <Box>
                          <Typography variant="body2" color="textSecondary">Hash</Typography>
                          <Typography variant="body1" fontWeight="medium" sx={{ fontFamily: 'monospace', fontSize: '0.9em', wordBreak: 'break-all' }}>
                            {binary.file_hash}
                          </Typography>
                        </Box>
                      </Grid>
                    )}
                  </Grid>
                </Grid>
                
                <Grid item xs={12} md={4}>
                  <Box display="flex" alignItems="center" justifyContent="center" height="100%">
                    <Card variant="outlined" sx={{ width: '100%', textAlign: 'center', p: 2 }}>
                      <Typography variant="h4" color="secondary" fontWeight="bold">
                        {results.length}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        Analysis Results
                      </Typography>
                    </Card>
                  </Box>
                </Grid>
              </Grid>
            </CardContent>
          </Card>

          {/* Analysis Data Section */}
          <Card>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6" fontWeight="bold">
                  Analysis Data
                </Typography>
              </Box>
              
              <Grid container spacing={2}>
                <Grid item xs={12} sm={6} md={2.4}>
                  <Card variant="outlined" sx={{ textAlign: 'center', p: 2 }}>
                    <Typography variant="h5" color="primary" fontWeight="bold">
                      {functions.length}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Functions
                    </Typography>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2.4}>
                  <Card variant="outlined" sx={{ textAlign: 'center', p: 2 }}>
                    <Typography variant="h5" color="success.main" fontWeight="bold">
                      {functions.filter(f => f.is_decompiled).length}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Decompiled
                    </Typography>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2.4}>
                  <Card variant="outlined" sx={{ textAlign: 'center', p: 2 }}>
                    <Typography variant="h5" color="secondary.main" fontWeight="bold">
                      {functions.filter(f => f.ai_analyzed || f.ai_summary || f.risk_score).length}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      AI Analyzed
                    </Typography>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2.4}>
                  <Card variant="outlined" sx={{ textAlign: 'center', p: 2 }}>
                    <Typography variant="h5" color="error.main" fontWeight="bold">
                      {functions.filter(f => f.risk_score && f.risk_score >= 70).length}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      High Risk
                    </Typography>
                  </Card>
                </Grid>
                <Grid item xs={12} sm={6} md={2.4}>
                  <Card variant="outlined" sx={{ textAlign: 'center', p: 2 }}>
                    <Typography variant="h5" color="warning.main" fontWeight="bold">
                      {vulnerabilitiesCount}
                    </Typography>
                    <Typography variant="body2" color="textSecondary">
                      Vulnerabilities
                    </Typography>
                  </Card>
                </Grid>
              </Grid>
            </CardContent>
          </Card>

          {/* Tabs Section */}
          <Card sx={{ mt: 3 }}>
            <Tabs value={tabValue} onChange={(e, newValue) => setTabValue(newValue)}>
              <Tab label="Functions" />
              <Tab 
                label={
                  <Box display="flex" alignItems="center" gap={2}>
                    DLL Analysis
                    <Code />
                  </Box>
                } 
              />
              <Tab 
                label={
                  <Box display="flex" alignItems="center" gap={2}>
                    Strings
                    <Storage />
                  </Box>
                } 
                onClick={() => stringsData.length === 0 && fetchComprehensiveData('strings')}
              />
              <Tab 
                label={
                  <Box display="flex" alignItems="center" gap={2}>
                    Symbols
                    <AccountTree />
                  </Box>
                } 
                onClick={() => symbolsData.length === 0 && fetchComprehensiveData('symbols')}
              />
              <Tab 
                label={
                  <Box display="flex" alignItems="center" gap={2}>
                    Memory
                    <Memory />
                  </Box>
                } 
                onClick={() => memoryBlocksData.length === 0 && fetchComprehensiveData('memory_blocks')}
              />
              <Tab 
                label={
                  <Box display="flex" alignItems="center" gap={2}>
                    Imports/Exports
                    <ImportExport />
                  </Box>
                } 
                onClick={() => (importsData.length === 0 || exportsData.length === 0) && Promise.all([fetchComprehensiveData('imports'), fetchComprehensiveData('exports')])}
              />
              <Tab 
                label={
                  <Box display="flex" alignItems="center" gap={2}>
                    Security Analysis
                    <Security />
                  </Box>
                } 
              />
              <Tab 
                label={
                  <Box display="flex" alignItems="center" gap={2}>
                    Fuzzing
                    <Speed />
                  </Box>
                } 
              />
            </Tabs>

            <TabPanel value={tabValue} index={0}>
              {functions.length > 0 ? (
            <>
              {/* Function Management Toolbar */}
              <Card sx={{ mt: 3, mb: 3 }}>
                <CardContent>
                  <Typography variant="h6" fontWeight="bold" mb={2}>
                    Functions ({functions.length})
                  </Typography>
                  
                  <Grid container spacing={2} alignItems="center">
                    {/* Search and Filter */}
                    <Grid item xs={12} md={6}>
                      <Box display="flex" gap={2}>
                        <TextField
                          fullWidth
                          size="small"
                          placeholder="Search functions by name or address..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          InputProps={{
                            startAdornment: (
                              <InputAdornment position="start">
                                <Search />
                              </InputAdornment>
                            )
                          }}
                        />
                        <TextField
                          select
                          size="small"
                          value={statusFilter}
                          onChange={(e) => setStatusFilter(e.target.value)}
                          SelectProps={{ native: true }}
                          sx={{ minWidth: 140 }}
                        >
                          <option value="all">All</option>
                          <option value="decompiled">Decompiled</option>
                          <option value="not_decompiled">Not Decompiled</option>
                          <option value="ai_analyzed">AI Analyzed</option>
                          <option value="external">External</option>
                          <option value="high_risk">High Risk</option>
                        </TextField>
                      </Box>
                    </Grid>

                    {/* Bulk Actions */}
                    <Grid item xs={12} md={4}>
                      <Box display="flex" gap={1}>
                        <Button
                          variant="contained"
                          color="primary"
                          onClick={handleBulkDecompile}
                          disabled={bulkDecompiling}
                          startIcon={bulkDecompiling ? <CircularProgress size={16} /> : <Code />}
                          size="small"
                        >
                          {bulkDecompiling ? 'Decompiling...' : 'Decompile All'}
                        </Button>
                        <Button
                          variant="contained"
                          color="secondary"
                          onClick={handleBulkAIExplain}
                          disabled={bulkAIExplaining || functions.filter(f => f.is_decompiled).length === 0} // AI analysis requires decompiled functions
                          startIcon={bulkAIExplaining ? <CircularProgress size={16} /> : <Psychology />}
                          size="small"
                        >
                          {bulkAIExplaining ? 'AI Analyzing...' : 'AI Explain All'}
                        </Button>
                      </Box>
                    </Grid>

                    {/* Results Count */}
                    <Grid item xs={12} md={2}>
                      <Card variant="outlined" sx={{ textAlign: 'center', p: 1 }}>
                        <Typography variant="h6" color="primary" fontWeight="bold">
                          {filteredFunctions.length}
                        </Typography>
                        <Typography variant="caption" color="textSecondary">
                          of {functions.length}
                        </Typography>
                      </Card>
                    </Grid>
                  </Grid>

                  {/* Progress Indicators */}
                  {(bulkDecompiling || bulkAIExplaining) && (
                    <Box sx={{ mt: 2 }}>
                      {bulkDecompiling && bulkDecompileProgress.total > 0 && (
                        <Box sx={{ mb: 1 }}>
                          <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                            <Typography variant="body2">
                              Decompiling Functions
                            </Typography>
                            <Typography variant="caption" color="textSecondary">
                              {bulkDecompileProgress.current} / {bulkDecompileProgress.total}
                            </Typography>
                          </Box>
                          <LinearProgress
                            variant="determinate"
                            value={(bulkDecompileProgress.current / bulkDecompileProgress.total) * 100}
                            sx={{ height: 6, borderRadius: 3 }}
                          />
                        </Box>
                      )}
                      {bulkAIExplaining && bulkAIProgress.total > 0 && (
                        <Box>
                          <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                            <Typography variant="body2">
                              AI Analysis in Progress
                            </Typography>
                            <Typography variant="caption" color="textSecondary">
                              {bulkAIProgress.current} / {bulkAIProgress.total}
                            </Typography>
                          </Box>
                          <LinearProgress
                            variant="determinate"
                            value={(bulkAIProgress.current / bulkAIProgress.total) * 100}
                            color="secondary"
                            sx={{ height: 6, borderRadius: 3 }}
                          />
                        </Box>
                      )}
                    </Box>
                  )}

                  {/* Quick Stats */}
                  <Box sx={{ mt: 2, pt: 2, borderTop: '1px solid', borderColor: 'divider' }}>
                    <Stack direction="row" spacing={1} flexWrap="wrap">
                      <Chip 
                        label={`${functions.filter(f => f.is_decompiled).length} Decompiled`}
                        color="success"
                        size="small"
                        icon={<Code />}
                      />
                      <Chip 
                        label={`${functions.filter(f => f.ai_analyzed || f.ai_summary || f.risk_score).length} AI Analyzed`}
                        color="secondary"
                        size="small"
                        icon={<Psychology />}
                        key={`ai-chip-${functions.filter(f => f.ai_analyzed || f.ai_summary || f.risk_score).length}`}
                      />
                      <Chip 
                        label={`${functions.filter(f => f.is_external).length} External`}
                        color="default"
                        size="small"
                      />
                      <Chip 
                        label={`${functions.filter(f => f.risk_score && f.risk_score >= 50).length} High Risk`}
                        color="error"
                        size="small"
                        icon={<Warning />}
                      />
                    </Stack>
                  </Box>
                </CardContent>
              </Card>

              {/* Enhanced Function Table with Collapsible Rows - Remove Parameters Column */}
              <Card key={`functions-${functions.filter(f => f.ai_analyzed).length}-${functions.length}`}>
                <TableContainer>
                  <Table>
                    <TableHead>
                      <TableRow sx={{ bgcolor: 'primary.main' }}>
                        <TableCell width="40px" sx={{ color: 'white', fontWeight: 'bold' }}></TableCell>
                        <TableCell 
                          sx={{ color: 'white', fontWeight: 'bold', cursor: 'pointer' }}
                          onClick={() => handleSort('address')}
                        >
                          <Box display="flex" alignItems="center">
                            Address
                            {sortBy === 'address' && (
                              sortOrder === 'asc' ? <ArrowUpward fontSize="small" sx={{ ml: 1 }} /> : <ArrowDownward fontSize="small" sx={{ ml: 1 }} />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell 
                          sx={{ color: 'white', fontWeight: 'bold', cursor: 'pointer' }}
                          onClick={() => handleSort('name')}
                        >
                          <Box display="flex" alignItems="center">
                            Name
                            {sortBy === 'name' && (
                              sortOrder === 'asc' ? <ArrowUpward fontSize="small" sx={{ ml: 1 }} /> : <ArrowDownward fontSize="small" sx={{ ml: 1 }} />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell 
                          sx={{ color: 'white', fontWeight: 'bold', cursor: 'pointer' }}
                          onClick={() => handleSort('size')}
                        >
                          <Box display="flex" alignItems="center">
                            Size
                            {sortBy === 'size' && (
                              sortOrder === 'asc' ? <ArrowUpward fontSize="small" sx={{ ml: 1 }} /> : <ArrowDownward fontSize="small" sx={{ ml: 1 }} />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell 
                          sx={{ color: 'white', fontWeight: 'bold', cursor: 'pointer' }}
                          onClick={() => handleSort('security')}
                        >
                          <Box display="flex" alignItems="center">
                            Security Analysis
                            {sortBy === 'security' && (
                              sortOrder === 'asc' ? <ArrowUpward fontSize="small" sx={{ ml: 1 }} /> : <ArrowDownward fontSize="small" sx={{ ml: 1 }} />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Status</TableCell>
                        <TableCell 
                          sx={{ color: 'white', fontWeight: 'bold', cursor: 'pointer' }}
                          onClick={() => handleSort('risk')}
                        >
                          <Box display="flex" alignItems="center">
                            AI Risk
                            {sortBy === 'risk' && (
                              sortOrder === 'asc' ? <ArrowUpward fontSize="small" sx={{ ml: 1 }} /> : <ArrowDownward fontSize="small" sx={{ ml: 1 }} />
                            )}
                          </Box>
                        </TableCell>
                        <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {filteredFunctions.map((func: Function) => (
                        <React.Fragment key={`${func.id}-${func.ai_analyzed}-${func.is_decompiled}-${func.risk_score}`}>
                          {/* Main Function Row - Remove Parameters Cell */}
                          <TableRow 
                            id={`function-${func.id}`}
                            hover 
                            onClick={() => toggleFunctionExpanded(func.id)}
                            sx={{ cursor: 'pointer' }}
                          >
                            <TableCell>
                              <IconButton size="small">
                                {expandedFunctions[func.id] ? <ExpandLess /> : <ExpandMore />}
                              </IconButton>
                            </TableCell>
                            <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.9em' }}>
                              {func.address}
                            </TableCell>
                            <TableCell>
                              <Box display="flex" alignItems="center" gap={1}>
                                <Typography 
                                  variant="body2" 
                                  fontWeight={func.is_external ? 'normal' : 'medium'}
                                  component="a"
                                  href={`#function-${func.id}`}
                                  onClick={(e) => {
                                    e.preventDefault();
                                    toggleFunctionExpanded(func.id);
                                  }}
                                  sx={{ 
                                    color: 'primary.main',
                                    textDecoration: 'none',
                                    cursor: 'pointer',
                                    '&:hover': {
                                      textDecoration: 'underline'
                                    }
                                  }}
                                >
                                  {func.name || func.original_name || 'Unknown'}
                                </Typography>
                              </Box>
                            </TableCell>
                            <TableCell>
                              {func.size ? `${func.size} bytes` : 'Unknown'}
                            </TableCell>
                            <TableCell>
                              {(() => {
                                const securitySummary = getSecurityAnalysisSummary(func.id);
                                if (securitySummary.count > 0) {
                                  return (
                                    <Box display="flex" alignItems="center" gap={1}>
                                      <Chip
                                        label={`${securitySummary.count} ${securitySummary.severity?.toUpperCase()}`}
                                        color={
                                          securitySummary.severity === 'critical' ? 'error' :
                                          securitySummary.severity === 'high' ? 'warning' :
                                          securitySummary.severity === 'medium' ? 'info' : 'default'
                                        }
                                        size="small"
                                        icon={<Security />}
                                        component="a"
                                        href={`#function-${func.id}`}
                                        clickable
                                        onClick={(e) => {
                                          e.preventDefault();
                                          toggleFunctionExpanded(func.id);
                                        }}
                                        sx={{ cursor: 'pointer' }}
                                      />
                                      {securitySummary.confidence && (
                                        <Chip
                                          label={`${securitySummary.confidence}%`}
                                          size="small"
                                          variant="outlined"
                                          color="info"
                                        />
                                      )}
                                    </Box>
                                  );
                                }
                                return (
                                  <Typography variant="body2" color="textSecondary">
                                    None
                                  </Typography>
                                );
                              })()}
                            </TableCell>
                            <TableCell>
                              <Box display="flex" gap={0.5} flexWrap="wrap">
                                {func.is_analyzed && (
                                  <Chip label="Analyzed" color="success" size="small" />
                                )}
                                {func.is_decompiled && (
                                  <Chip label="Decompiled" color="info" size="small" />
                                )}
                                {(func.ai_analyzed || func.ai_summary || func.risk_score) && (
                                  <Chip label="AI" color="secondary" size="small" />
                                )}
                                
                                {func.is_thunk && (
                                  <Chip label="Thunk" color="default" size="small" />
                                )}
                                {func.is_external && (
                                  <Chip label="External" color="default" size="small" />
                                )}
                              </Box>
                            </TableCell>
                            <TableCell>
                              {func.risk_score !== undefined && func.risk_score > 0 ? (
                                <Chip 
                                  label={`${func.risk_score}`} 
                                  color={getRiskColor(func.risk_score)} 
                                  size="small" 
                                  icon={<Security />}
                                />
                              ) : (
                                <Chip 
                                  label="Info" 
                                  color="default" 
                                  size="small" 
                                  icon={<Info />}
                                />
                              )}
                            </TableCell>
                            <TableCell onClick={(e) => e.stopPropagation()}>
                              <Box display="flex" gap={0.5}>
                                <Tooltip title="View Function Details">
                                  <IconButton
                                    size="small"
                                    onClick={() => toggleFunctionExpanded(func.id)}
                                  >
                                    <Code />
                                  </IconButton>
                                </Tooltip>

                              </Box>
                            </TableCell>
                          </TableRow>

                          {/* Collapsible Function Details Row - Adjust colspan */}
                          <TableRow>
                            <TableCell colSpan={8} sx={{ p: 0 }}>
                              <Collapse in={expandedFunctions[func.id]} timeout="auto" unmountOnExit>
                                <Box sx={{ p: 3, bgcolor: 'rgba(0,0,0,0.2)', border: '1px solid rgba(255,255,255,0.1)' }}>
                                  {functionData[func.id]?.loading?.fetchingDetails ? (
                                    <Box display="flex" justifyContent="center" alignItems="center" py={4}>
                                      <CircularProgress size={24} />
                                      <Typography variant="body2" color="textSecondary" sx={{ ml: 2 }}>
                                        Loading function details...
                                      </Typography>
                                    </Box>
                                  ) : (
                                    <Grid container spacing={3}>
                                      {/* Function Actions */}
                                      <Grid item xs={12}>
                                        <Box display="flex" gap={2} mb={2}>
                                          <Button
                                            variant={functionData[func.id]?.decompiled ? "outlined" : "contained"}
                                            size="small"
                                            startIcon={
                                              functionData[func.id]?.loading?.decompiling ? 
                                              <CircularProgress size={16} /> : <Code />
                                            }
                                            onClick={() => handleDecompileFunction(func.id)}
                                            disabled={functionData[func.id]?.loading?.decompiling}
                                            color={functionData[func.id]?.decompiled ? "success" : "primary"}
                                          >
                                            {functionData[func.id]?.loading?.decompiling ? 'Decompiling...' : 
                                             functionData[func.id]?.decompiled ? 'Decompiled ✓' : 'Decompile'}
                                          </Button>
                                          
                                          <Button
                                            variant={functionData[func.id]?.aiExplanation ? "outlined" : "contained"}
                                            size="small"
                                            startIcon={
                                              functionData[func.id]?.loading?.explaining ? 
                                              <CircularProgress size={16} /> : <Psychology />
                                            }
                                            onClick={() => handleExplainFunction(func.id)}
                                            disabled={
                                              functionData[func.id]?.loading?.explaining || 
                                              !functionData[func.id]?.decompiled
                                            }
                                            color={functionData[func.id]?.aiExplanation ? "success" : "secondary"}
                                          >
                                            {functionData[func.id]?.loading?.explaining ? 'Analyzing...' : 
                                             functionData[func.id]?.aiExplanation ? 'Explained ✓' : 'AI Explain'}
                                          </Button>
                                          
                                          
                                        </Box>
                                      </Grid>

                                      {/* Left Column: Function Information + AI Analysis */}
                                      <Grid item xs={12} md={6}>
                                        {/* Function Information */}
                                        <Card variant="outlined" sx={{ bgcolor: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }}>
                                          <CardContent>
                                            <Typography variant="h6" gutterBottom>
                                              Function Info
                                            </Typography>
                                            <Table size="small">
                                              <TableBody>
                                                <TableRow>
                                                  <TableCell><strong>Name</strong></TableCell>
                                                  <TableCell>{func.name || 'Unknown'}</TableCell>
                                                </TableRow>
                                                <TableRow>
                                                  <TableCell><strong>Address</strong></TableCell>
                                                  <TableCell sx={{ fontFamily: 'monospace' }}>{func.address}</TableCell>
                                                </TableRow>
                                                <TableRow>
                                                  <TableCell><strong>Size</strong></TableCell>
                                                  <TableCell>{func.size ? `${func.size} bytes` : 'Unknown'}</TableCell>
                                                </TableRow>
                                                <TableRow>
                                                  <TableCell><strong>Convention</strong></TableCell>
                                                  <TableCell>{func.calling_convention || 'Unknown'}</TableCell>
                                                </TableRow>
                                              </TableBody>
                                            </Table>
                                          </CardContent>
                                        </Card>

                                        {/* AI Analysis below Function Info */}
                                        {functionData[func.id]?.aiExplanation && (
                                          <Box sx={{ mt: 2 }}>
                                            <Card variant="outlined" sx={{ bgcolor: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }}>
                                              <CardContent>
                                                <Box display="flex" justifyContent="between" alignItems="center" mb={2}>
                                                  <Typography variant="h6">AI Security Analysis</Typography>
                                                  {functionData[func.id]?.aiExplanation?.cached && (
                                                    <Chip label="Cached" size="small" color="info" />
                                                  )}
                                                </Box>
                                                
                                                {/* Risk Score */}
                                                {functionData[func.id]?.aiExplanation?.risk_score !== undefined && (
                                                  <Box mb={2}>
                                                    <Box display="flex" alignItems="center" gap={1} mb={1}>
                                                      <Security color={getRiskColor(functionData[func.id]?.aiExplanation?.risk_score)} />
                                                      <Typography variant="subtitle2" fontSize="0.9rem">
                                                        Risk Score: {functionData[func.id]?.aiExplanation?.risk_score}/100
                                                      </Typography>
                                                      <Chip
                                                        label={getRiskLevel(functionData[func.id]?.aiExplanation?.risk_score)}
                                                        color={getRiskColor(functionData[func.id]?.aiExplanation?.risk_score)}
                                                        size="small"
                                                      />
                                                    </Box>
                                                    <LinearProgress
                                                      variant="determinate"
                                                      value={functionData[func.id]?.aiExplanation?.risk_score}
                                                      color={getRiskColor(functionData[func.id]?.aiExplanation?.risk_score) as any}
                                                      sx={{ height: 6, borderRadius: 3 }}
                                                    />
                                                  </Box>
                                                )}
                                                
                                                {/* AI Summary */}
                                                <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', fontSize: '0.85rem', lineHeight: 1.4 }}>
                                                  {(() => {
                                                    const aiData = functionData[func.id]?.aiExplanation;
                                                    if (typeof aiData?.ai_summary === 'string') {
                                                      return aiData.ai_summary;
                                                    } else if (typeof aiData === 'string') {
                                                      return aiData;
                                                    } else {
                                                      return 'No AI analysis available';
                                                    }
                                                  })()}
                                                </Typography>
                                              </CardContent>
                                            </Card>
                                          </Box>
                                        )}
                                      </Grid>

                                      {/* Decompiled Code */}
                                      {functionData[func.id]?.decompiled && (
                                        <Grid item xs={12} md={6}>
                                          <Card variant="outlined" sx={{ bgcolor: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }}>
                                            <CardContent>
                                              <Box display="flex" justifyContent="between" alignItems="center" mb={2}>
                                                <Typography variant="h6">Decompiled Code</Typography>
                                                {functionData[func.id]?.decompiled?.cached && (
                                                  <Chip label="Cached" size="small" color="info" />
                                                )}
                                              </Box>
                                              <Paper sx={{ p: 0, maxHeight: '400px', overflow: 'auto', bgcolor: '#181818', border: '1px solid rgba(255,255,255,0.1)' }}>
                                                <SyntaxHighlighter
                                                  language="c"
                                                  style={atomOneDark}
                                                  showLineNumbers
                                                  customStyle={{
                                                    margin: 0,
                                                    borderRadius: 0,
                                                    fontSize: '12px',
                                                    backgroundColor: '#181818'
                                                  }}
                                                >
                                                  {(() => {
                                                    // Safely extract decompiled code string
                                                    const decompiledData = functionData[func.id]?.decompiled;
                                                    if (decompiledData?.decompiled_code && typeof decompiledData.decompiled_code === 'string') {
                                                      return decompiledData.decompiled_code;
                                                    } else if (typeof decompiledData === 'string') {
                                                      return decompiledData;
                                                    } else {
                                                      return '// No code available';
                                                    }
                                                  })()}
                                                </SyntaxHighlighter>
                                              </Paper>
                                            </CardContent>
                                          </Card>
                                        </Grid>
                                      )}
                                    </Grid>
                                  )}
                                </Box>
                              </Collapse>
                            </TableCell>
                          </TableRow>

                        </React.Fragment>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </Card>
                </>
              ) : (
                <Box textAlign="center" py={4}>
                  <Typography variant="h6" color="textSecondary">
                    No Functions Found
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    Analysis may still be in progress or no functions were detected in this binary.
                  </Typography>
                </Box>
              )}
            </TabPanel>

            {/* Combined DLL Analysis Tab */}
            <TabPanel value={tabValue} index={1}>
              <Box>
                <Typography variant="h6" mb={2}>
                  DLL Analysis & Export Information
                </Typography>

                {(() => {
                  // Check if this binary has forwarder analysis
                  const forwarderData = securitySummary?.forwarder_analysis;
                  const isForwarderDLL = forwarderData?.is_forwarder;
                  
                  // Get exported functions for regular DLLs
                  const exportFunctions = functions.filter(f => 
                    f.name?.startsWith('dll_') || 
                    (exportsData.some(exp => exp.name === f.name)) ||
                    (f.name && !f.name.startsWith('FUN_') && !f.name.startsWith('SUB_') && !f.is_external)
                  );
                  
                  return (
                    <Box>
                      {/* DLL Type Detection Card */}
                      <Card sx={{ mb: 3 }}>
                        <CardContent>
                          <Typography variant="h6" gutterBottom>
                            DLL Type Analysis
                          </Typography>
                          
                          {isForwarderDLL ? (
                            <Alert severity="warning" sx={{ mb: 2 }}>
                              <Typography variant="body1" fontWeight="bold">
                                🔄 Windows API Forwarder DLL
                              </Typography>
                              <Typography variant="body2" mt={1}>
                                This DLL contains no actual executable code. It forwards API calls to other implementation DLLs.
                                This is normal behavior for Windows API Set DLLs.
                              </Typography>
                            </Alert>
                          ) : forwarderData ? (
                            <Alert severity="success" sx={{ mb: 2 }}>
                              <Typography variant="body1" fontWeight="bold">
                                ⚙️ Standard Implementation DLL
                              </Typography>
                              <Typography variant="body2" mt={1}>
                                This DLL contains actual executable code and functions.
                              </Typography>
                            </Alert>
                          ) : (
                            <Alert severity="info" sx={{ mb: 2 }}>
                              <Typography variant="body1">
                                🔍 DLL type analysis not available
                              </Typography>
                              <Typography variant="body2" mt={1}>
                                Run Security Analysis to determine DLL type and get detailed information.
                              </Typography>
                            </Alert>
                          )}

                          {forwarderData && (
                            <Grid container spacing={2}>
                              <Grid item xs={12} sm={3}>
                                <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                                  <Typography variant="h5" color="primary">
                                    {forwarderData.export_count || exportsData.length || 0}
                                  </Typography>
                                  <Typography variant="body2" color="textSecondary">
                                    Total Exports
                                  </Typography>
                                </Paper>
                              </Grid>
                              
                              <Grid item xs={12} sm={3}>
                                <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                                  <Typography variant="h5" color="secondary">
                                    {forwarderData.forwarding_entries?.length || 0}
                                  </Typography>
                                  <Typography variant="body2" color="textSecondary">
                                    API Forwards
                                  </Typography>
                                </Paper>
                              </Grid>
                              
                              <Grid item xs={12} sm={3}>
                                <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                                  <Typography variant="h5" color="warning.main">
                                    {forwarderData.function_count || exportFunctions.length || 0}
                                  </Typography>
                                  <Typography variant="body2" color="textSecondary">
                                    Actual Functions
                                  </Typography>
                                </Paper>
                              </Grid>

                              <Grid item xs={12} sm={3}>
                                <Paper variant="outlined" sx={{ p: 2, textAlign: 'center' }}>
                                  <Typography variant="h5" color="info.main">
                                    {forwarderData.target_dlls?.length || 0}
                                  </Typography>
                                  <Typography variant="body2" color="textSecondary">
                                    Target DLLs
                                  </Typography>
                                </Paper>
                              </Grid>
                            </Grid>
                          )}
                        </CardContent>
                      </Card>

                      {/* API Forwarder Information - shown for forwarder DLLs */}
                      {isForwarderDLL && forwarderData?.forwarding_entries?.length > 0 && (
                        <Card sx={{ mb: 3 }}>
                          <CardContent>
                            <Typography variant="h6" gutterBottom>
                              🔄 API Forwarding Table
                            </Typography>
                            
                            {/* Target DLLs */}
                            {forwarderData.target_dlls?.length > 0 && (
                              <Box mb={2}>
                                <Typography variant="subtitle1" mb={1}>
                                  Target Implementation DLLs:
                                </Typography>
                                <Box display="flex" flexWrap="wrap" gap={1}>
                                  {forwarderData.target_dlls.map((dll: string, index: number) => (
                                    <Chip
                                      key={index}
                                      label={dll}
                                      variant="outlined"
                                      color="primary"
                                      size="small"
                                    />
                                  ))}
                                </Box>
                              </Box>
                            )}

                            <TableContainer component={Paper} variant="outlined">
                              <Table size="small">
                                <TableHead>
                                  <TableRow>
                                    <TableCell>Export Name</TableCell>
                                    <TableCell>Target DLL</TableCell>
                                    <TableCell>Target Function</TableCell>
                                    <TableCell>Address</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {forwarderData.forwarding_entries.slice(0, 50).map((entry: any, index: number) => (
                                    <TableRow key={index}>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace">
                                          {entry.export_name}
                                        </Typography>
                                      </TableCell>
                                      <TableCell>
                                        <Chip
                                          label={entry.target_dll}
                                          size="small"
                                          variant="outlined"
                                          color="secondary"
                                        />
                                      </TableCell>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace">
                                          {entry.target_function}
                                        </Typography>
                                      </TableCell>
                                      <TableCell>
                                        <Typography variant="body2" fontFamily="monospace" color="textSecondary">
                                          {entry.export_address}
                                        </Typography>
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            </TableContainer>
                            
                            {forwarderData.forwarding_entries.length > 50 && (
                              <Typography variant="body2" color="textSecondary" mt={1}>
                                Showing first 50 of {forwarderData.forwarding_entries.length} forwarding entries
                              </Typography>
                            )}
                          </CardContent>
                        </Card>
                      )}

                      {/* DLL Exported Functions - shown for regular DLLs */}
                      {!isForwarderDLL && exportFunctions.length > 0 && (
                        <Card>
                          <CardContent>
                            <Typography variant="h6" gutterBottom>
                              ⚙️ Exported Functions ({exportFunctions.length})
                            </Typography>
                            
                            {/* Export Functions Toolbar */}
                            <Box sx={{ mb: 2, p: 2, bgcolor: 'grey.50', borderRadius: 1 }}>
                              <Stack direction="row" spacing={1} flexWrap="wrap">
                                <Chip 
                                  label={`${exportFunctions.filter(f => f.is_decompiled).length} Decompiled`}
                                  color="success"
                                  size="small"
                                  icon={<Code />}
                                />
                                <Chip 
                                  label={`${exportFunctions.filter(f => f.ai_analyzed || f.ai_summary || f.risk_score).length} AI Analyzed`}
                                  color="secondary"
                                  size="small"
                                  icon={<Psychology />}
                                />
                                <Chip 
                                  label={`${exportFunctions.filter(f => f.risk_score && f.risk_score >= 50).length} High Risk`}
                                  color="error"
                                  size="small"
                                  icon={<Warning />}
                                />
                              </Stack>
                            </Box>

                            <TableContainer component={Paper} variant="outlined">
                              <Table>
                                <TableHead>
                                  <TableRow>
                                    <TableCell>Function Name</TableCell>
                                    <TableCell>Address</TableCell>
                                    <TableCell>Size</TableCell>
                                    <TableCell>Status</TableCell>
                                    <TableCell>Risk Score</TableCell>
                                    <TableCell>Actions</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {exportFunctions.map((func: Function) => (
                                    <React.Fragment key={func.id}>
                                      <TableRow id={`export-function-${func.id}`}>
                                        <TableCell>
                                          <Box display="flex" alignItems="center" gap={1}>
                                            <IconButton
                                              size="small"
                                              onClick={() => toggleFunctionExpanded(func.id)}
                                              sx={{ mr: 1 }}
                                            >
                                              {expandedFunctions[func.id] ? <ExpandLess /> : <ExpandMore />}
                                            </IconButton>
                                            <Typography 
                                              variant="body2" 
                                              fontWeight="medium"
                                              sx={{ color: 'primary.main' }}
                                            >
                                              {func.name || func.original_name || 'Unknown'}
                                            </Typography>
                                            <Chip label="EXPORT" size="small" color="secondary" variant="outlined" />
                                          </Box>
                                        </TableCell>
                                        <TableCell>
                                          <Typography variant="body2" fontFamily="monospace">
                                            {func.address}
                                          </Typography>
                                        </TableCell>
                                        <TableCell>
                                          {func.size ? `${func.size} bytes` : 'Unknown'}
                                        </TableCell>
                                        <TableCell>
                                          <Box display="flex" gap={1}>
                                            {func.is_decompiled && (
                                              <Chip label="Decompiled" color="success" size="small" />
                                            )}
                                            {(func.ai_analyzed || func.ai_summary) && (
                                              <Chip label="AI Analyzed" color="secondary" size="small" />
                                            )}
                                          </Box>
                                        </TableCell>
                                        <TableCell>
                                          {func.risk_score ? (
                                            <Chip
                                              label={`${func.risk_score}%`}
                                              color={func.risk_score >= 70 ? 'error' : func.risk_score >= 40 ? 'warning' : 'success'}
                                              size="small"
                                            />
                                          ) : (
                                            <Typography variant="body2" color="textSecondary">
                                              -
                                            </Typography>
                                          )}
                                        </TableCell>
                                        <TableCell>
                                          <Box display="flex" gap={1}>
                                            {!func.is_decompiled && (
                                              <Tooltip title="Decompile Function">
                                                <IconButton
                                                  size="small"
                                                  onClick={() => handleDecompileFunction(func.id)}
                                                  disabled={functionData[func.id]?.loading?.decompiling}
                                                  color="primary"
                                                >
                                                  {functionData[func.id]?.loading?.decompiling ? (
                                                    <CircularProgress size={16} />
                                                  ) : (
                                                    <Code />
                                                  )}
                                                </IconButton>
                                              </Tooltip>
                                            )}
                                            {func.is_decompiled && !functionData[func.id]?.aiExplanation && (
                                              <Tooltip title="AI Analysis">
                                                <IconButton
                                                  size="small"
                                                  onClick={() => handleExplainFunction(func.id)}
                                                  disabled={functionData[func.id]?.loading?.explaining}
                                                  color="secondary"
                                                >
                                                  {functionData[func.id]?.loading?.explaining ? (
                                                    <CircularProgress size={16} />
                                                  ) : (
                                                    <Psychology />
                                                  )}
                                                </IconButton>
                                              </Tooltip>
                                            )}
                                          </Box>
                                        </TableCell>
                                      </TableRow>
                                      
                                      {/* Expandable Function Details */}
                                      <TableRow>
                                        <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={6}>
                                          <Collapse in={expandedFunctions[func.id]} timeout="auto" unmountOnExit>
                                            <Box sx={{ margin: 1 }}>
                                              {functionData[func.id]?.loading?.fetchingDetails ? (
                                                <Box display="flex" justifyContent="center" p={2}>
                                                  <CircularProgress size={24} />
                                                </Box>
                                              ) : (
                                                <Grid container spacing={2}>
                                                  {/* Function Signature */}
                                                  <Grid item xs={12}>
                                                    <Typography variant="subtitle2" fontWeight="bold">
                                                      Function Signature:
                                                    </Typography>
                                                    <Typography variant="body2" fontFamily="monospace" sx={{ 
                                                      backgroundColor: 'rgba(255, 255, 255, 0.05)', 
                                                      p: 1, 
                                                      borderRadius: 1 
                                                    }}>
                                                      {(() => {
                                                        // Extract the signature string safely
                                                        const decompiledData = functionData[func.id]?.decompiled;
                                                        if (typeof decompiledData === 'object' && decompiledData?.signature) {
                                                          return decompiledData.signature;
                                                        } else if (typeof decompiledData === 'string') {
                                                          // If it's just a string, show the function name
                                                          return func.name || 'Unknown function';
                                                        } else {
                                                          return func.name || 'Not available';
                                                        }
                                                      })()}
                                                    </Typography>
                                                  </Grid>

                                                  {/* Decompiled Code */}
                                                  {func.is_decompiled && functionData[func.id]?.decompiled && (
                                                    <Grid item xs={12}>
                                                      <Typography variant="subtitle2" fontWeight="bold">
                                                        Decompiled Code:
                                                      </Typography>
                                                      <SyntaxHighlighter 
                                                        language="c" 
                                                        style={atomOneDark}
                                                        customStyle={{
                                                          margin: 0,
                                                          fontSize: '0.8rem',
                                                          maxHeight: '300px',
                                                          overflow: 'auto'
                                                        }}
                                                      >
                                                        {(() => {
                                                          // Extract the actual string from the decompiled data
                                                          const decompiledData = functionData[func.id]?.decompiled;
                                                          if (typeof decompiledData === 'string') {
                                                            return decompiledData;
                                                          } else if (decompiledData?.decompiled_code) {
                                                            return decompiledData.decompiled_code;
                                                          } else if (func.decompiled_code) {
                                                            return func.decompiled_code;
                                                          } else {
                                                            return 'No code available';
                                                          }
                                                        })()}
                                                      </SyntaxHighlighter>
                                                    </Grid>
                                                  )}
                                                  
                                                  {/* AI Analysis */}
                                                  {functionData[func.id]?.aiExplanation && (
                                                    <Grid item xs={12}>
                                                      <Typography variant="subtitle2" fontWeight="bold" color="primary">
                                                        AI Analysis:
                                                      </Typography>
                                                      <Paper variant="outlined" sx={{ p: 2, bgcolor: 'blue.50' }}>
                                                        <Typography variant="body2">
                                                          {(() => {
                                                            // Safely extract AI explanation string
                                                            const aiData = functionData[func.id].aiExplanation;
                                                            if (typeof aiData === 'string') {
                                                              return aiData;
                                                            } else if (aiData?.ai_summary) {
                                                              return aiData.ai_summary;
                                                            } else if (aiData?.explanation) {
                                                              return aiData.explanation;
                                                            } else {
                                                              return 'AI analysis available but format not recognized';
                                                            }
                                                          })()}
                                                        </Typography>
                                                      </Paper>
                                                    </Grid>
                                                  )}
                                                </Grid>
                                              )}
                                            </Box>
                                          </Collapse>
                                        </TableCell>
                                      </TableRow>
                                    </React.Fragment>
                                  ))}
                                </TableBody>
                              </Table>
                            </TableContainer>
                          </CardContent>
                        </Card>
                      )}

                      {/* No Functions Found Message */}
                      {!isForwarderDLL && exportFunctions.length === 0 && (
                        <Alert severity="info">
                          <Typography variant="body1">
                            No exported functions found for analysis.
                          </Typography>
                          <Typography variant="body2" mt={1}>
                            This may be a forwarder DLL, contain only data exports, or require Security Analysis to populate data.
                          </Typography>
                        </Alert>
                      )}
                    </Box>
                  );
                })()}
              </Box>
            </TabPanel>

            {/* Strings Tab */}
            <TabPanel value={tabValue} index={2}>
              <Box>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">
                    Strings ({stringsData.length})
                  </Typography>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => fetchComprehensiveData('strings')}
                    disabled={dataLoading.strings}
                    startIcon={dataLoading.strings ? <CircularProgress size={16} /> : <Refresh />}
                  >
                    Refresh
                  </Button>
                </Box>
                
                {dataLoading.strings ? (
                  <Box display="flex" justifyContent="center" p={4}>
                    <CircularProgress />
                  </Box>
                ) : (
                  <TableContainer component={Paper}>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Address</TableCell>
                          <TableCell>Value</TableCell>
                          <TableCell>Length</TableCell>
                          <TableCell>Type</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {stringsData.map((str: any, index: number) => (
                          <TableRow key={index}>
                            <TableCell>
                              <Typography variant="body2" fontFamily="monospace">
                                {str.address}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ maxWidth: 300, wordBreak: 'break-all' }}>
                                {str.value}
                              </Typography>
                            </TableCell>
                            <TableCell>{str.length}</TableCell>
                            <TableCell>
                              <Chip label={str.dataType || str.type || 'String'} size="small" variant="outlined" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>
            </TabPanel>

            {/* Symbols Tab */}
            <TabPanel value={tabValue} index={3}>
              <Box>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">
                    Symbols ({symbolsData.length})
                  </Typography>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => fetchComprehensiveData('symbols')}
                    disabled={dataLoading.symbols}
                    startIcon={dataLoading.symbols ? <CircularProgress size={16} /> : <Refresh />}
                  >
                    Refresh
                  </Button>
                </Box>
                
                {dataLoading.symbols ? (
                  <Box display="flex" justifyContent="center" p={4}>
                    <CircularProgress />
                  </Box>
                ) : (
                  <TableContainer component={Paper}>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Name</TableCell>
                          <TableCell>Address</TableCell>
                          <TableCell>Type</TableCell>
                          <TableCell>Source</TableCell>
                          <TableCell>Namespace</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {symbolsData.map((symbol: any, index: number) => (
                          <TableRow key={index}>
                            <TableCell>
                              <Typography variant="body2" fontFamily="monospace">
                                {symbol.name}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" fontFamily="monospace">
                                {symbol.address}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip label={symbol.type || symbol.symbol_type} size="small" variant="outlined" />
                            </TableCell>
                            <TableCell>{symbol.source}</TableCell>
                            <TableCell>{symbol.namespace}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>
            </TabPanel>

            {/* Memory Blocks Tab */}
            <TabPanel value={tabValue} index={4}>
              <Box>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">
                    Memory Blocks ({memoryBlocksData.length})
                  </Typography>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => fetchComprehensiveData('memory_blocks')}
                    disabled={dataLoading.memory}
                    startIcon={dataLoading.memory ? <CircularProgress size={16} /> : <Refresh />}
                  >
                    Refresh
                  </Button>
                </Box>
                
                {dataLoading.memory ? (
                  <Box display="flex" justifyContent="center" p={4}>
                    <CircularProgress />
                  </Box>
                ) : (
                  <TableContainer component={Paper}>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Name</TableCell>
                          <TableCell>Start Address</TableCell>
                          <TableCell>End Address</TableCell>
                          <TableCell>Size</TableCell>
                          <TableCell>Permissions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {memoryBlocksData.map((block: any, index: number) => (
                          <TableRow key={index}>
                            <TableCell>
                              <Typography variant="body2" fontWeight="bold">
                                {block.name}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" fontFamily="monospace">
                                {block.start_address || block.start}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2" fontFamily="monospace">
                                {block.end_address || block.end}
                              </Typography>
                            </TableCell>
                            <TableCell>{formatFileSize(block.size)}</TableCell>
                            <TableCell>
                              <Stack direction="row" spacing={0.5}>
                                {(block.is_read || block.permissions?.read) && <Chip label="R" size="small" color="success" />}
                                {(block.is_write || block.permissions?.write) && <Chip label="W" size="small" color="warning" />}
                                {(block.is_execute || block.permissions?.execute) && <Chip label="X" size="small" color="error" />}
                                {(block.is_initialized || block.permissions?.initialized) && <Chip label="I" size="small" color="info" />}
                              </Stack>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>
            </TabPanel>

            {/* Imports/Exports Tab */}
            <TabPanel value={tabValue} index={5}>
              <Box>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">
                    Imports ({importsData.length}) / Exports ({exportsData.length})
                  </Typography>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={() => Promise.all([fetchComprehensiveData('imports'), fetchComprehensiveData('exports')])}
                    disabled={dataLoading.imports}
                    startIcon={dataLoading.imports ? <CircularProgress size={16} /> : <Refresh />}
                  >
                    Refresh
                  </Button>
                </Box>
                
                <Grid container spacing={3}>
                  {/* Imports Section */}
                  <Grid item xs={12} md={6}>
                    <Typography variant="h6" color="primary" mb={2}>
                      Imports ({importsData.length})
                    </Typography>
                    {dataLoading.imports ? (
                      <Box display="flex" justifyContent="center" p={2}>
                        <CircularProgress size={24} />
                      </Box>
                    ) : (
                      <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                        <Table stickyHeader size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Function</TableCell>
                              <TableCell>Library</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {importsData.map((imp: any, index: number) => (
                              <TableRow key={index}>
                                <TableCell>
                                  <Typography variant="body2" fontFamily="monospace">
                                    {imp.function_name || imp.name}
                                  </Typography>
                                </TableCell>
                                <TableCell>
                                  <Typography variant="body2">
                                    {imp.library || imp.module}
                                  </Typography>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    )}
                  </Grid>
                  
                  {/* Exports Section */}
                  <Grid item xs={12} md={6}>
                    <Typography variant="h6" color="secondary" mb={2}>
                      Exports ({exportsData.length})
                    </Typography>
                    {dataLoading.imports ? (
                      <Box display="flex" justifyContent="center" p={2}>
                        <CircularProgress size={24} />
                      </Box>
                    ) : (
                      <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
                        <Table stickyHeader size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Function</TableCell>
                              <TableCell>Address</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {exportsData.map((exp: any, index: number) => (
                              <TableRow key={index}>
                                <TableCell>
                                  <Typography variant="body2" fontFamily="monospace">
                                    {exp.function_name || exp.name}
                                  </Typography>
                                </TableCell>
                                <TableCell>
                                  <Typography variant="body2" fontFamily="monospace">
                                    {exp.address}
                                  </Typography>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    )}
                  </Grid>
                </Grid>
              </Box>
            </TabPanel>

            {/* Security Analysis Tab */}
            <TabPanel value={tabValue} index={6}>
              <UnifiedSecurityDashboard
                binary={binaryDetails?.binary}
                functions={functions}
                onRefresh={fetchSecurityFindings}
                onNavigateToFunction={(functionId) => {
                  // Switch to Functions tab (index 0)
                  setTabValue(0);
                  // Expand the specific function
                  setExpandedFunctions(prev => ({
                    ...prev,
                    [functionId]: true
                  }));
                  // Load function details if not already loaded
                  if (!functionData[functionId]?.decompiled && !functionData[functionId]?.loading?.fetchingDetails) {
                    loadFunctionDetails(functionId);
                  }
                  // Scroll to the function after a short delay
                  setTimeout(() => {
                    const functionElement = document.getElementById(`function-${functionId}`);
                    if (functionElement) {
                      functionElement.scrollIntoView({ 
                        behavior: 'smooth', 
                        block: 'center' 
                      });
                    }
                  }, 300);
                }}
              />
            </TabPanel>

            {/* Fuzzing Tab */}
            <TabPanel value={tabValue} index={7}>
              <SimpleFuzzingInterface 
                binaryId={binaryId!} 
                functions={functions} 
                onRefresh={fetchBinaryDetails} 
              />
            </TabPanel>
          </Card>
        </Grid>

        {/* Right Column: Enhanced AI Analysis Section */}
        <Grid item xs={12} lg={4}>
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
                <Box display="flex" alignItems="center" gap={1}>
                  <Psychology color="secondary" />
                  <Typography variant="h6" fontWeight="bold">
                    🤖 AI Binary Analysis
                  </Typography>
                </Box>
                {binaryAISummary && (
                  <Chip 
                    label="Available" 
                    color="success" 
                    size="small" 
                    icon={<Psychology />} 
                  />
                )}
              </Box>

              {!binaryAISummary ? (
                <Card variant="outlined" sx={{ p: 3, textAlign: 'center', bgcolor: 'rgba(255,255,255,0.02)' }}>
                  <Psychology sx={{ fontSize: 48, color: 'secondary.main', mb: 2 }} />
                  <Typography variant="h6" color="textSecondary" gutterBottom>
                    AI Analysis Ready
                  </Typography>
                  <Typography variant="body2" color="textSecondary" mb={3} sx={{ lineHeight: 1.6 }}>
                    Generate comprehensive security analysis including:
                    <br />• Binary purpose identification
                    <br />• Vulnerability assessment
                    <br />• Technical architecture review
                    <br />• Exploit path analysis
                  </Typography>
                  <Button
                    variant="contained"
                    color="secondary"
                    size="large"
                    startIcon={aiSummaryLoading ? <CircularProgress size={20} color="inherit" /> : <Psychology />}
                    onClick={handleStartAIAnalysis}
                    disabled={aiSummaryLoading}
                    fullWidth
                  >
                    {aiSummaryLoading ? 'Generating Analysis...' : 'Start AI Analysis'}
                  </Button>
                  {aiSummaryLoading && (
                    <Box mt={2}>
                      <LinearProgress color="secondary" />
                      <Typography variant="caption" color="textSecondary" mt={1}>
                        This may take 30-60 seconds...
                      </Typography>
                    </Box>
                  )}
                </Card>
              ) : (
                <Box>
                  {/* Binary Purpose Card */}
                  <Card variant="outlined" sx={{ mb: 2, bgcolor: 'rgba(255,255,255,0.02)' }}>
                    <CardContent sx={{ pb: '16px !important' }}>
                      <Typography variant="subtitle1" fontWeight="bold" color="info.main" gutterBottom>
                        🎯 Binary Purpose
                      </Typography>
                      <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                        {binaryAISummary.general_summary || binaryAISummary.summary}
                      </Typography>
                    </CardContent>
                  </Card>

                  {/* Vulnerability Assessment Card */}
                  {binaryAISummary.vulnerability_summary && (
                    <Card variant="outlined" sx={{ mb: 2, bgcolor: 'rgba(244, 67, 54, 0.05)', border: '1px solid rgba(244, 67, 54, 0.3)' }}>
                      <CardContent sx={{ pb: '16px !important' }}>
                        <Typography variant="subtitle1" fontWeight="bold" color="error.main" gutterBottom>
                          🛡️ Security Assessment
                        </Typography>
                        {(() => {
                          // Clean up and format the vulnerability summary
                          const cleanText = binaryAISummary.vulnerability_summary
                            .replace(/\*\*([^*]+)\*\*/g, '$1') // Remove bold markdown
                            .replace(/###\s*/g, '') // Remove markdown headers
                            .replace(/####\s*/g, '') // Remove markdown headers
                            .replace(/- \*\*([^*]+)\*\*:/g, '• $1:') // Clean up bullet points
                            .replace(/^\s*-\s*/gm, '• ') // Convert dashes to bullets
                            .trim();

                          // Extract key-value pairs and regular text
                          const lines = cleanText.split(/\n/).filter((line: string) => line.trim());
                          const tableRows: Array<{key: string, value: string}> = [];
                          const paragraphs: string[] = [];
                          
                          lines.forEach((line: string) => {
                            const cleanLine = line.replace(/^•\s*/, '').trim();
                            if (cleanLine.includes(':') && !cleanLine.toLowerCase().includes('function') && !cleanLine.includes('###')) {
                              const [key, ...valueParts] = cleanLine.split(':');
                              const value = valueParts.join(':').trim();
                              if (key.trim() && value) {
                                tableRows.push({ key: key.trim(), value });
                              }
                            } else if (cleanLine && !cleanLine.includes('•')) {
                              paragraphs.push(cleanLine);
                            }
                          });
                          
                          return (
                            <Box>
                              {/* Regular paragraphs first */}
                              {paragraphs.map((paragraph: string, index: number) => (
                                <Typography 
                                  key={index} 
                                  variant="body2" 
                                  sx={{ mb: 2, lineHeight: 1.5, color: 'white' }}
                                >
                                  {paragraph}
                                </Typography>
                              ))}
                              
                              {/* Table for key-value pairs */}
                              {tableRows.length > 0 && (
                                <Table size="small" sx={{ mt: 1 }}>
                                  <TableBody>
                                    {tableRows.map((row, index: number) => (
                                      <TableRow key={index}>
                                        <TableCell 
                                          sx={{ 
                                            fontWeight: 'medium',
                                            borderBottom: '1px solid rgba(255,255,255,0.1)',
                                            color: 'white',
                                            width: '35%',
                                            verticalAlign: 'top',
                                            py: 1
                                          }}
                                        >
                                          {row.key}
                                        </TableCell>
                                        <TableCell 
                                          sx={{ 
                                            borderBottom: '1px solid rgba(255,255,255,0.1)',
                                            color: 'white',
                                            lineHeight: 1.4,
                                            py: 1
                                          }}
                                        >
                                          {renderTextWithFunctionLinks(row.value)}
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              )}
                            </Box>
                          );
                        })()}
                      </CardContent>
                    </Card>
                  )}

                  {/* Technical Details Card */}
                  {binaryAISummary.technical_details && (
                    <Card variant="outlined" sx={{ mb: 2, bgcolor: 'rgba(255,255,255,0.02)' }}>
                      <CardContent sx={{ pb: '16px !important' }}>
                        <Typography variant="subtitle1" fontWeight="bold" color="secondary.main" gutterBottom>
                          🔧 Technical Analysis
                        </Typography>
                        {(() => {
                          // Clean up and format the technical details
                          const cleanText = binaryAISummary.technical_details
                            .replace(/\*\*([^*]+)\*\*/g, '$1') // Remove bold markdown
                            .replace(/###\s*/g, '') // Remove markdown headers
                            .replace(/####\s*/g, '') // Remove markdown headers
                            .replace(/- \*\*([^*]+)\*\*:/g, '• $1:') // Clean up bullet points
                            .replace(/^\s*-\s*/gm, '• ') // Convert dashes to bullets
                            .trim();

                          // Extract key-value pairs and regular text
                          const lines = cleanText.split(/\n/).filter((line: string) => line.trim());
                          const tableRows: Array<{key: string, value: string}> = [];
                          const paragraphs: string[] = [];
                          
                          lines.forEach((line: string) => {
                            const cleanLine = line.replace(/^•\s*/, '').trim();
                            if (cleanLine.includes(':') && !cleanLine.toLowerCase().includes('function') && !cleanLine.includes('###')) {
                              const [key, ...valueParts] = cleanLine.split(':');
                              const value = valueParts.join(':').trim();
                              if (key.trim() && value) {
                                tableRows.push({ key: key.trim(), value });
                              }
                            } else if (cleanLine && !cleanLine.includes('•')) {
                              paragraphs.push(cleanLine);
                            }
                          });
                          
                          return (
                            <Box>
                              {/* Regular paragraphs first */}
                              {paragraphs.map((paragraph: string, index: number) => (
                                <Typography 
                                  key={index} 
                                  variant="body2" 
                                  sx={{ mb: 2, lineHeight: 1.5, color: 'white' }}
                                >
                                  {paragraph}
                                </Typography>
                              ))}
                              
                              {/* Table for key-value pairs */}
                              {tableRows.length > 0 && (
                                <Table size="small" sx={{ mt: 1 }}>
                                  <TableBody>
                                    {tableRows.map((row, index: number) => (
                                      <TableRow key={index}>
                                        <TableCell 
                                          sx={{ 
                                            fontWeight: 'medium',
                                            borderBottom: '1px solid rgba(255,255,255,0.1)',
                                            color: 'white',
                                            width: '35%',
                                            verticalAlign: 'top',
                                            py: 1
                                          }}
                                        >
                                          {row.key}
                                        </TableCell>
                                        <TableCell 
                                          sx={{ 
                                            borderBottom: '1px solid rgba(255,255,255,0.1)',
                                            color: 'white',
                                            lineHeight: 1.4,
                                            py: 1
                                          }}
                                        >
                                          {renderTextWithFunctionLinks(row.value)}
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              )}
                            </Box>
                          );
                        })()}
                      </CardContent>
                    </Card>
                  )}

                  {/* Key Findings Card */}
                  {binaryAISummary.key_findings && binaryAISummary.key_findings.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 2, bgcolor: 'rgba(255,255,255,0.02)' }}>
                      <CardContent sx={{ pb: '16px !important' }}>
                        <Typography variant="subtitle1" fontWeight="bold" color="warning.main" gutterBottom>
                          🔍 Key Security Findings
                        </Typography>
                        <List dense sx={{ py: 0 }}>
                          {binaryAISummary.key_findings.map((finding: string, index: number) => (
                            <ListItem key={index} sx={{ px: 0, py: 0.5 }}>
                              <ListItemIcon sx={{ minWidth: 24 }}>
                                <Security color="warning" fontSize="small" />
                              </ListItemIcon>
                              <ListItemText 
                                primary={finding}
                                primaryTypographyProps={{ 
                                  variant: 'body2',
                                  sx: { fontSize: '0.85rem' }
                                }}
                              />
                            </ListItem>
                          ))}
                        </List>
                      </CardContent>
                    </Card>
                  )}

                  {/* Analysis Actions */}
                  <Box display="flex" justifyContent="space-between" alignItems="flex-end">
                    <Typography variant="caption" color="textSecondary">
                      <strong>Generated:</strong><br />
                      {binaryAISummary.created_at ? 
                        new Date(binaryAISummary.created_at).toLocaleString() : 
                        'Just now'
                      }
                    </Typography>
                    <Box display="flex" gap={1}>
                      <Button
                        variant="outlined"
                        size="small"
                        startIcon={<Clear />}
                        onClick={handleClearCache}
                        disabled={aiSummaryLoading}
                        color="warning"
                      >
                        Clear Cache
                      </Button>
                      <Button
                        variant="outlined"
                        size="small"
                        startIcon={aiSummaryLoading ? <CircularProgress size={16} /> : <Refresh />}
                        onClick={handleUpdateAIAnalysis}
                        disabled={aiSummaryLoading}
                        color="secondary"
                      >
                        {aiSummaryLoading ? 'Updating...' : 'Update'}
                      </Button>
                    </Box>
                  </Box>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Quick Action Bar */}
      {binary.analysis_status === 'processed' && (
        <Card sx={{ mb: 3, bgcolor: 'success.main', color: 'white' }}>
          <CardContent sx={{ py: 2 }}>
            <Box display="flex" justifyContent="space-between" alignItems="center">
              <Box display="flex" alignItems="center" gap={2}>
                <Info />
                <Typography variant="body1" fontWeight="medium">
                  Analysis completed successfully! Ready for detailed exploration.
                </Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      )}



      {/* Show message when no functions found */}
          </Box>
  );
};

export default BinaryDetails; 