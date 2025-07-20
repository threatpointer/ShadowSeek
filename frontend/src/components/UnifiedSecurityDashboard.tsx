import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Chip,
  LinearProgress,
  Alert,
  Paper,
  CircularProgress,
  Divider,
  IconButton,
  Collapse,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  ExpandLess,
  ExpandMore,
  BugReport as BugReportIcon,
  Launch as LaunchIcon,
  Code as CodeIcon,
} from '@mui/icons-material';
import { api } from '../utils/api';

interface SecurityFinding {
  id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  function_id?: string;
  classification: {
    cwe_id?: string;
    cve_id?: string;
    category?: string;
  };
  analysis: {
    ai_explanation?: string;
    pattern_matches?: any[];
    detection_methods: string[];
  };
  location: {
    address?: string;
    file_offset?: number;
    line_number?: number;
  };
  technical_details: {
    affected_code?: string;
    proof_of_concept?: string;
    remediation?: string;
    references?: string[];
  };
  risk_assessment: {
    risk_score: number;
    exploit_difficulty: string;
    false_positive_risk: string;
  };
  metadata: {
    analysis_version: string;
    correlation_score: number;
  };
  created_at: string;
}

interface UnifiedSecurityDashboardProps {
  binary: any;
  functions: any[];
  onRefresh: () => void;
  onNavigateToFunction?: (functionId: string) => void;
}

const UnifiedSecurityDashboard: React.FC<UnifiedSecurityDashboardProps> = ({
  binary,
  functions,
  onRefresh,
  onNavigateToFunction,
}) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<any>(null);
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [analysisProgress, setAnalysisProgress] = useState(0);
  const [analysisStatus, setAnalysisStatus] = useState<string>('');

  useEffect(() => {
    loadSecurityFindings();
  }, [binary.id]); // loadSecurityFindings is stable due to useCallback

  const loadSecurityFindings = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await api.get(`/binaries/${binary.id}/security-findings`);
      setFindings(response.data.findings || []);
      setSummary(response.data.summary || null);
    } catch (err: any) {
      console.error('Error loading security findings:', err);
      setError(err.response?.data?.error || 'Failed to load security findings');
    } finally {
      setLoading(false);
    }
  }, [binary.id]);

  const runSecurityAnalysis = async () => {
    try {
      setIsAnalyzing(true);
      setError(null);
      setAnalysisProgress(0);

      // Check if functions are decompiled for enhanced messaging
      const decompiledFunctions = functions.filter(f => f.is_decompiled);
      const hasDecompiledFunctions = decompiledFunctions.length > 0;

      if (hasDecompiledFunctions) {
        setAnalysisStatus(`Starting traditional security analysis on ${decompiledFunctions.length} decompiled functions...`);
      } else {
        setAnalysisStatus('Starting enhanced analysis: extracting binary data, auto-decompiling exports, running AI analysis...');
      }

      // Start binary-level security analysis (automatically selects traditional vs enhanced)
      const response = await api.post(`/binaries/${binary.id}/security-analysis`);
      
      if (response.data.success) {
        setAnalysisProgress(100);
        
        // Display analysis type and results
        const analysisType = response.data.analysis_type || 'security';
        const totalFindings = response.data.total_findings || 0;
        
        if (analysisType === 'enhanced') {
          const methods = response.data.analysis_methods || [];
          const exportDecomp = response.data.export_decompilation || {};
          const traditionalAnalysis = response.data.traditional_analysis || {};
          const coverage = response.data.coverage_analysis || {};
          
          let statusParts = [`${totalFindings} findings using ${methods.length} methods`];
          
          if (coverage.comprehensive_analysis) {
            const compData = coverage.comprehensive_analysis;
            statusParts.push(`Extracted ${compData.exports_found || 0} exports, ${compData.strings_found || 0} strings`);
          }
          
          if (exportDecomp.performed) {
            statusParts.push(`Auto-decompiled ${exportDecomp.exports_decompiled} exports`);
          }
          
          if (traditionalAnalysis.performed) {
            statusParts.push(`Analyzed ${traditionalAnalysis.functions_analyzed} functions`);
          }
          
          setAnalysisStatus(`Enhanced analysis pipeline complete: ${statusParts.join(' | ')}`);
        } else {
          setAnalysisStatus(`Traditional analysis complete: ${totalFindings} findings from ${decompiledFunctions.length} functions`);
        }
        
        // Reload findings
        await loadSecurityFindings();
        onRefresh(); // Refresh parent component
        
        // Show success message
        setTimeout(() => {
          setAnalysisStatus('');
          setAnalysisProgress(0);
        }, 3000);
      } else {
        throw new Error(response.data.error || 'Security analysis failed');
      }
    } catch (err: any) {
      console.error('Error running security analysis:', err);
      setError(err.response?.data?.error || 'Security analysis failed');
      setAnalysisStatus('');
      setAnalysisProgress(0);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <ErrorIcon color="error" />;
      case 'HIGH':
        return <WarningIcon color="warning" />;
      case 'MEDIUM':
        return <InfoIcon color="info" />;
      case 'LOW':
        return <InfoIcon color="action" />;
      default:
        return <InfoIcon />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'error';
      case 'HIGH':
        return 'warning';
      case 'MEDIUM':
        return 'info';
      case 'LOW':
        return 'default';
      default:
        return 'default';
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return 'success';
    if (confidence >= 70) return 'info';
    if (confidence >= 50) return 'warning';
    return 'error';
  };

  const toggleFindingExpansion = (findingId: string) => {
    setExpandedFinding(expandedFinding === findingId ? null : findingId);
  };

  // Helper function to find function by ID
  const getFunctionInfo = (functionId: string) => {
    return functions.find(f => f.id === functionId);
  };

  // Helper function to navigate to function
  const handleNavigateToFunction = (functionId: string) => {
    if (onNavigateToFunction) {
      onNavigateToFunction(functionId);
    }
  };

  const decompiledCount = functions.filter(f => f.is_decompiled).length;
  const canAnalyze = !isAnalyzing; // Enhanced analysis works with or without decompiled functions

  return (
    <Box>
      {/* Header Section */}
      <Box display="flex" alignItems="center" justifyContent="space-between" mb={3}>
        <Box display="flex" alignItems="center" gap={2}>
          <SecurityIcon color="primary" fontSize="large" />
          <Typography variant="h5" component="h2">
            Unified Security Analysis
          </Typography>
        </Box>
        
        <Button
          variant="contained"
          color="primary"
          onClick={runSecurityAnalysis}
          disabled={!canAnalyze}
          startIcon={<BugReportIcon />}
          size="large"
          title={decompiledCount > 0 
            ? 'Run traditional security analysis on decompiled functions'
            : 'Run enhanced security analysis using exports, strings, imports, and AI'
          }
        >
          {isAnalyzing ? 'Analyzing...' : 'Security Analysis'}
        </Button>
      </Box>

      {/* Status and Progress */}
      {(isAnalyzing || analysisStatus) && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box display="flex" alignItems="center" gap={2} mb={2}>
              {isAnalyzing && <CircularProgress size={24} />}
              <Typography variant="body1">
                {analysisStatus || 'Processing security analysis...'}
              </Typography>
            </Box>
            {isAnalyzing && (
              <LinearProgress 
                variant="determinate" 
                value={analysisProgress} 
                sx={{ height: 8, borderRadius: 4 }}
              />
            )}
          </CardContent>
        </Card>
      )}

      {/* Error Display */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Analysis Information */}
      {decompiledCount === 0 ? (
        <Alert severity="info" sx={{ mb: 3 }}>
          <Typography variant="subtitle2">Enhanced Security Analysis Pipeline</Typography>
          Will automatically: (1) Extract binary data (exports, imports, strings), (2) Auto-decompile exported functions, 
          (3) Run traditional analysis on decompiled exports, (4) Perform AI-driven comprehensive analysis. 
          Perfect for DLLs and binaries with limited existing analysis.
        </Alert>
      ) : (
        <Alert severity="success" sx={{ mb: 3 }}>
          <Typography variant="subtitle2">Traditional + Enhanced Analysis Available</Typography>
          {decompiledCount} decompiled functions found - will use comprehensive function-based analysis.
        </Alert>
      )}

      {/* Summary Statistics */}
      {summary && (
        <Grid container spacing={3} sx={{ mb: 3 }}>
          <Grid item xs={12} md={3}>
            <Card sx={{
              background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              color: 'white',
              boxShadow: '0 4px 20px rgba(102, 126, 234, 0.4)',
              borderRadius: '8px'
            }}>
              <CardContent sx={{ textAlign: 'center', py: 2 }}>
                <Typography variant="h4" component="div" fontWeight="700" sx={{ textShadow: '0 1px 2px rgba(0,0,0,0.1)' }}>
                  {summary.total_findings}
                </Typography>
                <Typography color="white" sx={{ opacity: 0.95, fontWeight: '500' }}>
                  Total Findings
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          
          <Grid item xs={12} md={9}>
            <Card sx={{
              background: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
              color: 'white',
              boxShadow: '0 4px 20px rgba(79, 172, 254, 0.4)',
              borderRadius: '8px'
            }}>
              <CardContent>
                <Typography variant="subtitle1" gutterBottom fontWeight="600" sx={{ textShadow: '0 1px 2px rgba(0,0,0,0.1)' }}>
                  Severity Breakdown
                </Typography>
                <Box display="flex" gap={1} flexWrap="wrap">
                  {Object.entries(summary.severity_counts).map(([severity, count]) => (
                    (count as number) > 0 && (
                      <Chip
                        key={severity}
                        label={`${severity}: ${count}`}
                        color={getSeverityColor(severity) as any}
                        size="small"
                        icon={getSeverityIcon(severity)}
                        sx={{ fontWeight: '500' }}
                      />
                    )
                  ))}
                </Box>
                <Typography variant="body2" color="white" sx={{ mt: 1, opacity: 0.95, fontWeight: '500' }}>
                  Average Confidence: {summary.average_confidence}%
                  <span style={{ display: 'block', fontSize: '0.8em', marginTop: '4px', opacity: 0.9 }}>
                    Based on AI analysis and pattern detection correlation
                  </span>
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Security Findings */}
      {loading ? (
        <Box display="flex" justifyContent="center" py={4}>
          <CircularProgress />
        </Box>
      ) : findings.length > 0 ? (
        <Box>
          <Typography variant="h6" gutterBottom>
            Security Findings ({findings.length})
          </Typography>
          
          {findings.map((finding) => {
            const functionInfo = finding.function_id ? getFunctionInfo(finding.function_id) : null;
            
            return (
              <Card key={finding.id} sx={{ mb: 2, border: '1px solid', borderColor: 'divider' }}>
                <CardContent>
                  {/* Header Section with improved layout */}
                  <Box display="flex" alignItems="flex-start" justifyContent="space-between" mb={2}>
                    <Box flex={1}>
                      {/* Title and Severity Row */}
                      <Box display="flex" alignItems="center" gap={2} mb={1}>
                        {getSeverityIcon(finding.severity)}
                        <Typography variant="h6" component="div" sx={{ fontWeight: 600 }}>
                          {finding.title}
                        </Typography>
                        <Chip
                          label={finding.severity}
                          color={getSeverityColor(finding.severity) as any}
                          size="small"
                          sx={{ fontWeight: 'bold' }}
                        />
                        <Chip
                          label={`${finding.confidence}% confidence`}
                          color={getConfidenceColor(finding.confidence) as any}
                          size="small"
                          variant="outlined"
                        />
                      </Box>

                      {/* Function Link Row */}
                      {functionInfo && (
                        <Box display="flex" alignItems="center" gap={1} mb={2}>
                          <CodeIcon color="primary" fontSize="small" />
                          <Typography
                            variant="body2"
                            component="button"
                            onClick={() => handleNavigateToFunction(finding.function_id!)}
                            sx={{
                              color: 'primary.main',
                              textDecoration: 'none',
                              cursor: 'pointer',
                              background: 'none',
                              border: 'none',
                              padding: 0,
                              fontFamily: 'inherit',
                              fontSize: 'inherit',
                              '&:hover': {
                                textDecoration: 'underline',
                              },
                            }}
                          >
                            <strong>Function:</strong> {functionInfo.name || functionInfo.original_name || 'Unknown'} @ {functionInfo.address}
                          </Typography>
                          <LaunchIcon 
                            color="primary" 
                            fontSize="small" 
                            sx={{ cursor: 'pointer' }}
                            onClick={() => handleNavigateToFunction(finding.function_id!)}
                          />
                        </Box>
                      )}

                      {/* Location Info */}
                      {finding.location.address && (
                        <Box display="flex" alignItems="center" gap={1} mb={2}>
                          <Typography variant="body2" color="text.secondary">
                            <strong>Address:</strong> {finding.location.address}
                          </Typography>
                        </Box>
                      )}
                    </Box>
                    
                    <IconButton
                      onClick={() => toggleFindingExpansion(finding.id)}
                      size="small"
                      sx={{ ml: 1 }}
                    >
                      {expandedFinding === finding.id ? <ExpandLess /> : <ExpandMore />}
                    </IconButton>
                  </Box>

                  {/* Description */}
                  <Typography variant="body1" color="text.secondary" paragraph sx={{ mb: 2 }}>
                    {finding.description}
                  </Typography>

                  {/* Classification Tags */}
                  <Box display="flex" gap={1} flexWrap="wrap" mb={2}>
                    {finding.classification.cwe_id && (
                      <Chip 
                        label={finding.classification.cwe_id} 
                        size="small" 
                        variant="outlined" 
                        color="info"
                      />
                    )}
                    {finding.classification.category && (
                      <Chip 
                        label={finding.classification.category} 
                        size="small" 
                        variant="outlined" 
                        color="default"
                      />
                    )}
                    <Chip 
                      label={`Risk Score: ${finding.risk_assessment.risk_score}/100`} 
                      size="small" 
                      variant="outlined" 
                      color="warning"
                    />
                  </Box>

                <Collapse in={expandedFinding === finding.id}>
                  <Divider sx={{ my: 2 }} />
                  
                  <Grid container spacing={3}>
                    {/* AI Explanation */}
                    {finding.analysis.ai_explanation && (
                      <Grid item xs={12} md={6}>
                        <Typography variant="subtitle2" gutterBottom>
                          AI Analysis
                        </Typography>
                        <Typography variant="body2" paragraph>
                          {finding.analysis.ai_explanation}
                        </Typography>
                      </Grid>
                    )}

                    {/* Technical Details */}
                    <Grid item xs={12} md={6}>
                      <Typography variant="subtitle2" gutterBottom>
                        Technical Details
                      </Typography>
                      {finding.location.address && (
                        <Typography variant="body2">
                          <strong>Address:</strong> {finding.location.address}
                        </Typography>
                      )}
                      <Typography variant="body2">
                        <strong>Risk Score:</strong> {finding.risk_assessment.risk_score}/100
                      </Typography>
                      <Typography variant="body2">
                        <strong>Exploit Difficulty:</strong> {finding.risk_assessment.exploit_difficulty}
                      </Typography>
                    </Grid>

                    {/* Affected Code */}
                    {finding.technical_details.affected_code && (
                      <Grid item xs={12}>
                        <Typography variant="subtitle2" gutterBottom>
                          Affected Code
                        </Typography>
                        <Paper sx={{ p: 2, backgroundColor: '#f5f5f5' }}>
                          <Typography
                            variant="body2"
                            component="pre"
                            sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}
                          >
                            {finding.technical_details.affected_code}
                          </Typography>
                        </Paper>
                      </Grid>
                    )}

                    {/* Remediation */}
                    {finding.technical_details.remediation && (
                      <Grid item xs={12}>
                        <Typography variant="subtitle2" gutterBottom>
                          Remediation
                        </Typography>
                        <Typography variant="body2">
                          {finding.technical_details.remediation}
                        </Typography>
                      </Grid>
                    )}

                    {/* Detection Methods */}
                    <Grid item xs={12}>
                      <Typography variant="subtitle2" gutterBottom>
                        Detection Methods
                      </Typography>
                      <Box display="flex" gap={1}>
                        {finding.analysis.detection_methods.map((method, index) => (
                          <Chip key={index} label={method} size="small" variant="outlined" />
                        ))}
                      </Box>
                    </Grid>
                  </Grid>
                </Collapse>
              </CardContent>
            </Card>
            );
          })}
        </Box>
      ) : !loading && !isAnalyzing && (
        <Card>
          <CardContent>
            <Box textAlign="center" py={4}>
              <SecurityIcon color="disabled" sx={{ fontSize: 64, mb: 2 }} />
              <Typography variant="h6" color="text.secondary" gutterBottom>
                No Security Analysis Results
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {decompiledCount > 0 
                  ? 'Click "Security Analysis" to start analyzing for vulnerabilities using traditional function analysis'
                  : 'Click "Security Analysis" to run the full pipeline: extract data → decompile exports → comprehensive analysis'
                }
              </Typography>
            </Box>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

export default UnifiedSecurityDashboard; 