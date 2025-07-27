import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Grid,
  Card,
  CardContent,
  Alert,
  LinearProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Divider,
  Tab,
  Tabs,
  CircularProgress
} from '@mui/material';
import {
  Compare,
  ExpandMore,
  Download,
  Visibility,
  Upload,
  FileUpload,
  Assessment,
  Info,
  Warning,
  Error as ErrorIcon
} from '@mui/icons-material';
import { toast } from 'react-toastify';
import { apiClient } from '../utils/api';
import { taskManager } from '../utils/taskManager';
import { debugTaskManager } from '../utils/taskManagerDebug';
import { notificationManager } from './NotificationCenter';

// Markdown rendering imports
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkBreaks from 'remark-breaks';
import rehypeHighlight from 'rehype-highlight';
import rehypeRaw from 'rehype-raw';
import 'highlight.js/styles/github-dark.css';

// Data visualization imports
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import mermaid from 'mermaid';

interface Binary {
  id: string;
  filename: string;
  original_filename: string;
  file_size: number;
  upload_time: string;
  analysis_status: string;
}

interface ComparisonResult {
  task_id: string;
  binary_id1: string;
  binary_id2: string;
  diff_type: string;
  status: string;
  results?: {
    differences: Array<{
      type: string;
      address: string;
      binary1_value: string;
      binary2_value: string;
      description: string;
    }>;
    similarity_score: number;
    summary: {
      total_differences: number;
      instruction_differences: number;
      data_differences: number;
      function_differences: number;
    };
  };
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`comparison-tabpanel-${index}`}
      aria-labelledby={`comparison-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children as React.ReactNode}
        </Box>
      )}
    </div>
  );
}

interface DiffResultsViewerProps {
  result: any;
}

const DiffResultsViewer: React.FC<DiffResultsViewerProps> = ({ result }) => {
  const [tab, setTab] = useState(0);
  
  // Handle new ghidriff structured results
  const isGhidriffResult = result && (result.engine || result.markdown || result.json_data);
  
  if (isGhidriffResult) {
    return (
      <Box sx={{ mt: 3 }}>
        <Typography variant="h6" gutterBottom sx={{ color: 'white', mb: 3 }}>
          📊 ghidriff Analysis Results ({result.engine})
        </Typography>
        
        <Box sx={{ borderBottom: 1, borderColor: 'rgba(255, 255, 255, 0.12)', mb: 2 }}>
          <Tabs 
            value={tab} 
            onChange={(_, v) => setTab(v)}
            sx={{
              '& .MuiTab-root': { color: 'rgba(255, 255, 255, 0.7)' },
              '& .Mui-selected': { color: '#90caf9' },
              '& .MuiTabs-indicator': { backgroundColor: '#90caf9' }
            }}
          >
            <Tab label="🎯 Interactive Analysis" />
            <Tab label="🔍 Raw Data" />
            {result.stdout && <Tab label="📋 Analysis Logs" />}
          </Tabs>
        </Box>

        <TabPanel value={tab} index={0}>
          {/* Enhanced Structured View */}
          <EnhancedGhidriffViewer 
            markdown={result.markdown} 
            jsonData={result.json_data} 
            summary={result.summary} 
          />
        </TabPanel>

        <TabPanel value={tab} index={1}>
          {/* Raw Data Tab */}
          <GhidriffRawDataView jsonData={result.json_data} />
        </TabPanel>
        
        {result.stdout && (
          <TabPanel value={tab} index={2}>
            {/* Logs Tab */}
            <GhidriffLogsView logs={result.stdout} />
          </TabPanel>
        )}
      </Box>
    );
  }
  
  // Fallback for legacy/other results
  const sectionKeys = Object.keys(result || {}).filter(
    (key) => Array.isArray(result[key]) && result[key].length > 0
  );
  
  if (sectionKeys.length === 0) {
    return (
      <Alert severity="info" sx={{ mt: 3, backgroundColor: 'rgba(33, 150, 243, 0.15)', color: '#90caf9' }}>
        No detailed diff data available. The comparison may still be processing or may have completed without detailed results.
      </Alert>
    );
  }
  
  return (
    <Box sx={{ mt: 3 }}>
      <Tabs value={tab} onChange={(_, v) => setTab(v)}>
        {sectionKeys.map((key, idx) => (
          <Tab key={key} label={key.charAt(0).toUpperCase() + key.slice(1)} />
        ))}
      </Tabs>
      {sectionKeys.map((key, idx) => (
        <TabPanel key={key} value={tab} index={idx}>
          <TableContainer component={Paper} sx={{ background: '#181818' }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  {Object.keys(result[key][0] || {}).map((col) => (
                    <TableCell key={col} sx={{ color: 'white', fontWeight: 'bold' }}>{col}</TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {result[key].map((row: any, i: number) => (
                  <TableRow key={i}>
                    {Object.values(row).map((val, j) => (
                      <TableCell key={j} sx={{ color: 'white' }}>{String(val)}</TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </TabPanel>
      ))}
    </Box>
  );
};

// Component to display ghidriff summary statistics
const GhidriffSummaryView: React.FC<{ summary: any; jsonData: any }> = ({ summary, jsonData }) => {
  if (!summary && !jsonData) {
    return (
      <Alert severity="info" sx={{ backgroundColor: 'rgba(33, 150, 243, 0.15)', color: '#90caf9' }}>
        No summary data available
      </Alert>
    );
  }

  const data = summary || jsonData || {};
  
  return (
    <Grid container spacing={3}>
      <Grid item xs={12} md={6}>
        <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
          <CardContent>
            <Typography variant="h6" gutterBottom sx={{ color: '#90caf9' }}>
              🔍 Function Analysis
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography>Total Functions:</Typography>
                <Chip label={data.total_functions || data.total_funcs_len || 'N/A'} size="small" />
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography>Matched Functions:</Typography>
                <Chip label={data.matched_functions || data.matched_funcs_len || 'N/A'} size="small" color="success" />
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography>Modified Functions:</Typography>
                <Chip label={data.modified_functions || data.modified_funcs_len || 'N/A'} size="small" color="warning" />
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography>Added Functions:</Typography>
                <Chip label={data.added_functions || data.added_funcs_len || 'N/A'} size="small" color="primary" />
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography>Deleted Functions:</Typography>
                <Chip label={data.deleted_functions || data.deleted_funcs_len || 'N/A'} size="small" color="error" />
              </Box>
            </Box>
          </CardContent>
        </Card>
      </Grid>
      
      <Grid item xs={12} md={6}>
        <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
          <CardContent>
            <Typography variant="h6" gutterBottom sx={{ color: '#90caf9' }}>
              📊 Similarity Metrics
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography>Overall Similarity:</Typography>
                <Chip 
                  label={data.similarity_percent || data.func_match_overall_percent || 'N/A'} 
                  size="small" 
                  sx={{ 
                    backgroundColor: '#4caf50',
                    color: 'white',
                    fontWeight: 'bold'
                  }} 
                />
              </Box>
              <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                <Typography>Analysis Time:</Typography>
                <Typography>
                  {data.diff_time_seconds || data.diff_time 
                    ? `${Math.round((data.diff_time_seconds || data.diff_time) * 100) / 100}s`
                    : 'N/A'
                  }
                </Typography>
              </Box>
            </Box>
          </CardContent>
        </Card>
      </Grid>
      
      {(data.match_types || data.diff_types) && (
        <Grid item xs={12}>
          <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ color: '#90caf9' }}>
                🏷️ Analysis Details
              </Typography>
              <Grid container spacing={2}>
                {data.match_types && (
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ mb: 1 }}>Match Types:</Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                      {Object.entries(data.match_types).map(([type, count]: [string, any]) => (
                        <Chip 
                          key={type} 
                          label={`${type}: ${count}`} 
                          size="small" 
                          sx={{ backgroundColor: 'rgba(76, 175, 80, 0.2)', color: '#4caf50' }}
                        />
                      ))}
                    </Box>
                  </Grid>
                )}
                {data.diff_types && (
                  <Grid item xs={12} md={6}>
                    <Typography variant="subtitle2" sx={{ mb: 1 }}>Diff Types:</Typography>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                      {Object.entries(data.diff_types).map(([type, count]: [string, any]) => (
                        <Chip 
                          key={type} 
                          label={`${type}: ${count}`} 
                          size="small" 
                          sx={{ backgroundColor: 'rgba(255, 152, 0, 0.2)', color: '#ff9800' }}
                        />
                      ))}
                    </Box>
                  </Grid>
                )}
              </Grid>
            </CardContent>
          </Card>
        </Grid>
      )}
    </Grid>
  );
};

// Enhanced component to display ghidriff markdown report with proper Mermaid rendering
const GhidriffMarkdownView: React.FC<{ markdown: string }> = ({ markdown }) => {
  const [renderedMermaid, setRenderedMermaid] = useState<{ [key: string]: string }>({});

  // Extract and render Mermaid diagrams
  useEffect(() => {
    const renderMermaidDiagrams = async () => {
      if (!markdown) return;

      const mermaidBlocks: { [key: string]: string } = {};
      const mermaidRegex = /```mermaid\n([\s\S]*?)```/g;
      let match;
      let index = 0;

      while ((match = mermaidRegex.exec(markdown)) !== null) {
        const mermaidCode = match[1].trim();
        const id = `mermaid-${index++}`;
        
        try {
          const { svg } = await mermaid.render(id, mermaidCode);
          mermaidBlocks[mermaidCode] = svg;
        } catch (error) {
          console.error('Error rendering mermaid diagram:', error);
          mermaidBlocks[mermaidCode] = ''; // Failed to render
        }
      }

      setRenderedMermaid(mermaidBlocks);
    };

    renderMermaidDiagrams();
  }, [markdown]);

  if (!markdown || markdown.trim() === '') {
    return (
      <Alert severity="info" sx={{ backgroundColor: 'rgba(33, 150, 243, 0.15)', color: '#90caf9' }}>
        No markdown report available
      </Alert>
    );
  }

  return (
    <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ color: '#90caf9', mb: 2 }}>
          📝 ghidriff Analysis Report
        </Typography>
        <Box 
          sx={{ 
            backgroundColor: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: 1,
            p: 3,
            maxHeight: '800px',
            overflow: 'auto',
            color: '#f0f6fc',
            // Enhanced styling for better readability
            '& h1, & h2, & h3, & h4, & h5, & h6': {
              color: '#90caf9',
              borderBottom: '1px solid #30363d',
              paddingBottom: '0.5rem',
              marginBottom: '1rem',
              marginTop: '1.5rem'
            },
            '& h1': { fontSize: '1.8rem', fontWeight: 'bold' },
            '& h2': { fontSize: '1.5rem', fontWeight: 'bold' },
            '& h3': { fontSize: '1.3rem', fontWeight: 'bold' },
            '& h4': { fontSize: '1.1rem', fontWeight: 'bold' },
            '& p': { lineHeight: 1.6, marginBottom: '1rem' },
            '& table': {
              borderCollapse: 'collapse',
              width: '100%',
              marginBottom: '1.5rem',
              backgroundColor: '#161b22',
              fontSize: '0.9rem'
            },
            '& th, & td': {
              border: '1px solid #30363d',
              padding: '10px 12px',
              textAlign: 'left',
              verticalAlign: 'top'
            },
            '& th': {
              backgroundColor: '#21262d',
              color: '#90caf9',
              fontWeight: 'bold',
              position: 'sticky',
              top: 0
            },
            '& tr:nth-of-type(even)': {
              backgroundColor: '#0d1117'
            },
            '& tr:hover': {
              backgroundColor: '#1c2128'
            },
            '& code': {
              backgroundColor: 'rgba(110, 118, 129, 0.4)',
              padding: '3px 6px',
              borderRadius: '4px',
              fontSize: '0.85em',
              fontFamily: 'SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace',
              border: '1px solid rgba(110, 118, 129, 0.2)'
            },
            '& pre': {
              backgroundColor: '#161b22',
              border: '1px solid #30363d',
              borderRadius: '6px',
              padding: '16px',
              overflow: 'auto',
              marginBottom: '1.5rem',
              fontSize: '0.85rem',
              lineHeight: 1.4,
              '& code': {
                backgroundColor: 'transparent',
                padding: 0,
                border: 'none'
              }
            },
            '& blockquote': {
              borderLeft: '4px solid #90caf9',
              paddingLeft: '1rem',
              marginLeft: 0,
              color: '#8b949e',
              fontStyle: 'italic',
              backgroundColor: 'rgba(144, 202, 249, 0.05)',
              padding: '1rem',
              borderRadius: '0 4px 4px 0'
            },
            '& ul, & ol': {
              paddingLeft: '2rem',
              marginBottom: '1rem'
            },
            '& li': {
              marginBottom: '0.5rem',
              lineHeight: 1.5
            },
            '& a': {
              color: '#90caf9',
              textDecoration: 'none',
              borderBottom: '1px solid transparent',
              '&:hover': {
                borderBottom: '1px solid #90caf9'
              }
            },
            '& hr': {
              border: 'none',
              borderTop: '2px solid #30363d',
              margin: '3rem 0'
            },
            // Enhanced diff styling
            '& .diff': {
              backgroundColor: '#161b22',
              border: '1px solid #30363d',
              borderRadius: '6px',
              overflow: 'hidden',
              marginBottom: '1.5rem'
            },
            '& .diff .line-added': { 
              backgroundColor: 'rgba(46, 160, 67, 0.15)', 
              color: '#3fb950',
              display: 'block',
              padding: '2px 8px',
              borderLeft: '3px solid #3fb950'
            },
            '& .diff .line-removed': { 
              backgroundColor: 'rgba(248, 81, 73, 0.15)', 
              color: '#f85149',
              display: 'block',
              padding: '2px 8px',
              borderLeft: '3px solid #f85149'
            }
          }}
        >
          <ReactMarkdown
            remarkPlugins={[remarkGfm, remarkBreaks]}
            rehypePlugins={[
              [rehypeHighlight, { 
                ignoreMissing: true,
                detect: false,
                subset: ['javascript', 'typescript', 'python', 'java', 'cpp', 'c', 'bash', 'shell', 'json', 'xml', 'html', 'css', 'sql', 'diff', 'asm', 'assembly']
              }], 
              rehypeRaw
            ]}
            components={{
              code: ({ node, inline, className, children, ...props }) => {
                const match = /language-(\w+)/.exec(className || '');
                const language = match ? match[1] : '';
                
                // Handle mermaid code blocks with actual diagram rendering
                if (language === 'mermaid' && !inline) {
                  const mermaidCode = String(children).trim();
                  const renderedSvg = renderedMermaid[mermaidCode];
                  
                  return (
                    <Box 
                      sx={{ 
                        backgroundColor: '#1e1e1e',
                        border: '2px solid #90caf9',
                        borderRadius: '8px',
                        padding: '20px',
                        marginBottom: '2rem',
                        textAlign: 'center'
                      }}
                    >
                      <Typography variant="body2" sx={{ mb: 2, fontWeight: 'bold', color: '#90caf9' }}>
                        📊 Interactive Diagram
                      </Typography>
                      {renderedSvg ? (
                        <Box
                          sx={{
                            '& svg': { 
                              maxWidth: '100%', 
                              height: 'auto',
                              backgroundColor: 'white',
                              borderRadius: '4px',
                              padding: '10px'
                            }
                          }}
                          dangerouslySetInnerHTML={{ __html: renderedSvg }}
                        />
                      ) : (
                        <Box sx={{ 
                          backgroundColor: '#161b22',
                          border: '1px solid #30363d',
                          borderRadius: '4px',
                          padding: '12px',
                          textAlign: 'left',
                          color: '#8b949e'
                        }}>
                          <Typography variant="body2" sx={{ mb: 1, color: '#f85149' }}>
                            ⚠️ Failed to render diagram
                          </Typography>
                          <pre style={{ fontSize: '12px', overflow: 'auto', margin: 0 }}>
                            {children}
                          </pre>
                        </Box>
                      )}
                    </Box>
                  );
                }
                
                return !inline && match ? (
                  <pre className={className} {...props}>
                    <code className={className}>
                      {children}
                    </code>
                  </pre>
                ) : (
                  <code className={className} {...props}>
                    {children}
                  </code>
                );
              },
              // Enhanced diff block rendering
              div: ({ node, className, children, ...props }) => {
                if (className?.includes('diff')) {
                  return (
                    <Box className="diff" sx={{ marginBottom: '1.5rem' }}>
                      {children}
                    </Box>
                  );
                }
                return <div className={className} {...props}>{children}</div>;
              },
              // Better table rendering
              table: ({ node, children, ...props }) => (
                <Box sx={{ overflow: 'auto', marginBottom: '1.5rem' }}>
                  <table {...props}>{children}</table>
                </Box>
              )
            }}
          >
            {markdown}
          </ReactMarkdown>
        </Box>
        <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            size="small"
            startIcon={<Download />}
            onClick={() => {
              const blob = new Blob([markdown], { type: 'text/markdown' });
              const url = URL.createObjectURL(blob);
              const link = document.createElement('a');
              link.href = url;
              link.download = 'ghidriff_report.md';
              link.click();
              URL.revokeObjectURL(url);
            }}
            sx={{ color: 'white', borderColor: 'rgba(255, 255, 255, 0.5)' }}
          >
            Download Report
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};

// Component to display raw ghidriff JSON data
const GhidriffRawDataView: React.FC<{ jsonData: any }> = ({ jsonData }) => {
  if (!jsonData) {
    return (
      <Alert severity="info" sx={{ backgroundColor: 'rgba(33, 150, 243, 0.15)', color: '#90caf9' }}>
        No raw data available
      </Alert>
    );
  }

  return (
    <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ color: '#90caf9', mb: 2 }}>
          🔍 Raw ghidriff Data
        </Typography>
        <Box 
          sx={{ 
            backgroundColor: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: 1,
            p: 2,
            maxHeight: '600px',
            overflow: 'auto',
            fontFamily: 'monospace',
            fontSize: '12px'
          }}
        >
          <pre style={{ margin: 0, color: '#f0f6fc' }}>
            {JSON.stringify(jsonData, null, 2)}
          </pre>
        </Box>
        <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            size="small"
            startIcon={<Download />}
            onClick={() => {
              const dataStr = JSON.stringify(jsonData, null, 2);
              const blob = new Blob([dataStr], { type: 'application/json' });
              const url = URL.createObjectURL(blob);
              const link = document.createElement('a');
              link.href = url;
              link.download = 'ghidriff_data.json';
              link.click();
              URL.revokeObjectURL(url);
            }}
            sx={{ color: 'white', borderColor: 'rgba(255, 255, 255, 0.5)' }}
          >
            Download JSON
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};

// Enhanced logs viewer that parses and structures the log content
const EnhancedLogsViewer: React.FC<{ logs: string }> = ({ logs }) => {
  const [selectedPhase, setSelectedPhase] = useState<string | null>(null);
  
  // Parse logs into structured sections
  const parseLogSections = (logText: string) => {
    const lines = logText.split('\n');
    const sections: { [key: string]: { lines: string[], timing?: string, status: 'info' | 'warning' | 'error' } } = {};
    let currentSection = 'General';
    let currentLines: string[] = [];
    
    const analysisPhases = [
      'ASCII Strings', 'Apply Data Archives', 'Call Convention ID', 'Decompiler Parameter ID',
      'Decompiler Switch Analysis', 'Demangler Microsoft', 'Function ID', 'PDB Universal',
      'Reference', 'Stack', 'Subroutine References', 'Windows x86 PE'
    ];
    
    lines.forEach(line => {
      const trimmedLine = line.trim();
      
      // Detect analysis phases
      const foundPhase = analysisPhases.find(phase => trimmedLine.includes(phase) && trimmedLine.includes('secs'));
      if (foundPhase) {
        if (currentLines.length > 0) {
          sections[currentSection] = { 
            lines: [...currentLines], 
            status: getLineStatus(currentLines.join('\n'))
          };
        }
        const timing = trimmedLine.match(/[\d.]+\s+secs/)?.[0];
        sections[foundPhase] = { 
          lines: [trimmedLine], 
          timing,
          status: 'info'
        };
        currentSection = foundPhase;
        currentLines = [];
        return;
      }
      
      // Detect major sections
      if (trimmedLine.includes('Loading file:///') || trimmedLine.includes('Searching') || 
          trimmedLine.includes('Creating project:') || trimmedLine.includes('Using Loader:')) {
        if (currentLines.length > 0) {
          sections[currentSection] = { 
            lines: [...currentLines], 
            status: getLineStatus(currentLines.join('\n'))
          };
        }
        currentSection = 'Binary Loading & Analysis Setup';
        currentLines = [line];
        return;
      }
      
      if (trimmedLine.includes('PDB analyzer') || trimmedLine.includes('resolveCount:')) {
        if (currentLines.length > 0) {
          sections[currentSection] = { 
            lines: [...currentLines], 
            status: getLineStatus(currentLines.join('\n'))
          };
        }
        currentSection = 'PDB Symbol Processing';
        currentLines = [line];
        return;
      }
      
      currentLines.push(line);
    });
    
    // Add remaining lines
    if (currentLines.length > 0) {
      sections[currentSection] = { 
        lines: currentLines, 
        status: getLineStatus(currentLines.join('\n'))
      };
    }
    
    return sections;
  };
  
  const getLineStatus = (text: string): 'info' | 'warning' | 'error' => {
    if (text.toLowerCase().includes('error') || text.toLowerCase().includes('failed')) return 'error';
    if (text.toLowerCase().includes('warn') || text.toLowerCase().includes('skip')) return 'warning';
    return 'info';
  };
  
  const getStatusIcon = (status: 'info' | 'warning' | 'error') => {
    switch (status) {
      case 'error': return <ErrorIcon sx={{ color: '#f44336', fontSize: 16 }} />;
      case 'warning': return <Warning sx={{ color: '#ff9800', fontSize: 16 }} />;
      default: return <Info sx={{ color: '#2196f3', fontSize: 16 }} />;
    }
  };
  
  const logSections = parseLogSections(logs);
  const analysisPhases = Object.entries(logSections).filter(([key, data]) => data.timing);
  const otherSections = Object.entries(logSections).filter(([key, data]) => !data.timing);
  
  return (
    <Box>
      {/* Analysis Performance Summary */}
      {analysisPhases.length > 0 && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ color: '#90caf9', mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
            <Assessment fontSize="small" />
            Analysis Performance Summary
          </Typography>
          <Grid container spacing={1}>
            {analysisPhases.map(([phase, data]) => (
              <Grid item xs={12} sm={6} md={4} key={phase}>
                <Card 
                  sx={{ 
                    backgroundColor: '#2a2a2a', 
                    cursor: 'pointer',
                    border: selectedPhase === phase ? '1px solid #90caf9' : '1px solid transparent',
                    '&:hover': { backgroundColor: '#333' }
                  }}
                  onClick={() => setSelectedPhase(selectedPhase === phase ? null : phase)}
                >
                  <CardContent sx={{ p: 1.5, '&:last-child': { pb: 1.5 } }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <Typography variant="caption" sx={{ color: '#e0e0e0', fontSize: '0.75rem' }}>
                        {phase}
                      </Typography>
                      <Chip 
                        label={data.timing} 
                        size="small" 
                        sx={{ 
                          fontSize: '0.7rem', 
                          height: 20,
                          backgroundColor: '#90caf9', 
                          color: '#000' 
                        }} 
                      />
                    </Box>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}
      
      {/* Detailed Phase Information */}
      {selectedPhase && logSections[selectedPhase] && (
        <Box sx={{ mb: 3 }}>
          <Typography variant="h6" sx={{ color: '#90caf9', mb: 2 }}>
            {selectedPhase} Details
          </Typography>
          <Box sx={{ 
            backgroundColor: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: 1,
            p: 2,
            maxHeight: '300px',
            overflow: 'auto',
            fontFamily: 'monospace',
            fontSize: '12px',
            whiteSpace: 'pre-wrap',
            color: '#f0f6fc'
          }}>
            {logSections[selectedPhase].lines.join('\n')}
          </Box>
        </Box>
      )}
      
      {/* Log Sections */}
      <Box>
        <Typography variant="h6" sx={{ color: '#90caf9', mb: 2 }}>
          Analysis Sections
        </Typography>
        {otherSections.map(([sectionName, sectionData]) => (
          <Accordion 
            key={sectionName}
            sx={{ 
              backgroundColor: '#1e1e1e', 
              color: 'white',
              '&:before': { display: 'none' },
              mb: 1
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMore sx={{ color: 'white' }} />}
              sx={{ 
                backgroundColor: '#2a2a2a',
                '& .MuiAccordionSummary-content': { alignItems: 'center' }
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                {getStatusIcon(sectionData.status)}
                <Typography variant="subtitle2">{sectionName}</Typography>
                <Chip 
                  label={`${sectionData.lines.length} lines`} 
                  size="small" 
                  sx={{ ml: 1 }}
                />
              </Box>
            </AccordionSummary>
            <AccordionDetails sx={{ backgroundColor: '#1a1a1a' }}>
              <Box sx={{ 
                backgroundColor: '#0d1117',
                border: '1px solid #30363d',
                borderRadius: 1,
                p: 2,
                maxHeight: '400px',
                overflow: 'auto',
                fontFamily: 'monospace',
                fontSize: '12px',
                whiteSpace: 'pre-wrap',
                color: '#f0f6fc'
              }}>
                {sectionData.lines.join('\n')}
              </Box>
            </AccordionDetails>
          </Accordion>
        ))}
      </Box>
      
      {/* Raw Logs Section */}
      <Accordion sx={{ 
        backgroundColor: '#1e1e1e', 
        color: 'white',
        '&:before': { display: 'none' },
        mt: 2
      }}>
        <AccordionSummary
          expandIcon={<ExpandMore sx={{ color: 'white' }} />}
          sx={{ backgroundColor: '#2a2a2a' }}
        >
          <Typography variant="subtitle2">📄 Complete Raw Logs</Typography>
        </AccordionSummary>
        <AccordionDetails sx={{ backgroundColor: '#1a1a1a' }}>
          <Box sx={{ 
            backgroundColor: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: 1,
            p: 2,
            maxHeight: '500px',
            overflow: 'auto',
            fontFamily: 'monospace',
            fontSize: '12px',
            whiteSpace: 'pre-wrap',
            color: '#f0f6fc'
          }}>
            {logs}
          </Box>
        </AccordionDetails>
      </Accordion>
    </Box>
  );
};

// Intelligent AI Insights component with web search and real research
const IntelligentAIInsights: React.FC<{ summary: any; parsedData: any; jsonData: any }> = ({ summary, parsedData, jsonData }) => {
  const [aiInsights, setAiInsights] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Use binary names from parsed data
  const { binary1Name, binary2Name } = useMemo(() => {
    // Use the parsed binary names from the markdown
    if (parsedData?.binaryNames) {
      return {
        binary1Name: parsedData.binaryNames.binary1,
        binary2Name: parsedData.binaryNames.binary2
      };
    }
    
    // Fallback to extracting from summary
    let binary1Name = 'Unknown Binary 1';
    let binary2Name = 'Unknown Binary 2';
    
    try {
      if (summary?.binary1) binary1Name = summary.binary1.replace(/^.*_/, '').replace(/\.[^.]+$/, '');
      if (summary?.binary2) binary2Name = summary.binary2.replace(/^.*_/, '').replace(/\.[^.]+$/, '');
      
      // Clean up common UUID prefixes
      binary1Name = binary1Name.replace(/^[a-f0-9-]{36}_/, '');
      binary2Name = binary2Name.replace(/^[a-f0-9-]{36}_/, '');
    } catch (e) {
      console.warn('Error extracting binary names:', e);
    }
    
    return { binary1Name, binary2Name };
  }, [parsedData, summary]);

  // Fetch AI insights with web search
  const fetchAIInsights = useCallback(async () => {
    if (loading || aiInsights) return;
    
    setLoading(true);
    setError(null);
    
    try {
      // Create analysis context using the extracted binary names
      const analysisContext = {
        binary1: binary1Name,
        binary2: binary2Name,
        functionStats: parsedData.functionStats,
        binaryMetadata: parsedData.binaryMetadata,
        addedFunctions: parsedData.addedFunctions.length,
        deletedFunctions: parsedData.deletedFunctions.length,
        modifiedFunctions: parsedData.modifiedFunctions.length,
        analysisType: 'binary_comparison'
      };
      
      // Make API call to get AI insights with web search
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
      
      const response = await fetch('/api/ai/insights', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          context: analysisContext,
          includeWebSearch: true,
          searchQueries: [
            `${binary1Name} security vulnerabilities CVE`,
            `${binary2Name} security vulnerabilities CVE`,
            `${binary1Name} ${binary2Name} changelog release notes`,
            `${binary1Name} security research papers`,
            `${binary2Name} vulnerability reports`
          ]
        }),
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok) {
        throw new Error(`AI service error: ${response.status}`);
      }
      
      const insights = await response.json();
      setAiInsights(insights);
      
    } catch (err: any) {
      console.error('Error fetching AI insights:', err);
      setError(err?.message || 'Failed to fetch AI insights');
    } finally {
      setLoading(false);
    }
  }, [binary1Name, binary2Name, parsedData, loading, aiInsights]);

  // Auto-fetch insights when component mounts
  useEffect(() => {
    fetchAIInsights();
  }, [fetchAIInsights]);

  return (
    <Grid container spacing={3}>
      <Grid item xs={12}>
        <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
              <Typography variant="h6" sx={{ color: '#90caf9' }}>
                🤖 AI-Powered Security Intelligence
              </Typography>
              {loading && <CircularProgress size={24} sx={{ color: '#90caf9' }} />}
              {!loading && !aiInsights && !error && (
                <Button 
                  variant="outlined" 
                  onClick={fetchAIInsights}
                  sx={{ borderColor: '#90caf9', color: '#90caf9' }}
                >
                  Analyze with AI
                </Button>
              )}
            </Box>

            {/* Binary Information Header */}
            <Box sx={{ mb: 4 }}>
              <Typography variant="h6" gutterBottom sx={{ color: '#81c784' }}>
                📊 Binary Analysis: {binary1Name} ↔ {binary2Name}
              </Typography>
              <Typography variant="body2" sx={{ opacity: 0.8 }}>
                Intelligent analysis combining structural comparison with real-time security intelligence
              </Typography>
            </Box>

            {/* Loading State */}
            {loading && (
              <Card sx={{ backgroundColor: '#2a2a2a', p: 3, mb: 3 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <CircularProgress size={20} sx={{ color: '#90caf9' }} />
                  <Typography variant="body2">
                    🔍 Researching security intelligence for {binary1Name} and {binary2Name}...
                  </Typography>
                </Box>
                <Typography variant="body2" sx={{ mt: 1, fontSize: '0.85rem', opacity: 0.7 }}>
                  • Querying CVE databases<br/>
                  • Searching for security research<br/>
                  • Analyzing vulnerability reports<br/>
                  • Checking release notes and changelogs
                </Typography>
              </Card>
            )}

            {/* Error State */}
            {error && (
              <Alert severity="error" sx={{ mb: 3, backgroundColor: 'rgba(244, 67, 54, 0.15)' }}>
                <Typography variant="body2">
                  <strong>AI Analysis Failed:</strong> {error}
                </Typography>
                <Typography variant="body2" sx={{ mt: 1 }}>
                  Falling back to structural analysis insights only.
                </Typography>
              </Alert>
            )}

            {/* AI Insights Results */}
            {aiInsights && (
              <Box>
                {/* Security Intelligence */}
                {aiInsights.securityFindings && (
                  <Box sx={{ mb: 4 }}>
                    <Typography variant="h6" gutterBottom sx={{ color: '#f44336' }}>
                      🚨 Security Intelligence
                    </Typography>
                    <Grid container spacing={2}>
                      {aiInsights.securityFindings.map((finding: any, index: number) => (
                        <Grid item xs={12} md={6} key={index}>
                          <Card sx={{ 
                            backgroundColor: finding.severity === 'high' ? '#4a1a1a' : '#1a2332',
                            border: `1px solid ${finding.severity === 'high' ? '#f44336' : '#90caf9'}`,
                            p: 2 
                          }}>
                            <Typography variant="body2" sx={{ 
                              fontWeight: 'bold', 
                              color: finding.severity === 'high' ? '#f44336' : '#90caf9',
                              mb: 1 
                            }}>
                              {finding.title}
                            </Typography>
                            <Typography variant="body2" sx={{ mb: 1 }}>
                              {finding.description}
                            </Typography>
                            {finding.cveId && (
                              <Chip 
                                label={finding.cveId} 
                                size="small" 
                                sx={{ 
                                  backgroundColor: finding.severity === 'high' ? '#f44336' : '#90caf9',
                                  color: 'white'
                                }} 
                              />
                            )}
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                )}

                {/* Version Analysis */}
                {aiInsights.versionAnalysis && (
                  <Box sx={{ mb: 4 }}>
                    <Typography variant="h6" gutterBottom sx={{ color: '#ffb74d' }}>
                      📈 Version Intelligence
                    </Typography>
                    <Card sx={{ backgroundColor: '#2a2a2a', p: 3 }}>
                      <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                        {aiInsights.versionAnalysis.summary}
                      </Typography>
                      {aiInsights.versionAnalysis.releaseNotes && (
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="body2" sx={{ fontWeight: 'bold', mb: 1 }}>
                            Key Changes:
                          </Typography>
                          <Box component="ul" sx={{ pl: 2, m: 0 }}>
                            {aiInsights.versionAnalysis.releaseNotes.map((note: string, index: number) => (
                              <li key={index}>
                                <Typography variant="body2" sx={{ mb: 0.5 }}>
                                  {note}
                                </Typography>
                              </li>
                            ))}
                          </Box>
                        </Box>
                      )}
                    </Card>
                  </Box>
                )}

                {/* Research Links */}
                {aiInsights.researchLinks && aiInsights.researchLinks.length > 0 && (
                  <Box sx={{ mb: 4 }}>
                    <Typography variant="h6" gutterBottom sx={{ color: '#ba68c8' }}>
                      🔗 Research Resources
                    </Typography>
                    <Grid container spacing={2}>
                      {aiInsights.researchLinks.map((link: any, index: number) => (
                        <Grid item xs={12} md={6} key={index}>
                          <Card sx={{ backgroundColor: '#2d1a33', border: '1px solid #ba68c8', p: 2 }}>
                            <Typography variant="body2" sx={{ fontWeight: 'bold', color: '#ba68c8', mb: 1 }}>
                              {link.title}
                            </Typography>
                            <Typography variant="body2" sx={{ mb: 2, fontSize: '0.85rem' }}>
                              {link.description}
                            </Typography>
                            <Button
                              variant="outlined"
                              size="small"
                              href={link.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              sx={{ borderColor: '#ba68c8', color: '#ba68c8' }}
                            >
                              View Source
                            </Button>
                          </Card>
                        </Grid>
                      ))}
                    </Grid>
                  </Box>
                )}

                {/* AI Recommendations */}
                {aiInsights.recommendations && (
                  <Box>
                    <Typography variant="h6" gutterBottom sx={{ color: '#4caf50' }}>
                      💡 AI Recommendations
                    </Typography>
                    <Card sx={{ backgroundColor: '#0d4f1c', border: '1px solid #4caf50', p: 3 }}>
                      <Box component="ul" sx={{ pl: 2, m: 0 }}>
                        {aiInsights.recommendations.map((rec: string, index: number) => (
                          <li key={index}>
                            <Typography variant="body2" sx={{ mb: 1, lineHeight: 1.6 }}>
                              {rec}
                            </Typography>
                          </li>
                        ))}
                      </Box>
                    </Card>
                  </Box>
                )}
              </Box>
            )}

                         {/* Fallback: Rich structural insights when AI is not available */}
             {!aiInsights && !loading && !error && (
               <Box>
                 <Typography variant="h6" gutterBottom sx={{ color: '#ffb74d' }}>
                   📊 Structural Analysis Summary
                 </Typography>
                 <Card sx={{ backgroundColor: '#2a2a2a', p: 3, mb: 3 }}>
                   <Typography variant="body2" sx={{ lineHeight: 1.6, mb: 2 }}>
                     <strong>Binary Comparison:</strong> {binary1Name} ↔ {binary2Name}
                   </Typography>
                   
                   {parsedData.functionStats.total_funcs_len ? (
                     <Typography variant="body2" sx={{ lineHeight: 1.6, mb: 2 }}>
                       <strong>Function Analysis:</strong> {parsedData.functionStats.total_funcs_len} total functions analyzed with {parsedData.functionStats.match_percentage}% match rate.
                     </Typography>
                   ) : null}
                   
                   <Typography variant="body2" sx={{ lineHeight: 1.6, mb: 2 }}>
                     <strong>Changes Detected:</strong>
                   </Typography>
                   <Box component="ul" sx={{ pl: 2, m: 0 }}>
                     <li>
                       <Typography variant="body2" sx={{ color: '#81c784' }}>
                         ➕ <strong>{parsedData.addedFunctions.length} functions added</strong>
                         {parsedData.addedFunctions.length > 0 && parsedData.addedFunctions.slice(0, 3).map((func: any, i: number) => 
                           <span key={i} style={{ fontSize: '0.8rem', opacity: 0.8 }}> {func.name}</span>
                         )}
                         {parsedData.addedFunctions.length > 3 && <span style={{ fontSize: '0.8rem', opacity: 0.8 }}> and {parsedData.addedFunctions.length - 3} more...</span>}
                       </Typography>
                     </li>
                     <li>
                       <Typography variant="body2" sx={{ color: '#e57373' }}>
                         ➖ <strong>{parsedData.deletedFunctions.length} functions removed</strong>
                         {parsedData.deletedFunctions.length > 0 && parsedData.deletedFunctions.slice(0, 3).map((func: any, i: number) => 
                           <span key={i} style={{ fontSize: '0.8rem', opacity: 0.8 }}> {func.name}</span>
                         )}
                         {parsedData.deletedFunctions.length > 3 && <span style={{ fontSize: '0.8rem', opacity: 0.8 }}> and {parsedData.deletedFunctions.length - 3} more...</span>}
                       </Typography>
                     </li>
                     <li>
                       <Typography variant="body2" sx={{ color: '#ffb74d' }}>
                         🔄 <strong>{parsedData.modifiedFunctions.length} functions modified</strong>
                         {parsedData.modifiedFunctions.length > 0 && parsedData.modifiedFunctions.slice(0, 3).map((func: any, i: number) => 
                           <span key={i} style={{ fontSize: '0.8rem', opacity: 0.8 }}> {func.name}</span>
                         )}
                         {parsedData.modifiedFunctions.length > 3 && <span style={{ fontSize: '0.8rem', opacity: 0.8 }}> and {parsedData.modifiedFunctions.length - 3} more...</span>}
                       </Typography>
                     </li>
                   </Box>
                   
                   {Object.keys(parsedData.binaryMetadata).length > 0 && parsedData.binaryMetadata.size_change && (
                     <Typography variant="body2" sx={{ lineHeight: 1.6, mt: 2 }}>
                       <strong>Binary Size:</strong> {parsedData.binaryMetadata.size_change > 0 ? 'Increased' : 'Decreased'} by {Math.abs(Math.round(parsedData.binaryMetadata.size_change / 1024))} KB ({parsedData.binaryMetadata.size_change_percent}%)
                     </Typography>
                   )}
                 </Card>
                 
                 <Card sx={{ backgroundColor: '#0d4f1c', border: '1px solid #4caf50', p: 3 }}>
                   <Typography variant="h6" gutterBottom sx={{ color: '#4caf50' }}>
                     💡 Quick Recommendations
                   </Typography>
                   <Box component="ul" sx={{ pl: 2, m: 0 }}>
                     <li>
                       <Typography variant="body2" sx={{ mb: 1 }}>
                         <strong>Testing:</strong> Focus on {parsedData.addedFunctions.length + parsedData.modifiedFunctions.length} changed functions during QA
                       </Typography>
                     </li>
                     <li>
                       <Typography variant="body2" sx={{ mb: 1 }}>
                         <strong>Security:</strong> Review modified functions for potential security implications
                       </Typography>
                     </li>
                     {parsedData.addedFunctions.length > 10 && (
                       <li>
                         <Typography variant="body2" sx={{ mb: 1 }}>
                           <strong>Integration:</strong> High number of new functions ({parsedData.addedFunctions.length}) suggests major feature additions - plan extended testing
                         </Typography>
                       </li>
                     )}
                   </Box>
                 </Card>
               </Box>
             )}
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );
};

// Enhanced ghidriff results viewer with structured data extraction and visualization
const EnhancedGhidriffViewer: React.FC<{ markdown: string; jsonData: any; summary: any }> = ({ markdown, jsonData, summary }) => {
  const [selectedTab, setSelectedTab] = useState(0);
  const [mermaidDiagrams, setMermaidDiagrams] = useState<{ [key: string]: string }>({});

  // Initialize mermaid
  useEffect(() => {
    mermaid.initialize({
      theme: 'dark',
      themeVariables: {
        primaryColor: '#90caf9',
        primaryTextColor: '#ffffff',
        primaryBorderColor: '#90caf9',
        lineColor: '#ffffff',
        sectionBkgColor: '#1e1e1e',
        altSectionBkgColor: '#2a2a2a',
        gridColor: '#ffffff',
        tertiaryColor: '#2a2a2a'
      }
    });
  }, []);

  // Parse ghidriff markdown to extract structured data - FIXED VERSION
  const parsedData = useMemo(() => {
    if (!markdown || typeof markdown !== 'string') {
      return {
        metadata: {},
        functionStats: {},
        performanceStats: [],
        addedFunctions: [],
        deletedFunctions: [],
        modifiedFunctions: [],
        mermaidCharts: [],
        binaryMetadata: {},
        strings: { added: [], deleted: [] },
        hasData: false,
        binaryNames: { binary1: 'Unknown Binary 1', binary2: 'Unknown Binary 2' }
      };
    }
    
    const lines = markdown.split('\n');
    const data: any = {
      metadata: {},
      functionStats: {},
      performanceStats: [],
      addedFunctions: [],
      deletedFunctions: [],
      modifiedFunctions: [],
      mermaidCharts: [],
      binaryMetadata: {},
      strings: { added: [], deleted: [] },
      hasData: true,
      binaryNames: { binary1: 'Unknown Binary 1', binary2: 'Unknown Binary 2' }
    };

    let currentSection = '';
    let inCodeBlock = false;
    let codeBlockLanguage = '';
    let codeBlockContent = '';
    let inBinaryMetadataDiff = false;

    // Extract binary names from the title (first line)
    if (lines.length > 0) {
      const titleLine = lines[0];
      if (titleLine.startsWith('# ') && titleLine.includes('Diff')) {
        const titleMatch = titleLine.match(/# (.+)-(\w+)\.exe-(.+)-(\w+)\.exe Diff/);
        if (titleMatch) {
          // Extract clean binary names
          const binary1Base = titleMatch[2]; // e.g., "plink-078"
          const binary2Base = titleMatch[4]; // e.g., "plink-079"
          data.binaryNames.binary1 = `${binary1Base}.exe`;
          data.binaryNames.binary2 = `${binary2Base}.exe`;
        }
      }
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();

      // Handle code blocks
      if (line.startsWith('```')) {
        if (!inCodeBlock) {
          inCodeBlock = true;
          codeBlockLanguage = line.substring(3);
          codeBlockContent = '';
        } else {
          inCodeBlock = false;
          if (codeBlockLanguage === 'mermaid') {
            // Extract function statistics from mermaid pie charts
            if (codeBlockContent.includes('Function Matches')) {
              const unmatchedMatch = codeBlockContent.match(/"unmatched_funcs_len"\s*:\s*(\d+)/);
              const matchedMatch = codeBlockContent.match(/"matched_funcs_len"\s*:\s*(\d+)/);
              
              if (unmatchedMatch && matchedMatch) {
                data.functionStats.unmatched_funcs_len = parseInt(unmatchedMatch[1]);
                data.functionStats.matched_funcs_len = parseInt(matchedMatch[1]);
                data.functionStats.total_funcs_len = data.functionStats.matched_funcs_len + data.functionStats.unmatched_funcs_len;
                data.functionStats.match_percentage = ((data.functionStats.matched_funcs_len / data.functionStats.total_funcs_len) * 100).toFixed(2);
              }
            }
            
            if (codeBlockContent.includes('Function Similarity')) {
              const codeChangesMatch = codeBlockContent.match(/"matched_funcs_with_code_changes_len"\s*:\s*(\d+)/);
              const nonCodeChangesMatch = codeBlockContent.match(/"matched_funcs_with_non_code_changes_len"\s*:\s*(\d+)/);
              const noChangesMatch = codeBlockContent.match(/"matched_funcs_no_changes_len"\s*:\s*(\d+)/);
              
              if (codeChangesMatch) data.functionStats.matched_funcs_with_code_changes_len = parseInt(codeChangesMatch[1]);
              if (nonCodeChangesMatch) data.functionStats.matched_funcs_with_non_code_changes_len = parseInt(nonCodeChangesMatch[1]);
              if (noChangesMatch) data.functionStats.matched_funcs_no_changes_len = parseInt(noChangesMatch[1]);
              
              if (data.functionStats.matched_funcs_no_changes_len && data.functionStats.matched_funcs_len) {
                data.functionStats.similarity_percentage = ((data.functionStats.matched_funcs_no_changes_len / data.functionStats.matched_funcs_len) * 100).toFixed(2);
              }
            }
            
            data.mermaidCharts.push({
              id: `chart-${data.mermaidCharts.length}`,
              content: codeBlockContent,
              type: codeBlockContent.includes('pie') ? 'pie' : 'flowchart'
            });
          }
          codeBlockLanguage = '';
        }
        continue;
      }

      if (inCodeBlock) {
        codeBlockContent += line + '\n';
        continue;
      }

      // Track sections
      if (line.startsWith('# ')) {
        currentSection = line.substring(2).trim();
        if (currentSection === 'Binary Metadata Diff') {
          inBinaryMetadataDiff = true;
        } else {
          inBinaryMetadataDiff = false;
        }
      }

      // Extract binary metadata changes
      if (inBinaryMetadataDiff && line.startsWith('+') && line.includes('# of')) {
        const match = line.match(/\+# of ([^:]+):\s*(\d+)/);
        if (match) {
          const key = match[1].toLowerCase().replace(/\s+/g, '_');
          data.binaryMetadata[`new_${key}`] = parseInt(match[2]);
        }
      }
      
      if (inBinaryMetadataDiff && line.startsWith('-') && line.includes('# of')) {
        const match = line.match(/\-# of ([^:]+):\s*(\d+)/);
        if (match) {
          const key = match[1].toLowerCase().replace(/\s+/g, '_');
          data.binaryMetadata[`old_${key}`] = parseInt(match[2]);
        }
      }

      // Extract file size changes
      if (inBinaryMetadataDiff && line.startsWith('+') && line.includes('# of Bytes:')) {
        const match = line.match(/\+# of Bytes:\s*(\d+)/);
        if (match) data.binaryMetadata.new_bytes = parseInt(match[1]);
      }
      
      if (inBinaryMetadataDiff && line.startsWith('-') && line.includes('# of Bytes:')) {
        const match = line.match(/\-# of Bytes:\s*(\d+)/);
        if (match) data.binaryMetadata.old_bytes = parseInt(match[1]);
      }

      // Extract function lists from sections (NOT from TOC, but from actual sections)
      if (currentSection === 'Deleted') {
        // Look for function patterns like "## FUN_140004910" or direct function names
        if (line.startsWith('## ') || (line.match(/^FUN_[0-9a-fA-F]+$/) && line.length > 5)) {
          const functionName = line.replace(/^## /, '').trim();
          if (functionName.startsWith('FUN_')) {
            data.deletedFunctions.push({ name: functionName, details: [] });
          }
        }
        // Also check TOC format
        if (line.startsWith('\t* [') || line.includes('[FUN_')) {
          const functionName = line.match(/\[([^\]]+)\]/)?.[1] || line.match(/(FUN_[0-9a-fA-F]+)/)?.[1];
          if (functionName && functionName.startsWith('FUN_')) {
            data.deletedFunctions.push({ name: functionName, details: [] });
          }
        }
      }

      if (currentSection === 'Added') {
        if (line.startsWith('## ') || (line.match(/^FUN_[0-9a-fA-F]+$/) && line.length > 5)) {
          const functionName = line.replace(/^## /, '').trim();
          if (functionName.startsWith('FUN_')) {
            data.addedFunctions.push({ name: functionName, details: [] });
          }
        }
        if (line.startsWith('\t* [') || line.includes('[FUN_')) {
          const functionName = line.match(/\[([^\]]+)\]/)?.[1] || line.match(/(FUN_[0-9a-fA-F]+)/)?.[1];
          if (functionName && functionName.startsWith('FUN_')) {
            data.addedFunctions.push({ name: functionName, details: [] });
          }
        }
      }

      if (currentSection === 'Modified') {
        if (line.startsWith('## ') || (line.match(/^FUN_[0-9a-fA-F]+$/) && line.length > 5)) {
          const functionName = line.replace(/^## /, '').trim();
          if (functionName.startsWith('FUN_')) {
            data.modifiedFunctions.push({ name: functionName, details: [] });
          }
        }
        if (line.startsWith('\t* [') || line.includes('[FUN_')) {
          const functionName = line.match(/\[([^\]]+)\]/)?.[1] || line.match(/(FUN_[0-9a-fA-F]+)/)?.[1];
          if (functionName && functionName.startsWith('FUN_')) {
            data.modifiedFunctions.push({ name: functionName, details: [] });
          }
        }
      }
    }

    // Calculate additional metrics
    if (data.binaryMetadata.new_bytes && data.binaryMetadata.old_bytes) {
      data.binaryMetadata.size_change = data.binaryMetadata.new_bytes - data.binaryMetadata.old_bytes;
      data.binaryMetadata.size_change_percent = ((data.binaryMetadata.size_change / data.binaryMetadata.old_bytes) * 100).toFixed(2);
    }

    // If function stats are empty but we have function lists, calculate from lists
    if (!data.functionStats.total_funcs_len && (data.addedFunctions.length > 0 || data.deletedFunctions.length > 0 || data.modifiedFunctions.length > 0)) {
      data.functionStats.added_funcs_len = data.addedFunctions.length;
      data.functionStats.deleted_funcs_len = data.deletedFunctions.length;
      data.functionStats.modified_funcs_len = data.modifiedFunctions.length;
      data.functionStats.total_changes = data.addedFunctions.length + data.deletedFunctions.length + data.modifiedFunctions.length;
    }

    console.log('📊 Parsed ghidriff data (FIXED):', data); // Debug log
    return data;
  }, [markdown]); // Dependency array for useMemo

  // Chart colors
  const CHART_COLORS = ['#90caf9', '#f48fb1', '#ffb74d', '#81c784', '#e57373', '#ba68c8'];

  // Render mermaid diagrams
  useEffect(() => {
    const renderDiagrams = async () => {
      const diagrams: { [key: string]: string } = {};
      
      for (const chart of parsedData.mermaidCharts) {
        try {
          const { svg } = await mermaid.render(`mermaid-${chart.id}`, chart.content);
          diagrams[chart.id] = svg;
        } catch (error) {
          console.error('Error rendering mermaid diagram:', error);
        }
      }
      
      setMermaidDiagrams(diagrams);
    };

    if (parsedData.mermaidCharts.length > 0) {
      renderDiagrams();
    }
  }, [parsedData.mermaidCharts]); // Dependency array for useEffect

  // Prepare chart data (using useMemo for optimization)
  const functionMatchData = useMemo(() => [
    { name: 'Matched Functions', value: parsedData.functionStats.matched_funcs_len || 0, color: '#81c784' },
    { name: 'Unmatched Functions', value: parsedData.functionStats.unmatched_funcs_len || 0, color: '#e57373' }
  ], [parsedData.functionStats]);

  const functionSimilarityData = useMemo(() => [
    { name: 'No Changes', value: parsedData.functionStats.matched_funcs_no_changes_len || 0, color: '#81c784' },
    { name: 'Code Changes', value: parsedData.functionStats.matched_funcs_with_code_changes_len || 0, color: '#ffb74d' },
    { name: 'Non-Code Changes', value: parsedData.functionStats.matched_funcs_with_non_code_changes_len || 0, color: '#90caf9' }
  ], [parsedData.functionStats]);

  const performanceData = useMemo(() =>
    parsedData.performanceStats
      .sort((a: any, b: any) => b.time - a.time)
      .slice(0, 10),
    [parsedData.performanceStats]
  );

  // Don't render until data is parsed
  if (!parsedData.hasData) {
    return <CircularProgress />;
  }

  // Determine which tabs to show based on available data
  const availableTabs = [
    // Only show Overview if we have meaningful function stats OR function lists
    { label: '📊 Overview', id: 'overview', hasData: 
        parsedData.functionStats.total_funcs_len > 0 || 
        parsedData.functionStats.total_changes > 0 ||
        (parsedData.addedFunctions.length + parsedData.deletedFunctions.length + parsedData.modifiedFunctions.length) > 0 
    },
    { label: '🔍 Function Analysis', id: 'functions', hasData: parsedData.addedFunctions.length > 0 || parsedData.deletedFunctions.length > 0 || parsedData.modifiedFunctions.length > 0 },
    { label: '📋 Details', id: 'details', hasData: Object.keys(parsedData.binaryMetadata).length > 0 },
    { label: '🤖 AI Insights', id: 'ai', hasData: parsedData.hasData },
    { label: '📝 Raw Report', id: 'raw', hasData: true }
  ];

  const visibleTabs = availableTabs.filter(tab => tab.hasData);

  return (
    <Box>
      <Box sx={{ borderBottom: 1, borderColor: 'rgba(255, 255, 255, 0.12)', mb: 3 }}>
        <Tabs
          value={selectedTab}
          onChange={(_, v) => setSelectedTab(v)}
          sx={{
            '& .MuiTab-root': { color: 'rgba(255, 255, 255, 0.7)' },
            '& .Mui-selected': { color: '#90caf9' },
            '& .MuiTabs-indicator': { backgroundColor: '#90caf9' }
          }}
        >
          {visibleTabs.map((tab, index) => (
            <Tab key={tab.id} label={tab.label} />
          ))}
        </Tabs>
      </Box>

      {/* Overview Tab */}
      {selectedTab === 0 && (
        <Grid container spacing={3}>
          {/* Key Statistics */}
          <Grid item xs={12}>
            <Card sx={{ backgroundColor: '#1e1e1e', color: 'white', mb: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#90caf9', mb: 3 }}>
                  📈 Analysis Summary
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: '#90caf9', fontWeight: 'bold' }}>
                        {parsedData.functionStats.total_funcs_len || 
                         (parsedData.functionStats.matched_funcs_len + parsedData.functionStats.unmatched_funcs_len) ||
                         'N/A'}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">Total Functions</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: '#81c784', fontWeight: 'bold' }}>
                        {parsedData.functionStats.matched_funcs_len || 'N/A'}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">Matched</Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: '#ffb74d', fontWeight: 'bold' }}>
                        {(parsedData.addedFunctions.length + parsedData.deletedFunctions.length + parsedData.modifiedFunctions.length) || 'N/A'}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {parsedData.addedFunctions.length > 0 || parsedData.deletedFunctions.length > 0 || parsedData.modifiedFunctions.length > 0 
                          ? `${parsedData.addedFunctions.length}➕ ${parsedData.deletedFunctions.length}➖ ${parsedData.modifiedFunctions.length}🔄` 
                          : 'Changes'}
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: '#f48fb1', fontWeight: 'bold' }}>
                        {parsedData.functionStats.match_percentage || 
                         (parsedData.functionStats.total_funcs_len && parsedData.functionStats.matched_funcs_len 
                          ? ((parsedData.functionStats.matched_funcs_len / parsedData.functionStats.total_funcs_len) * 100).toFixed(1) 
                          : 'N/A')}%
                      </Typography>
                      <Typography variant="body2" color="text.secondary">Match Rate</Typography>
                    </Box>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Charts */}
          {functionMatchData.some(d => d.value > 0) && (
            <Grid item xs={12} md={6}>
              <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
                <CardContent>
                  <Typography variant="h6" gutterBottom sx={{ color: '#90caf9' }}>
                    Function Matches
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={functionMatchData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {functionMatchData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#2a2a2a',
                          border: '1px solid #90caf9',
                          borderRadius: '4px',
                          color: 'white'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>
          )}

          {functionSimilarityData.some(d => d.value > 0) && (
            <Grid item xs={12} md={6}>
              <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
                <CardContent>
                  <Typography variant="h6" gutterBottom sx={{ color: '#90caf9' }}>
                    Function Similarity
                  </Typography>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={functionSimilarityData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {functionSimilarityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#2a2a2a',
                          border: '1px solid #90caf9',
                          borderRadius: '4px',
                          color: 'white'
                        }}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            </Grid>
          )}

          {/* Mermaid Diagrams */}
          {Object.entries(mermaidDiagrams).map(([id, svg]) => (
            <Grid item xs={12} key={id}>
              <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
                <CardContent>
                  <Typography variant="h6" gutterBottom sx={{ color: '#90caf9' }}>
                    📊 Analysis Flow Diagram
                  </Typography>
                  <Box
                    sx={{
                      textAlign: 'center',
                      '& svg': { maxWidth: '100%', height: 'auto' }
                    }}
                    dangerouslySetInnerHTML={{ __html: svg }}
                  />
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Function Analysis Tab */}
      {visibleTabs[selectedTab]?.id === 'functions' && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#81c784' }}>
                  ➕ Added Functions ({parsedData.addedFunctions.length})
                </Typography>
                <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {parsedData.addedFunctions.slice(0, 20).map((func: any, index: number) => (
                    <Typography key={index} variant="body2" sx={{ py: 0.5, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                      {func.name}
                    </Typography>
                  ))}
                  {parsedData.addedFunctions.length > 20 && (
                    <Typography variant="body2" sx={{ fontStyle: 'italic', color: 'text.secondary', mt: 1 }}>
                      ... and {parsedData.addedFunctions.length - 20} more
                    </Typography>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#e57373' }}>
                  ➖ Deleted Functions ({parsedData.deletedFunctions.length})
                </Typography>
                <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {parsedData.deletedFunctions.slice(0, 20).map((func: any, index: number) => (
                    <Typography key={index} variant="body2" sx={{ py: 0.5, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                      {func.name}
                    </Typography>
                  ))}
                  {parsedData.deletedFunctions.length > 20 && (
                    <Typography variant="body2" sx={{ fontStyle: 'italic', color: 'text.secondary', mt: 1 }}>
                      ... and {parsedData.deletedFunctions.length - 20} more
                    </Typography>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={4}>
            <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#ffb74d' }}>
                  🔄 Modified Functions ({parsedData.modifiedFunctions.length})
                </Typography>
                <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {parsedData.modifiedFunctions.slice(0, 20).map((func: any, index: number) => (
                    <Typography key={index} variant="body2" sx={{ py: 0.5, fontFamily: 'monospace', fontSize: '0.9rem' }}>
                      {func.name}
                    </Typography>
                  ))}
                  {parsedData.modifiedFunctions.length > 20 && (
                    <Typography variant="body2" sx={{ fontStyle: 'italic', color: 'text.secondary', mt: 1 }}>
                      ... and {parsedData.modifiedFunctions.length - 20} more
                    </Typography>
                  )}
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Details Tab */}
      {visibleTabs[selectedTab]?.id === 'details' && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ color: '#90caf9' }}>
                  📋 Binary Metadata Changes
                </Typography>
                
                {parsedData.binaryMetadata.old_bytes && parsedData.binaryMetadata.new_bytes && (
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="h6" gutterBottom>File Size</Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                      <Typography>
                        {Math.round(parsedData.binaryMetadata.old_bytes / 1024)} KB → {Math.round(parsedData.binaryMetadata.new_bytes / 1024)} KB
                      </Typography>
                      <Chip
                        label={`${parsedData.binaryMetadata.size_change > 0 ? '+' : ''}${Math.round(parsedData.binaryMetadata.size_change / 1024)} KB (${parsedData.binaryMetadata.size_change_percent}%)`}
                        color={parsedData.binaryMetadata.size_change > 0 ? 'warning' : 'success'}
                        size="small"
                      />
                    </Box>
                  </Box>
                )}

                <TableContainer component={Paper} sx={{ backgroundColor: '#2a2a2a' }}>
                  <Table>
                    <TableHead>
                      <TableRow>
                        <TableCell sx={{ color: 'white' }}>Metric</TableCell>
                        <TableCell sx={{ color: 'white' }}>Old</TableCell>
                        <TableCell sx={{ color: 'white' }}>New</TableCell>
                        <TableCell sx={{ color: 'white' }}>Change</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {Object.keys(parsedData.binaryMetadata)
                        .filter(key => key.startsWith('old_'))
                        .map(key => {
                          const metric = key.replace('old_', '');
                          const oldValue = parsedData.binaryMetadata[key];
                          const newValue = parsedData.binaryMetadata[`new_${metric}`];
                          const change = newValue - oldValue;
                          
                          return (
                            <TableRow key={metric}>
                              <TableCell sx={{ color: 'white', textTransform: 'capitalize' }}>
                                {metric.replace(/_/g, ' ')}
                              </TableCell>
                              <TableCell sx={{ color: 'white' }}>{oldValue?.toLocaleString()}</TableCell>
                              <TableCell sx={{ color: 'white' }}>{newValue?.toLocaleString()}</TableCell>
                              <TableCell sx={{ color: change > 0 ? '#ffb74d' : change < 0 ? '#81c784' : 'white' }}>
                                {change > 0 ? '+' : ''}{change?.toLocaleString()}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

            {/* AI Insights Tab */}
      {visibleTabs[selectedTab]?.id === 'ai' && (
        <IntelligentAIInsights 
          summary={summary} 
          parsedData={parsedData} 
          jsonData={jsonData}
        />
      )}

      {/* Raw Report Tab */}
      {visibleTabs[selectedTab]?.id === 'raw' && (
        <Box>
          {markdown ? (
            <GhidriffMarkdownView markdown={markdown} />
          ) : (
            <Card sx={{ backgroundColor: '#1e1e1e', color: 'white', p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ color: '#f48fb1' }}>
                📄 No Markdown Report Available
              </Typography>
              <Typography variant="body2" color="text.secondary">
                The analysis may have failed or no markdown report was generated. 
                Check the other tabs for available information or logs.
              </Typography>
            </Card>
          )}
        </Box>
      )}
    </Box>
  );
};

// Component to display ghidriff analysis logs
const GhidriffLogsView: React.FC<{ logs: string }> = ({ logs }) => {
  if (!logs) {
    return (
      <Alert severity="info" sx={{ backgroundColor: 'rgba(33, 150, 243, 0.15)', color: '#90caf9' }}>
        No analysis logs available
      </Alert>
    );
  }

  return (
    <Card sx={{ backgroundColor: '#1e1e1e', color: 'white' }}>
      <CardContent>
        <Typography variant="h6" gutterBottom sx={{ color: '#90caf9', mb: 2 }}>
          📋 Ghidra Analysis Logs
        </Typography>
        <EnhancedLogsViewer logs={logs} />
        <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
          <Button
            variant="outlined"
            size="small"
            startIcon={<Download />}
            onClick={() => {
              const blob = new Blob([logs], { type: 'text/plain' });
              const url = URL.createObjectURL(blob);
              const link = document.createElement('a');
              link.href = url;
              link.download = 'ghidriff_analysis.log';
              link.click();
              URL.revokeObjectURL(url);
            }}
            sx={{ color: 'white', borderColor: 'rgba(255, 255, 255, 0.5)' }}
          >
            Download Logs
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
};

const BinaryComparison: React.FC = () => {
  const [binaries, setBinaries] = useState<Binary[]>([]);
  const [selectedBinary1, setSelectedBinary1] = useState<string>('');
  const [selectedBinary2, setSelectedBinary2] = useState<string>('');
  const [diffType, setDiffType] = useState<string>('simple');
  const [performanceMode, setPerformanceMode] = useState<string>('balanced');
  const [loading, setLoading] = useState(false);
  const [comparisonResult, setComparisonResult] = useState<ComparisonResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const [taskId, setTaskId] = useState<string | null>(null);
  
  // File upload states
  const [file1, setFile1] = useState<File | null>(null);
  const [file2, setFile2] = useState<File | null>(null);
  const [uploadProgress1, setUploadProgress1] = useState(0);
  const [uploadProgress2, setUploadProgress2] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [uploadedBinary1, setUploadedBinary1] = useState<Binary | null>(null);
  const [uploadedBinary2, setUploadedBinary2] = useState<Binary | null>(null);

  // New state for past results
  const [pastResults, setPastResults] = useState<any[]>([]);
  const [loadingPastResults, setLoadingPastResults] = useState(false);
  const [selectedPastResult, setSelectedPastResult] = useState<any | null>(null);

  useEffect(() => {
    fetchBinaries();
    
    // Check for active tasks on mount
    const activeTasks = taskManager.getActiveTasks();
    if (activeTasks.length > 0) {
      console.log(`Found ${activeTasks.length} active comparison tasks`);
    }

    // Cleanup function
    return () => {
      // Stop monitoring current task when component unmounts
      if (taskId) {
        taskManager.stopMonitoring(taskId);
      }
    };
  }, [taskId]);

  // Fetch past results when Past Results tab is selected or when a comparison completes
  const fetchPastResults = useCallback(async () => {
    if (loadingPastResults) return;
    
    setLoadingPastResults(true);
    try {
      const results = await apiClient.getPastBinaryDiffResults();
      console.log('BinaryComparison - Fetched past results:', results);
      setPastResults(results);
    } catch (err) {
      console.error('Failed to fetch past results:', err);
      toast.error('Failed to fetch past results');
    } finally {
      setLoadingPastResults(false);
    }
  }, [loadingPastResults]);

  useEffect(() => {
    if (tabValue === 2 && pastResults.length === 0) {
      fetchPastResults();
    }
  }, [tabValue, fetchPastResults]);

  // Refresh past results when a comparison completes
  useEffect(() => {
    if (comparisonResult) {
      fetchPastResults();
    }
  }, [comparisonResult, fetchPastResults]);

  // Listen for binary comparison completion events and auto-refresh past results
  useEffect(() => {
    const handleComparisonCompleted = (event: CustomEvent) => {
      console.log('Binary comparison completed event received:', event.detail);
      toast.success('Binary comparison completed! Results available in Past Results.');
      
      // Auto-refresh past results
      fetchPastResults();
      
      // If we're not on the Past Results tab, show a notification to check it
      if (tabValue !== 2) {
        toast.info('Check the "Past Results" tab to view your comparison results.');
      }
    };

    window.addEventListener('binary_comparison_completed', handleComparisonCompleted as EventListener);
    
    return () => {
      window.removeEventListener('binary_comparison_completed', handleComparisonCompleted as EventListener);
    };
  }, [fetchPastResults, tabValue]);

  const fetchBinaries = async () => {
    try {
      const response = await apiClient.getBinaries(1, 50); // Get more binaries for comparison
      setBinaries(response.binaries);
    } catch (err) {
      toast.error('Failed to fetch binaries');
      console.error('Error fetching binaries:', err);
    }
  };
  
  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };
  
  const handleFileChange1 = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setFile1(event.target.files[0]);
    }
  };
  
  const handleFileChange2 = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setFile2(event.target.files[0]);
    }
  };
  
  const uploadBinary = async (file: File, setProgress: (progress: number) => void) => {
    try {
      const response = await apiClient.uploadBinary(file, (progress) => {
        setProgress(progress * 100);
      });
      
      return response.binary;
    } catch (err) {
      console.error('Error uploading binary:', err);
      throw err;
    }
  };
  
  const handleUploadAndCompare = async () => {
    if (!file1 || !file2) {
      toast.error('Please select two binary files to compare');
      return;
    }
    
    try {
      setUploading(true);
      setError(null);
      
      // Upload both files
      const [binary1, binary2] = await Promise.all([
        uploadBinary(file1, setUploadProgress1),
        uploadBinary(file2, setUploadProgress2)
      ]);
      
      setUploadedBinary1(binary1);
      setUploadedBinary2(binary2);
      
      // Start comparison
      await startComparison(binary1.id, binary2.id);
      
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to upload and compare binaries');
      toast.error('Failed to upload and compare binaries');
    } finally {
      setUploading(false);
    }
  };

  const startComparison = async (binary1Id: string, binary2Id: string) => {
    if (!binary1Id || !binary2Id) {
      toast.error('Please select two binaries to compare');
      return;
    }

    if (binary1Id === binary2Id) {
      toast.error('Please select two different binaries');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setComparisonResult(null);
      
      // Get binary names for display
      const binary1 = binaries.find(b => b.id === binary1Id) || uploadedBinary1;
      const binary2 = binaries.find(b => b.id === binary2Id) || uploadedBinary2;
      
      // Start comparison task
      const response = await apiClient.compareBinaries(binary1Id, binary2Id, diffType, performanceMode);
      const taskId = response.task_id;
      setTaskId(taskId);
      
      console.log('Comparison task started:', response);
      
      // Add task to persistent manager
      const taskInfo = {
        taskId,
        type: 'binary_comparison' as const,
        status: response.status === 'completed' ? 'completed' as const : 'running' as const,
        progress: response.status === 'completed' ? 100 : 0,
        binary1Id,
        binary2Id,
        binary1Name: binary1?.original_filename,
        binary2Name: binary2?.original_filename,
        diffType
      };
      
      console.log('Adding task to manager:', taskInfo);
      taskManager.addTask(taskInfo);
      
      // Debug task manager state
      setTimeout(() => {
        debugTaskManager();
      }, 100);

      // Add notification for task start
      notificationManager.addNotification({
        type: 'info',
        title: 'Binary Comparison Started',
        message: `Comparing ${binary1?.original_filename || 'Binary 1'} vs ${binary2?.original_filename || 'Binary 2'} using ${diffType} engine`,
        persistent: true,
        taskId
      });

      // Set up monitoring for this specific task
      taskManager.monitorTask(taskId, (progress) => {
        console.log('Task progress update:', progress);
        
        if (progress.status === 'completed' && progress.results) {
          // Parse results if they're a string
          let results = progress.results;
          if (typeof results === 'string') {
            try {
              results = JSON.parse(results);
            } catch (e) {
              console.error('Error parsing results:', e);
            }
          }
          
          setComparisonResult({
            task_id: taskId,
            binary_id1: binary1Id,
            binary_id2: binary2Id,
            diff_type: diffType,
            status: 'completed',
            results
          });
          
            setLoading(false);
          
          // Add success notification
          notificationManager.addNotification({
            type: 'success',
            title: 'Binary Comparison Completed',
            message: `Successfully compared ${binary1?.original_filename || 'Binary 1'} vs ${binary2?.original_filename || 'Binary 2'}`,
            persistent: true,
            taskId
          });
          
              toast.success('Binary comparison completed');
        } else if (progress.status === 'failed') {
          setError(`Comparison failed: ${progress.error || 'Unknown error'}`);
          setLoading(false);
          
          // Add error notification
          notificationManager.addNotification({
            type: 'error',
            title: 'Binary Comparison Failed',
            message: `Failed to compare ${binary1?.original_filename || 'Binary 1'} vs ${binary2?.original_filename || 'Binary 2'}: ${progress.error || 'Unknown error'}`,
            persistent: true,
            taskId
          });
          
              toast.error('Binary comparison failed');
            }
      });
      
      // Check if the task is already completed (immediate completion mode)
      if (response.status === 'completed') {
        console.log('Task completed immediately, fetching results');
        try {
          const result = await apiClient.getBinaryComparisonResults(taskId);
          
          let results = result.diff_result;
          if (typeof results === 'string') {
            try {
              results = JSON.parse(results);
            } catch (e) {
              console.error('Error parsing immediate results:', e);
            }
          }
          
          setComparisonResult({
            task_id: taskId,
            binary_id1: binary1Id,
            binary_id2: binary2Id,
            diff_type: diffType,
            status: 'completed',
            results
          });
          
          setLoading(false);
          toast.success('Binary comparison completed');
          return;
        } catch (err) {
          console.error('Error fetching immediate results:', err);
          setError('Error fetching comparison results');
          toast.error('Error fetching comparison results');
          setLoading(false);
          return;
        }
      }
      
      // Task will be monitored by the persistent task manager
      toast.info('Binary comparison started. You can navigate away - progress will be tracked.');
      
    } catch (err: any) {
      console.error('Error starting comparison:', err);
      setError(err.response?.data?.error || 'Failed to compare binaries');
      toast.error('Failed to compare binaries');
      setLoading(false);
    }
  };

  const handleCompare = () => {
    startComparison(selectedBinary1, selectedBinary2);
  };

  const renderComparisonSummary = () => {
    if (!comparisonResult?.results) return null;

    const { results } = comparisonResult;
    const binary1 = binaries.find(b => b.id === comparisonResult.binary_id1) || uploadedBinary1;
    const binary2 = binaries.find(b => b.id === comparisonResult.binary_id2) || uploadedBinary2;

    // Constants for Binary 1 and Binary 2 colors
    const binary1Color = '#1976d2'; // Blue
    const binary2Color = '#2e7d32'; // Green

    return (
      <Card sx={{ mb: 3, boxShadow: 3, backgroundColor: '#1e1e1e', borderRadius: 2 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold', borderBottom: '1px solid #333', pb: 1, color: '#fff' }}>
            Comparison Summary
          </Typography>
          
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper 
                elevation={2} 
                sx={{ 
                  p: 2, 
                  backgroundColor: binary1Color, 
                  color: 'white',
                  borderLeft: '4px solid #0d47a1',
                  borderRadius: 1
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 1 }}>
                  Binary 1: {binary1?.original_filename}
                </Typography>
                <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', mb: 0.5, opacity: 0.9 }}>
                  <Box component="span" sx={{ fontWeight: 'bold', mr: 1 }}>Size:</Box> 
                  {formatFileSize(binary1?.file_size || 0)}
                </Typography>
                <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', opacity: 0.9 }}>
                  <Box component="span" sx={{ fontWeight: 'bold', mr: 1 }}>Upload Time:</Box>
                  {binary1?.upload_time ? new Date(binary1.upload_time).toLocaleString() : 'N/A'}
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper 
                elevation={2} 
                sx={{ 
                  p: 2, 
                  backgroundColor: binary2Color, 
                  color: 'white',
                  borderLeft: '4px solid #1b5e20',
                  borderRadius: 1
                }}
              >
                <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 1 }}>
                  Binary 2: {binary2?.original_filename}
                </Typography>
                <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', mb: 0.5, opacity: 0.9 }}>
                  <Box component="span" sx={{ fontWeight: 'bold', mr: 1 }}>Size:</Box> 
                  {formatFileSize(binary2?.file_size || 0)}
                </Typography>
                <Typography variant="body2" sx={{ display: 'flex', alignItems: 'center', opacity: 0.9 }}>
                  <Box component="span" sx={{ fontWeight: 'bold', mr: 1 }}>Upload Time:</Box>
                  {binary2?.upload_time ? new Date(binary2.upload_time).toLocaleString() : 'N/A'}
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Paper 
            elevation={1} 
            sx={{ 
              p: 2, 
              backgroundColor: '#2d2d2d', 
              color: 'white',
              mb: 2,
              borderRadius: 1
            }}
          >
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} sm={4}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="body2" color="rgba(255, 255, 255, 0.7)" gutterBottom>
                    Similarity Score
                  </Typography>
                  <Box 
                    sx={{ 
                      position: 'relative', 
                      display: 'inline-flex',
                      borderRadius: '50%',
                      boxShadow: '0 0 10px rgba(255, 255, 255, 0.1)'
                    }}
                  >
                    <CircularProgress 
                      variant="determinate" 
                      value={results.similarity_score * 100} 
                      size={80}
                      thickness={5}
                      sx={{
                        color: results.similarity_score > 0.8 ? '#4caf50' : 
                               results.similarity_score > 0.5 ? '#ff9800' : '#f44336',
                      }}
                    />
                    <Box
                      sx={{
                        top: 0,
                        left: 0,
                        bottom: 0,
                        right: 0,
                        position: 'absolute',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                      }}
                    >
                      <Typography
                        variant="caption"
                        component="div"
                        sx={{ fontWeight: 'bold', fontSize: '1rem', color: 'white' }}
                      >
                        {`${Math.round(results.similarity_score * 100)}%`}
                      </Typography>
                    </Box>
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} sm={8}>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Chip 
                      label={`${results.summary.total_differences} Total Differences`} 
                      color="default"
                      sx={{ 
                        fontWeight: 'bold', 
                        fontSize: '0.9rem',
                        minWidth: '180px',
                        backgroundColor: 'rgba(255, 255, 255, 0.15)',
                        color: 'white'
                      }}
                    />
                  </Box>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                    <Chip 
                      label={`${results.summary.instruction_differences} Instructions`} 
                      sx={{
                        backgroundColor: '#1976d2',
                        color: 'white'
                      }}
                      size="small"
                    />
                    <Chip 
                      label={`${results.summary.data_differences} Data`} 
                      sx={{
                        backgroundColor: '#ff9800',
                        color: 'white'
                      }}
                      size="small"
                    />
                    <Chip 
                      label={`${results.summary.function_differences} Functions`} 
                      sx={{
                        backgroundColor: '#9c27b0',
                        color: 'white'
                      }}
                      size="small"
                    />
                  </Box>
                </Box>
              </Grid>
            </Grid>
          </Paper>
        </CardContent>
      </Card>
    );
  };
  
  // Helper function to format file size
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const renderDifferences = () => {
    if (!comparisonResult?.results?.differences) return null;

    // Function to highlight differences between two strings
    const highlightDifferences = (str1: string, str2: string, isFirstBinary: boolean) => {
      if (str1 === 'N/A' || str2 === 'N/A') {
        return str1;
      }

      // For simple values like "mov eax, 1" vs "mov eax, 2", highlight just the different part
      if (str1.length < 30 && str2.length < 30) {
        const parts1 = str1.split(' ');
        const parts2 = str2.split(' ');
        
        if (parts1.length === parts2.length) {
          return parts1.map((part, i) => {
            if (i < parts2.length && part !== parts2[i]) {
              return (
                <React.Fragment key={i}>
                  {i > 0 && ' '}
                  <span style={{ 
                    backgroundColor: isFirstBinary ? 'rgba(244, 67, 54, 0.7)' : 'rgba(76, 175, 80, 0.7)',
                    padding: '0 3px',
                    borderRadius: '2px',
                    fontWeight: 'bold'
                  }}>
                    {part}
                  </span>
                </React.Fragment>
              );
            }
            return <React.Fragment key={i}>{i > 0 && ' '}{part}</React.Fragment>;
          });
        }
      }
      
      // For longer code blocks, just return as is for now
      return str1;
    };

    // Constants for Binary 1 and Binary 2 colors
    const binary1Color = '#1976d2'; // Blue
    const binary2Color = '#2e7d32'; // Green

    return (
      <Card sx={{ boxShadow: 3, backgroundColor: '#1e1e1e', borderRadius: 2 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ fontWeight: 'bold', borderBottom: '1px solid #333', pb: 1, color: '#fff' }}>
            Detailed Differences
          </Typography>
          
          <TableContainer sx={{ maxHeight: '600px' }}>
            <Table stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell 
                    width="10%" 
                    sx={{ 
                      backgroundColor: '#2c3e50', 
                      color: 'white',
                      fontWeight: 'bold'
                    }}
                  >
                    Type
                  </TableCell>
                  <TableCell 
                    width="15%" 
                    sx={{ 
                      backgroundColor: '#2c3e50', 
                      color: 'white',
                      fontWeight: 'bold'
                    }}
                  >
                    Address
                  </TableCell>
                  <TableCell 
                    width="30%" 
                    sx={{ 
                      backgroundColor: binary1Color, 
                      color: 'white',
                      fontWeight: 'bold'
                    }}
                  >
                    Binary 1
                  </TableCell>
                  <TableCell 
                    width="30%" 
                    sx={{ 
                      backgroundColor: binary2Color, 
                      color: 'white',
                      fontWeight: 'bold'
                    }}
                  >
                    Binary 2
                  </TableCell>
                  <TableCell 
                    width="15%" 
                    sx={{ 
                      backgroundColor: '#2c3e50', 
                      color: 'white',
                      fontWeight: 'bold'
                    }}
                  >
                    Description
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {comparisonResult.results.differences.map((diff, index) => (
                  <TableRow key={index} sx={{ '&:nth-of-type(odd)': { backgroundColor: 'rgba(255, 255, 255, 0.03)' } }}>
                    <TableCell sx={{ backgroundColor: '#212121', color: 'white' }}>
                      <Chip 
                        label={diff.type}
                        size="small"
                        color={
                          diff.type === 'instruction' ? 'primary' :
                          diff.type === 'function' ? 'secondary' :
                          diff.type === 'data' ? 'warning' : 'default'
                        }
                        sx={{ fontWeight: 'bold' }}
                      />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', fontWeight: 'bold', backgroundColor: '#212121', color: '#bdbdbd' }}>
                      {diff.address}
                    </TableCell>
                    <TableCell 
                      sx={{ 
                        fontFamily: 'monospace', 
                        backgroundColor: '#212121', 
                        padding: '12px',
                        color: 'white',
                        position: 'relative',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        borderLeft: `4px solid ${binary1Color}`
                      }}
                    >
                      {diff.binary1_value === 'N/A' ? (
                        <Typography 
                          sx={{ 
                            fontStyle: 'italic', 
                            color: '#90caf9',
                            fontWeight: 'bold',
                            backgroundColor: 'rgba(25, 118, 210, 0.2)',
                            padding: '4px 8px',
                            borderRadius: '4px',
                            display: 'inline-block'
                          }}
                        >
                          Not present in Binary 1
                        </Typography>
                      ) : (
                        <Box component="pre" 
                          sx={{ 
                            margin: 0, 
                            fontFamily: 'monospace',
                            fontSize: '14px',
                            overflowX: 'auto',
                            color: '#ffffff',
                            padding: '6px',
                            borderRadius: '2px',
                            backgroundColor: 'rgba(0, 0, 0, 0.2)'
                          }}
                        >
                          {highlightDifferences(diff.binary1_value, diff.binary2_value, true)}
                        </Box>
                      )}
                    </TableCell>
                    <TableCell 
                      sx={{ 
                        fontFamily: 'monospace', 
                        backgroundColor: '#212121', 
                        padding: '12px',
                        color: 'white',
                        position: 'relative',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        borderLeft: `4px solid ${binary2Color}`
                      }}
                    >
                      {diff.binary2_value === 'N/A' ? (
                        <Typography 
                          sx={{ 
                            fontStyle: 'italic', 
                            color: '#a5d6a7',
                            fontWeight: 'bold',
                            backgroundColor: 'rgba(46, 125, 50, 0.2)',
                            padding: '4px 8px',
                            borderRadius: '4px',
                            display: 'inline-block'
                          }}
                        >
                          Not present in Binary 2
                        </Typography>
                      ) : (
                        <Box component="pre" 
                          sx={{ 
                            margin: 0, 
                            fontFamily: 'monospace',
                            fontSize: '14px',
                            overflowX: 'auto',
                            color: '#ffffff',
                            padding: '6px',
                            borderRadius: '2px',
                            backgroundColor: 'rgba(0, 0, 0, 0.2)'
                          }}
                        >
                          {highlightDifferences(diff.binary2_value, diff.binary1_value, false)}
                        </Box>
                      )}
                    </TableCell>
                    <TableCell sx={{ backgroundColor: '#263238', color: 'white' }}>
                      <Typography sx={{ fontSize: '14px' }}>
                        {diff.description}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>
    );
  };

  const renderExistingBinariesTab = () => {
    // Constants for Binary 1 and Binary 2 colors
    const binary1Color = '#1976d2'; // Blue
    const binary2Color = '#2e7d32'; // Green
    
    return (
      <Paper sx={{ p: 3, mb: 3, backgroundColor: '#1e1e1e', color: 'white', borderRadius: 2 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">
          Select Binaries to Compare
        </Typography>
          <Button
            size="small"
            variant="outlined"
            onClick={async () => {
              console.log('=== DEBUG TASK MANAGER ===');
              debugTaskManager();
              const activeTasks = taskManager.getActiveTasks();
              console.log('Active tasks from manual check:', activeTasks);
              
              // Force visibility change detection
              document.dispatchEvent(new Event('visibilitychange'));
              
              // Refresh past results too
              fetchPastResults();
              
              // Load test utility and run sync test
              try {
                const testModule = await import('../utils/testTaskSync');
                if (testModule.testTaskSync) {
                  testModule.testTaskSync();
                } else if ((window as any).testTaskSync) {
                  (window as any).testTaskSync();
                }
              } catch (error) {
                console.error('Failed to load test utility:', error);
              }
              
              // Test notification system
              notificationManager.addNotification({
                type: 'info',
                title: 'Debug Check',
                message: activeTasks.length > 0 
                  ? `Found ${activeTasks.length} active task(s). Status bar should be visible. Notification should be pulsing orange.`
                  : 'No active tasks found. Task manager will sync with backend. Check past results.',
                persistent: false
              });
            }}
            sx={{ 
              color: 'rgba(255,255,255,0.7)', 
              borderColor: 'rgba(255,255,255,0.3)',
              fontSize: '0.75rem',
              py: 0.5,
              px: 1
            }}
          >
            Debug Tasks
          </Button>
        </Box>
        
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={3}>
            <Typography variant="subtitle2" gutterBottom sx={{ color: binary1Color, fontWeight: 'bold' }}>Binary 1</Typography>
            <FormControl fullWidth variant="outlined" sx={{ 
              '& .MuiOutlinedInput-root': {
                color: 'white',
                '& fieldset': {
                  borderColor: binary1Color,
                },
                '&:hover fieldset': {
                  borderColor: binary1Color,
                },
                '&.Mui-focused fieldset': {
                  borderColor: binary1Color,
                }
              },
              '& .MuiInputLabel-root': {
                color: binary1Color,
              },
              '& .MuiInputLabel-root.Mui-focused': {
                color: binary1Color,
              }
            }}>
              <InputLabel>Select Binary 1</InputLabel>
              <Select
                value={selectedBinary1}
                onChange={(e) => setSelectedBinary1(e.target.value)}
                label="Select Binary 1"
              >
                {binaries.map((binary) => (
                  <MenuItem key={binary.id} value={binary.id}>
                    {binary.original_filename} ({formatFileSize(binary.file_size)})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={3}>
            <Typography variant="subtitle2" gutterBottom sx={{ color: binary2Color, fontWeight: 'bold' }}>Binary 2</Typography>
            <FormControl fullWidth variant="outlined" sx={{ 
              '& .MuiOutlinedInput-root': {
                color: 'white',
                '& fieldset': {
                  borderColor: binary2Color,
                },
                '&:hover fieldset': {
                  borderColor: binary2Color,
                },
                '&.Mui-focused fieldset': {
                  borderColor: binary2Color,
                }
              },
              '& .MuiInputLabel-root': {
                color: binary2Color,
              },
              '& .MuiInputLabel-root.Mui-focused': {
                color: binary2Color,
              }
            }}>
              <InputLabel>Select Binary 2</InputLabel>
              <Select
                value={selectedBinary2}
                onChange={(e) => setSelectedBinary2(e.target.value)}
                label="Select Binary 2"
              >
                {binaries.map((binary) => (
                  <MenuItem key={binary.id} value={binary.id}>
                    {binary.original_filename} ({formatFileSize(binary.file_size)})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={3}>
            <Typography variant="subtitle2" gutterBottom sx={{ color: 'rgba(255, 255, 255, 0.7)' }}>Diff Engine</Typography>
            <FormControl fullWidth variant="outlined" sx={{ 
              '& .MuiOutlinedInput-root': {
                color: 'white',
                '& fieldset': { borderColor: 'rgba(255, 255, 255, 0.23)' },
                '&:hover fieldset': { borderColor: 'rgba(255, 255, 255, 0.5)' },
              },
              '& .MuiInputLabel-root': { color: 'rgba(255, 255, 255, 0.7)' }
            }}>
              <InputLabel>Diff Engine</InputLabel>
              <Select
                value={diffType}
                onChange={(e) => setDiffType(e.target.value)}
                label="Diff Engine"
              >
                <MenuItem value="simple">Simple Diff</MenuItem>
                <MenuItem value="version_tracking">Version Tracking Diff</MenuItem>
                <MenuItem value="structural_graph">Structural Graph Diff</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={3}>
            <Typography variant="subtitle2" gutterBottom sx={{ color: '#90caf9', fontWeight: 'bold' }}>⚡ Performance Mode</Typography>
            <FormControl fullWidth variant="outlined" sx={{ 
              '& .MuiOutlinedInput-root': {
                color: 'white',
                '& fieldset': { borderColor: '#90caf9' },
                '&:hover fieldset': { borderColor: '#90caf9' },
                '&.Mui-focused fieldset': { borderColor: '#90caf9' },
              },
              '& .MuiInputLabel-root': { color: '#90caf9' },
              '& .MuiInputLabel-root.Mui-focused': { color: '#90caf9' }
            }}>
              <InputLabel>Performance Mode</InputLabel>
              <Select
                value={performanceMode}
                onChange={(e) => setPerformanceMode(e.target.value)}
                label="Performance Mode"
              >
                <MenuItem value="speed">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    ⚡ Speed
                    <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.6)' }}>
                      (Fast, reduced accuracy)
                    </Typography>
                  </Box>
                </MenuItem>
                <MenuItem value="balanced">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    ⚖️ Balanced
                    <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.6)' }}>
                      (Good speed/accuracy)
                    </Typography>
                  </Box>
                </MenuItem>
                <MenuItem value="accuracy">
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    🎯 Accuracy
                    <Typography variant="caption" sx={{ color: 'rgba(255, 255, 255, 0.6)' }}>
                      (Max precision, slower)
                    </Typography>
                  </Box>
                </MenuItem>
              </Select>
            </FormControl>
          </Grid>
        </Grid>
        
        <Button
          variant="contained"
          startIcon={<Compare />}
          onClick={handleCompare}
          disabled={loading || !selectedBinary1 || !selectedBinary2}
          sx={{ 
            mr: 2,
            background: `linear-gradient(90deg, ${binary1Color} 0%, ${binary2Color} 100%)`,
            '&:hover': {
              background: `linear-gradient(90deg, ${binary1Color} 20%, ${binary2Color} 100%)`,
            }
          }}
        >
          {loading ? 'Comparing...' : 'Compare Binaries'}
        </Button>
        <Typography variant="body2" sx={{ mt: 2, color: 'rgba(255,255,255,0.6)' }}>
          Note: Binary diffing can take several minutes for large files. Please be patient while the analysis completes.
        </Typography>
      </Paper>
    );
  };
  
  const renderUploadTab = () => {
    // Constants for Binary 1 and Binary 2 colors
    const binary1Color = '#1976d2'; // Blue
    const binary2Color = '#2e7d32'; // Green
    
    return (
      <Paper sx={{ p: 3, mb: 3, backgroundColor: '#1e1e1e', color: 'white', borderRadius: 2 }}>
        <Typography variant="h6" gutterBottom>
          Upload Binaries to Compare
        </Typography>
        
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle2" gutterBottom sx={{ color: binary1Color, fontWeight: 'bold' }}>Binary 1</Typography>
            <input
              accept=".exe,.dll,.so,.dylib,.bin,.elf"
              style={{ display: 'none' }}
              id="binary-upload-1"
              type="file"
              onChange={handleFileChange1}
              disabled={uploading}
            />
            <label htmlFor="binary-upload-1">
              <Button
                variant="outlined"
                component="span"
                startIcon={<FileUpload />}
                disabled={uploading}
                fullWidth
                sx={{ 
                  mb: 1,
                  color: 'white',
                  borderColor: binary1Color,
                  backgroundColor: 'rgba(25, 118, 210, 0.1)',
                  '&:hover': {
                    borderColor: binary1Color,
                    backgroundColor: 'rgba(25, 118, 210, 0.2)'
                  }
                }}
              >
                Select File
              </Button>
            </label>
            {file1 && (
              <Typography variant="body2" noWrap sx={{ color: binary1Color }}>
                {file1.name} ({(file1.size / 1024).toFixed(1)} KB)
              </Typography>
            )}
            {uploadProgress1 > 0 && uploadProgress1 < 100 && (
              <LinearProgress variant="determinate" value={uploadProgress1} sx={{ mt: 1, backgroundColor: 'rgba(25, 118, 210, 0.2)', '& .MuiLinearProgress-bar': { backgroundColor: binary1Color } }} />
            )}
          </Grid>
          
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle2" gutterBottom sx={{ color: binary2Color, fontWeight: 'bold' }}>Binary 2</Typography>
            <input
              accept=".exe,.dll,.so,.dylib,.bin,.elf"
              style={{ display: 'none' }}
              id="binary-upload-2"
              type="file"
              onChange={handleFileChange2}
              disabled={uploading}
            />
            <label htmlFor="binary-upload-2">
              <Button
                variant="outlined"
                component="span"
                startIcon={<FileUpload />}
                disabled={uploading}
                fullWidth
                sx={{ 
                  mb: 1,
                  color: 'white',
                  borderColor: binary2Color,
                  backgroundColor: 'rgba(46, 125, 50, 0.1)',
                  '&:hover': {
                    borderColor: binary2Color,
                    backgroundColor: 'rgba(46, 125, 50, 0.2)'
                  }
                }}
              >
                Select File
              </Button>
            </label>
            {file2 && (
              <Typography variant="body2" noWrap sx={{ color: binary2Color }}>
                {file2.name} ({(file2.size / 1024).toFixed(1)} KB)
              </Typography>
            )}
            {uploadProgress2 > 0 && uploadProgress2 < 100 && (
              <LinearProgress variant="determinate" value={uploadProgress2} sx={{ mt: 1, backgroundColor: 'rgba(46, 125, 50, 0.2)', '& .MuiLinearProgress-bar': { backgroundColor: binary2Color } }} />
            )}
          </Grid>
          
          <Grid item xs={12} md={4}>
            <FormControl fullWidth variant="outlined" sx={{ 
              '& .MuiOutlinedInput-root': {
                color: 'white',
                '& fieldset': {
                  borderColor: 'rgba(255, 255, 255, 0.23)',
                },
                '&:hover fieldset': {
                  borderColor: 'rgba(255, 255, 255, 0.5)',
                },
              },
              '& .MuiInputLabel-root': {
                color: 'rgba(255, 255, 255, 0.7)',
              }
            }}>
              <InputLabel>Diff Engine</InputLabel>
              <Select
                value={diffType}
                onChange={(e) => setDiffType(e.target.value)}
                label="Diff Engine"
                disabled={uploading}
              >
                <MenuItem value="simple">Simple Diff</MenuItem>
                <MenuItem value="version_tracking">Version Tracking Diff</MenuItem>
                <MenuItem value="structural_graph">Structural Graph Diff</MenuItem>
              </Select>
            </FormControl>
          </Grid>
        </Grid>
        
        <Button
          variant="contained"
          startIcon={<Upload />}
          onClick={handleUploadAndCompare}
          disabled={uploading || !file1 || !file2}
          sx={{
            background: `linear-gradient(90deg, ${binary1Color} 0%, ${binary2Color} 100%)`,
            '&:hover': {
              background: `linear-gradient(90deg, ${binary1Color} 20%, ${binary2Color} 100%)`,
            }
          }}
        >
          {uploading ? (
            <>
              <CircularProgress size={20} sx={{ mr: 1 }} />
              Uploading...
            </>
          ) : 'Upload & Compare'}
        </Button>
        <Typography variant="body2" sx={{ mt: 2, color: 'rgba(255,255,255,0.6)' }}>
          Note: Binary diffing can take several minutes for large files. Please be patient while the analysis completes.
        </Typography>
      </Paper>
    );
  };

  return (
    <Box sx={{ p: 3, backgroundColor: '#121212', color: 'white', minHeight: '100vh' }}>
      <Typography variant="h4" gutterBottom>
        Binary Comparison
      </Typography>
      
      <Box sx={{ borderBottom: 1, borderColor: 'rgba(255, 255, 255, 0.12)', mb: 2 }}>
        <Tabs 
          value={tabValue} 
          onChange={handleTabChange} 
          aria-label="comparison tabs"
          sx={{
            '& .MuiTab-root': {
              color: 'rgba(255, 255, 255, 0.7)',
              '&.Mui-selected': {
                color: '#90caf9',
              },
            },
            '& .MuiTabs-indicator': {
              backgroundColor: '#90caf9',
            },
          }}
        >
          <Tab label="Compare Existing Binaries" />
          <Tab label="Upload & Compare New Binaries" />
          <Tab label="Past Results" />
        </Tabs>
      </Box>
      
      <TabPanel value={tabValue} index={0}>
        {renderExistingBinariesTab()}
      </TabPanel>
      
      <TabPanel value={tabValue} index={1}>
        {renderUploadTab()}
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        {loadingPastResults ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
            <CircularProgress />
          </Box>
        ) : (
          <Box>
            <Typography variant="h6" sx={{ mb: 2 }}>Past Binary Comparison Results</Typography>
            <TableContainer component={Paper} sx={{ background: '#181818' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Created At</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Binary 1</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Binary 2</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Task ID</TableCell>
                    <TableCell sx={{ color: 'white', fontWeight: 'bold' }}>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pastResults.map((r) => {
                    const binary1 = binaries.find(b => b.id === r.binary_id);
                    const binary2 = binaries.find(b => b.id === (r.meta_data?.binary_id2 || ''));
                    return (
                      <TableRow key={r.id}>
                        <TableCell sx={{ color: 'white' }}>{r.created_at}</TableCell>
                        <TableCell sx={{ color: 'white' }}>{binary1 ? `${binary1.original_filename} (${binary1.id})` : r.binary_id}</TableCell>
                        <TableCell sx={{ color: 'white' }}>{binary2 ? `${binary2.original_filename} (${binary2.id})` : (r.meta_data?.binary_id2 || '')}</TableCell>
                        <TableCell sx={{ color: 'white' }}>{r.task_id}</TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Button
                              variant="outlined"
                              size="small"
                              onClick={() => {
                                let parsedResults = r.results;
                                if (typeof parsedResults === 'string') {
                                  try {
                                    parsedResults = JSON.parse(parsedResults);
                                  } catch (e) {
                                    toast.error('Failed to parse diff result JSON');
                                    return;
                                  }
                                }
                                setSelectedPastResult({ ...r, results: parsedResults });
                              }}
                              sx={{ color: 'white', borderColor: 'rgba(255, 255, 255, 0.5)' }}
                            >
                              VIEW
                            </Button>
                            <Button
                              variant="outlined"
                              size="small"
                              color="error"
                              onClick={async () => {
                                if (window.confirm('Are you sure you want to delete this comparison result?')) {
                                  try {
                                    await apiClient.deleteBinaryDiffResult(r.id);
                                    toast.success('Result deleted successfully');
                                    fetchPastResults(); // Refresh the list
                                  } catch (error) {
                                    console.error('Failed to delete result:', error);
                                    toast.error('Failed to delete result');
                                  }
                                }
                              }}
                              sx={{ borderColor: 'rgba(244, 67, 54, 0.5)' }}
                            >
                              DELETE
                            </Button>
                          </Box>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
            {selectedPastResult && (
              <Box sx={{ mt: 4 }}>
                <Typography variant="subtitle1" sx={{ mb: 1 }}>Diff Result Details</Typography>
                <DiffResultsViewer result={selectedPastResult.results} />
                <Button sx={{ mt: 2 }} onClick={() => setSelectedPastResult(null)}>
                  Close
                </Button>
              </Box>
            )}
          </Box>
        )}
      </TabPanel>

      {loading && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress sx={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', '& .MuiLinearProgress-bar': { backgroundColor: '#90caf9' } }} />
          <Typography variant="body2" sx={{ mt: 1, color: 'rgba(255, 255, 255, 0.7)' }}>
            {taskId ? 
              'Binary comparison in progress... You can navigate away - progress will be tracked in the status bar below.' : 
              'Starting binary comparison...'
            }
          </Typography>
          {taskId && (
            <Typography variant="caption" sx={{ display: 'block', mt: 0.5, color: 'rgba(255, 255, 255, 0.5)' }}>
              Task ID: {taskId}
            </Typography>
          )}
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3, backgroundColor: 'rgba(211, 47, 47, 0.15)', color: '#f44336' }}>
          {error}
        </Alert>
      )}

      {comparisonResult && (
        <Box>
          {renderComparisonSummary()}
          <DiffResultsViewer result={comparisonResult.results || {}} />
          <Box sx={{ mt: 2 }}>
            <Button
              variant="outlined"
              startIcon={<Download />}
              onClick={() => {
                // Export comparison results
                const dataStr = JSON.stringify(comparisonResult, null, 2);
                const dataBlob = new Blob([dataStr], { type: 'application/json' });
                const url = URL.createObjectURL(dataBlob);
                const link = document.createElement('a');
                link.href = url;
                link.download = `comparison_${comparisonResult.binary_id1}_${comparisonResult.binary_id2}.json`;
                link.click();
              }}
              sx={{
                color: 'white',
                borderColor: 'rgba(255, 255, 255, 0.5)',
                '&:hover': {
                  borderColor: 'white',
                  backgroundColor: 'rgba(255, 255, 255, 0.08)'
                }
              }}
            >
              Export Results
            </Button>
          </Box>
        </Box>
      )}
    </Box>
  );
};

export default BinaryComparison; 