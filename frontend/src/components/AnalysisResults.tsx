import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Alert,
  LinearProgress,
  Tabs,
  Tab,
  Card,
  CardContent,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Grid
} from '@mui/material';
import {
  ExpandMore,
  Code,
  AccountTree,
  BugReport,
  Memory,
  Search,
  Functions
} from '@mui/icons-material';
import { useParams } from 'react-router-dom';
import ReactJsonView from 'react18-json-view';
import SyntaxHighlighter from 'react-syntax-highlighter';
// @ts-ignore - Type definitions missing for style imports
import tomorrow from 'react-syntax-highlighter/dist/styles/tomorrow';
import { apiClient, AnalysisResult, formatDate } from '../utils/api';

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

// Function to render function data in a table
const FunctionDataTable = ({ functions }: { functions: any[] }) => {
  if (!functions || functions.length === 0) {
    return <Typography color="error">No function data available</Typography>;
  }

  return (
    <TableContainer component={Paper} sx={{ mt: 2 }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell><strong>Address</strong></TableCell>
            <TableCell><strong>Name</strong></TableCell>
            <TableCell><strong>Size</strong></TableCell>
            <TableCell><strong>Parameters</strong></TableCell>
            <TableCell><strong>Return Type</strong></TableCell>
            <TableCell><strong>Calling Convention</strong></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {functions.slice(0, 100).map((func, index) => (
            <TableRow key={index} hover>
              <TableCell>{func.address}</TableCell>
              <TableCell>{func.name || '(unnamed)'}</TableCell>
              <TableCell>{func.size || 'N/A'}</TableCell>
              <TableCell>{func.parameter_count || '0'}</TableCell>
              <TableCell>{func.return_type || 'unknown'}</TableCell>
              <TableCell>{func.calling_convention || 'default'}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {functions.length > 100 && (
        <Box sx={{ p: 2, textAlign: 'center' }}>
          <Typography variant="body2" color="text.secondary">
            Showing 100 of {functions.length} functions
          </Typography>
        </Box>
      )}
    </TableContainer>
  );
};

// Function to render memory regions in a table
const MemoryRegionsTable = ({ regions }: { regions: any[] }) => {
  if (!regions || regions.length === 0) {
    return <Typography color="error">No memory region data available</Typography>;
  }

  return (
    <TableContainer component={Paper} sx={{ mt: 2 }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell><strong>Name</strong></TableCell>
            <TableCell><strong>Start Address</strong></TableCell>
            <TableCell><strong>End Address</strong></TableCell>
            <TableCell><strong>Size</strong></TableCell>
            <TableCell><strong>Permissions</strong></TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {regions.map((region, index) => (
            <TableRow key={index} hover>
              <TableCell>{region.name}</TableCell>
              <TableCell>{region.start_address || region.start}</TableCell>
              <TableCell>{region.end_address || region.end}</TableCell>
              <TableCell>{formatBytes(region.size)}</TableCell>
              <TableCell>
                {region.is_read || region.read ? 'R' : '-'}
                {region.is_write || region.write ? 'W' : '-'}
                {region.is_execute || region.execute ? 'X' : '-'}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

// Helper function to format bytes
const formatBytes = (bytes: number) => {
  if (!bytes) return 'N/A';
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = bytes;
  let unitIndex = 0;
  
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex++;
  }
  
  return `${value.toFixed(2)} ${units[unitIndex]}`;
};

// Updated interface to include binary information
interface AnalysisResultWithBinary extends AnalysisResult {
  binary?: {
    original_filename: string;
    file_size: number;
    upload_time: string;
    architecture: string;
    file_hash: string;
    analysis_status: string;
  };
}

// Helper function to safely format dates
const safeFormatDate = (dateString?: string): string => {
  if (!dateString) return 'N/A';
  return formatDate(dateString);
};

// Main component to display analysis results
const AnalysisResults: React.FC = () => {
  const { analysisId } = useParams<{ analysisId: string }>();
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [analysisData, setAnalysisData] = useState<AnalysisResultWithBinary | null>(null);
  const [tabValue, setTabValue] = useState<number>(0);
  const [functionData, setFunctionData] = useState<any[]>([]);
  const [memoryRegions, setMemoryRegions] = useState<any[]>([]);

  useEffect(() => {
    const fetchAnalysisResults = async () => {
      try {
        setLoading(true);
        setError(null);
        
        if (!analysisId) {
          setError('No analysis ID provided');
          setLoading(false);
          return;
        }
        
        // Fetch the main analysis results
        const result = await apiClient.getAnalysisResults(analysisId);
        setAnalysisData(result);
        
        // Fetch functions for this binary
        try {
          const functionsResult = await apiClient.getBinaryFunctions(result.binary_id);
          setFunctionData(functionsResult.functions || []);
        } catch (funcError) {
          console.error('Error fetching functions:', funcError);
        }
        
        // Extract memory regions from results
        try {
          // Look for memory regions in the analysis results
          const memoryRegionsResult = result.results.find((r: any) => 
            r.analysis_type === 'getMemoryRegions' || 
            (r.results && r.results.memory_regions)
          );
          
          if (memoryRegionsResult) {
            const regions = memoryRegionsResult.results.memory_regions || [];
            setMemoryRegions(regions);
          }
        } catch (memError) {
          console.error('Error extracting memory regions:', memError);
        }
        
      } catch (err) {
        console.error('Error fetching analysis results:', err);
        setError('Failed to load analysis results. Please try again later.');
      } finally {
        setLoading(false);
      }
    };

    if (analysisId) {
      fetchAnalysisResults();
    }
  }, [analysisId]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Typography variant="h5" gutterBottom>Loading Analysis Results</Typography>
        <LinearProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error">{error}</Alert>
      </Box>
    );
  }

  if (!analysisData) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="warning">No analysis data found for ID: {analysisId}</Alert>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Analysis Results
        <Chip 
          label={analysisData.binary?.analysis_status || 'Unknown'}
          color={analysisData.binary?.analysis_status === 'Completed' || analysisData.binary?.analysis_status === 'completed' ? 'success' : 'warning'}
          size="small"
        />
      </Typography>
      
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>Binary Information</Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="body2"><strong>Name:</strong> {analysisData.binary?.original_filename}</Typography>
              <Typography variant="body2"><strong>Size:</strong> {analysisData.binary?.file_size} bytes</Typography>
              <Typography variant="body2"><strong>Upload Time:</strong> {safeFormatDate(analysisData.binary?.upload_time)}</Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="body2"><strong>Architecture:</strong> {analysisData.binary?.architecture || 'Unknown'}</Typography>
              <Typography variant="body2"><strong>File Hash:</strong> {analysisData.binary?.file_hash || 'Not calculated'}</Typography>
              <Typography variant="body2"><strong>Analysis Status:</strong> {analysisData.binary?.analysis_status}</Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
        <Tabs value={tabValue} onChange={handleTabChange} aria-label="analysis tabs">
          <Tab icon={<Functions />} label="Functions" />
          <Tab icon={<Memory />} label="Memory Regions" />
          <Tab icon={<Code />} label="Raw Results" />
        </Tabs>
      </Box>

      <Box role="tabpanel" hidden={tabValue !== 0}>
        {tabValue === 0 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Functions ({functionData.length})
            </Typography>
            <FunctionDataTable functions={functionData} />
          </Box>
        )}
      </Box>

      <Box role="tabpanel" hidden={tabValue !== 1}>
        {tabValue === 1 && (
          <Box>
            <Typography variant="h6" gutterBottom>
              Memory Regions ({memoryRegions.length})
            </Typography>
            <MemoryRegionsTable regions={memoryRegions} />
          </Box>
        )}
      </Box>

      <Box role="tabpanel" hidden={tabValue !== 2}>
        {tabValue === 2 && (
          <Box>
            <Typography variant="h6" gutterBottom>Raw Analysis Results</Typography>
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMore />}>
                <Typography>Analysis Results JSON</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <ReactJsonView 
                  src={analysisData.results} 
                  theme="vscode"
                  collapsed={2}
                  enableClipboard={false}
                />
              </AccordionDetails>
            </Accordion>
          </Box>
        )}
      </Box>
    </Box>
  );
};

export default AnalysisResults; 