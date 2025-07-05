import React, { useState, useEffect, useCallback } from 'react';
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
  FileUpload
} from '@mui/icons-material';
import { toast } from 'react-toastify';
import { apiClient } from '../utils/api';

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
          {children}
        </Box>
      )}
    </div>
  );
}

const BinaryComparison: React.FC = () => {
  const [binaries, setBinaries] = useState<Binary[]>([]);
  const [selectedBinary1, setSelectedBinary1] = useState<string>('');
  const [selectedBinary2, setSelectedBinary2] = useState<string>('');
  const [diffType, setDiffType] = useState<string>('instructions');
  const [loading, setLoading] = useState(false);
  const [comparisonResult, setComparisonResult] = useState<ComparisonResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [pollingInterval, setPollingInterval] = useState<NodeJS.Timeout | null>(null);
  
  // File upload states
  const [file1, setFile1] = useState<File | null>(null);
  const [file2, setFile2] = useState<File | null>(null);
  const [uploadProgress1, setUploadProgress1] = useState(0);
  const [uploadProgress2, setUploadProgress2] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [uploadedBinary1, setUploadedBinary1] = useState<Binary | null>(null);
  const [uploadedBinary2, setUploadedBinary2] = useState<Binary | null>(null);

  useEffect(() => {
    fetchBinaries();
    
    // Clean up polling interval on component unmount
    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, []);

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
      
      // Stop any existing polling
      if (pollingInterval) {
        clearInterval(pollingInterval);
        setPollingInterval(null);
      }
      
      // Start comparison task
      const response = await apiClient.compareBinaries(binary1Id, binary2Id, diffType);
      setTaskId(response.task_id);
      
      console.log('Comparison task started:', response);
      
      // Check if the task is already completed (new immediate completion mode)
      if (response.status === 'completed') {
        console.log('Task completed immediately, fetching results');
        try {
          const result = await apiClient.getBinaryComparisonResults(response.task_id);
          setComparisonResult(result);
          toast.success('Binary comparison completed');
          setLoading(false);
          return;
        } catch (err) {
          console.error('Error fetching immediate results:', err);
          setError('Error fetching comparison results');
          toast.error('Error fetching comparison results');
          setLoading(false);
          return;
        }
      }
      
      // If not completed immediately, set up polling
      let pollCount = 0;
      const maxPolls = 30; // Maximum number of polling attempts (30 * 2 seconds = 60 seconds max wait)
      
      // Set up polling for task status
      const interval = setInterval(async () => {
        try {
          pollCount++;
          console.log(`Polling attempt ${pollCount} for task ${response.task_id}`);
          
          if (pollCount > maxPolls) {
            clearInterval(interval);
            setPollingInterval(null);
            setError('Comparison timed out. Please try again or check server logs.');
            toast.error('Binary comparison timed out');
            setLoading(false);
            return;
          }
          
          const result = await apiClient.getBinaryComparisonResults(response.task_id);
          console.log('Poll result:', result);
          
          if (result.status === 'completed' || result.status === 'failed') {
            // Task is done, stop polling
            clearInterval(interval);
            setPollingInterval(null);
            
            if (result.status === 'completed') {
              setComparisonResult(result);
              toast.success('Binary comparison completed');
            } else {
              setError(`Comparison failed: ${result.error || 'Unknown error'}`);
              toast.error('Binary comparison failed');
            }
            
            setLoading(false);
          } else {
            // Update progress if available
            if (result.progress) {
              // You could update a progress bar here if you want
              console.log(`Task progress: ${result.progress}%`);
            }
          }
        } catch (err: any) {
          console.error('Error polling task status:', err);
          // Don't stop polling on error, just log it
          // The timeout will eventually stop polling if errors persist
        }
      }, 2000); // Poll every 2 seconds
      
      setPollingInterval(interval);
      
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
        <Typography variant="h6" gutterBottom>
          Select Binaries to Compare
        </Typography>
        
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={4}>
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
          
          <Grid item xs={12} md={4}>
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
          
          <Grid item xs={12} md={4}>
            <Typography variant="subtitle2" gutterBottom sx={{ color: 'rgba(255, 255, 255, 0.7)' }}>Comparison Options</Typography>
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
              <InputLabel>Comparison Type</InputLabel>
              <Select
                value={diffType}
                onChange={(e) => setDiffType(e.target.value)}
                label="Comparison Type"
              >
                <MenuItem value="instructions">Instructions</MenuItem>
                <MenuItem value="functions">Functions</MenuItem>
                <MenuItem value="data">Data Sections</MenuItem>
                <MenuItem value="all">All Differences</MenuItem>
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
              <InputLabel>Comparison Type</InputLabel>
              <Select
                value={diffType}
                onChange={(e) => setDiffType(e.target.value)}
                label="Comparison Type"
                disabled={uploading}
              >
                <MenuItem value="instructions">Instructions</MenuItem>
                <MenuItem value="functions">Functions</MenuItem>
                <MenuItem value="data">Data Sections</MenuItem>
                <MenuItem value="all">All Differences</MenuItem>
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
        </Tabs>
      </Box>
      
      <TabPanel value={tabValue} index={0}>
        {renderExistingBinariesTab()}
      </TabPanel>
      
      <TabPanel value={tabValue} index={1}>
        {renderUploadTab()}
      </TabPanel>

      {loading && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress sx={{ backgroundColor: 'rgba(255, 255, 255, 0.1)', '& .MuiLinearProgress-bar': { backgroundColor: '#90caf9' } }} />
          <Typography variant="body2" sx={{ mt: 1, color: 'rgba(255, 255, 255, 0.7)' }}>
            {taskId ? 'Processing comparison...' : 'Comparing binaries...'}
          </Typography>
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
          {renderDifferences()}
          
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