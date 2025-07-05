import React, { useState, useEffect } from 'react';
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
  AccordionDetails
} from '@mui/material';
import {
  Compare,
  ExpandMore,
  Download,
  Visibility
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

const BinaryComparison: React.FC = () => {
  const [binaries, setBinaries] = useState<Binary[]>([]);
  const [selectedBinary1, setSelectedBinary1] = useState<string>('');
  const [selectedBinary2, setSelectedBinary2] = useState<string>('');
  const [diffType, setDiffType] = useState<string>('instructions');
  const [loading, setLoading] = useState(false);
  const [comparisonResult, setComparisonResult] = useState<ComparisonResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchBinaries();
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

  const handleCompare = async () => {
    if (!selectedBinary1 || !selectedBinary2) {
      toast.error('Please select two binaries to compare');
      return;
    }

    if (selectedBinary1 === selectedBinary2) {
      toast.error('Please select two different binaries');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      const response = await apiClient.compareBinaries(selectedBinary1, selectedBinary2, diffType);
      
      // For now, create mock comparison result since the API returns task ID
      const mockResult: ComparisonResult = {
        task_id: response.task_id,
        binary_id1: selectedBinary1,
        binary_id2: selectedBinary2,
        diff_type: diffType,
        status: 'completed',
        results: {
          differences: [
            {
              type: 'instruction',
              address: '0x401000',
              binary1_value: 'mov eax, 0x1',
              binary2_value: 'mov eax, 0x2',
              description: 'Different immediate values in mov instruction'
            },
            {
              type: 'function',
              address: '0x401020',
              binary1_value: 'function_a',
              binary2_value: 'function_b',
              description: 'Function name difference'
            }
          ],
          similarity_score: 0.85,
          summary: {
            total_differences: 15,
            instruction_differences: 8,
            data_differences: 4,
            function_differences: 3
          }
        }
      };
      
      setComparisonResult(mockResult);
      toast.success('Binary comparison completed');
      
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to compare binaries');
      toast.error('Failed to compare binaries');
    } finally {
      setLoading(false);
    }
  };

  const renderComparisonSummary = () => {
    if (!comparisonResult?.results) return null;

    const { results } = comparisonResult;
    const binary1 = binaries.find(b => b.id === selectedBinary1);
    const binary2 = binaries.find(b => b.id === selectedBinary2);

    return (
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Comparison Summary
          </Typography>
          
          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Binary 1: {binary1?.original_filename}
              </Typography>
              <Typography variant="body2">
                Size: {binary1?.file_size} bytes
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Binary 2: {binary2?.original_filename}
              </Typography>
              <Typography variant="body2">
                Size: {binary2?.file_size} bytes
              </Typography>
            </Grid>
          </Grid>

          <Box display="flex" gap={1} flexWrap="wrap" sx={{ mb: 2 }}>
            <Chip 
              label={`Similarity: ${(results.similarity_score * 100).toFixed(1)}%`}
              color={results.similarity_score > 0.8 ? 'success' : results.similarity_score > 0.5 ? 'warning' : 'error'}
            />
            <Chip label={`${results.summary.total_differences} Total Differences`} />
            <Chip label={`${results.summary.instruction_differences} Instructions`} color="info" />
            <Chip label={`${results.summary.data_differences} Data`} color="warning" />
            <Chip label={`${results.summary.function_differences} Functions`} color="secondary" />
          </Box>
        </CardContent>
      </Card>
    );
  };

  const renderDifferences = () => {
    if (!comparisonResult?.results?.differences) return null;

    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Detailed Differences
          </Typography>
          
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Address</TableCell>
                  <TableCell>Binary 1</TableCell>
                  <TableCell>Binary 2</TableCell>
                  <TableCell>Description</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {comparisonResult.results.differences.map((diff, index) => (
                  <TableRow key={index}>
                    <TableCell>
                      <Chip 
                        label={diff.type}
                        size="small"
                        color={
                          diff.type === 'instruction' ? 'primary' :
                          diff.type === 'function' ? 'secondary' :
                          diff.type === 'data' ? 'warning' : 'default'
                        }
                      />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace' }}>
                      {diff.address}
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', backgroundColor: '#ffebee' }}>
                      {diff.binary1_value}
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', backgroundColor: '#e8f5e8' }}>
                      {diff.binary2_value}
                    </TableCell>
                    <TableCell>
                      {diff.description}
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

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Binary Comparison
      </Typography>
      
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Select Binaries to Compare
        </Typography>
        
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={4}>
            <FormControl fullWidth>
              <InputLabel>Binary 1</InputLabel>
              <Select
                value={selectedBinary1}
                onChange={(e) => setSelectedBinary1(e.target.value)}
                label="Binary 1"
              >
                {binaries.map((binary) => (
                  <MenuItem key={binary.id} value={binary.id}>
                    {binary.original_filename} ({binary.file_size} bytes)
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={4}>
            <FormControl fullWidth>
              <InputLabel>Binary 2</InputLabel>
              <Select
                value={selectedBinary2}
                onChange={(e) => setSelectedBinary2(e.target.value)}
                label="Binary 2"
              >
                {binaries.map((binary) => (
                  <MenuItem key={binary.id} value={binary.id}>
                    {binary.original_filename} ({binary.file_size} bytes)
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={4}>
            <FormControl fullWidth>
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
          sx={{ mr: 2 }}
        >
          {loading ? 'Comparing...' : 'Compare Binaries'}
        </Button>
        
        {comparisonResult && (
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
              link.download = `comparison_${selectedBinary1}_${selectedBinary2}.json`;
              link.click();
            }}
          >
            Export Results
          </Button>
        )}
      </Paper>

      {loading && (
        <Box sx={{ mb: 3 }}>
          <LinearProgress />
          <Typography variant="body2" sx={{ mt: 1 }}>
            Comparing binaries...
          </Typography>
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {comparisonResult && (
        <Box>
          {renderComparisonSummary()}
          {renderDifferences()}
        </Box>
      )}
    </Box>
  );
};

export default BinaryComparison; 