import React, { useState, useEffect } from 'react';
import {
  Grid,
  Typography,
  Paper,
  Box,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Alert,
  Tooltip,
  IconButton,
  CircularProgress,
  Pagination,
  Stack,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Card,
  CardContent,
  useTheme
} from '@mui/material';
import {
  CloudUpload,
  Refresh,
  PlayArrow,
  Visibility,
  CheckCircle,
  Error as ErrorIcon,
  Warning as WarningIcon,
  HourglassEmpty,
  Pending,
  Memory,
  Settings,
  Storage as StorageIcon,
  Delete,
  Stop
} from '@mui/icons-material';
import { apiClient, Binary, SystemStatus } from '../utils/api';
import { useNavigate } from 'react-router-dom';
import TaskProgress from './TaskProgress';
import { toast } from 'react-toastify';

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const [binaries, setBinaries] = useState<Binary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedBinary, setSelectedBinary] = useState<Binary | null>(null);
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  
  // Delete confirmation state
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [binaryToDelete, setBinaryToDelete] = useState<Binary | null>(null);
  const [deleting, setDeleting] = useState(false);
  
  // Stop tasks state
  const [stoppingTasks, setStoppingTasks] = useState<string | null>(null);
  
  // Pagination for binaries
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 15;

  const fetchBinaries = async () => {
    try {
      setRefreshing(true);
      const response = await apiClient.getBinaries();
      setBinaries(response.binaries);
      setError(null);
    } catch (err) {
      setError('Failed to fetch binaries');
      console.error('Error fetching binaries:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchSystemStatus = async () => {
    try {
      const status = await apiClient.getSystemStatus();
      setSystemStatus(status);
    } catch (err) {
      console.warn('Could not fetch system status:', err);
    }
  };

  const handleStartAnalysis = async (binaryId: string) => {
    try {
      await apiClient.startAnalysis(binaryId);
      fetchBinaries(); // Refresh to show updated status
    } catch (err) {
      console.error('Error starting analysis:', err);
      setError('Failed to start analysis');
    }
  };

  const handleRefresh = () => {
    fetchBinaries();
    fetchSystemStatus();
  };

  const handlePageChange = (event: React.ChangeEvent<unknown>, value: number) => {
    setCurrentPage(value);
  };

  const handleViewBinary = (binary: Binary) => {
    navigate(`/binary/${binary.id}`);
  };

  const handleUploadRedirect = () => {
    navigate('/upload');
  };

  const handleDeleteBinary = (binary: Binary) => {
    setBinaryToDelete(binary);
    setDeleteConfirmOpen(true);
  };

  const handleStopTasks = async (binary: Binary) => {
    try {
      setStoppingTasks(binary.id);
      const result = await apiClient.stopBinaryTasks(binary.id);
      
      if (result.cancelled_tasks > 0) {
        toast.success(`Stopped ${result.cancelled_tasks} task(s) for ${binary.original_filename}`);
      } else {
        toast.info(`No active tasks found for ${binary.original_filename}`);
      }
      
      // Refresh data to show updated status
      fetchBinaries();
      fetchSystemStatus();
      
    } catch (err: any) {
      const errorMessage = err.response?.data?.error || err.message || 'Failed to stop tasks';
      toast.error(`Failed to stop tasks: ${errorMessage}`);
      console.error('Error stopping tasks:', err);
    } finally {
      setStoppingTasks(null);
    }
  };

  const handleDeleteConfirm = async () => {
    if (!binaryToDelete) return;
    
    try {
      setDeleting(true);
      
      // If binary is processing, stop tasks first
      const isProcessing = binaryToDelete.analysis_status === 'running' || binaryToDelete.analysis_status === 'analyzing';
      if (isProcessing) {
        try {
          const result = await apiClient.stopBinaryTasks(binaryToDelete.id);
          if (result.cancelled_tasks > 0) {
            toast.info(`Stopped ${result.cancelled_tasks} task(s) before deletion`);
          }
        } catch (stopError) {
          console.warn('Failed to stop tasks before deletion, proceeding anyway:', stopError);
        }
      }
      
      // Delete the binary
      await apiClient.deleteBinary(binaryToDelete.id);
      
      // Remove from local state
      setBinaries(prev => prev.filter(b => b.id !== binaryToDelete.id));
      
      // Reset dialog state
      setDeleteConfirmOpen(false);
      setBinaryToDelete(null);
      
      // Refresh system status to update counts
      fetchSystemStatus();
      
      toast.success(`Deleted ${binaryToDelete.original_filename} successfully`);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to delete binary');
      console.error('Error deleting binary:', err);
      toast.error(`Failed to delete ${binaryToDelete.original_filename}: ${err.response?.data?.error || err.message}`);
    } finally {
      setDeleting(false);
    }
  };

  const handleDeleteCancel = () => {
    setDeleteConfirmOpen(false);
    setBinaryToDelete(null);
  };

  useEffect(() => {
    fetchBinaries();
    fetchSystemStatus();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      fetchBinaries();
      fetchSystemStatus();
    }, 30000);

    return () => clearInterval(interval);
  }, []);

  const getAnalysisStatusChip = (binary: Binary) => {
    const status = binary.analysis_status;
    
    // Handle capitalized statuses
    if (status === 'Completed' || status === 'completed') {
      return (
        <Chip 
          label="Completed" 
          color="success" 
          size="small" 
          icon={<CheckCircle />}
          sx={{ 
            backgroundColor: '#4caf50',
            color: 'white',
            fontWeight: 600
          }}
        />
      );
    }
    
    if (status === 'Analyzed' || status === 'analyzed') {
      return (
        <Chip 
          label="Analyzed" 
          size="small" 
          icon={<CheckCircle />}
          sx={{ 
            backgroundColor: '#2196f3',
            color: 'white',
            fontWeight: 600
          }}
        />
      );
    }
    
    if (status === 'Decompiled' || status === 'decompiled') {
      return (
        <Chip 
          label="Decompiled" 
          size="small" 
          icon={<Memory />}
          sx={{ 
            backgroundColor: '#9c27b0',
            color: 'white',
            fontWeight: 600
          }}
        />
      );
    }
    
    if (status === 'failed' || status === 'Failed') {
      return (
        <Chip 
          label="Failed" 
          color="error" 
          size="small" 
          icon={<ErrorIcon />}
          sx={{ 
            backgroundColor: '#f44336',
            color: 'white',
            fontWeight: 600
          }}
        />
      );
    }
    
    if (status === 'running' || status === 'analyzing' || status === 'Analyzing') {
      return (
        <Chip 
          label="Analyzing" 
          color="warning" 
          size="small" 
          icon={<HourglassEmpty />}
          sx={{ 
            backgroundColor: '#ff9800',
            color: 'white',
            fontWeight: 600
          }}
        />
      );
    }
    
    if (status === 'uploaded' || status === 'pending' || status === 'Pending') {
      return (
        <Chip 
          label="Pending" 
          size="small" 
          icon={<Pending />}
          sx={{ 
            backgroundColor: '#9e9e9e',
            color: 'white',
            fontWeight: 600
          }}
        />
      );
    }
    
    // Default fallback for unknown statuses
    return (
      <Chip 
        label={status} 
        color="default" 
        size="small"
        sx={{ 
          backgroundColor: '#607d8b',
          color: 'white',
          fontWeight: 600
        }}
      />
    );
  };

  const getAnalysisActions = (binary: Binary) => {
    const isProcessing = binary.analysis_status === 'running' || binary.analysis_status === 'analyzing';
    
    return (
      <Box display="flex" gap={0.5}>
        <Tooltip title="View Details">
          <IconButton
            size="small"
            onClick={() => handleViewBinary(binary)}
            color="primary"
          >
            <Visibility fontSize="small" />
          </IconButton>
        </Tooltip>
        
        {isProcessing ? (
          <Tooltip title="Stop All Tasks">
            <IconButton
              size="small"
              onClick={() => handleStopTasks(binary)}
              color="warning"
              disabled={stoppingTasks === binary.id}
            >
              {stoppingTasks === binary.id ? (
                <CircularProgress size={16} />
              ) : (
                <Stop fontSize="small" />
              )}
            </IconButton>
          </Tooltip>
        ) : (
          <Tooltip title="Start Basic Analysis">
            <IconButton
              size="small"
              onClick={() => handleStartAnalysis(binary.id)}
              color="primary"
            >
              <PlayArrow fontSize="small" />
            </IconButton>
          </Tooltip>
        )}
        
        <Tooltip title={isProcessing ? "Delete Binary (will stop tasks first)" : "Delete Binary"}>
          <IconButton
            size="small"
            onClick={() => handleDeleteBinary(binary)}
            color="error"
          >
            <Delete fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
    );
  };

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleString();
  };

  // Calculate pagination for binaries
  const totalPages = Math.ceil(binaries.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const currentBinaries = binaries.slice(startIndex, endIndex);

  if (loading && binaries.length === 0 && !systemStatus) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minHeight="400px">
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Top Status Cards - Uniform Height */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} md={4}>
          <Card sx={{ height: 200, display: 'flex', flexDirection: 'column' }}>
            <CardContent sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Memory sx={{ mr: 1, color: theme.palette.primary.main }} />
                <Typography variant="h6">System Status</Typography>
              </Box>
              {loading && !systemStatus ? (
                <Box display="flex" justifyContent="center" alignItems="center" flexGrow={1}>
                  <CircularProgress size={24} />
                </Box>
              ) : systemStatus ? (
                <Box flexGrow={1}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1.5 }}>
                    <Typography variant="body2">Ghidra Bridge:</Typography>
                    <Chip 
                      label={systemStatus.ghidra_bridge_connected ? 'Connected' : 'Disconnected'}
                      color={systemStatus.ghidra_bridge_connected ? 'success' : 'error'}
                      size="small"
                    />
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1.5 }}>
                    <Typography variant="body2">Running:</Typography>
                    <Typography variant="body2" fontWeight="medium">{systemStatus.tasks.running}</Typography>
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1.5 }}>
                    <Typography variant="body2">Queued:</Typography>
                    <Typography variant="body2" fontWeight="medium">{systemStatus.tasks.queued}</Typography>
                  </Box>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 'auto', display: 'block' }}>
                    Updated: {formatDate(systemStatus.server_time)}
                  </Typography>
                </Box>
              ) : (
                <Box display="flex" justifyContent="center" alignItems="center" flexGrow={1}>
                  <Typography variant="body2" color="error">
                    Failed to load status
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ height: 200, display: 'flex', flexDirection: 'column' }}>
            <CardContent sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <StorageIcon sx={{ mr: 1, color: theme.palette.primary.main }} />
                <Typography variant="h6">Analytics</Typography>
              </Box>
              {loading && !systemStatus ? (
                <Box display="flex" justifyContent="center" alignItems="center" flexGrow={1}>
                  <CircularProgress size={24} />
                </Box>
              ) : systemStatus ? (
                <Box flexGrow={1}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1.5 }}>
                    <Typography variant="body2">Total Binaries:</Typography>
                    <Typography variant="h6" color="primary">{systemStatus.binaries}</Typography>
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1.5 }}>
                    <Typography variant="body2">Total Tasks:</Typography>
                    <Typography variant="h6" color="secondary">{systemStatus.tasks.total}</Typography>
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1.5 }}>
                    <Typography variant="body2">Active Tasks:</Typography>
                    <Typography variant="h6" color="warning.main">
                      {systemStatus.tasks.running + systemStatus.tasks.queued}
                    </Typography>
                  </Box>
                </Box>
              ) : (
                <Box display="flex" justifyContent="center" alignItems="center" flexGrow={1}>
                  <Typography variant="body2" color="error">
                    Failed to load analytics
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={4}>
          <Card sx={{ height: 200, display: 'flex', flexDirection: 'column' }}>
            <CardContent sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
              <Box display="flex" alignItems="center" mb={2}>
                <CloudUpload color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">Quick Actions</Typography>
              </Box>
              <Box flexGrow={1} display="flex" flexDirection="column" justifyContent="center" gap={1.5}>
                <Button 
                  variant="contained" 
                  fullWidth
                  onClick={handleUploadRedirect}
                  startIcon={<CloudUpload />}
                  sx={{ py: 1.5 }}
                >
                  Upload Binary
                </Button>
                <Button 
                  variant="outlined" 
                  fullWidth
                  onClick={() => navigate('/config')}
                  startIcon={<Settings />}
                  sx={{ py: 1.5 }}
                >
                  Configuration
                </Button>
                <Button 
                  variant="outlined" 
                  fullWidth
                  onClick={handleRefresh}
                  startIcon={<Refresh />}
                  sx={{ py: 1.5 }}
                  disabled={refreshing}
                >
                  {refreshing ? 'Refreshing...' : 'Refresh Data'}
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Two-Column Layout for Binaries and Tasks */}
      <Grid container spacing={2} sx={{ height: '60vh' }}>
        {/* Left Column - Binaries (wider) */}
        <Grid item xs={8} sx={{ height: '100%' }}>
          <Paper sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
            {/* Header */}
            <Box display="flex" justifyContent="space-between" alignItems="center" p={2}>
              <Typography variant="h6">
                Binaries ({binaries.length})
              </Typography>
              <Box display="flex" gap={1}>
                <Button
                  variant="contained"
                  startIcon={<CloudUpload />}
                  onClick={handleUploadRedirect}
                  size="small"
                >
                  Upload
                </Button>
                <Tooltip title="Refresh">
                  <IconButton size="small" onClick={handleRefresh} disabled={refreshing}>
                    {refreshing ? <CircularProgress size={20} /> : <Refresh />}
                  </IconButton>
                </Tooltip>
              </Box>
            </Box>

            {/* Binary Table */}
            <Box sx={{ flexGrow: 1, overflow: 'hidden' }}>
              {currentBinaries.length === 0 ? (
                <Box p={3} textAlign="center">
                  <Typography variant="body2" color="text.secondary">
                    No binaries uploaded yet
                  </Typography>
                  <Button
                    variant="outlined"
                    startIcon={<CloudUpload />}
                    onClick={handleUploadRedirect}
                    sx={{ mt: 2 }}
                  >
                    Upload Your First Binary
                  </Button>
                </Box>
              ) : (
                <TableContainer sx={{ height: '100%', overflow: 'auto' }}>
                  <Table stickyHeader size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Name</TableCell>
                        <TableCell>Size</TableCell>
                        <TableCell>Status</TableCell>
                        <TableCell>Uploaded</TableCell>
                        <TableCell align="center">Actions</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {currentBinaries.map((binary) => (
                        <TableRow key={binary.id} hover>
                          <TableCell>
                            <Typography 
                              variant="body2" 
                              sx={{ 
                                maxWidth: 200, 
                                overflow: 'hidden', 
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}
                              title={binary.original_filename}
                            >
                              {binary.original_filename}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" color="text.secondary">
                              {binary.file_size ? `${(binary.file_size / 1024 / 1024).toFixed(2)} MB` : 'Unknown'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {getAnalysisStatusChip(binary)}
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption" color="text.secondary">
                              {binary.upload_time ? new Date(binary.upload_time).toLocaleDateString() : 'Unknown'}
                            </Typography>
                          </TableCell>
                          <TableCell align="center">
                            {getAnalysisActions(binary)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Box>

            {/* Pagination */}
            {totalPages > 1 && (
              <Box sx={{ p: 2, borderTop: '1px solid', borderColor: 'divider' }}>
                <Box display="flex" justifyContent="center">
                  <Pagination
                    count={totalPages}
                    page={currentPage}
                    onChange={handlePageChange}
                    color="primary"
                    size="small"
                    showFirstButton
                    showLastButton
                  />
                </Box>
                <Typography variant="caption" color="text.secondary" textAlign="center" sx={{ display: 'block', mt: 1 }}>
                  Showing {startIndex + 1}-{Math.min(endIndex, binaries.length)} of {binaries.length} binaries
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Right Column - Tasks (narrower) */}
        <Grid item xs={4} sx={{ height: '100%' }}>
          <TaskProgress 
            showAll={true} 
            autoRefresh={true} 
            refreshIntervalMs={5000}
            showControls={true}
            maxHeight={window.innerHeight * 0.6}
            compact={true}
          />
        </Grid>
      </Grid>

      {/* Binary Details Dialog */}
      {selectedBinary && (
        <Dialog open={true} onClose={() => setSelectedBinary(null)} maxWidth="md" fullWidth>
          <DialogTitle>Binary Details</DialogTitle>
          <DialogContent>
            <Typography variant="body1"><strong>Name:</strong> {selectedBinary.original_filename}</Typography>
            <Typography variant="body1"><strong>Size:</strong> {selectedBinary.file_size ? `${(selectedBinary.file_size / 1024 / 1024).toFixed(2)} MB` : 'Unknown'}</Typography>
            <Typography variant="body1"><strong>Status:</strong> {selectedBinary.analysis_status}</Typography>
            <Typography variant="body1"><strong>Uploaded:</strong> {selectedBinary.upload_time ? new Date(selectedBinary.upload_time).toLocaleString() : 'Unknown'}</Typography>
            {selectedBinary.architecture && (
              <Typography variant="body1"><strong>Architecture:</strong> {selectedBinary.architecture}</Typography>
            )}
            {selectedBinary.mime_type && (
              <Typography variant="body1"><strong>MIME Type:</strong> {selectedBinary.mime_type}</Typography>
            )}
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setSelectedBinary(null)}>Close</Button>
            <Button onClick={() => handleViewBinary(selectedBinary)} variant="contained">
              View Full Details
            </Button>
          </DialogActions>
        </Dialog>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteConfirmOpen}
        onClose={handleDeleteCancel}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box display="flex" alignItems="center" gap={1}>
            <Delete color="error" />
            Confirm Delete
          </Box>
        </DialogTitle>
        <DialogContent>
          {binaryToDelete && (
            <>
              <Typography variant="body1" sx={{ mb: 2 }}>
                Are you sure you want to delete the binary <strong>{binaryToDelete.original_filename}</strong>?
              </Typography>
              
              {/* Show warning for processing binaries */}
              {(binaryToDelete.analysis_status === 'running' || binaryToDelete.analysis_status === 'analyzing') && (
                <Alert severity="warning" sx={{ mb: 2 }}>
                  <Typography variant="body2" fontWeight="bold">
                    This binary is currently being processed!
                  </Typography>
                  <Typography variant="body2">
                    All running tasks will be stopped before deletion.
                  </Typography>
                </Alert>
              )}
              
              <Typography variant="body2" color="text.secondary">
                This action will permanently delete:
              </Typography>
              <Typography variant="body2" color="text.secondary" component="ul" sx={{ mt: 1, ml: 2 }}>
                <li>The binary file and all associated data</li>
                <li>All analysis results and function data</li>
                <li>All decompiled code and AI explanations</li>
                <li>All task history and logs</li>
                <li>All security findings and vulnerability data</li>
                <li>All fuzzing harnesses and test data</li>
              </Typography>
              <Typography variant="body2" color="error" sx={{ mt: 2, fontWeight: 'bold' }}>
                This action cannot be undone.
              </Typography>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleDeleteCancel} disabled={deleting}>
            Cancel
          </Button>
          <Button 
            onClick={handleDeleteConfirm} 
            color="error" 
            variant="contained"
            disabled={deleting}
            startIcon={deleting ? <CircularProgress size={16} /> : <Delete />}
          >
            {deleting ? 'Deleting...' : 'Delete Permanently'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default Dashboard; 