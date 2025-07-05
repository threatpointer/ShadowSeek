import React, { useState, useEffect } from 'react';
import { 
  Card, 
  CardContent, 
  Typography, 
  Button, 
  Grid, 
  Alert,
  Box,
  Chip,
  CircularProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Container,
  useTheme,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  IconButton,
  Tooltip
} from '@mui/material';
import { 
  Warning, 
  Cancel, 
  Refresh, 
  Settings, 
  Storage,
  CheckCircle,
  Error as ErrorIcon,
  Memory as MemoryIcon,
  Delete,
  FolderDelete,
  ExpandMore,
  CleaningServices,
  RestoreFromTrash,
  TableChart,
  Assessment,
  Functions
} from '@mui/icons-material';
import { apiClient } from '../utils/api';
import { toast } from 'react-toastify';

interface SystemStatusData {
  task_counts: Record<string, number>;
  binary_counts: Record<string, number>;
  timestamp: string;
  ghidra_bridge_connected: boolean;
}

interface DatabaseStats {
  core_tables: Record<string, number>;
  binary_data: Record<string, number>;
  function_data: Record<string, number>;
  security_data: Record<string, number>;
  fuzzing_data: Record<string, number>;
  system_data: Record<string, number>;
  totals: Record<string, number>;
  grand_total: number;
}

const SystemManagement: React.FC = () => {
  const theme = useTheme();
  const [status, setStatus] = useState<SystemStatusData | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [bridgeConnected, setBridgeConnected] = useState<boolean>(false);
  const [bridgeChecking, setBridgeChecking] = useState<boolean>(false);
  const [databaseStats, setDatabaseStats] = useState<DatabaseStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(false);
  
  const [confirmDialog, setConfirmDialog] = useState<{
    open: boolean;
    title: string;
    message: string;
    action: () => void;
    severity?: 'warning' | 'error';
  }>({ open: false, title: '', message: '', action: () => {} });

  const fetchStatus = async () => {
    try {
      setLoading(true);
      const response = await apiClient.getSystemStatus();
      
      // Convert to the expected format
      const formattedStatus: SystemStatusData = {
        task_counts: {
          queued: response.tasks.queued,
          running: response.tasks.running,
          completed: 0,
          failed: 0
        },
        binary_counts: {
          pending: 0,
          analyzing: 0,
          completed: 0,
          failed: 0
        },
        timestamp: response.server_time,
        ghidra_bridge_connected: response.ghidra_bridge_connected
      };
      
      setStatus(formattedStatus);
      setBridgeConnected(response.ghidra_bridge_connected);
    } catch (error) {
      console.error('Error fetching system status:', error);
      toast.error('Failed to fetch system status');
      setBridgeConnected(false);
    } finally {
      setLoading(false);
    }
  };

  const fetchDatabaseStats = async () => {
    try {
      setStatsLoading(true);
      const stats = await apiClient.getSystemDatabaseStats();
      setDatabaseStats(stats);
    } catch (error) {
      console.error('Error fetching database stats:', error);
      toast.error('Failed to fetch database statistics');
    } finally {
      setStatsLoading(false);
    }
  };

  const checkBridgeStatus = async () => {
    try {
      setBridgeChecking(true);
      const connected = await apiClient.directMcpCheck();
      setBridgeConnected(connected);
    } catch (error) {
      console.error('Error checking bridge status:', error);
      setBridgeConnected(false);
      toast.error('Failed to check bridge status');
    } finally {
      setBridgeChecking(false);
    }
  };

  const showConfirmDialog = (title: string, message: string, action: () => void, severity: 'warning' | 'error' = 'warning') => {
    setConfirmDialog({ open: true, title, message, action, severity });
  };

  const handleConfirmClose = (confirmed: boolean) => {
    if (confirmed) {
      confirmDialog.action();
    }
    setConfirmDialog({ open: false, title: '', message: '', action: () => {} });
  };

  const cancelAllTasks = async () => {
    try {
      setActionLoading('cancel-all');
      await apiClient.cancelAllTasks();
      toast.success(`Successfully cancelled all tasks`);
      fetchStatus();
    } catch (error: any) {
      toast.error(`Failed to cancel tasks: ${error.response?.data?.error || error.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const resetCompleteSystem = async () => {
    try {
      setActionLoading('reset-complete');
      const result = await apiClient.resetCompleteSystem();
      
      toast.success(`Complete system reset successful! Deleted ${result.details.total_records} records.`);
      
      // Refresh all data
      fetchStatus();
      fetchDatabaseStats();
      
    } catch (error: any) {
      toast.error(`Failed to reset system: ${error.response?.data?.error || error.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const cleanDatabaseTable = async (tableName: string, displayName: string) => {
    try {
      setActionLoading(`clean-${tableName}`);
      const result = await apiClient.cleanDatabaseTable(tableName);
      
      if (result.total_deleted) {
        toast.success(`Cleaned ${displayName}: Deleted ${result.total_deleted} total records (${result.deleted_count} from ${displayName}, ${result.total_deleted - result.deleted_count} related).`);
      } else {
        toast.success(`Cleaned ${displayName}: Deleted ${result.deleted_count} records.`);
      }
      
      fetchDatabaseStats();
      fetchStatus();
      
    } catch (error: any) {
      toast.error(`Failed to clean ${displayName}: ${error.response?.data?.error || error.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const cleanSystemFiles = async () => {
    try {
      setActionLoading('clean-files');
      const result = await apiClient.cleanSystemFiles();
      
      toast.success(`Cleaned system files: Removed ${result.files_deleted} files from ${result.directories_cleaned.length} directories.`);
      
    } catch (error: any) {
      toast.error(`Failed to clean files: ${error.response?.data?.error || error.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleCancelAllTasks = () => {
    showConfirmDialog(
      'Cancel All Tasks',
      'Are you sure you want to cancel ALL queued and running tasks? This action cannot be undone.',
      cancelAllTasks
    );
  };

  const handleResetCompleteSystem = () => {
    showConfirmDialog(
      'Complete System Reset',
      'WARNING: This will DELETE ALL database entries and files, making the system completely fresh. Only essential configurations will be preserved. This action cannot be undone!',
      resetCompleteSystem,
      'error'
    );
  };

  const handleCleanTable = (tableName: string, displayName: string) => {
    showConfirmDialog(
      `Clean ${displayName}`,
      `Are you sure you want to delete all entries from the ${displayName} table? This action cannot be undone.`,
      () => cleanDatabaseTable(tableName, displayName),
      tableName === 'binaries' ? 'error' : 'warning'
    );
  };

  const handleCleanFiles = () => {
    showConfirmDialog(
      'Clean System Files',
      'Are you sure you want to delete all uploaded files and temporary files? This will remove all binary files from the system.',
      cleanSystemFiles,
      'warning'
    );
  };

  const handleRefresh = () => {
    fetchStatus();
    fetchDatabaseStats();
    checkBridgeStatus();
  };

  useEffect(() => {
    fetchStatus();
    fetchDatabaseStats();
    checkBridgeStatus();
    
    const interval = setInterval(() => {
      fetchStatus();
      fetchDatabaseStats();
    }, 60000);
    
    return () => clearInterval(interval);
  }, []);

  const getStatusColor = (status: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
    switch (status) {
      case 'queued':
      case 'processing':
        return 'warning';
      case 'completed':
        return 'success';
      case 'failed':
      case 'cancelled':
        return 'error';
      case 'analyzing':
        return 'info';
      default:
        return 'default';
    }
  };

  const renderTableStats = (title: string, data: Record<string, number>, icon: React.ReactNode, tableCategoryKey: string) => (
    <Accordion>
      <AccordionSummary expandIcon={<ExpandMore />}>
        <Box display="flex" alignItems="center" gap={1}>
          {icon}
          <Typography variant="h6">{title}</Typography>
          <Chip 
            label={databaseStats?.totals[tableCategoryKey] || 0} 
            size="small" 
            color="primary" 
          />
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Table</TableCell>
                <TableCell align="right">Records</TableCell>
                <TableCell align="center">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {Object.entries(data).map(([tableName, count]) => (
                <TableRow key={tableName}>
                  <TableCell>
                    <Typography variant="body2" sx={{ textTransform: 'capitalize' }}>
                      {tableName.replace(/_/g, ' ')}
                    </Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Chip 
                      label={count} 
                      size="small" 
                      color={count > 0 ? 'default' : 'success'}
                    />
                  </TableCell>
                  <TableCell align="center">
                    <Tooltip title={`Clean ${tableName.replace(/_/g, ' ')} table`}>
                      <IconButton
                        size="small"
                        onClick={() => handleCleanTable(tableName, tableName.replace(/_/g, ' '))}
                        disabled={count === 0 || actionLoading !== null}
                        color="error"
                      >
                        {actionLoading === `clean-${tableName}` ? (
                          <CircularProgress size={16} />
                        ) : (
                          <Delete fontSize="small" />
                        )}
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </AccordionDetails>
    </Accordion>
  );

  const hasStuckTasks = (status?.task_counts?.queued || 0) > 0 || (status?.task_counts?.running || 0) > 0;

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        System Management
      </Typography>
      
      <Box sx={{ mb: 3, display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
        <Button
          variant="outlined"
          onClick={handleRefresh}
          disabled={loading || bridgeChecking || statsLoading}
          startIcon={(loading || bridgeChecking || statsLoading) ? <CircularProgress size={16} /> : <Refresh />}
        >
          Refresh All
        </Button>
      </Box>

      <Grid container spacing={3}>
        {/* System Status */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <MemoryIcon sx={{ mr: 1, color: theme.palette.primary.main }} />
                <Typography variant="h6">System Status</Typography>
              </Box>
              
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                {bridgeChecking ? (
                  <CircularProgress size={20} />
                ) : bridgeConnected ? (
                  <CheckCircle sx={{ color: theme.palette.success.main }} />
                ) : (
                  <ErrorIcon sx={{ color: theme.palette.error.main }} />
                )}
                <Typography variant="body1" sx={{ ml: 1 }}>
                  Ghidra Bridge: {bridgeChecking ? 'Checking...' : bridgeConnected ? 'Connected' : 'Disconnected'}
                </Typography>
              </Box>

              {status && (
                <Box>
                  <Typography variant="body2" color="textSecondary" gutterBottom>
                    Active Tasks
                  </Typography>
                  <Box display="flex" gap={1} flexWrap="wrap">
                    <Chip 
                      label={`Queued: ${status.task_counts.queued}`} 
                      size="small" 
                      color={getStatusColor('queued')} 
                    />
                    <Chip 
                      label={`Running: ${status.task_counts.running}`} 
                      size="small" 
                      color={getStatusColor('running')} 
                    />
                  </Box>
                </Box>
              )}

              {!bridgeConnected && !bridgeChecking && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  Ghidra Bridge is not connected. Binary analysis will not work.
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Database Overview */}
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                <Storage sx={{ mr: 1, color: theme.palette.primary.main }} />
                <Typography variant="h6">Database Overview</Typography>
                {statsLoading && <CircularProgress size={20} sx={{ ml: 1 }} />}
              </Box>
              
              {databaseStats ? (
                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="textSecondary">Total Records</Typography>
                    <Typography variant="h5" color="primary">{databaseStats.grand_total}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="textSecondary">Core Tables</Typography>
                    <Typography variant="h6">{databaseStats.totals.core_total}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="textSecondary">Security Data</Typography>
                    <Typography variant="h6">{databaseStats.totals.security_data_total}</Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2" color="textSecondary">Fuzzing Data</Typography>
                    <Typography variant="h6">{databaseStats.totals.fuzzing_data_total}</Typography>
                  </Grid>
                </Grid>
              ) : (
                <Typography variant="body2" color="textSecondary">
                  Loading database statistics...
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* System Operations */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <Settings sx={{ mr: 1 }} />
                System Operations
              </Typography>

              {hasStuckTasks && (
                <Alert severity="warning" sx={{ mb: 3 }}>
                  <Typography variant="subtitle2">Stuck Tasks Detected</Typography>
                  <Typography variant="body2">
                    There are {(status?.task_counts?.queued || 0) + (status?.task_counts?.running || 0)} tasks that may be stuck.
                  </Typography>
                </Alert>
              )}

              <Box display="flex" gap={2} flexWrap="wrap">
                <Button
                  variant="contained"
                  color="warning"
                  onClick={handleCancelAllTasks}
                  disabled={actionLoading !== null}
                  startIcon={actionLoading === 'cancel-all' ? <CircularProgress size={16} /> : <Cancel />}
                >
                  Cancel All Tasks
                </Button>

                <Button
                  variant="contained"
                  color="info"
                  onClick={handleCleanFiles}
                  disabled={actionLoading !== null}
                  startIcon={actionLoading === 'clean-files' ? <CircularProgress size={16} /> : <FolderDelete />}
                >
                  Clean Files
                </Button>

                <Button
                  variant="contained"
                  color="error"
                  onClick={handleResetCompleteSystem}
                  disabled={actionLoading !== null}
                  startIcon={actionLoading === 'reset-complete' ? <CircularProgress size={16} /> : <RestoreFromTrash />}
                >
                  Complete Reset
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Database Management */}
        <Grid item xs={12}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
                <TableChart sx={{ mr: 1 }} />
                Database Management
              </Typography>

              {databaseStats ? (
                <Box>
                  {renderTableStats('Core Tables', databaseStats.core_tables, <Assessment />, 'core_total')}
                  {renderTableStats('Binary Data', databaseStats.binary_data, <Storage />, 'binary_data_total')}
                  {renderTableStats('Function Data', databaseStats.function_data, <Functions />, 'function_data_total')}
                  {renderTableStats('Security Data', databaseStats.security_data, <Warning />, 'security_data_total')}
                  {renderTableStats('Fuzzing Data', databaseStats.fuzzing_data, <CleaningServices />, 'fuzzing_data_total')}
                </Box>
              ) : (
                <Box display="flex" alignItems="center" justifyContent="center" py={4}>
                  <CircularProgress />
                  <Typography variant="body2" sx={{ ml: 2 }}>
                    Loading database statistics...
                  </Typography>
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {status && (
        <Typography variant="caption" color="text.secondary" sx={{ mt: 2, display: 'block' }}>
          Last updated: {new Date(status.timestamp).toLocaleString()}
        </Typography>
      )}

      {/* Confirmation Dialog */}
      <Dialog
        open={confirmDialog.open}
        onClose={() => handleConfirmClose(false)}
        aria-labelledby="confirm-dialog-title"
        aria-describedby="confirm-dialog-description"
      >
        <DialogTitle id="confirm-dialog-title" sx={{ 
          display: 'flex', 
          alignItems: 'center',
          color: confirmDialog.severity === 'error' ? 'error.main' : 'warning.main'
        }}>
          {confirmDialog.severity === 'error' ? <ErrorIcon sx={{ mr: 1 }} /> : <Warning sx={{ mr: 1 }} />}
          {confirmDialog.title}
        </DialogTitle>
        <DialogContent>
          <DialogContentText id="confirm-dialog-description">
            {confirmDialog.message}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => handleConfirmClose(false)} color="primary">
            Cancel
          </Button>
          <Button 
            onClick={() => handleConfirmClose(true)} 
            color={confirmDialog.severity === 'error' ? 'error' : 'warning'} 
            variant="contained"
          >
            Confirm
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
};

export default SystemManagement; 