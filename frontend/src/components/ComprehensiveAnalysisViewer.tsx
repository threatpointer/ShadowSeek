import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Card,
  CardContent,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  TextField,
  Chip,
  Alert,
  CircularProgress,
  Button,
  Grid,
  Accordion,
  AccordionSummary,
  AccordionDetails
} from '@mui/material';
import {
  ExpandMore,
  Refresh,
  Search,
  Memory,
  Code,
  AccountTree,
  Security,
  Functions,
  Storage,
  Link
} from '@mui/icons-material';
import { toast } from 'react-toastify';
import { apiClient } from '../utils/api';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div role="tabpanel" hidden={value !== index}>
    {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
  </div>
);

interface ComprehensiveAnalysisViewerProps {
  binaryId: string;
  open: boolean;
  onClose: () => void;
}

const ComprehensiveAnalysisViewer: React.FC<ComprehensiveAnalysisViewerProps> = ({
  binaryId,
  open,
  onClose
}) => {
  const [activeTab, setActiveTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysisData, setAnalysisData] = useState<any>(null);
  
  // Data for different tabs
  const [functionsData, setFunctionsData] = useState<any>({ data: [], pagination: null });
  const [instructionsData, setInstructionsData] = useState<any>({ data: [], pagination: null });
  const [stringsData, setStringsData] = useState<any>({ data: [], pagination: null });
  const [symbolsData, setSymbolsData] = useState<any>({ data: [], pagination: null });
  const [importsData, setImportsData] = useState<any>({ data: [], pagination: null });
  const [exportsData, setExportsData] = useState<any>({ data: [], pagination: null });
  const [memoryData, setMemoryData] = useState<any>({ data: [], pagination: null });
  const [xrefsData, setXrefsData] = useState<any>({ data: [], pagination: null });
  
  // Pagination and search states
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(25);
  const [searchTerm, setSearchTerm] = useState('');

  const dataTypes = [
    { key: 'functions', label: 'Functions', icon: <Functions />, state: functionsData, setState: setFunctionsData },
    { key: 'instructions', label: 'Instructions', icon: <Code />, state: instructionsData, setState: setInstructionsData },
    { key: 'strings', label: 'Strings', icon: <Storage />, state: stringsData, setState: setStringsData },
    { key: 'symbols', label: 'Symbols', icon: <AccountTree />, state: symbolsData, setState: setSymbolsData },
    { key: 'imports', label: 'Imports', icon: <Security />, state: importsData, setState: setImportsData },
    { key: 'exports', label: 'Exports', icon: <Security />, state: exportsData, setState: setExportsData },
    { key: 'memory-regions', label: 'Memory Regions', icon: <Memory />, state: memoryData, setState: setMemoryData },
    { key: 'cross-references', label: 'Cross References', icon: <Link />, state: xrefsData, setState: setXrefsData }
  ];

  useEffect(() => {
    if (open) {
      loadAnalysisOverview();
    }
  }, [open, binaryId]);

  useEffect(() => {
    if (open && activeTab >= 0) {
      loadTabData(activeTab);
    }
  }, [activeTab, page, rowsPerPage, searchTerm, open]);

  const loadAnalysisOverview = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const analysis = await apiClient.getComprehensiveAnalysis(binaryId);
      setAnalysisData(analysis);
    } catch (err: any) {
      setError('Failed to load comprehensive analysis data');
      console.error('Error loading analysis:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadTabData = async (tabIndex: number) => {
    if (tabIndex < 0 || tabIndex >= dataTypes.length) return;
    
    const dataType = dataTypes[tabIndex];
    setLoading(true);
    
    try {
      const result = await apiClient.getComprehensiveData(
        binaryId,
        dataType.key,
        page + 1,
        rowsPerPage,
        searchTerm
      );
      
      dataType.setState({
        data: result.data || [],
        pagination: result.pagination || null
      });
    } catch (err: any) {
      toast.error(`Failed to load ${dataType.label.toLowerCase()}`);
      console.error(`Error loading ${dataType.key}:`, err);
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
    setPage(0); // Reset page when changing tabs
    setSearchTerm(''); // Reset search when changing tabs
  };

  const handlePageChange = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleRowsPerPageChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const handleSearchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(event.target.value);
    setPage(0);
  };

  const renderFunctionsTable = (data: any[]) => (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Address</TableCell>
            <TableCell>Name</TableCell>
            <TableCell>Size</TableCell>
            <TableCell>Signature</TableCell>
            <TableCell>Status</TableCell>
            <TableCell>Parameters</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {data.map((func) => (
            <TableRow key={func.id}>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {func.address}
              </TableCell>
              <TableCell>{func.name || func.original_name || 'Unknown'}</TableCell>
              <TableCell>{func.size || 0} bytes</TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem', maxWidth: 300 }}>
                {func.signature ? func.signature.substring(0, 50) + (func.signature.length > 50 ? '...' : '') : 'N/A'}
              </TableCell>
              <TableCell>
                <Box display="flex" gap={0.5}>
                  {func.is_decompiled && <Chip label="Decompiled" size="small" color="success" />}
                  {func.is_external && <Chip label="External" size="small" color="info" />}
                  {func.is_thunk && <Chip label="Thunk" size="small" color="warning" />}
                </Box>
              </TableCell>
              <TableCell>{func.parameters?.length || 0}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderInstructionsTable = (data: any[]) => (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Address</TableCell>
            <TableCell>Mnemonic</TableCell>
            <TableCell>Operands</TableCell>
            <TableCell>Length</TableCell>
            <TableCell>Bytes</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {data.map((instr) => (
            <TableRow key={instr.id}>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {instr.address}
              </TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontWeight: 'bold' }}>
                {instr.mnemonic}
              </TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                {instr.operands?.join(', ') || ''}
              </TableCell>
              <TableCell>{instr.length}</TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
                {instr.bytes?.map((b: number) => b.toString(16).padStart(2, '0')).join(' ') || ''}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderStringsTable = (data: any[]) => (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Address</TableCell>
            <TableCell>Value</TableCell>
            <TableCell>Length</TableCell>
            <TableCell>Type</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {data.map((str) => (
            <TableRow key={str.id}>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {str.address}
              </TableCell>
              <TableCell sx={{ maxWidth: 400, wordBreak: 'break-word' }}>
                {str.value.length > 100 ? str.value.substring(0, 100) + '...' : str.value}
              </TableCell>
              <TableCell>{str.length}</TableCell>
              <TableCell>{str.string_type || str.type}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderSymbolsTable = (data: any[]) => (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Address</TableCell>
            <TableCell>Name</TableCell>
            <TableCell>Type</TableCell>
            <TableCell>Namespace</TableCell>
            <TableCell>Primary</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {data.map((symbol) => (
            <TableRow key={symbol.id}>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {symbol.address}
              </TableCell>
              <TableCell>{symbol.name}</TableCell>
              <TableCell>{symbol.symbol_type}</TableCell>
              <TableCell>{symbol.namespace}</TableCell>
              <TableCell>
                {symbol.is_primary && <Chip label="Primary" size="small" color="primary" />}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderImportsTable = (data: any[]) => (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Name</TableCell>
            <TableCell>Library</TableCell>
            <TableCell>Address</TableCell>
            <TableCell>Namespace</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {data.map((imp) => (
            <TableRow key={imp.id}>
              <TableCell sx={{ fontWeight: 'bold' }}>{imp.name}</TableCell>
              <TableCell>{imp.library}</TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {imp.address || 'N/A'}
              </TableCell>
              <TableCell>{imp.namespace}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderMemoryTable = (data: any[]) => (
    <TableContainer>
      <Table size="small">
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
          {data.map((region) => (
            <TableRow key={region.id}>
              <TableCell sx={{ fontWeight: 'bold' }}>{region.name}</TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {region.start_address}
              </TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {region.end_address}
              </TableCell>
              <TableCell>{(region.size / 1024).toFixed(1)} KB</TableCell>
              <TableCell>
                <Box display="flex" gap={0.5}>
                  {region.permissions?.read && <Chip label="R" size="small" color="info" />}
                  {region.permissions?.write && <Chip label="W" size="small" color="warning" />}
                  {region.permissions?.execute && <Chip label="X" size="small" color="error" />}
                </Box>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderXrefsTable = (data: any[]) => (
    <TableContainer>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>From Address</TableCell>
            <TableCell>To Address</TableCell>
            <TableCell>Type</TableCell>
            <TableCell>Operand Index</TableCell>
            <TableCell>Primary</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {data.map((xref) => (
            <TableRow key={xref.id}>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {xref.from_address}
              </TableCell>
              <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                {xref.to_address}
              </TableCell>
              <TableCell>{xref.reference_type}</TableCell>
              <TableCell>{xref.operand_index ?? 'N/A'}</TableCell>
              <TableCell>
                {xref.is_primary && <Chip label="Primary" size="small" color="primary" />}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );

  const renderTable = (tabIndex: number, data: any[]) => {
    switch (tabIndex) {
      case 0: return renderFunctionsTable(data);
      case 1: return renderInstructionsTable(data);
      case 2: return renderStringsTable(data);
      case 3: return renderSymbolsTable(data);
      case 4: return renderImportsTable(data);
      case 5: return renderImportsTable(data); // Exports use same structure as imports
      case 6: return renderMemoryTable(data);
      case 7: return renderXrefsTable(data);
      default: return <Typography>No data available</Typography>;
    }
  };

  if (!open) return null;

  return (
    <Paper sx={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, zIndex: 1300, overflow: 'auto' }}>
      <Box sx={{ p: 3 }}>
        <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
          <Typography variant="h4">
            🔍 Comprehensive Analysis Results
          </Typography>
          <Box display="flex" gap={2}>
            <Button variant="outlined" onClick={loadAnalysisOverview} startIcon={<Refresh />}>
              Refresh
            </Button>
            <Button variant="contained" onClick={onClose}>
              Close
            </Button>
          </Box>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error}
          </Alert>
        )}

        {/* Analysis Overview */}
        {analysisData && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom>
                📊 Analysis Overview
              </Typography>
              <Grid container spacing={2}>
                {analysisData.analysis?.statistics && Object.entries(analysisData.analysis.statistics).map(([key, value]) => (
                  <Grid item xs={6} md={3} key={key}>
                    <Box textAlign="center">
                      <Typography variant="h5" color="primary">
                        {String(value)}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                      </Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        )}

        {/* Data Tabs */}
        <Card>
          <Tabs
            value={activeTab}
            onChange={handleTabChange}
            variant="scrollable"
            scrollButtons="auto"
            sx={{ borderBottom: 1, borderColor: 'divider' }}
          >
            {dataTypes.map((dataType, index) => (
              <Tab
                key={dataType.key}
                label={
                  <Box display="flex" alignItems="center" gap={1}>
                    {dataType.icon}
                    {dataType.label}
                  </Box>
                }
              />
            ))}
          </Tabs>

          {dataTypes.map((dataType, index) => (
            <TabPanel key={dataType.key} value={activeTab} index={index}>
              <Box mb={2}>
                <TextField
                  size="small"
                  placeholder={`Search ${dataType.label.toLowerCase()}...`}
                  value={searchTerm}
                  onChange={handleSearchChange}
                  InputProps={{
                    startAdornment: <Search sx={{ mr: 1, color: 'text.secondary' }} />
                  }}
                  sx={{ minWidth: 300 }}
                />
              </Box>

              {loading ? (
                <Box display="flex" justifyContent="center" p={4}>
                  <CircularProgress />
                </Box>
              ) : (
                <>
                  {renderTable(index, dataType.state.data)}
                  
                  {dataType.state.pagination && (
                    <TablePagination
                      component="div"
                      count={dataType.state.pagination.total}
                      page={page}
                      onPageChange={handlePageChange}
                      rowsPerPage={rowsPerPage}
                      onRowsPerPageChange={handleRowsPerPageChange}
                      rowsPerPageOptions={[10, 25, 50, 100]}
                    />
                  )}
                </>
              )}
            </TabPanel>
          ))}
        </Card>
      </Box>
    </Paper>
  );
};

export default ComprehensiveAnalysisViewer; 