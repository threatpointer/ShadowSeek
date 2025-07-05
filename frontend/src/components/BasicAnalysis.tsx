import React, { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  Card,
  CardContent,
  Grid,
  Alert,
  CircularProgress,
  List,
  ListItem,
  ListItemText,
  Divider,
  Chip
} from '@mui/material';
import { PlayArrow, Check } from '@mui/icons-material';
import { toast } from 'react-toastify';
import { apiClient } from '../utils/api';

interface BasicAnalysisProps {
  binaryId: string;
  binaryDetails: any;
  onAnalysisComplete?: () => void;
}

const BasicAnalysis: React.FC<BasicAnalysisProps> = ({ 
  binaryId, 
  binaryDetails, 
  onAnalysisComplete 
}) => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleStartBasicAnalysis = async () => {
    try {
      setIsAnalyzing(true);
      setError(null);
      
      await apiClient.startAnalysis(binaryId, {
        analysis_type: 'basic'
      });
      
      toast.success('Basic analysis started successfully');
      
      // Poll for completion
      const checkInterval = setInterval(async () => {
        try {
          const details = await apiClient.getBinaryDetails(binaryId);
          
          if (details.binary.analysis_status === 'Completed' || details.binary.analysis_status === 'processed') {
            clearInterval(checkInterval);
            setIsAnalyzing(false);
            toast.success('Basic analysis completed!');
            
            if (onAnalysisComplete) {
              onAnalysisComplete();
            }
          } else if (details.binary.analysis_status === 'Failed' || details.binary.analysis_status === 'failed') {
            clearInterval(checkInterval);
            setIsAnalyzing(false);
            setError('Analysis failed');
            toast.error('Basic analysis failed');
          }
        } catch (err) {
          console.error('Error checking analysis status:', err);
        }
      }, 3000);
      
      // Stop polling after 10 minutes
      setTimeout(() => {
        clearInterval(checkInterval);
        setIsAnalyzing(false);
      }, 600000);
      
    } catch (err: any) {
      setIsAnalyzing(false);
      setError(err.response?.data?.error || 'Failed to start basic analysis');
      toast.error('Failed to start basic analysis');
    }
  };

  const getAnalysisStatusColor = (status: string) => {
    switch (status) {
      case 'Completed':
      case 'processed': return 'success';
      case 'Analyzed': return 'info';
      case 'Decompiled': return 'secondary';
      case 'Analyzing':
      case 'analyzing': return 'warning';
      case 'Failed':
      case 'failed': return 'error';
      case 'Pending':
      case 'pending': return 'primary';
      default: return 'default';
    }
  };

  const renderAnalysisOverview = () => {
    if (!binaryDetails) return null;

    const { binary, functions = [], results = [] } = binaryDetails;
    const basicAnalysisResult = results.find((r: any) => r.analysis_type === 'basic_analysis');

    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Current Analysis Status
          </Typography>
          
          <Grid container spacing={2}>
            <Grid item xs={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Status
              </Typography>
              <Chip 
                label={binary.analysis_status || 'unknown'}
                color={getAnalysisStatusColor(binary.analysis_status)}
                size="small"
              />
            </Grid>
            
            <Grid item xs={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Functions Found
              </Typography>
              <Typography variant="body1">
                {functions.length}
              </Typography>
            </Grid>
            
            {binary.architecture && (
              <Grid item xs={6}>
                <Typography variant="subtitle2" color="text.secondary">
                  Architecture
                </Typography>
                <Typography variant="body1">
                  {binary.architecture}
                </Typography>
              </Grid>
            )}
            
            {basicAnalysisResult && (
              <Grid item xs={6}>
                <Typography variant="subtitle2" color="text.secondary">
                  Last Analysis
                </Typography>
                <Typography variant="body1">
                  {new Date(basicAnalysisResult.created_at).toLocaleString()}
                </Typography>
              </Grid>
            )}
          </Grid>
        </CardContent>
      </Card>
    );
  };

  const renderAnalysisActions = () => {
    const canAnalyze = !isAnalyzing;
    const hasExistingAnalysis = binaryDetails?.binary?.analysis_status === 'Completed' || 
                              binaryDetails?.binary?.analysis_status === 'processed' ||
                              binaryDetails?.binary?.analysis_status === 'Analyzed' ||
                              binaryDetails?.binary?.analysis_status === 'Decompiled';

    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Basic Analysis Actions
          </Typography>
          
          <Typography variant="body2" color="text.secondary" paragraph>
            Basic analysis extracts fundamental information from the binary including:
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemText primary="Program metadata (name, architecture, compiler)" />
            </ListItem>
            <ListItem>
              <ListItemText primary="Function identification and basic properties" />
            </ListItem>
            <ListItem>
              <ListItemText primary="Import and export tables" />
            </ListItem>
            <ListItem>
              <ListItemText primary="Memory layout and sections" />
            </ListItem>
            <ListItem>
              <ListItemText primary="Basic string extraction" />
            </ListItem>
          </List>
          
          <Divider sx={{ my: 2 }} />
          
          <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
            <Button
              variant="contained"
              startIcon={isAnalyzing ? <CircularProgress size={20} /> : <PlayArrow />}
              onClick={handleStartBasicAnalysis}
              disabled={!canAnalyze}
              color="primary"
            >
              {isAnalyzing ? 'Analyzing...' : hasExistingAnalysis ? 'Re-run Basic Analysis' : 'Start Basic Analysis'}
            </Button>
            
            {hasExistingAnalysis && (
              <Chip 
                icon={<Check />}
                label="Previously Analyzed"
                color="success"
                variant="outlined"
                size="small"
              />
            )}
          </Box>
          
          {isAnalyzing && (
            <Alert severity="info" sx={{ mt: 2 }}>
              Basic analysis is running. This typically takes 1-3 minutes depending on binary size.
            </Alert>
          )}
        </CardContent>
      </Card>
    );
  };

  const renderAnalysisResults = () => {
    if (!binaryDetails?.functions?.length) return null;

    const { functions } = binaryDetails;
    const libraryFunctions = functions.filter((f: any) => f.is_external).length;
    const userFunctions = functions.length - libraryFunctions;

    return (
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom>
            Analysis Results Summary
          </Typography>
          
          <Grid container spacing={3}>
            <Grid item xs={6} md={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="primary.main">
                  {functions.length}
                </Typography>
                <Typography variant="subtitle2" color="text.secondary">
                  Total Functions
                </Typography>
              </Box>
            </Grid>
            
            <Grid item xs={6} md={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="success.main">
                  {userFunctions}
                </Typography>
                <Typography variant="subtitle2" color="text.secondary">
                  User Functions
                </Typography>
              </Box>
            </Grid>
            
            <Grid item xs={6} md={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="warning.main">
                  {libraryFunctions}
                </Typography>
                <Typography variant="subtitle2" color="text.secondary">
                  Library Functions
                </Typography>
              </Box>
            </Grid>
            
            <Grid item xs={6} md={3}>
              <Box textAlign="center">
                <Typography variant="h4" color="info.main">
                  {functions.filter((f: any) => f.size > 0).length}
                </Typography>
                <Typography variant="subtitle2" color="text.secondary">
                  Sized Functions
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </CardContent>
      </Card>
    );
  };

  return (
    <Box>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      
      <Grid container spacing={3}>
        <Grid item xs={12}>
          {renderAnalysisOverview()}
        </Grid>
        
        <Grid item xs={12}>
          {renderAnalysisActions()}
        </Grid>
        
        {binaryDetails?.functions?.length > 0 && (
          <Grid item xs={12}>
            {renderAnalysisResults()}
          </Grid>
        )}
      </Grid>
    </Box>
  );
};

export default BasicAnalysis; 