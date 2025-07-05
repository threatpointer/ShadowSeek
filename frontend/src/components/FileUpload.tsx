import React, { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import {
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Container,
  Grid,
  LinearProgress,
  Paper,
  Typography,
  useTheme
} from '@mui/material';
import {
  CloudUpload as CloudUploadIcon, 
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  InsertDriveFile as FileIcon
} from '@mui/icons-material';
import { apiClient, formatFileSize } from '../utils/api';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';

  interface UploadingFile {
    file: File;
    progress: number;
    status: 'uploading' | 'success' | 'error' | 'analyzing';
    error?: string;
    binary_id?: string;
    auto_analysis?: { 
      status: string; 
      task_id?: string; 
      analysis_type?: string; 
      error?: string; 
    };
  }

const FileUpload: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [uploadingFiles, setUploadingFiles] = useState<UploadingFile[]>([]);
  const [isUploading, setIsUploading] = useState(false);

  const startAnalysis = async (binaryId: string, fileName: string) => {
    try {
      // Update file status to analyzing
      setUploadingFiles(prev => 
        prev.map(f => 
          f.binary_id === binaryId 
            ? { ...f, status: 'analyzing' } 
            : f
        )
      );
      
      // Start basic analysis (comprehensive analysis is now automatic)
      await apiClient.startAnalysis(binaryId);
      
      toast.success(`Analysis started for ${fileName}`);
      
      // Navigate to binary details
      navigate(`/binary/${binaryId}`);
    } catch (error) {
      console.error('Analysis error:', error);
      toast.error(`Failed to start analysis for ${fileName}`);
      
      // Update file status back to success
      setUploadingFiles(prev => 
        prev.map(f => 
          f.binary_id === binaryId 
            ? { ...f, status: 'success' } 
            : f
        )
      );
    }
  };

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;
    
    setIsUploading(true);
    
    // Add files to the uploading list
    const newUploadingFiles: UploadingFile[] = acceptedFiles.map(file => ({
      file,
      progress: 0,
      status: 'uploading'
    }));
    
    setUploadingFiles(prev => [...prev, ...newUploadingFiles]);
    
    // Upload each file
    for (const uploadFile of newUploadingFiles) {
      try {
        const response = await apiClient.uploadBinary(
          uploadFile.file,
          (progress) => {
            setUploadingFiles(prev => 
              prev.map(f => 
                f.file === uploadFile.file 
                ? { ...f, progress }
                : f
              )
            );
          }
        );

        const binaryId = response.binary?.id;
        const autoAnalysis = (response as any).auto_analysis;
        
        // Update file status based on upload and auto-analysis result
        let status: UploadingFile['status'] = 'success';
        let message = `${uploadFile.file.name} uploaded successfully!`;
        
        if (autoAnalysis?.status === 'started') {
          status = 'analyzing';
          message = `${uploadFile.file.name} uploaded and comprehensive analysis started!`;
          toast.success(message);
        } else if (autoAnalysis?.status === 'failed') {
          message = `${uploadFile.file.name} uploaded but automatic analysis failed to start`;
          toast.warning(message);
        } else {
          toast.success(message);
        }
        
        // Update file status
        setUploadingFiles(prev => 
          prev.map(f => 
            f.file === uploadFile.file 
            ? { 
                ...f, 
                status: status, 
                progress: 100,
                binary_id: binaryId,
                auto_analysis: autoAnalysis
              }
            : f
          )
        );

        // Navigate to binary details immediately if comprehensive analysis started
        if (binaryId && autoAnalysis?.status === 'started') {
          // Small delay to allow user to see the success message
          setTimeout(() => {
            navigate(`/binary/${binaryId}`);
          }, 1500);
        } else if (binaryId) {
          // Manual analysis trigger option for failed auto-analysis
          console.log('Auto-analysis failed, user can manually start analysis');
        }
        
      } catch (error) {
        console.error('Upload error:', error);
        toast.error(`Failed to upload ${uploadFile.file.name}`);
        
        // Update file status to error
        setUploadingFiles(prev => 
          prev.map(f => 
            f.file === uploadFile.file 
            ? { ...f, status: 'error', progress: 0 }
            : f
          )
        );
      }
    }
    
    setIsUploading(false);
  }, [navigate]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ 
    onDrop,
    accept: {
      'application/x-msdownload': ['.exe', '.dll'],
      'application/x-executable': ['.so', '.bin', '.elf'],
      'application/octet-stream': ['.dylib']
    },
    disabled: isUploading,
    multiple: true
  });
  
  const viewBinary = (binaryId: string) => {
    navigate(`/binary/${binaryId}`);
  };

  return (
    <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
      <Typography variant="h4" gutterBottom>
        Upload Binary Files
      </Typography>
      
      <Paper
        {...getRootProps()}
        sx={{
          p: 3,
          mb: 3,
          border: '2px dashed',
          borderColor: isDragActive ? 'primary.main' : 'divider',
          backgroundColor: isDragActive ? 'action.hover' : 'background.paper',
          cursor: isUploading ? 'not-allowed' : 'pointer',
          textAlign: 'center',
          transition: 'all 0.2s ease'
        }}
      >
        <input {...getInputProps()} />
        <CloudUploadIcon sx={{ fontSize: 48, mb: 2, color: 'primary.main' }} />
        <Typography variant="h6">
          {isDragActive ? 'Drop the files here' : 'Drag and drop binary files here, or click to select files'}
          </Typography>
        <Typography variant="body2" color="textSecondary">
          Supported file types: .exe, .dll, .so, .dylib, .bin, .elf
            </Typography>
        {isUploading && (
          <CircularProgress size={24} sx={{ mt: 2 }} />
        )}
      </Paper>

      {uploadingFiles.length > 0 && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Upload Progress
            </Typography>
            
            <Grid container spacing={2}>
              {uploadingFiles.map((file, index) => (
                <Grid item xs={12} key={index}>
                  <Box sx={{ 
                    p: 2, 
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 1,
                    mb: 1
                  }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      <FileIcon sx={{ mr: 1 }} />
                      <Typography variant="body1" noWrap sx={{ flexGrow: 1 }}>
                        {file.file.name}
                      </Typography>
                      <Typography variant="body2" color="textSecondary">
                        {formatFileSize(file.file.size)}
                      </Typography>
          </Box>
          
                    {file.status === 'uploading' && (
                      <Box sx={{ width: '100%' }}>
                        <LinearProgress 
                          variant="determinate" 
                          value={file.progress * 100} 
                          sx={{ mb: 1 }}
                        />
                        <Typography variant="body2" color="textSecondary" align="right">
                          {Math.round(file.progress * 100)}%
                        </Typography>
                      </Box>
                    )}
                    
                    {file.status === 'analyzing' && (
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <CircularProgress size={20} sx={{ mr: 1 }} />
                          <Typography variant="body2" color="primary">
                            Starting analysis...
                        </Typography>
                        </Box>
                        <Button 
                          variant="outlined" 
                          size="small"
                          onClick={() => file.binary_id && viewBinary(file.binary_id)}
                        >
                          View Details
                        </Button>
                      </Box>
                    )}
                    
                    {file.status === 'success' && (
                      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center' }}>
                          <CheckCircleIcon sx={{ color: 'success.main', mr: 1 }} />
                          <Typography variant="body2" color="success.main">
                            Upload complete
                            </Typography>
                          </Box>
                        <Box>
                            <Button
                            variant="contained" 
                              size="small"
                            onClick={() => file.binary_id && startAnalysis(file.binary_id, file.file.name)}
                            sx={{ mr: 1 }}
                          >
                            Analyze
                          </Button>
                          <Button 
                              variant="outlined"
                            size="small"
                            onClick={() => file.binary_id && viewBinary(file.binary_id)}
                            >
                              View Details
                            </Button>
                          </Box>
                      </Box>
                    )}
                    
                    {file.status === 'error' && (
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <ErrorIcon sx={{ color: 'error.main', mr: 1 }} />
                        <Typography variant="body2" color="error">
                          {file.error || 'Upload failed'}
                        </Typography>
                      </Box>
          )}
        </Box>
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      )}
    </Container>
  );
};

export default FileUpload; 