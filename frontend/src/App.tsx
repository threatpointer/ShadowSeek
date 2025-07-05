import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, AppBar, Toolbar, Typography, Button, Box } from '@mui/material';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

// Components
import Dashboard from './components/Dashboard';
import FileUpload from './components/FileUpload';
import AnalysisResults from './components/AnalysisResults';
import Configuration from './components/Configuration';
import BinaryDetails from './components/BinaryDetails';
import BinaryComparison from './components/BinaryComparison';
import ShadowSeekVulnerabilityDashboard from './components/VulnerabilityDashboard';
import FuzzingDashboard from './components/FuzzingDashboard';
import SystemManagement from './components/SystemManagement';
import DocumentationViewer from './components/DocumentationViewer';

// Theme configuration
const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00bcd4',
    },
    secondary: {
      main: '#ff9800',
    },
    background: {
      default: '#121212',
      paper: '#1e1e1e',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h4: {
      fontWeight: 600,
    },
    h6: {
      fontWeight: 500,
    },
  },
  components: {
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#1e1e1e',
          borderBottom: '1px solid #333',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: 'none',
        },
      },
    },
  },
});

const App: React.FC = () => {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Box sx={{ flexGrow: 1 }}>
          <AppBar position="static" elevation={0}>
            <Toolbar>
              <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                🔍 ShadowSeek
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, mr: 2 }}>
                <Button 
                  color="inherit" 
                  href="/" 
                  sx={{ color: 'inherit', textDecoration: 'none', cursor: 'pointer' }}
                >
                  Dashboard
                </Button>
                <Button 
                  color="inherit" 
                  href="/upload" 
                  sx={{ color: 'inherit', textDecoration: 'none', cursor: 'pointer' }}
                >
                  Upload
                </Button>
                <Button 
                  color="inherit" 
                  href="/comparison" 
                  sx={{ color: 'inherit', textDecoration: 'none', cursor: 'pointer' }}
                >
                  Compare
                </Button>
                <Button 
                  color="inherit" 
                  href="/vulnerabilities" 
                  sx={{ color: 'inherit', textDecoration: 'none', cursor: 'pointer' }}
                >
                  Security Hub
                </Button>
                <Button 
                  color="inherit" 
                  href="/fuzzing" 
                  sx={{ color: 'inherit', textDecoration: 'none', cursor: 'pointer' }}
                >
                  Fuzzing
                </Button>
                <Button 
                  color="inherit" 
                  href="/docs" 
                  sx={{ color: 'inherit', textDecoration: 'none', cursor: 'pointer' }}
                >
                  Documentation
                </Button>
                <Button 
                  color="inherit" 
                  href="/config" 
                  sx={{ color: 'inherit', textDecoration: 'none', cursor: 'pointer' }}
                >
                  Config
                </Button>
                <Button 
                  color="inherit" 
                  href="/system" 
                  sx={{ color: 'inherit', textDecoration: 'none', cursor: 'pointer' }}
                >
                  System
                </Button>
              </Box>
              <Typography variant="body2" sx={{ opacity: 0.7 }}>
                v1.0.0
              </Typography>
            </Toolbar>
          </AppBar>
          
          <Box component="main">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/upload" element={<FileUpload />} />
              <Route path="/binary/:binaryId" element={<BinaryDetails />} />
              <Route path="/analysis/:resultId" element={<AnalysisResults />} />
              <Route path="/comparison" element={<BinaryComparison />} />
              <Route path="/vulnerabilities" element={<ShadowSeekVulnerabilityDashboard />} />
              <Route path="/fuzzing" element={<FuzzingDashboard />} />
              <Route path="/docs" element={<DocumentationViewer />} />
              <Route path="/docs/*" element={<DocumentationViewer />} />
              <Route path="/config" element={<Configuration />} />
              <Route path="/binaries/:id/compare" element={<BinaryComparison />} />
              <Route path="/system" element={<SystemManagement />} />
            </Routes>
          </Box>
        </Box>
        
        <ToastContainer
          position="bottom-right"
          autoClose={5000}
          hideProgressBar={false}
          newestOnTop={false}
          closeOnClick
          rtl={false}
          pauseOnFocusLoss
          draggable
          pauseOnHover
          theme="dark"
        />
      </Router>
    </ThemeProvider>
  );
};

export default App; 