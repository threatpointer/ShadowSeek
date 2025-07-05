import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Card,
  CardContent,
  CardActions,
  Alert,
  Switch,
  FormControlLabel,
  Divider,
  Chip,
  LinearProgress,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Tabs,
  Tab,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  Save,
  Refresh,
  Settings,
  Storage,
  Memory,
  Speed,
  Psychology,
  Cloud,
  Computer,
  Visibility,
  VisibilityOff,
  Science
} from '@mui/icons-material';
import { toast } from 'react-toastify';
import { apiClient, Configuration as ConfigurationType } from '../utils/api';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <div hidden={value !== index}>
    {value === index && <Box sx={{ p: 2 }}>{children}</Box>}
  </div>
);

const Configuration: React.FC = () => {
  const [config, setConfig] = useState<ConfigurationType>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const [showApiKeys, setShowApiKeys] = useState<{[key: string]: boolean}>({});
  const [testingConnection, setTestingConnection] = useState<{[key: string]: boolean}>({});

  useEffect(() => {
    fetchConfiguration();
  }, []);

  const fetchConfiguration = async () => {
    try {
      setLoading(true);
      const configuration = await apiClient.getConfiguration();
      setConfig(configuration);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to fetch configuration');
      console.error('Error fetching configuration:', err);
    } finally {
      setLoading(false);
    }
  };

  const saveConfiguration = async () => {
    try {
      setSaving(true);
      await apiClient.updateConfiguration(config);
      toast.success('Configuration saved successfully');
      setError(null);
    } catch (err: any) {
      const errorMessage = err.response?.data?.error || 'Failed to save configuration';
      setError(errorMessage);
      toast.error(errorMessage);
      console.error('Error saving configuration:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleConfigChange = (key: string, value: any) => {
    setConfig(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const toggleApiKeyVisibility = (provider: string) => {
    setShowApiKeys(prev => ({
      ...prev,
      [provider]: !prev[provider]
    }));
  };

  const testLLMConnection = async (provider: string) => {
    setTestingConnection(prev => ({ ...prev, [provider]: true }));
    
    try {
      let testData = {};
      
      if (provider === 'OpenAI') {
        testData = {
          provider: 'openai',
          api_key: config.openai_api_key,
          model: config.openai_model,
          base_url: config.openai_base_url
        };
      } else if (provider === 'Gemini') {
        testData = {
          provider: 'gemini',
          api_key: config.gemini_api_key,
          model: config.gemini_model
        };
      } else if (provider === 'Claude') {
        testData = {
          provider: 'claude',
          api_key: config.claude_api_key,
          model: config.claude_model
        };
      }
      
      const response = await apiClient.testAIConnection(testData);
      toast.success(response.message || `${provider} connection test successful!`);
    } catch (err: any) {
      const errorMessage = err.response?.data?.error || `${provider} connection test failed`;
      toast.error(errorMessage);
    } finally {
      setTestingConnection(prev => ({ ...prev, [provider]: false }));
    }
  };

  const resetToDefaults = () => {
    setConfig({
      // Ghidra Settings
      ghidra_install_dir: process.platform === 'win32' 
        ? 'D:\\Ghidra\\ghidra_11.3_PUBLIC' 
        : '/opt/ghidra',
      ghidra_bridge_port: 4768,
      ghidra_max_processes: 4,
      ghidra_timeout: 3600,
      
      // Server Settings
      flask_host: '127.0.0.1',
      flask_port: 5000,
      max_file_size: 1073741824,
      upload_folder: './uploads',
      temp_folder: './temp',
      
      // Analysis Settings
      analysis_timeout: 1800,
      max_concurrent_analyses: 2,
      enable_debug_logging: false,
      auto_cleanup_temp_files: true,
      
      // LLM Settings
      llm_provider: 'openai',
      openai_api_key: '',
      openai_model: 'gpt-3.5-turbo',
      openai_base_url: 'https://api.openai.com/v1',
      gemini_api_key: '',
      gemini_model: 'gemini-pro',
      claude_api_key: '',
      claude_model: 'claude-3-sonnet-20240229',
      ollama_base_url: 'http://localhost:11434',
      ollama_model: 'llama2',
      llm_timeout: 60,
      llm_max_tokens: 1500,
      llm_temperature: 0.3
    });
    toast.info('Configuration reset to defaults');
  };

  if (loading) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" height="400px">
        <LinearProgress sx={{ width: '50%' }} />
      </Box>
    );
  }

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">
          Configuration
        </Typography>
        <Box>
          <Button
            variant="outlined"
            onClick={resetToDefaults}
            sx={{ mr: 1 }}
          >
            Reset to Defaults
          </Button>
          <Button
            variant="outlined"
            onClick={fetchConfiguration}
            startIcon={<Refresh />}
            sx={{ mr: 1 }}
          >
            Refresh
          </Button>
          <Button
            variant="contained"
            onClick={saveConfiguration}
            disabled={saving}
            startIcon={<Save />}
          >
            {saving ? 'Saving...' : 'Save Configuration'}
          </Button>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Paper>
        <Tabs value={tabValue} onChange={(_, newValue) => setTabValue(newValue)}>
          <Tab label="AI/LLM Settings" icon={<Psychology />} />
          <Tab label="Ghidra Settings" icon={<Memory />} />
          <Tab label="System Settings" icon={<Settings />} />
          <Tab label="Analysis Settings" icon={<Speed />} />
        </Tabs>

        <TabPanel value={tabValue} index={0}>
          {/* AI/LLM Configuration */}
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={3}>
                    <Psychology color="primary" sx={{ mr: 1 }} />
                    <Typography variant="h6">
                      AI Provider Selection
                    </Typography>
                  </Box>
                  
                  <FormControl fullWidth margin="normal">
                    <InputLabel>Primary LLM Provider</InputLabel>
                    <Select
                      value={config.llm_provider || 'openai'}
                      onChange={(e) => handleConfigChange('llm_provider', e.target.value)}
                      label="Primary LLM Provider"
                    >
                      <MenuItem value="openai">
                        <Box display="flex" alignItems="center">
                          <Cloud sx={{ mr: 1 }} />
                          OpenAI (GPT-3.5/GPT-4)
                        </Box>
                      </MenuItem>
                      <MenuItem value="gemini">
                        <Box display="flex" alignItems="center">
                          <Cloud sx={{ mr: 1 }} />
                          Google Gemini
                        </Box>
                      </MenuItem>
                      <MenuItem value="claude">
                        <Box display="flex" alignItems="center">
                          <Cloud sx={{ mr: 1 }} />
                          Anthropic Claude
                        </Box>
                      </MenuItem>
                      <MenuItem value="ollama">
                        <Box display="flex" alignItems="center">
                          <Computer sx={{ mr: 1 }} />
                          Ollama (Local)
                        </Box>
                      </MenuItem>
                    </Select>
                  </FormControl>
                </CardContent>
              </Card>
            </Grid>

            {/* OpenAI Configuration */}
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                    <Box display="flex" alignItems="center">
                      <Cloud color="primary" sx={{ mr: 1 }} />
                      <Typography variant="h6">OpenAI</Typography>
                    </Box>
                    <Chip 
                      label={config.llm_provider === 'openai' ? 'Active' : 'Available'} 
                      color={config.llm_provider === 'openai' ? 'primary' : 'default'}
                      size="small"
                    />
                  </Box>
                  
                  <TextField
                    fullWidth
                    label="API Key"
                    type={showApiKeys.openai ? 'text' : 'password'}
                    value={config.openai_api_key || ''}
                    onChange={(e) => handleConfigChange('openai_api_key', e.target.value)}
                    margin="normal"
                    helperText="Get your API key from https://platform.openai.com/"
                    InputProps={{
                      endAdornment: (
                        <IconButton onClick={() => toggleApiKeyVisibility('openai')}>
                          {showApiKeys.openai ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      )
                    }}
                  />
                  
                  <FormControl fullWidth margin="normal">
                    <InputLabel>Model</InputLabel>
                    <Select
                      value={config.openai_model || 'gpt-3.5-turbo'}
                      onChange={(e) => handleConfigChange('openai_model', e.target.value)}
                      label="Model"
                    >
                      <MenuItem value="gpt-3.5-turbo">GPT-3.5 Turbo (Fast)</MenuItem>
                      <MenuItem value="gpt-4">GPT-4 (Advanced)</MenuItem>
                      <MenuItem value="gpt-4-turbo">GPT-4 Turbo</MenuItem>
                    </Select>
                  </FormControl>
                  
                  <TextField
                    fullWidth
                    label="Base URL"
                    value={config.openai_base_url || 'https://api.openai.com/v1'}
                    onChange={(e) => handleConfigChange('openai_base_url', e.target.value)}
                    margin="normal"
                    helperText="For OpenAI-compatible APIs"
                  />

                  <Box mt={2}>
                    <Button
                      variant="outlined"
                      startIcon={testingConnection.openai ? <LinearProgress /> : <Science />}
                      onClick={() => testLLMConnection('OpenAI')}
                      disabled={testingConnection.openai || !config.openai_api_key}
                      size="small"
                    >
                      {testingConnection.openai ? 'Testing...' : 'Test Connection'}
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Google Gemini Configuration */}
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                    <Box display="flex" alignItems="center">
                      <Cloud color="primary" sx={{ mr: 1 }} />
                      <Typography variant="h6">Google Gemini</Typography>
                    </Box>
                    <Chip 
                      label={config.llm_provider === 'gemini' ? 'Active' : 'Available'} 
                      color={config.llm_provider === 'gemini' ? 'primary' : 'default'}
                      size="small"
                    />
                  </Box>
                  
                  <TextField
                    fullWidth
                    label="API Key"
                    type={showApiKeys.gemini ? 'text' : 'password'}
                    value={config.gemini_api_key || ''}
                    onChange={(e) => handleConfigChange('gemini_api_key', e.target.value)}
                    margin="normal"
                    helperText="Get your API key from Google AI Studio"
                    InputProps={{
                      endAdornment: (
                        <IconButton onClick={() => toggleApiKeyVisibility('gemini')}>
                          {showApiKeys.gemini ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      )
                    }}
                  />
                  
                  <FormControl fullWidth margin="normal">
                    <InputLabel>Model</InputLabel>
                    <Select
                      value={config.gemini_model || 'gemini-pro'}
                      onChange={(e) => handleConfigChange('gemini_model', e.target.value)}
                      label="Model"
                    >
                      <MenuItem value="gemini-pro">Gemini Pro</MenuItem>
                      <MenuItem value="gemini-1.5-pro">Gemini 1.5 Pro</MenuItem>
                      <MenuItem value="gemini-1.5-flash">Gemini 1.5 Flash</MenuItem>
                    </Select>
                  </FormControl>

                  <Box mt={2}>
                    <Button
                      variant="outlined"
                      startIcon={testingConnection.gemini ? <LinearProgress /> : <Science />}
                      onClick={() => testLLMConnection('Gemini')}
                      disabled={testingConnection.gemini || !config.gemini_api_key}
                      size="small"
                    >
                      {testingConnection.gemini ? 'Testing...' : 'Test Connection'}
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Claude Configuration */}
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                    <Box display="flex" alignItems="center">
                      <Cloud color="primary" sx={{ mr: 1 }} />
                      <Typography variant="h6">Anthropic Claude</Typography>
                    </Box>
                    <Chip 
                      label={config.llm_provider === 'claude' ? 'Active' : 'Available'} 
                      color={config.llm_provider === 'claude' ? 'primary' : 'default'}
                      size="small"
                    />
                  </Box>
                  
                  <TextField
                    fullWidth
                    label="API Key"
                    type={showApiKeys.claude ? 'text' : 'password'}
                    value={config.claude_api_key || ''}
                    onChange={(e) => handleConfigChange('claude_api_key', e.target.value)}
                    margin="normal"
                    helperText="Get your API key from Anthropic Console"
                    InputProps={{
                      endAdornment: (
                        <IconButton onClick={() => toggleApiKeyVisibility('claude')}>
                          {showApiKeys.claude ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      )
                    }}
                  />
                  
                  <FormControl fullWidth margin="normal">
                    <InputLabel>Model</InputLabel>
                    <Select
                      value={config.claude_model || 'claude-3-sonnet-20240229'}
                      onChange={(e) => handleConfigChange('claude_model', e.target.value)}
                      label="Model"
                    >
                      <MenuItem value="claude-3-haiku-20240307">Claude 3 Haiku (Fast)</MenuItem>
                      <MenuItem value="claude-3-sonnet-20240229">Claude 3 Sonnet (Balanced)</MenuItem>
                      <MenuItem value="claude-3-opus-20240229">Claude 3 Opus (Advanced)</MenuItem>
                    </Select>
                  </FormControl>

                  <Box mt={2}>
                    <Button
                      variant="outlined"
                      startIcon={testingConnection.claude ? <LinearProgress /> : <Science />}
                      onClick={() => testLLMConnection('Claude')}
                      disabled={testingConnection.claude || !config.claude_api_key}
                      size="small"
                    >
                      {testingConnection.claude ? 'Testing...' : 'Test Connection'}
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Ollama Configuration */}
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
                    <Box display="flex" alignItems="center">
                      <Computer color="primary" sx={{ mr: 1 }} />
                      <Typography variant="h6">Ollama (Local)</Typography>
                    </Box>
                    <Chip 
                      label={config.llm_provider === 'ollama' ? 'Active' : 'Available'} 
                      color={config.llm_provider === 'ollama' ? 'primary' : 'default'}
                      size="small"
                    />
                  </Box>
                  
                  <TextField
                    fullWidth
                    label="Base URL"
                    value={config.ollama_base_url || 'http://localhost:11434'}
                    onChange={(e) => handleConfigChange('ollama_base_url', e.target.value)}
                    margin="normal"
                    helperText="URL of your Ollama server"
                  />
                  
                  <TextField
                    fullWidth
                    label="Model"
                    value={config.ollama_model || 'llama2'}
                    onChange={(e) => handleConfigChange('ollama_model', e.target.value)}
                    margin="normal"
                    helperText="e.g. llama2, codellama, mistral, llama3"
                  />

                  <Box mt={2}>
                    <Button
                      variant="outlined"
                      startIcon={testingConnection.ollama ? <LinearProgress /> : <Science />}
                      onClick={() => testLLMConnection('Ollama')}
                      disabled={testingConnection.ollama}
                      size="small"
                    >
                      {testingConnection.ollama ? 'Testing...' : 'Test Connection'}
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* LLM General Settings */}
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    General LLM Settings
                  </Typography>
                  
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={4}>
                      <TextField
                        fullWidth
                        label="Timeout (seconds)"
                        type="number"
                        value={config.llm_timeout || 60}
                        onChange={(e) => handleConfigChange('llm_timeout', parseInt(e.target.value))}
                        inputProps={{ min: 10, max: 300 }}
                        helperText="Request timeout for LLM calls"
                      />
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <TextField
                        fullWidth
                        label="Max Tokens"
                        type="number"
                        value={config.llm_max_tokens || 1500}
                        onChange={(e) => handleConfigChange('llm_max_tokens', parseInt(e.target.value))}
                        inputProps={{ min: 100, max: 4000 }}
                        helperText="Maximum tokens in response"
                      />
                    </Grid>
                    <Grid item xs={12} md={4}>
                      <TextField
                        fullWidth
                        label="Temperature"
                        type="number"
                        value={config.llm_temperature || 0.3}
                        onChange={(e) => handleConfigChange('llm_temperature', parseFloat(e.target.value))}
                        inputProps={{ min: 0, max: 1, step: 0.1 }}
                        helperText="Creativity level (0-1)"
                      />
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          {/* Ghidra Configuration */}
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <Memory color="primary" sx={{ mr: 1 }} />
                    <Typography variant="h6">
                      Ghidra Configuration
                    </Typography>
                  </Box>
                  
                  <TextField
                    fullWidth
                    label="Ghidra Install Directory"
                    value={config.ghidra_install_dir || ''}
                    onChange={(e) => handleConfigChange('ghidra_install_dir', e.target.value)}
                    margin="normal"
                    helperText="Path to Ghidra installation directory"
                  />
                  
                  <TextField
                    fullWidth
                    label="Bridge Port"
                    type="number"
                    value={config.ghidra_bridge_port || 4768}
                    onChange={(e) => handleConfigChange('ghidra_bridge_port', parseInt(e.target.value))}
                    margin="normal"
                    helperText="Port for Ghidra Bridge server"
                    inputProps={{ min: 1024, max: 65535 }}
                  />
                  
                  <TextField
                    fullWidth
                    label="Max Processes"
                    type="number"
                    value={config.ghidra_max_processes || 4}
                    onChange={(e) => handleConfigChange('ghidra_max_processes', parseInt(e.target.value))}
                    margin="normal"
                    helperText="Maximum number of concurrent Ghidra processes"
                    inputProps={{ min: 1, max: 16 }}
                  />
                  
                  <TextField
                    fullWidth
                    label="Process Timeout (seconds)"
                    type="number"
                    value={config.ghidra_timeout || 3600}
                    onChange={(e) => handleConfigChange('ghidra_timeout', parseInt(e.target.value))}
                    margin="normal"
                    helperText="Timeout for Ghidra analysis processes"
                    inputProps={{ min: 60, max: 7200 }}
                  />
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          {/* System Configuration */}
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <Settings color="primary" sx={{ mr: 1 }} />
                    <Typography variant="h6">
                      Server Configuration
                    </Typography>
                  </Box>
                  
                  <TextField
                    fullWidth
                    label="Flask Host"
                    value={config.flask_host || '127.0.0.1'}
                    onChange={(e) => handleConfigChange('flask_host', e.target.value)}
                    margin="normal"
                  />
                  
                  <TextField
                    fullWidth
                    label="Flask Port"
                    type="number"
                    value={config.flask_port || 5000}
                    onChange={(e) => handleConfigChange('flask_port', parseInt(e.target.value))}
                    margin="normal"
                    inputProps={{ min: 1024, max: 65535 }}
                  />
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <Storage color="primary" sx={{ mr: 1 }} />
                    <Typography variant="h6">
                      File Upload Configuration
                    </Typography>
                  </Box>
                  
                  <TextField
                    fullWidth
                    label="Max File Size (bytes)"
                    type="number"
                    value={config.max_file_size || 1073741824}
                    onChange={(e) => handleConfigChange('max_file_size', parseInt(e.target.value))}
                    margin="normal"
                    helperText="Maximum file size for uploads (1GB = 1073741824)"
                    inputProps={{ min: 1048576, max: 10737418240 }} // 1MB to 10GB
                  />
                  
                  <TextField
                    fullWidth
                    label="Upload Folder"
                    value={config.upload_folder || './uploads'}
                    onChange={(e) => handleConfigChange('upload_folder', e.target.value)}
                    margin="normal"
                    helperText="Directory for storing uploaded files"
                  />
                  
                  <TextField
                    fullWidth
                    label="Temp Folder"
                    value={config.temp_folder || './temp'}
                    onChange={(e) => handleConfigChange('temp_folder', e.target.value)}
                    margin="normal"
                    helperText="Directory for temporary files"
                  />
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        <TabPanel value={tabValue} index={3}>
          {/* Analysis Configuration */}
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card>
                <CardContent>
                  <Box display="flex" alignItems="center" mb={2}>
                    <Speed color="primary" sx={{ mr: 1 }} />
                    <Typography variant="h6">
                      Analysis Configuration
                    </Typography>
                  </Box>
                  
                  <TextField
                    fullWidth
                    label="Analysis Timeout (seconds)"
                    type="number"
                    value={config.analysis_timeout || 1800}
                    onChange={(e) => handleConfigChange('analysis_timeout', parseInt(e.target.value))}
                    margin="normal"
                    helperText="Timeout for individual analysis tasks"
                    inputProps={{ min: 60, max: 7200 }}
                  />
                  
                  <TextField
                    fullWidth
                    label="Max Concurrent Analyses"
                    type="number"
                    value={config.max_concurrent_analyses || 2}
                    onChange={(e) => handleConfigChange('max_concurrent_analyses', parseInt(e.target.value))}
                    margin="normal"
                    helperText="Maximum number of concurrent analysis tasks"
                    inputProps={{ min: 1, max: 8 }}
                  />
                  
                  <Box mt={2}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={config.enable_debug_logging || false}
                          onChange={(e) => handleConfigChange('enable_debug_logging', e.target.checked)}
                        />
                      }
                      label="Enable Debug Logging"
                    />
                  </Box>
                  
                  <Box mt={1}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={config.auto_cleanup_temp_files !== false}
                          onChange={(e) => handleConfigChange('auto_cleanup_temp_files', e.target.checked)}
                        />
                      }
                      label="Auto Cleanup Temp Files"
                    />
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>
      </Paper>
    </Box>
  );
};

export default Configuration; 