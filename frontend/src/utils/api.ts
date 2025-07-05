import axios, { AxiosInstance, AxiosResponse } from 'axios';

// API Base URL - uses proxy in development
const API_BASE_URL = process.env.NODE_ENV === 'production' 
  ? window.location.origin 
  : 'http://localhost:5000';

// Create axios instance
const api: AxiosInstance = axios.create({
  baseURL: `${API_BASE_URL}/api`,
  timeout: 300000, // 5 minutes for large file uploads
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('API Request Error:', error);
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response: AxiosResponse) => {
    console.log(`API Response: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    console.error('API Response Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// Types
export interface SystemStatus {
  status: string;
  ghidra_bridge_connected: boolean;
  binaries: number;
  tasks: {
    total: number;
    running: number;
    queued: number;
  };
  ghidra_bridge: string;
  server_time: string;
}

export interface Binary {
  id: string;
  filename: string;
  original_filename: string;
  file_path: string;
  file_size: number;
  file_hash?: string;
  mime_type?: string;
  architecture?: string;
  upload_time: string;
  analysis_status: string;
  metadata?: any;
}

export interface BinaryDetails {
  binary: Binary;
  results: AnalysisResult[];
  functions: Function[];
}

export interface AnalysisResult {
  id: string;
  binary_id: string;
  task_id?: string;
  analysis_type: string;
  function_address?: string;
  created_at: string;
  results: any;
  metadata?: any;
}

export interface Function {
  id: string;
  binary_id: string;
  address: string;
  name?: string;
  original_name?: string;
  size?: number;
  parameter_count?: number;
  return_type?: string;
  calling_convention?: string;
  is_analyzed: boolean;
  is_decompiled: boolean;
  has_cfg: boolean;
  is_thunk?: boolean;
  is_external?: boolean;
  ai_analyzed?: boolean;
  decompiled_code?: string;
  ai_summary?: string;
  risk_score?: number;
  created_at: string;
  updated_at: string;
  metadata?: any;
}

export interface AnalysisTask {
  id: string;
  binary_id: string;
  task_type: string;
  status: string;
  priority: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  parameters?: any;
  progress: number;
  error_message?: string;
}

export interface UploadResponse {
  binary_id: string;
  filename: string;
  size: number;
  task_id: string;
  status: string;
}

export interface TaskResponse {
  task_id: string;
  celery_task_id?: string;
  status: string;
}

export interface CFGResponse {
  task_id: string;
  function_address: string;
  status: string;
}

export interface Configuration {
  [key: string]: any;
}

export interface BinaryUploadResponse {
  id: string;
  filename: string;
  original_filename: string;
  file_path: string;
  file_size: number;
  status: string;
}

// API Client Class
class ApiClient {
  // System endpoints
  async getSystemStatus(): Promise<SystemStatus> {
    try {
      const response = await api.get('/status');
      return response.data;
    } catch (error) {
      console.error('Failed to fetch system status:', error);
      // Return a fallback status object
      return {
        status: 'error',
        binaries: 0,
        tasks: {
          total: 0,
          running: 0,
          queued: 0
        },
        ghidra_bridge: 'disconnected',
        ghidra_bridge_connected: false,
        server_time: new Date().toISOString()
      };
    }
  }

  async checkMcpConnection(): Promise<boolean> {
    try {
      const response = await api.get('/status');
      return response.data.ghidra_bridge_connected === true;
    } catch (error) {
      console.error('Ghidra bridge connection check failed:', error);
      return false;
    }
  }

  async directMcpCheck(): Promise<boolean> {
    try {
      // Check bridge connection via API
      const response = await api.get('/status');
      console.log('Ghidra bridge connection check:', response.data);
      
      // Update the UI with the bridge server status
      const systemStatus: SystemStatus = response.data;
      
      // Dispatch an event to notify components
      window.dispatchEvent(new CustomEvent('ghidra_bridge_status_update', { 
        detail: { connected: systemStatus.ghidra_bridge_connected, status: systemStatus }
      }));
      
      return systemStatus.ghidra_bridge_connected;
    } catch (error) {
      console.error('Ghidra bridge connection check failed:', error);
      
      // Dispatch an event to notify components
      window.dispatchEvent(new CustomEvent('ghidra_bridge_status_update', { 
        detail: { connected: false }
      }));
      
      return false;
    }
  }

  async directUploadBinary(file: File, onProgress?: (progress: number) => void): Promise<BinaryUploadResponse> {
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await axios.post('http://localhost:8080/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total) {
            const progress = progressEvent.loaded / progressEvent.total;
            if (onProgress) {
              onProgress(progress);
            }
          }
        }
      });
      
      console.log('Direct MCP upload successful:', response.data);
      
      return {
        id: response.data.id,
        filename: response.data.filename,
        original_filename: response.data.original_filename,
        file_path: response.data.file_path,
        file_size: response.data.file_size,
        status: 'uploaded'
      };
    } catch (error) {
      console.error('Direct MCP upload failed:', error);
      throw error;
    }
  }

  async getHealth(): Promise<{ status: string; timestamp: string; version: string }> {
    const response = await api.get('/health');
    return response.data;
  }

  // Binary endpoints
  async getBinaries(page: number = 1, perPage: number = 10): Promise<{
    binaries: Binary[];
  }> {
    const response = await api.get('/binaries');
    return response.data;
  }

  async getBinaryDetails(binaryId: string): Promise<BinaryDetails> {
    const response = await api.get(`/binaries/${binaryId}`);
    // Ensure functions and results are arrays even if they're missing in the response
    const data = response.data;
    if (!data.functions) data.functions = [];
    if (!data.results) data.results = [];
    return data;
  }

  async uploadBinary(file: File, onProgress?: (progress: number) => void): Promise<{
    message: string;
    binary: Binary;
  }> {
    try {
      const formData = new FormData();
      formData.append('file', file);

      const response = await api.post('/binaries', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent.total && onProgress) {
            const progress = Math.round((progressEvent.loaded) / progressEvent.total);
            onProgress(progress);
          }
        },
      });
      return response.data;
    } catch (error) {
      console.error('Failed to upload binary:', error);
      throw error;
    }
  }

  async downloadBinary(binaryId: string): Promise<Blob> {
    const response = await api.get(`/binaries/${binaryId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  }

  async deleteBinary(binaryId: string): Promise<{ message: string }> {
    const response = await api.delete(`/binaries/${binaryId}`);
    return response.data;
  }

  // Analysis endpoints
  async startAnalysis(binaryId: string, options?: { analysis_type?: string; parameters?: any }): Promise<TaskResponse> {
    const response = await api.post(`/binaries/${binaryId}/analyze`, {
      analysis_type: options?.analysis_type || 'basic',
      parameters: options?.parameters || {}
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    return response.data;
  }

  async analyzeFunction(
    binaryId: string,
    functionAddress: string,
    analysisTypes: string[]
  ): Promise<TaskResponse> {
    const response = await api.post('/analysis/function', {
      binary_id: binaryId,
      function_address: functionAddress,
      analysis_types: analysisTypes,
    });
    return response.data;
  }

  async generateCFG(
    binaryId: string,
    functionAddress: string,
    includeInstructions: boolean = false
  ): Promise<CFGResponse> {
    const response = await api.post('/analysis/cfg', {
      binary_id: binaryId,
      function_address: functionAddress,
      include_instructions: includeInstructions,
    });
    return response.data;
  }

  async getCFG(
    binaryId: string,
    functionAddress: string,
    includeInstructions: boolean = true
  ): Promise<any> {
    const response = await api.get(`/analysis/cfg/${binaryId}/${functionAddress}`, {
      params: { include_instructions: includeInstructions }
    });
    return response.data;
  }

  /**
   * Generate binary CFG for all functions in a binary
   */
  async generateBinaryCFG(
    binaryId: string,
    options: {
      includeInstructions?: boolean;
      maxFunctions?: number;
    } = {}
  ): Promise<any> {
    const response = await api.post(`/binaries/${binaryId}/cfg`, {
      include_instructions: options.includeInstructions || false,
      max_functions: options.maxFunctions || 50
    });
    return response.data;
  }

  /**
   * Get existing binary CFG data
   */
  async getBinaryCFG(binaryId: string): Promise<any> {
    const response = await api.get(`/binaries/${binaryId}/cfg`);
    return response.data;
  }

  async compareBinaries(
    binaryId1: string,
    binaryId2: string,
    diffType: string = 'instructions'
  ): Promise<any> {
    const response = await api.post('/analysis/diff', {
      binary_id1: binaryId1,
      binary_id2: binaryId2,
      diff_type: diffType,
    });
    return response.data;
  }

  async searchPatterns(
    binaryId: string,
    patternTypes: string[] = ['crypto', 'dangerous_functions', 'strings']
  ): Promise<any> {
    const response = await api.post('/analysis/patterns', {
      binary_id: binaryId,
      pattern_types: patternTypes,
    });
    return response.data;
  }

  async runVulnerabilityScan(
    binaryId: string,
    scanTypes: string[] = ['buffer_overflow', 'format_string', 'integer_overflow']
  ): Promise<any> {
    const response = await api.post('/analysis/vulnerabilities', {
      binary_id: binaryId,
      scan_types: scanTypes,
    });
    return response.data;
  }

  async executeSymbolicAnalysis(
    binaryId: string,
    functionAddress: string,
    maxDepth: number = 10,
    timeout: number = 300
  ): Promise<any> {
    const response = await api.post('/analysis/symbolic', {
      binary_id: binaryId,
      function_address: functionAddress,
      max_depth: maxDepth,
      timeout: timeout,
    });
    return response.data;
  }

  async getBinaryFunctions(binaryId: string): Promise<any> {
    const response = await api.get(`/binaries/${binaryId}/functions`);
    return response.data;
  }

  async getAnalysisSummary(binaryId: string): Promise<any> {
    const response = await api.get(`/analysis/results/${binaryId}`);
    return response.data;
  }

  // Task endpoints
  async getTaskStatus(taskId: string): Promise<AnalysisTask> {
    const response = await api.get(`/tasks/${taskId}`);
    return response.data;
  }

  async getBinaryTasks(binaryId: string): Promise<AnalysisTask[]> {
    const response = await api.get(`/binaries/${binaryId}/tasks`);
    return response.data.tasks;
  }

  async getAllTasks(): Promise<AnalysisTask[]> {
    const response = await api.get('/tasks');
    return response.data.tasks;
  }

  // Results endpoints
  async getAnalysisResult(resultId: string): Promise<AnalysisResult> {
    const response = await api.get(`/results/${resultId}`);
    return response.data;
  }

  async getAnalysisResults(analysisId: string | undefined): Promise<AnalysisResult> {
    if (!analysisId) {
      throw new Error('Analysis ID is required');
    }
    const response = await api.get(`/analysis/results/${analysisId}`);
    return response.data;
  }

  // Functions endpoints
  async getFunctions(binaryId: string): Promise<{ functions: Function[] }> {
    const response = await api.get(`/functions/${binaryId}`);
    return response.data;
  }

  // Configuration endpoints
  async getConfiguration(): Promise<Configuration> {
    const response = await api.get('/config');
    return response.data;
  }

  async updateConfiguration(config: Configuration): Promise<{ status: string }> {
    const response = await api.post('/config', config);
    return response.data;
  }

  async testAIConnection(testData: any): Promise<{ success: boolean; message: string }> {
    const response = await api.post('/config/test-connection', testData);
    return response.data;
  }

  // Task management
  async cancelTask(taskId: string): Promise<{ status: string }> {
    const response = await api.post(`/tasks/cancel/${taskId}`);
    return response.data;
  }
  
  async cancelAllTasks(): Promise<{ status: string }> {
    const response = await api.post('/tasks/cancel-all', {});
    return response.data;
  }

  async stopBinaryTasks(binaryId: string): Promise<{ status: string; message: string; cancelled_tasks: number }> {
    const response = await api.post('/tasks/cancel-all', { binary_id: binaryId });
    return response.data;
  }

  // New Function-specific endpoints
  async decompileFunction(functionId: string): Promise<any> {
    const response = await api.post(`/functions/${functionId}/decompile`);
    return response.data;
  }

  async explainFunction(functionId: string): Promise<any> {
    const response = await api.post(`/functions/${functionId}/explain`);
    return response.data;
  }

  async getFunctionCFG(functionId: string): Promise<any> {
    const response = await api.get(`/functions/${functionId}/cfg`);
    return response.data;
  }

  async getFunctionDetails(functionId: string): Promise<any> {
    const response = await api.get(`/functions/${functionId}`);
    return response.data;
  }

  async bulkDecompileFunctions(binaryId: string): Promise<any> {
    // Use longer timeout for bulk operations (15 minutes)
    const response = await api.post(`/binaries/${binaryId}/decompile-all`, {}, {
      timeout: 900000  // 15 minutes
    });
    return response.data;
  }

  async bulkAIExplainFunctions(binaryId: string): Promise<any> {
    // Use longer timeout for bulk AI operations (30 minutes)
    const response = await api.post(`/binaries/${binaryId}/ai-explain-all`, {}, {
      timeout: 1800000  // 30 minutes - AI processing takes longer
    });
    return response.data;
  }

  async getTaskStatusById(taskId: string): Promise<any> {
    const response = await api.get(`/tasks/${taskId}/status`);
    return response.data;
  }

  // Binary AI Summary endpoints
  async generateBinaryAISummary(binaryId: string): Promise<any> {
    const response = await api.post(`/binaries/${binaryId}/ai-summary`);
    return response.data;
  }

  async getBinaryAISummary(binaryId: string): Promise<any> {
    const response = await api.get(`/binaries/${binaryId}/ai-summary`);
    return response.data;
  }

  // Comprehensive Analysis endpoints
  async startComprehensiveAnalysis(binaryId: string): Promise<any> {
    const response = await api.post(`/binaries/${binaryId}/comprehensive-analysis`, {}, {
      timeout: 1800000  // 30 minute timeout for comprehensive analysis
    });
    return response.data;
  }

  async getComprehensiveAnalysis(binaryId: string): Promise<any> {
    try {
      const response = await api.get(`/binaries/${binaryId}/comprehensive-analysis`);
      return response.data;
    } catch (error: any) {
      if (error.response?.status === 404) {
        return null; // No comprehensive analysis available
      }
      throw error;
    }
  }

  async getComprehensiveData(binaryId: string, dataType: string, page: number = 1, perPage: number = 100, search: string = ''): Promise<any> {
    const response = await api.get(`/binaries/${binaryId}/comprehensive-data/${dataType}`, {
      params: {
        page,
        per_page: perPage,
        search
      }
    });
    return response.data;
  }

  // ===================================================================
  // VULNERABILITY DETECTION API METHODS
  // ===================================================================

  /**
   * Start vulnerability scan for a binary
   */
  async scanVulnerabilities(binaryId: string, scanTypes: string[] = ['buffer_overflow', 'format_string', 'integer_overflow']): Promise<any> {
    const response = await api.post(`/binaries/${binaryId}/vulnerabilities/scan`, {
      scan_types: scanTypes,
      parameters: {}
    });
    return response.data;
  }

  /**
   * Get vulnerabilities for a binary with pagination and filtering
   */
  async getVulnerabilities(binaryId: string, options: {
    page?: number;
    perPage?: number;
    severity?: string;
    type?: string;
  } = {}): Promise<any> {
    const params = new URLSearchParams();
    if (options.page) params.append('page', options.page.toString());
    if (options.perPage) params.append('per_page', options.perPage.toString());
    if (options.severity) params.append('severity', options.severity);
    if (options.type) params.append('type', options.type);

    const response = await api.get(`/binaries/${binaryId}/vulnerabilities?${params.toString()}`);
    return response.data;
  }

  /**
   * Get latest vulnerability report for a binary
   */
  async getVulnerabilityReport(binaryId: string): Promise<any> {
    const response = await api.get(`/binaries/${binaryId}/vulnerability-report`);
    return response.data;
  }

  /**
   * Get vulnerability summary for a binary
   */
  async getVulnerabilitySummary(binaryId: string): Promise<any> {
    const response = await api.get(`/binaries/${binaryId}/vulnerability-summary`);
    return response.data;
  }

  /**
   * Get detailed information about a specific vulnerability
   */
  async getVulnerabilityDetails(vulnerabilityId: string): Promise<any> {
    const response = await api.get(`/vulnerabilities/${vulnerabilityId}`);
    return response.data;
  }

  /**
   * Update vulnerability information (e.g., mark as false positive)
   */
  async updateVulnerability(vulnerabilityId: string, updates: {
    false_positive_risk?: string;
    confidence?: number;
    remediation?: string;
  }): Promise<any> {
    const response = await api.put(`/vulnerabilities/${vulnerabilityId}`, updates);
    return response.data;
  }

  /**
   * Get available vulnerability detection patterns
   */
  async getVulnerabilityPatterns(): Promise<any> {
    const response = await api.get('/vulnerability-patterns');
    return response.data;
  }

  /**
   * Get system-wide vulnerability statistics
   */
  async getVulnerabilityStats(): Promise<any> {
    const response = await api.get('/vulnerability-stats');
    return response.data;
  }

  // ===================================================================
  // UNIFIED SECURITY ANALYSIS API METHODS
  // ===================================================================

  /**
   * Start unified security analysis for a binary
   */
  async startSecurityAnalysis(binaryId: string, analysisTypes: string[] = ['ai_analysis', 'pattern_matching', 'static_analysis']): Promise<any> {
    const response = await api.post(`/binaries/${binaryId}/security-analysis`, {
      analysis_types: analysisTypes,
      ai_enabled: true,
      pattern_matching: true,
      confidence_threshold: 40
    });
    return response.data;
  }

  /**
   * Get unified security findings for a binary with pagination and filtering
   */
  async getSecurityFindings(binaryId: string, options: {
    page?: number;
    perPage?: number;
    severity?: string;
    confidence_min?: number;
    category?: string;
  } = {}): Promise<any> {
    const params = new URLSearchParams();
    if (options.page) params.append('page', options.page.toString());
    if (options.perPage) params.append('per_page', options.perPage.toString());
    if (options.severity) params.append('severity', options.severity);
    if (options.confidence_min) params.append('confidence_min', options.confidence_min.toString());
    if (options.category) params.append('category', options.category);

    const response = await api.get(`/binaries/${binaryId}/security-findings?${params.toString()}`);
    return response.data;
  }

  /**
   * Get detailed information about a specific security finding
   */
  async getSecurityFindingDetails(findingId: string): Promise<any> {
    const response = await api.get(`/security-findings/${findingId}`);
    return response.data;
  }

  /**
   * Update security finding information
   */
  async updateSecurityFinding(findingId: string, updates: {
    false_positive_risk?: string;
    confidence?: number;
    remediation?: string;
    notes?: string;
  }): Promise<any> {
    const response = await api.put(`/security-findings/${findingId}`, updates);
    return response.data;
  }

  /**
   * Get comprehensive security summary for a binary
   */
  async getSecuritySummary(binaryId: string): Promise<any> {
    try {
      const findings = await this.getSecurityFindings(binaryId, { perPage: 1000 });
      const summary = {
        total: findings.total_findings || 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        overall_risk_score: 0,
        confidence_distribution: { high: 0, medium: 0, low: 0 }
      };

      if (findings.findings && findings.findings.length > 0) {
        findings.findings.forEach((finding: any) => {
          // Count by severity
          switch (finding.severity?.toUpperCase()) {
            case 'CRITICAL': summary.critical++; break;
            case 'HIGH': summary.high++; break;
            case 'MEDIUM': summary.medium++; break;
            case 'LOW': summary.low++; break;
            case 'INFO': summary.info++; break;
          }

          // Count by confidence
          const confidence = finding.confidence || 0;
          if (confidence >= 80) summary.confidence_distribution.high++;
          else if (confidence >= 50) summary.confidence_distribution.medium++;
          else summary.confidence_distribution.low++;
        });

        // Calculate overall risk score based on findings and confidence
        const riskWeight = {
          critical: 100,
          high: 75, 
          medium: 50,
          low: 25,
          info: 5
        };
        
        const totalWeight = summary.critical * riskWeight.critical +
                          summary.high * riskWeight.high +
                          summary.medium * riskWeight.medium +
                          summary.low * riskWeight.low +
                          summary.info * riskWeight.info;
        
        summary.overall_risk_score = Math.min(100, Math.round(totalWeight / Math.max(1, summary.total)));
      }

      return { 
        summary, 
        findings: findings.findings || [],
        total_pages: findings.total_pages || 1,
        current_page: findings.current_page || 1
      };
    } catch (error) {
      console.error('Error getting security summary:', error);
      return {
        summary: { 
          total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, 
          overall_risk_score: 0, confidence_distribution: { high: 0, medium: 0, low: 0 }
        },
        findings: [],
        total_pages: 1,
        current_page: 1
      };
    }
  }

  // ===================================================================
  // FUZZING HARNESS API METHODS
  // ===================================================================

  /**
   * Generate fuzzing harness for a binary
   */
  async generateFuzzingHarness(
    binaryId: string, 
    options: {
      harness_types?: string[];
      min_risk_score?: number;
      target_severities?: string[];
      ai_enabled?: boolean;
      include_seeds?: boolean;
    } = {}
  ): Promise<any> {
    const { harness_types = ['AFL++'], min_risk_score = 40.0, target_severities = ['HIGH', 'MEDIUM'], ai_enabled = true, include_seeds = true } = options;
    
    const response = await api.post(`/binaries/${binaryId}/generate-fuzzing-harness`, {
      harness_types,
      min_risk_score,
      target_severities,
      ai_enabled,
      include_seeds
    });
    
    return response.data;
  }

  /**
   * Get supported fuzzers
   */
  async getSupportedFuzzers(): Promise<any> {
    const response = await api.get('/fuzzing/supported-fuzzers');
    return response.data;
  }

  /**
   * Get fuzzing harnesses for a binary
   */
  async getFuzzingHarnesses(binaryId: string): Promise<any> {
    const response = await api.get(`/binaries/${binaryId}/fuzzing-harnesses`);
    return response.data;
  }

  /**
   * Get fuzzing harness details
   */
  async getFuzzingHarnessDetails(harnessId: string): Promise<any> {
    const response = await api.get(`/fuzzing-harnesses/${harnessId}`);
    return response.data;
  }

  /**
   * Delete a fuzzing harness
   */
  async deleteFuzzingHarness(harnessId: string): Promise<any> {
    const response = await api.delete(`/fuzzing-harnesses/${harnessId}`);
    return response.data;
  }

  /**
   * Download fuzzing harness file
   */
  async downloadFuzzingHarnessFile(harnessId: string, fileType: 'harness' | 'makefile' | 'readme' | 'package'): Promise<void> {
    const response = await api.get(`/fuzzing-harnesses/${harnessId}/download/${fileType}`, {
      responseType: 'blob'
    });
    
    const url = window.URL.createObjectURL(new Blob([response.data]));
    const link = document.createElement('a');
    link.href = url;
    
    // Set filename based on type
    const extension = fileType === 'harness' ? 'c' : fileType === 'makefile' ? 'make' : fileType === 'readme' ? 'md' : 'zip';
    link.setAttribute('download', `fuzzing_harness_${harnessId}.${extension}`);
    
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
  }

  // System management methods
  async getSystemDatabaseStats(): Promise<any> {
    const response = await api.get('/system/database-stats');
    return response.data;
  }

  async resetCompleteSystem(): Promise<{ 
    status: string; 
    message: string; 
    details: {
      cancelled_tasks: number;
      deleted_records: Record<string, number>;
      configs_reset: number;
      directories_cleaned: string[];
      total_records: number;
    }
  }> {
    const response = await api.post('/system/reset-complete');
    return response.data;
  }

  async cleanDatabaseTable(tableName: string): Promise<{
    status: string;
    message: string;
    deleted_count: number;
    related_deletions?: Record<string, number>;
    files_deleted?: number;
    total_deleted?: number;
  }> {
    const response = await api.post(`/system/clean-table/${tableName}`);
    return response.data;
  }

  async cleanSystemFiles(): Promise<{
    status: string;
    message: string;
    files_deleted: number;
    directories_cleaned: Array<{
      directory: string;
      files_deleted: number;
    }>;
  }> {
    const response = await api.post('/system/clean-files');
    return response.data;
  }

  // Binary Status Management
  async updateBinaryStatus(binaryId: string): Promise<{ success: boolean; message: string; old_status: string; new_status: string; statistics: any }> {
    const response = await api.post(`/binaries/${binaryId}/update-status`);
    return response.data;
  }

  async getBinaryStatusInfo(binaryId: string): Promise<{ binary_id: string; filename: string; current_status: string; statistics: any; fuzzing_ready: boolean; status_explanation: any }> {
    const response = await api.get(`/binaries/${binaryId}/status-info`);
    return response.data;
  }

  async updateAllBinaryStatuses(): Promise<{ success: boolean; message: string; total_binaries: number; updated_binaries: number; updates: any[] }> {
    const response = await api.post('/binaries/update-all-statuses');
    return response.data;
  }

  async getFuzzingReadyBinaries(): Promise<{ fuzzing_ready_binaries: any[]; total_ready: number }> {
    const response = await api.get('/binaries/fuzzing-ready');
    return response.data;
  }
}

// Export singleton instance
export const apiClient = new ApiClient();

// Export axios instance for custom requests
export { api };

// Utility functions
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

export const formatDate = (dateString: string): string => {
  return new Date(dateString).toLocaleString();
};

export const getStatusColor = (status: string): 'default' | 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' => {
  const normalizedStatus = status.toLowerCase();
  
  switch (normalizedStatus) {
    case 'uploaded': 
    case 'pending': return 'primary';
    case 'queued': return 'info';
    case 'running': 
    case 'analyzing': return 'warning';
    case 'decompiled': return 'secondary';
    case 'analyzed': return 'info';
    case 'completed': 
    case 'success': return 'success';
    case 'failed': 
    case 'error': return 'error';
    default: return 'default';
  }
};

// Fuzzing harness generation with multi-fuzzer support
export const generateFuzzingHarness = async (
  binaryId: string, 
  options: {
    harness_types?: string[];
    min_risk_score?: number;
    target_severities?: string[];
    ai_enabled?: boolean;
    include_seeds?: boolean;
  } = {}
) => {
  const { harness_types = ['AFL++'], min_risk_score = 40.0, target_severities = ['HIGH', 'MEDIUM'], ai_enabled = true, include_seeds = true } = options;
  
  const response = await fetch(`/api/binaries/${binaryId}/generate-fuzzing-harness`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      harness_types,
      min_risk_score,
      target_severities,
      ai_enabled,
      include_seeds
    })
  });
  
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to generate fuzzing harness');
  }
  
  return response.json();
};

// Get supported fuzzers
export const getSupportedFuzzers = async () => {
  const response = await fetch('/api/fuzzing/supported-fuzzers');
  
  if (!response.ok) {
    throw new Error('Failed to get supported fuzzers');
  }
  
  return response.json();
};

// Get fuzzing harnesses for a binary
export const getFuzzingHarnesses = async (binaryId: string) => {
  const response = await fetch(`/api/binaries/${binaryId}/fuzzing-harnesses`);
  
  if (!response.ok) {
    throw new Error('Failed to get fuzzing harnesses');
  }
  
  return response.json();
};

// Download fuzzing harness file
export const downloadFuzzingHarnessFile = async (harnessId: string, fileType: 'harness' | 'makefile' | 'readme' | 'package') => {
  const response = await fetch(`/api/fuzzing-harnesses/${harnessId}/download/${fileType}`);
  
  if (!response.ok) {
    throw new Error(`Failed to download ${fileType}`);
  }
  
  // Handle file download
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  
  // Get filename from response headers if available
  const contentDisposition = response.headers.get('content-disposition');
  const filename = contentDisposition 
    ? contentDisposition.split('filename=')[1]?.replace(/"/g, '') 
    : `${fileType}.${fileType === 'harness' ? 'c' : fileType === 'package' ? 'zip' : 'txt'}`;
  
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}; 