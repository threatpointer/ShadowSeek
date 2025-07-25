#!/usr/bin/env python3
"""
Unified Security Analysis Engine

This module provides the core unified security analysis system that combines
AI-powered analysis with pattern-based vulnerability detection to provide
consistent, evidence-based security findings.
"""

import logging
import re
import json
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from flask_app import db
from flask_app.models import (
    Function, UnifiedSecurityFinding, SecurityEvidence, VulnerabilityPattern,
    Configuration
)
from flask_app.ai_service import AIService
from flask_app.vulnerability_engine import VulnerabilityEngine

logger = logging.getLogger(__name__)

class UnifiedSecurityAnalyzer:
    """
    Core unified security analysis engine that combines AI intelligence
    with pattern-based vulnerability detection
    """
    
    def __init__(self):
        self.ai_service = AIService()
        self.vulnerability_engine = VulnerabilityEngine()
        self.risk_correlator = RiskCorrelationEngine()
        self.confidence_calculator = ConfidenceCalculator()
        
        # Load configuration
        self._load_config()
    
    def _load_config(self):
        """Load unified security analysis configuration"""
        try:
            self.enabled = self._get_config_bool('unified_security_enabled', True)
            self.confidence_threshold = self._get_config_int('unified_security_confidence_threshold', 30)
            self.correlation_weight = self._get_config_float('unified_security_correlation_weight', 0.6)
            self.ai_weight = self._get_config_float('unified_security_ai_weight', 0.4)
            self.pattern_weight = self._get_config_float('unified_security_pattern_weight', 0.6)
            
        except Exception as e:
            logger.warning(f"Error loading unified security config, using defaults: {e}")
            self.enabled = True
            self.confidence_threshold = 70
            self.correlation_weight = 0.6
            self.ai_weight = 0.4
            self.pattern_weight = 0.6
    
    def _get_config_bool(self, key: str, default: bool) -> bool:
        """Get boolean configuration value"""
        config = Configuration.query.filter_by(key=key).first()
        if config:
            return config.get_value() if isinstance(config.get_value(), bool) else default
        return default
    
    def _get_config_int(self, key: str, default: int) -> int:
        """Get integer configuration value"""
        config = Configuration.query.filter_by(key=key).first()
        if config:
            return config.get_value() if isinstance(config.get_value(), int) else default
        return default
    
    def _get_config_float(self, key: str, default: float) -> float:
        """Get float configuration value"""
        config = Configuration.query.filter_by(key=key).first()
        if config:
            return config.get_value() if isinstance(config.get_value(), float) else default
        return default
    
    def analyze_function_security(self, function: Function) -> Dict[str, Any]:
        """
        Perform unified security analysis on a function
        
        Args:
            function: Function object to analyze
            
        Returns:
            Dict containing unified security analysis results
        """
        if not self.enabled:
            logger.warning("Unified security analysis is disabled")
            return {'error': 'Unified security analysis is disabled'}

        if not function.decompiled_code:
            logger.warning(f"Function {function.address} has no decompiled code")
            return {'error': 'Function must be decompiled before security analysis'}

        try:
            logger.info(f"Starting unified security analysis for function {function.address} ({function.name or 'unnamed'})")
            
            # Step 1: AI-powered security analysis
            ai_analysis = self._perform_ai_security_analysis(function)
            logger.info(f"AI analysis result for {function.address}: success={ai_analysis.get('success')}")
            
            # Step 2: Pattern-based vulnerability detection
            pattern_analysis = self._perform_pattern_analysis(function)
            logger.info(f"Pattern analysis result for {function.address}: success={pattern_analysis.get('success')}")
            
            # Step 3: Correlate and validate results
            unified_findings = self.risk_correlator.correlate_findings(
                function, ai_analysis, pattern_analysis
            )
            logger.info(f"Correlation resulted in {len(unified_findings)} findings for {function.address}")
            
            # Step 4: Calculate confidence scores
            for finding in unified_findings:
                finding['confidence'] = self.confidence_calculator.calculate_confidence(
                    finding, ai_analysis, pattern_analysis
                )
            
            # Step 5: Filter by confidence threshold
            high_confidence_findings = [
                f for f in unified_findings 
                if f['confidence'] >= self.confidence_threshold
            ]
            logger.info(f"Filtered {len(unified_findings)} findings to {len(high_confidence_findings)} high-confidence findings for {function.address}")
            
            # Step 6: Store findings in database
            stored_findings = self._store_unified_findings(function, high_confidence_findings)
            logger.info(f"Stored {len(stored_findings)} findings for {function.address}")
            
            return {
                'success': True,
                'function_id': function.id,
                'total_findings': len(unified_findings),
                'high_confidence_findings': len(high_confidence_findings),
                'stored_findings': len(stored_findings),
                'findings': stored_findings,
                'analysis_metadata': {
                    'ai_analysis_success': ai_analysis.get('success', False),
                    'pattern_analysis_success': pattern_analysis.get('success', False),
                    'confidence_threshold': self.confidence_threshold
                }
            }
            
        except Exception as e:
            logger.error(f"Error in unified security analysis for {function.address}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {'error': f'Unified security analysis failed: {str(e)}'}
    
    def _perform_ai_security_analysis(self, function: Function) -> Dict[str, Any]:
        """Perform AI-powered security analysis with enhanced security prompts"""
        try:
            # Enhanced security-focused prompt
            security_prompt = self._build_security_prompt(function)
            
            # Get AI analysis
            response = self.ai_service.analyze_function_security(
                function.decompiled_code,
                function.name or function.address,
                security_prompt
            )
            
            # Handle AI service response
            if response and response.get('success') and response.get('security_analysis'):
                security_analysis = response['security_analysis']
                return {
                    'success': True,
                    'security_issues': security_analysis.get('issues', []),
                    'risk_assessment': security_analysis.get('risk_assessment', {}),
                    'recommendations': security_analysis.get('recommendations', []),
                    'raw_response': response.get('raw_response', '')
                }
            else:
                error_msg = response.get('error', 'Invalid AI response format') if isinstance(response, dict) else 'AI analysis failed'
                return {'success': False, 'error': error_msg}
                
        except Exception as e:
            logger.error(f"AI security analysis failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _build_security_prompt(self, function: Function) -> str:
        """Build enhanced security-focused analysis prompt"""
        return f"""
Analyze this function for security vulnerabilities. Provide a comprehensive security assessment focusing on:

1. **Buffer Overflow Risks**: 
   - Unbounded string operations (strcpy, strcat, sprintf)
   - Array access without bounds checking
   - Stack-based buffer overflows

2. **Format String Vulnerabilities**:
   - Variable format strings in printf family functions
   - User-controlled format parameters

3. **Command Injection**:
   - System calls with user input (system, exec family)
   - Shell command construction

4. **Integer Overflow/Underflow**:
   - Arithmetic operations on user input
   - Memory allocation size calculations

5. **Memory Management Issues**:
   - Use-after-free vulnerabilities
   - Double-free conditions
   - Memory leaks

6. **Cryptographic Weaknesses**:
   - Use of deprecated algorithms (MD5, SHA1)
   - Weak key generation or management

For each identified security issue, provide:
- **Title**: Brief descriptive title
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, or INFO
- **CWE ID**: Common Weakness Enumeration identifier
- **Description**: Detailed explanation of the vulnerability
- **Location**: Line numbers or code references
- **Impact**: Potential security impact
- **Remediation**: Specific fix recommendations
- **Confidence**: Your confidence level (0-100)

Function: {function.name or function.address}
Code:
{function.decompiled_code}

Respond in JSON format:
{{
  "security_analysis": {{
    "issues": [
      {{
        "title": "Buffer Overflow in strcpy",
        "severity": "HIGH",
        "cwe_id": "CWE-120",
        "description": "...",
        "location": "line 15",
        "impact": "...",
        "remediation": "...",
        "confidence": 85
      }}
    ],
    "risk_assessment": {{
      "overall_risk": "HIGH",
      "exploit_difficulty": "MEDIUM",
      "false_positive_risk": "LOW"
    }},
    "recommendations": ["...", "..."]
  }}
}}
"""
    
    def _perform_pattern_analysis(self, function: Function) -> Dict[str, Any]:
        """Perform comprehensive pattern-based vulnerability detection with 75+ dangerous functions"""
        try:
            # Get comprehensive dangerous functions list from vulnerability engine
            dangerous_functions = self.vulnerability_engine.dangerous_functions
            
            # Find dangerous function usage
            dangerous_func_findings = self._analyze_dangerous_functions(function, dangerous_functions)
            
            # Use existing vulnerability engine for additional pattern matching
            scan_result = self.vulnerability_engine.scan_function(
                function, ['buffer_overflow', 'format_string', 'command_injection', 'crypto_weakness', 'integer_overflow', 'use_after_free']
            )
            
            # Combine dangerous function findings with pattern findings
            all_vulnerabilities = dangerous_func_findings + scan_result.get('vulnerabilities', [])
            
            return {
                'success': True,
                'vulnerabilities': all_vulnerabilities,
                'dangerous_functions_found': len(dangerous_func_findings),
                'pattern_matches_found': len(scan_result.get('vulnerabilities', [])),
                'patterns_matched': scan_result.get('patterns_matched', []),
                'scan_metadata': scan_result.get('metadata', {}),
                'total_checks': len(dangerous_functions)
            }
            
        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _analyze_dangerous_functions(self, function: Function, dangerous_functions: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze function for usage of 75+ dangerous functions"""
        findings = []
        code = function.decompiled_code
        
        for func_name, description in dangerous_functions.items():
            # More sophisticated pattern matching
            patterns = [
                rf'\b{re.escape(func_name)}\s*\(',  # Direct function call
                rf'&{re.escape(func_name)}\b',      # Function pointer reference
                rf'\b{re.escape(func_name)}\b.*\(',  # Function with possible prefix
            ]
            
            found_usage = False
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    found_usage = True
                    break
            
            if found_usage:
                # Extract context around the dangerous function
                affected_code = self._extract_function_context(code, func_name)
                severity = self._get_comprehensive_function_severity(func_name)
                
                finding = {
                    'function_id': function.id,
                    'type': 'dangerous_function_usage',
                    'severity': severity,
                    'title': f'Usage of dangerous function: {func_name}',
                    'description': f'{description}. Function: {func_name}',
                    'address': function.address,
                    'cwe_id': self._get_function_cwe(func_name),
                    'risk_score': self._get_comprehensive_risk_score(func_name, severity),
                    'affected_code': affected_code,
                    'remediation': self._get_comprehensive_remediation(func_name),
                    'confidence': 90,  # High confidence for exact function matches
                    'detection_method': 'dangerous_function_analysis',
                    'category': self._get_function_category(func_name)
                }
                findings.append(finding)
        
        return findings
    
    def _extract_function_context(self, code: str, func_name: str) -> str:
        """Extract code context around a dangerous function usage"""
        lines = code.split('\n')
        context_lines = []
        
        for i, line in enumerate(lines):
            if re.search(rf'\b{re.escape(func_name)}\b', line, re.IGNORECASE):
                # Get 3 lines before and after for better context
                start = max(0, i - 3)
                end = min(len(lines), i + 4)
                context_lines = lines[start:end]
                break
        
        if context_lines:
            return '\n'.join(context_lines)
        else:
            # Fallback to first 300 characters
            return code[:300] + '...' if len(code) > 300 else code
    
    def _get_comprehensive_function_severity(self, func_name: str) -> str:
        """Get comprehensive severity mapping for dangerous functions"""
        critical_funcs = [
            'gets', 'system', 'CreateRemoteThread', 'SetWindowsHookEx', 
            'ImpersonateLoggedOnUser', 'WinExec', 'ShellExecute'
        ]
        
        high_funcs = [
            'strcpy', 'strcat', 'sprintf', 'vsprintf', 'execl', 'execle', 
            'execlp', 'execv', 'execvp', 'execve', 'CreateProcess', 
            'LoadLibrary', 'LoadLibraryEx', 'popen', 'alloca'
        ]
        
        medium_funcs = [
            'printf', 'fprintf', 'vfprintf', 'scanf', 'sscanf', 'fscanf',
            'snprintf', 'strncpy', 'strncat', 'memcpy', 'memmove', 'memset',
            'malloc', 'calloc', 'realloc', 'free', 'tmpnam', 'tmpfile', 
            'mktemp', 'open', 'fopen', 'socket', 'bind', 'listen', 'accept',
            'connect', 'recv', 'send', 'GetProcAddress', 'dlopen', 'LogonUser'
        ]
        
        if func_name in critical_funcs:
            return 'CRITICAL'
        elif func_name in high_funcs:
            return 'HIGH'
        elif func_name in medium_funcs:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_function_cwe(self, func_name: str) -> str:
        """Get CWE classification for dangerous functions"""
        cwe_mapping = {
            # Buffer Overflow
            'strcpy': 'CWE-120', 'strcat': 'CWE-120', 'sprintf': 'CWE-120',
            'vsprintf': 'CWE-120', 'gets': 'CWE-120', 'alloca': 'CWE-120',
            'memcpy': 'CWE-120', 'memmove': 'CWE-120', 'strncpy': 'CWE-120',
            'strncat': 'CWE-120', 'snprintf': 'CWE-120',
            
            # Format String
            'printf': 'CWE-134', 'fprintf': 'CWE-134', 'vfprintf': 'CWE-134',
            'scanf': 'CWE-134', 'sscanf': 'CWE-134', 'fscanf': 'CWE-134',
            
            # Command Injection
            'system': 'CWE-78', 'popen': 'CWE-78', 'WinExec': 'CWE-78',
            'ShellExecute': 'CWE-78', 'CreateProcess': 'CWE-78',
            'execl': 'CWE-78', 'execle': 'CWE-78', 'execlp': 'CWE-78',
            'execv': 'CWE-78', 'execvp': 'CWE-78', 'execve': 'CWE-78',
            
            # Memory Management
            'malloc': 'CWE-401', 'calloc': 'CWE-401', 'realloc': 'CWE-401',
            'free': 'CWE-415', 'memset': 'CWE-119',
            
            # File System
            'tmpnam': 'CWE-377', 'tmpfile': 'CWE-377', 'mktemp': 'CWE-377',
            'open': 'CWE-22', 'fopen': 'CWE-22',
            
            # Network
            'socket': 'CWE-200', 'bind': 'CWE-200', 'listen': 'CWE-200',
            'accept': 'CWE-20', 'connect': 'CWE-20', 'recv': 'CWE-20',
            'send': 'CWE-200',
            
            # Dynamic Loading
            'LoadLibrary': 'CWE-426', 'LoadLibraryEx': 'CWE-426',
            'GetProcAddress': 'CWE-426', 'dlopen': 'CWE-426',
            
            # Authentication
            'getlogin': 'CWE-287', 'crypt': 'CWE-327', 'LogonUser': 'CWE-287',
            
            # Process Control
            'CreateRemoteThread': 'CWE-94', 'SetWindowsHookEx': 'CWE-94',
            'ImpersonateLoggedOnUser': 'CWE-250',
            
            # Crypto
            'MD5': 'CWE-327', 'SHA1': 'CWE-327'
        }
        
        return cwe_mapping.get(func_name, 'CWE-20')  # Default to improper input validation
    
    def _get_comprehensive_risk_score(self, func_name: str, severity: str) -> int:
        """Calculate comprehensive risk score"""
        base_scores = {
            'CRITICAL': 95,
            'HIGH': 80,
            'MEDIUM': 60,
            'LOW': 40,
            'INFO': 20
        }
        
        # Function-specific adjustments
        high_risk_funcs = ['gets', 'system', 'CreateRemoteThread']
        if func_name in high_risk_funcs:
            return min(base_scores.get(severity, 50) + 10, 100)
        
        return base_scores.get(severity, 50)
    
    def _get_comprehensive_remediation(self, func_name: str) -> str:
        """Get comprehensive remediation advice"""
        remediation_mapping = {
            # Buffer Overflow Functions
            'strcpy': 'Replace with strncpy() or safer string handling functions like strlcpy()',
            'strcat': 'Replace with strncat() or safer string handling functions like strlcat()',
            'sprintf': 'Replace with snprintf() and specify buffer size limits',
            'vsprintf': 'Replace with vsnprintf() and specify buffer size limits',
            'gets': 'Replace with fgets() specifying buffer size - gets() is fundamentally unsafe',
            'alloca': 'Replace with malloc() and proper bounds checking, or use fixed-size stack arrays',
            
            # Format String Functions  
            'printf': 'Use explicit format strings, never pass user input as format parameter',
            'fprintf': 'Use explicit format strings, never pass user input as format parameter',
            'scanf': 'Use format width specifiers and validate input lengths',
            
            # Command Execution
            'system': 'Replace with execv() family functions and validate/sanitize all inputs',
            'popen': 'Replace with safer process creation methods and validate inputs',
            'WinExec': 'Replace with CreateProcess() and validate all parameters',
            'ShellExecute': 'Replace with CreateProcess() and validate all parameters',
            'CreateProcess': 'Validate all command line parameters and avoid shell interpretation',
            
            # Memory Management
            'malloc': 'Check return value for NULL and pair with corresponding free()',
            'free': 'Set pointer to NULL after free() to prevent use-after-free',
            'realloc': 'Check return value and handle failure cases properly',
            
            # File System
            'tmpnam': 'Replace with mkstemp() or tmpfile_s() for secure temporary files',
            'tmpfile': 'Use mkstemp() or tmpfile_s() for secure temporary file creation',
            'open': 'Validate file paths and use appropriate access controls',
            'fopen': 'Validate file paths and use appropriate access controls',
            
            # Network
            'socket': 'Implement proper error handling and access controls',
            'bind': 'Validate bind addresses and implement access controls',
            'accept': 'Validate incoming connections and implement rate limiting',
            'recv': 'Validate received data length and content',
            
            # Dynamic Loading
            'LoadLibrary': 'Validate library paths and use LoadLibraryEx with appropriate flags',
            'GetProcAddress': 'Validate function names and implement allow-lists',
            'dlopen': 'Validate library paths and use RTLD_NOW flag',
            
            # Authentication
            'getlogin': 'Use more secure authentication methods and validate results',
            'crypt': 'Replace with modern password hashing functions like bcrypt or Argon2',
            'LogonUser': 'Implement secure credential handling and validation',
            
            # Process Control  
            'CreateRemoteThread': 'Avoid if possible, implement strict access controls if required',
            'SetWindowsHookEx': 'Implement proper cleanup and access validation',
            'ImpersonateLoggedOnUser': 'Implement privilege dropping and proper access controls'
        }
        
        return remediation_mapping.get(func_name, 'Review function usage and implement proper input validation and security controls')
    
    def _get_function_category(self, func_name: str) -> str:
        """Get vulnerability category for dangerous function"""
        categories = {
            'buffer_overflow': [
                'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'alloca',
                'memcpy', 'memmove', 'strncpy', 'strncat', 'snprintf'
            ],
            'format_string': [
                'printf', 'fprintf', 'vfprintf', 'scanf', 'sscanf', 'fscanf'
            ],
            'command_injection': [
                'system', 'popen', 'execl', 'execle', 'execlp', 'execv', 
                'execvp', 'execve', 'WinExec', 'ShellExecute', 'CreateProcess'
            ],
            'memory_management': [
                'malloc', 'calloc', 'realloc', 'free', 'memset'
            ],
            'file_system': [
                'tmpnam', 'tmpfile', 'mktemp', 'open', 'fopen'
            ],
            'network_security': [
                'socket', 'bind', 'listen', 'accept', 'connect', 'recv', 'send'
            ],
            'dynamic_loading': [
                'LoadLibrary', 'LoadLibraryEx', 'GetProcAddress', 'dlopen'
            ],
            'authentication': [
                'getlogin', 'crypt', 'LogonUser'
            ],
            'process_control': [
                'CreateRemoteThread', 'SetWindowsHookEx', 'ImpersonateLoggedOnUser',
                'abort', 'assert', 'raise', 'vfork', 'clone'
            ],
            'crypto_weakness': [
                'MD5', 'SHA1'
            ]
        }
        
        for category, functions in categories.items():
            if func_name in functions:
                return category
        
        return 'other'
    
    def _store_unified_findings(self, function: Function, findings: List[Dict]) -> List[Dict]:
        """Store unified security findings in database, replacing previous findings for this function"""
        stored_findings = []
        try:
            # Delete previous findings for this function
            UnifiedSecurityFinding.query.filter_by(function_id=function.id).delete()
            db.session.commit()
            for finding_data in findings:
                # Create unified security finding
                finding = UnifiedSecurityFinding(
                    binary_id=function.binary_id,
                    function_id=function.id,
                    title=finding_data['title'],
                    description=finding_data['description'],
                    severity=finding_data['severity'],
                    confidence=finding_data['confidence'],
                    cwe_id=finding_data.get('cwe_id'),
                    category=finding_data.get('category'),
                    ai_explanation=finding_data.get('ai_explanation'),
                    pattern_matches=finding_data.get('pattern_matches'),
                    detection_methods=finding_data.get('detection_methods', []),
                    address=function.address,
                    affected_code=finding_data.get('affected_code'),
                    remediation=finding_data.get('remediation'),
                    risk_score=finding_data.get('risk_score', 0),
                    exploit_difficulty=finding_data.get('exploit_difficulty', 'MEDIUM'),
                    correlation_score=finding_data.get('correlation_score', 0)
                )
                
                db.session.add(finding)
                db.session.flush()  # Get the ID
                
                # Store supporting evidence
                for evidence_data in finding_data.get('evidence', []):
                    evidence = SecurityEvidence(
                        finding_id=finding.id,
                        evidence_type=evidence_data['type'],
                        source=evidence_data['source'],
                        confidence_impact=evidence_data.get('confidence_impact', 0),
                        raw_data=evidence_data.get('raw_data'),
                        processed_data=evidence_data.get('processed_data'),
                        description=evidence_data.get('description')
                    )
                    db.session.add(evidence)
                
                stored_findings.append(finding.to_dict())
            
            db.session.commit()
            logger.info(f"Stored {len(stored_findings)} unified security findings")
            
        except Exception as e:
            logger.error(f"Error storing unified findings: {e}")
            db.session.rollback()
            raise
        
        return stored_findings


class RiskCorrelationEngine:
    """Engine for correlating AI findings with pattern-based detections"""
    
    def correlate_findings(self, function: Function, ai_analysis: Dict, pattern_analysis: Dict) -> List[Dict]:
        """Correlate AI and pattern analysis results into unified findings"""
        unified_findings = []
        
        if not ai_analysis.get('success') and not pattern_analysis.get('success'):
            return unified_findings
        
        # Process AI findings
        ai_issues = ai_analysis.get('security_issues', [])
        pattern_vulns = pattern_analysis.get('vulnerabilities', [])
        
        # Create mapping of AI issues to pattern matches
        for ai_issue in ai_issues:
            # Find matching patterns
            matching_patterns = self._find_matching_patterns(ai_issue, pattern_vulns)
            
            unified_finding = {
                'title': ai_issue.get('title', 'Security Issue'),
                'description': ai_issue.get('description', ''),
                'severity': self._normalize_severity(ai_issue.get('severity', 'MEDIUM')),
                'cwe_id': ai_issue.get('cwe_id'),
                'category': self._extract_category(ai_issue),
                'ai_explanation': ai_issue.get('description'),
                'pattern_matches': matching_patterns,
                'detection_methods': self._get_detection_methods(ai_issue, matching_patterns),
                'affected_code': self._extract_affected_code(ai_issue, function),
                'remediation': ai_issue.get('remediation'),
                'risk_score': self._calculate_risk_score(ai_issue, matching_patterns),
                'exploit_difficulty': self._get_exploit_difficulty(ai_issue),
                'correlation_score': len(matching_patterns) * 20,  # Higher if patterns match
                'evidence': self._build_evidence(ai_issue, matching_patterns)
            }

            # --- NEW LOGIC: Cap risk score for simple getters unless justified ---
            if (
                unified_finding['risk_score'] > 40 and
                self._is_simple_getter(function, ai_issue, matching_patterns)
            ):
                if not self._ai_justifies_high_risk(ai_issue):
                    unified_finding['risk_score'] = 40
                    unified_finding['notes'] = (
                        "Risk score capped due to simple getter pattern and lack of strong justification for high risk."
                    )
            # ---------------------------------------------------------------

            unified_findings.append(unified_finding)
        
        # Add pattern-only findings (not matched by AI)
        matched_pattern_ids = []
        for finding in unified_findings:
            for pattern in finding.get('pattern_matches', []):
                matched_pattern_ids.append(pattern.get('id'))
        
        for pattern_vuln in pattern_vulns:
            if pattern_vuln.get('id') not in matched_pattern_ids:
                # Create finding from pattern only
                unified_finding = {
                    'title': pattern_vuln.get('title', 'Pattern-Detected Vulnerability'),
                    'description': pattern_vuln.get('description', ''),
                    'severity': pattern_vuln.get('severity', 'MEDIUM'),
                    'cwe_id': pattern_vuln.get('cwe_id'),
                    'category': pattern_vuln.get('type'),
                    'ai_explanation': None,
                    'pattern_matches': [pattern_vuln],
                    'detection_methods': ['pattern_matching'],
                    'affected_code': pattern_vuln.get('affected_code'),
                    'remediation': pattern_vuln.get('remediation'),
                    'risk_score': pattern_vuln.get('risk_score', 50),
                    'exploit_difficulty': 'MEDIUM',
                    'correlation_score': 0,  # No AI correlation
                    'evidence': self._build_evidence(None, [pattern_vuln])
                }
                
                unified_findings.append(unified_finding)
        
        return unified_findings

    def _is_simple_getter(self, function, ai_issue, matching_patterns):
        """Detect if a function is a simple getter (no params, just returns a static value, no dangerous patterns)"""
        # No dangerous patterns found
        if matching_patterns:
            return False
        # No parameters and code is a single return statement
        code = function.decompiled_code.strip()
        if hasattr(function, 'parameter_count') and function.parameter_count in (None, 0):
            # Check for a single return statement (allow whitespace and comments)
            code_lines = [line.strip() for line in code.splitlines() if line.strip() and not line.strip().startswith('//')]
            if len(code_lines) == 2 and code_lines[0].startswith('return') and code_lines[0].endswith(';'):
                return True
            if re.match(r"^return [^;]+;\s*$", code, re.MULTILINE):
                return True
        # AI summary/description mentions 'returns value at address', 'getter', 'static value', etc.
        desc = (ai_issue.get('description') or '').lower()
        if any(kw in desc for kw in ['returns value at address', 'getter', 'static value', 'returns a value from', 'returns the value at']):
            return True
        return False

    def _ai_justifies_high_risk(self, ai_issue):
        desc = (ai_issue.get('description') or '').lower()
        for keyword in ['cryptographic key', 'password', 'private key', 'secret', 'authentication token', 'credential']:
            if keyword in desc:
                return True
        return False
    
    def _find_matching_patterns(self, ai_issue: Dict, pattern_vulns: List[Dict]) -> List[Dict]:
        """Find vulnerability patterns that match an AI-identified issue"""
        matching_patterns = []
        
        ai_cwe = ai_issue.get('cwe_id', '').lower()
        ai_title = ai_issue.get('title', '').lower()
        ai_desc = ai_issue.get('description', '').lower()
        
        for pattern in pattern_vulns:
            pattern_cwe = pattern.get('cwe_id', '').lower()
            pattern_type = pattern.get('type', '').lower()
            pattern_title = pattern.get('title', '').lower()
            
            # Match by CWE ID
            if ai_cwe and pattern_cwe and ai_cwe == pattern_cwe:
                matching_patterns.append(pattern)
                continue
            
            # Match by vulnerability type keywords
            type_keywords = {
                'buffer': ['buffer', 'overflow', 'strcpy', 'strcat', 'sprintf'],
                'format': ['format', 'string', 'printf', 'sprintf'],
                'command': ['command', 'injection', 'system', 'exec'],
                'crypto': ['crypto', 'md5', 'sha1', 'hash']
            }
            
            for category, keywords in type_keywords.items():
                if any(keyword in ai_title or keyword in ai_desc for keyword in keywords):
                    if category in pattern_type or any(keyword in pattern_title for keyword in keywords):
                        matching_patterns.append(pattern)
                        break
        
        return matching_patterns
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity levels"""
        severity_map = {
            'critical': 'CRITICAL',
            'high': 'HIGH', 
            'medium': 'MEDIUM',
            'low': 'LOW',
            'info': 'INFO',
            'informational': 'INFO'
        }
        return severity_map.get(severity.lower(), 'MEDIUM')
    
    def _extract_category(self, ai_issue: Dict) -> str:
        """Extract vulnerability category from AI issue"""
        title = ai_issue.get('title', '').lower()
        desc = ai_issue.get('description', '').lower()
        
        if any(keyword in title or keyword in desc for keyword in ['buffer', 'overflow']):
            return 'buffer_overflow'
        elif any(keyword in title or keyword in desc for keyword in ['format', 'string']):
            return 'format_string'
        elif any(keyword in title or keyword in desc for keyword in ['command', 'injection']):
            return 'command_injection'
        elif any(keyword in title or keyword in desc for keyword in ['crypto', 'hash']):
            return 'crypto_weakness'
        else:
            return 'other'
    
    def _get_detection_methods(self, ai_issue: Dict, matching_patterns: List[Dict]) -> List[str]:
        """Get list of detection methods used"""
        methods = ['ai_analysis']
        if matching_patterns:
            methods.append('pattern_matching')
        return methods
    
    def _get_exploit_difficulty(self, ai_issue: Dict) -> str:
        """Safely extract exploit difficulty from AI issue"""
        try:
            impact = ai_issue.get('impact')
            if isinstance(impact, dict):
                return impact.get('exploit_difficulty', 'MEDIUM')
            elif isinstance(impact, str):
                # If impact is a string, try to infer difficulty
                impact_lower = impact.lower()
                if any(word in impact_lower for word in ['easy', 'trivial', 'simple']):
                    return 'LOW'
                elif any(word in impact_lower for word in ['hard', 'difficult', 'complex']):
                    return 'HIGH'
                else:
                    return 'MEDIUM'
            else:
                return 'MEDIUM'
        except:
            return 'MEDIUM'
    
    def _extract_affected_code(self, ai_issue: Dict, function: Function) -> str:
        """Extract affected code snippet"""
        location = ai_issue.get('location', '')
        if location and 'line' in location.lower():
            # Try to extract specific lines
            try:
                line_num = int(re.search(r'\d+', location).group())
                lines = function.decompiled_code.split('\n')
                if 0 <= line_num - 1 < len(lines):
                    # Return line with context
                    start = max(0, line_num - 3)
                    end = min(len(lines), line_num + 2)
                    return '\n'.join(lines[start:end])
            except:
                pass
        
        # Return first 200 characters as fallback
        return function.decompiled_code[:200] + '...' if len(function.decompiled_code) > 200 else function.decompiled_code
    
    def _calculate_risk_score(self, ai_issue: Dict, matching_patterns: List[Dict]) -> int:
        """Calculate overall risk score"""
        ai_confidence = ai_issue.get('confidence', 50)
        pattern_scores = [p.get('risk_score', 50) for p in matching_patterns]
        
        if pattern_scores:
            avg_pattern_score = sum(pattern_scores) / len(pattern_scores)
            # Weight AI and pattern scores
            return int((ai_confidence * 0.4) + (avg_pattern_score * 0.6))
        else:
            return int(ai_confidence * 0.8)  # Lower confidence without pattern validation
    
    def _build_evidence(self, ai_issue: Optional[Dict], matching_patterns: List[Dict]) -> List[Dict]:
        """Build evidence list for the finding"""
        evidence = []
        
        if ai_issue:
            evidence.append({
                'type': 'ai_analysis',
                'source': 'ai_service',
                'confidence_impact': ai_issue.get('confidence', 50) - 50,
                'raw_data': ai_issue,
                'description': f"AI identified: {ai_issue.get('title', 'Security issue')}"
            })
        
        for pattern in matching_patterns:
            evidence.append({
                'type': 'pattern_match',
                'source': 'vulnerability_engine',
                'confidence_impact': 20,  # Patterns add confidence
                'raw_data': pattern,
                'description': f"Pattern matched: {pattern.get('title', 'Vulnerability pattern')}"
            })
        
        return evidence


class ConfidenceCalculator:
    """Calculator for confidence scores based on multiple evidence sources"""
    
    def calculate_confidence(self, finding: Dict, ai_analysis: Dict, pattern_analysis: Dict) -> int:
        """Calculate confidence score for a unified finding"""
        base_confidence = 50
        
        # AI analysis contribution
        if finding.get('ai_explanation'):
            ai_confidence = 70  # Base AI confidence
            base_confidence += 20
        
        # Pattern validation contribution
        pattern_matches = finding.get('pattern_matches', [])
        if pattern_matches:
            pattern_confidence = min(len(pattern_matches) * 15, 30)  # Max 30 points
            base_confidence += pattern_confidence
        
        # Correlation bonus
        correlation_score = finding.get('correlation_score', 0)
        if correlation_score > 0:
            base_confidence += min(correlation_score, 20)  # Max 20 points correlation bonus
        
        # Evidence quality
        evidence_count = len(finding.get('evidence', []))
        evidence_bonus = min(evidence_count * 5, 15)  # Max 15 points
        base_confidence += evidence_bonus
        
        # Cap at 100
        return min(base_confidence, 100) 