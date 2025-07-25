#!/usr/bin/env python3
"""
Enhanced Security Analysis Engine

This module provides enhanced security analysis that works with multiple data sources:
- Exported functions (with decompilation)
- Strings analysis for security patterns
- Symbols and imports analysis
- Memory layout analysis
- AI-driven analysis across all available data

Designed to provide security value even when traditional function analysis is limited.
"""

import logging
import re
import json
import time
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

from flask_app import db
from flask_app.models import (
    Binary, Function, Import, Export, BinaryString, MemoryRegion, Symbol,
    UnifiedSecurityFinding, SecurityEvidence, Configuration
)
from flask_app.multi_provider_ai_service import MultiProviderAIService
from flask_app.forwarder_dll_analyzer import ForwarderDLLAnalyzer

logger = logging.getLogger(__name__)

class EnhancedSecurityAnalyzer:
    """
    Enhanced security analyzer that works with multiple data sources
    to provide security insights even when function analysis is limited
    """
    
    def __init__(self):
        self.ai_service = MultiProviderAIService()
        self._load_config()
    
    def reload_ai_service(self):
        """Reload AI service with updated configuration"""
        logger.info("Reloading AI service in enhanced security analyzer")
        self.ai_service = MultiProviderAIService()
        provider_name = getattr(self.ai_service, 'provider_name', 'unknown')
        logger.info(f"Enhanced security analyzer reinitialized with {provider_name} provider")
        return self.ai_service.client is not None
        
        # Initialize forwarder DLL analyzer
        from flask_app.config import Config
        config = Config()
        self.forwarder_analyzer = ForwarderDLLAnalyzer(
            ghidra_install_dir=config.GHIDRA_INSTALL_DIR,
            projects_dir=config.GHIDRA_PROJECTS_DIR,
            scripts_dir=config.ANALYSIS_SCRIPTS_DIR
        )
        
        # Security patterns for string analysis
        self.security_string_patterns = {
            'crypto_weak': [
                r'MD5|SHA1(?![\d])|DES(?![\w])',
                r'RC4|MD4|SHA0'
            ],
            'credential_exposure': [
                r'password|passwd|pwd|secret|token|api[_-]?key',
                r'private[_-]?key|secret[_-]?key|auth[_-]?token'
            ],
            'command_injection': [
                r'system\s*\(|exec\s*\(|popen\s*\(',
                r'cmd\.exe|powershell|bash|sh\s+'
            ],
            'sql_injection': [
                r'SELECT\s+.*FROM|INSERT\s+INTO|UPDATE\s+.*SET',
                r'DROP\s+TABLE|DELETE\s+FROM'
            ],
            'buffer_overflow_indicators': [
                r'strcpy|strcat|sprintf|gets|scanf',
                r'memcpy|memmove|memset.*size'
            ]
        }
        
        # Suspicious import patterns
        self.suspicious_imports = {
            'process_injection': [
                'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
                'OpenProcess', 'SetWindowsHookEx', 'NtCreateThreadEx'
            ],
            'privilege_escalation': [
                'AdjustTokenPrivileges', 'ImpersonateLoggedOnUser', 'LogonUser',
                'CreateProcessAsUser', 'DuplicateTokenEx'
            ],
            'crypto_api': [
                'CryptCreateHash', 'CryptHashData', 'CryptEncrypt', 'CryptDecrypt',
                'BCryptCreateHash', 'BCryptEncrypt', 'BCryptDecrypt'
            ],
            'network_operations': [
                'WSAStartup', 'socket', 'bind', 'listen', 'accept', 'connect',
                'send', 'recv', 'HttpSendRequest', 'InternetConnect'
            ]
        }
    
    def _load_config(self):
        """Load enhanced security analysis configuration"""
        try:
            self.confidence_threshold = self._get_config_int('enhanced_security_confidence_threshold', 60)
            self.decompile_exports = self._get_config_bool('enhanced_security_decompile_exports', True)
            self.max_exports_to_analyze = self._get_config_int('enhanced_security_max_exports', 10)
        except Exception as e:
            logger.warning(f"Error loading enhanced security config, using defaults: {e}")
            self.confidence_threshold = 60
            self.decompile_exports = True
            self.max_exports_to_analyze = 10
    
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
    
    def analyze_binary_security(self, binary: Binary) -> Dict[str, Any]:
        """
        Perform enhanced security analysis on a binary using multiple data sources
        
        Args:
            binary: Binary object to analyze
            
        Returns:
            Dict containing comprehensive security analysis results
        """
        try:
            logger.info(f"Starting enhanced security analysis for binary {binary.id} ({binary.filename})")
            
            results = {
                'success': True,
                'binary_id': binary.id,
                'analysis_methods': [],
                'findings': [],
                'total_findings': 0,
                'coverage_analysis': {},
                'forwarder_analysis': None
            }
            
            # Check if this is a forwarder DLL first - simplified detection
            if binary.filename.lower().endswith('.dll'):
                logger.info(f"Checking if {binary.filename} is a forwarder/API Set DLL...")
                
                try:
                    # Simple forwarder detection based on existing data
                    forwarder_result = self._detect_forwarder_dll_simple(binary)
                    
                    if forwarder_result.get('is_forwarder'):
                        results['forwarder_analysis'] = forwarder_result
                        logger.info(f"Detected forwarder DLL: {len(forwarder_result.get('forwarding_entries', []))} forwarding entries")
                        
                        # For forwarder DLLs, create special findings
                        forwarding_finding = {
                            'type': 'forwarder_dll_info',
                            'severity': 'info',
                            'title': 'Windows API Forwarder DLL',
                            'description': f"API Forwarder DLL: {len(forwarder_result.get('forwarding_entries', []))} forwards to {len(forwarder_result.get('target_dlls', []))} target DLLs",
                            'evidence': forwarder_result.get('forwarding_entries', []),
                            'confidence': 100.0,
                            'method': 'forwarder_analysis'
                        }
                        
                        results['findings'].append(forwarding_finding)
                        results['analysis_methods'].append('forwarder_analysis')
                        
                        # For pure forwarders, we can skip other analysis
                        if forwarder_result.get('function_count', 0) == 0:
                            logger.info("Pure forwarder DLL detected - skipping code analysis")
                            results['total_findings'] = len(results['findings'])
                            return results
                    else:
                        logger.info("Not a forwarder DLL - proceeding with normal analysis")
                        results['forwarder_analysis'] = forwarder_result  # Include negative result too
                        
                except Exception as e:
                    logger.error(f"Error during forwarder DLL analysis: {e}")
                    # Continue with normal analysis if forwarder check fails
            
            # First check if we have any comprehensive analysis data
            exports_count = Export.query.filter_by(binary_id=binary.id).count()
            imports_count = Import.query.filter_by(binary_id=binary.id).count()
            strings_count = BinaryString.query.filter_by(binary_id=binary.id).count()
            
            if exports_count == 0 and imports_count == 0 and strings_count == 0:
                logger.info(f"No comprehensive analysis data found for binary {binary.id}. Running comprehensive analysis first...")
                comp_result = self._run_comprehensive_analysis(binary)
                if comp_result.get('success'):
                    results['coverage_analysis']['comprehensive_analysis'] = comp_result
                    # Refresh counts after comprehensive analysis
                    exports_count = Export.query.filter_by(binary_id=binary.id).count()
                    logger.info(f"Comprehensive analysis completed: {exports_count} exports, {imports_count} imports, {strings_count} strings")
            
            # Check if we need to decompile exports
            decompiled_functions = Function.query.filter_by(binary_id=binary.id, is_decompiled=True).count()
            
            if decompiled_functions == 0 and exports_count > 0:
                logger.info(f"No decompiled functions found but {exports_count} exports available. Running export decompilation...")
                export_decompile_result = self._decompile_exports_for_security(binary)
                if export_decompile_result.get('success'):
                    results['coverage_analysis']['export_decompilation'] = export_decompile_result
                    # Refresh function count after decompilation
                    decompiled_functions = Function.query.filter_by(binary_id=binary.id, is_decompiled=True).count()
                    logger.info(f"Export decompilation completed: {decompiled_functions} functions now available")
            
            # If we now have decompiled functions, use traditional analysis on them
            if decompiled_functions > 0:
                logger.info(f"Running traditional security analysis on {decompiled_functions} decompiled functions")
                traditional_results = self._run_traditional_security_analysis(binary)
                if traditional_results['findings']:
                    results['findings'].extend(traditional_results['findings'])
                    results['analysis_methods'].append('traditional_function_analysis')
                    results['coverage_analysis']['traditional_analysis'] = traditional_results['metadata']
            
            # Method 1: Analyze exported functions (name-based analysis)
            exports_count = Export.query.filter_by(binary_id=binary.id).count()
            if exports_count > 0:
                export_results = self._analyze_exported_functions(binary)
                if export_results['findings']:
                    results['findings'].extend(export_results['findings'])
                    results['analysis_methods'].append('exported_functions')
                    results['coverage_analysis']['exported_functions'] = export_results['metadata']
            
            # Method 2: AI-driven strings analysis
            strings_count = BinaryString.query.filter_by(binary_id=binary.id).count()
            if strings_count > 0:
                string_results = self._analyze_strings_for_security(binary)
                if string_results['findings']:
                    results['findings'].extend(string_results['findings'])
                    results['analysis_methods'].append('strings_analysis')
                    results['coverage_analysis']['strings_analysis'] = string_results['metadata']
            
            # Method 3: Imports and symbols analysis
            imports_count = Import.query.filter_by(binary_id=binary.id).count()
            symbols_count = Symbol.query.filter_by(binary_id=binary.id).count()
            if imports_count > 0 or symbols_count > 0:
                import_results = self._analyze_imports_and_symbols(binary)
                if import_results['findings']:
                    results['findings'].extend(import_results['findings'])
                    results['analysis_methods'].append('imports_symbols')
                    results['coverage_analysis']['imports_symbols'] = import_results['metadata']
            
            # Method 4: Memory layout analysis
            memory_count = MemoryRegion.query.filter_by(binary_id=binary.id).count()
            if memory_count > 0:
                memory_results = self._analyze_memory_layout(binary)
                if memory_results['findings']:
                    results['findings'].extend(memory_results['findings'])
                    results['analysis_methods'].append('memory_layout')
                    results['coverage_analysis']['memory_layout'] = memory_results['metadata']
            
            # Method 5: AI-powered comprehensive analysis (always run if any data available)
            if any([exports_count, strings_count, imports_count, symbols_count, memory_count]) > 0:
                ai_results = self._ai_comprehensive_analysis(binary)
                if ai_results['findings']:
                    results['findings'].extend(ai_results['findings'])
                    results['analysis_methods'].append('ai_comprehensive')
                    results['coverage_analysis']['ai_comprehensive'] = ai_results['metadata']
            
            # Store findings in database
            stored_findings = self._store_enhanced_findings(binary, results['findings'])
            results['total_findings'] = len(stored_findings)
            results['stored_findings'] = stored_findings
            
            logger.info(f"Enhanced security analysis completed for binary {binary.id}: "
                       f"{len(results['analysis_methods'])} methods, {results['total_findings']} findings")
            
            return results
            
        except Exception as e:
            logger.error(f"Error in enhanced security analysis for binary {binary.id}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {'success': False, 'error': f'Enhanced security analysis failed: {str(e)}'}
    
    def _analyze_exported_functions(self, binary: Binary) -> Dict[str, Any]:
        """Analyze exported functions, decompiling them if needed"""
        try:
            # Get exports from database
            exports_query = Export.query.filter_by(binary_id=binary.id).all()
            exports_data = [export.to_dict() for export in exports_query]
            findings = []
            
            logger.info(f"Analyzing {len(exports_data)} exported functions for security patterns")
            
            # Limit exports to analyze to prevent overwhelming analysis
            exports_to_analyze = exports_data[:self.max_exports_to_analyze]
            
            # For each export, check if it's already a function and decompiled
            for export in exports_to_analyze:
                export_name = export.get('name', 'unknown')
                export_address = export.get('address', '')
                
                # Check if this export has security-relevant patterns in its name
                security_rating = self._rate_export_security_relevance(export_name)
                if security_rating['risk_level'] != 'low':
                    
                    # Try to get existing function
                    function = Function.query.filter_by(
                        binary_id=binary.id, 
                        address=export_address
                    ).first()
                    
                    if function and function.decompiled_code:
                        # Use existing decompiled function for traditional analysis
                        func_findings = self._analyze_function_code_patterns(function, export_name)
                        findings.extend(func_findings)
                    else:
                        # Create finding based on export name analysis
                        name_finding = {
                            'title': f'Security-Relevant Export: {export_name}',
                            'description': security_rating['description'],
                            'severity': security_rating['severity'],
                            'confidence': security_rating['confidence'],
                            'category': 'exported_function',
                            'cwe_id': security_rating.get('cwe_id'),
                            'detection_methods': ['export_name_analysis'],
                            'affected_code': f'Exported function: {export_name} at {export_address}',
                            'remediation': security_rating.get('remediation', 'Review exported function implementation for security issues'),
                            'risk_score': security_rating['confidence'],
                            'address': export_address
                        }
                        findings.append(name_finding)
            
            return {
                'findings': findings,
                'metadata': {
                    'total_exports': len(exports_data),
                    'analyzed_exports': len(exports_to_analyze),
                    'findings_count': len(findings)
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing exported functions: {e}")
            return {'findings': [], 'metadata': {'error': str(e)}}
    
    def _rate_export_security_relevance(self, export_name: str) -> Dict[str, Any]:
        """Rate the security relevance of an exported function name"""
        export_lower = export_name.lower()
        
        # High-risk patterns
        if any(pattern in export_lower for pattern in [
            'auth', 'login', 'password', 'encrypt', 'decrypt', 'hash', 
            'token', 'key', 'cert', 'crypto', 'security', 'validate'
        ]):
            return {
                'risk_level': 'high',
                'severity': 'MEDIUM',
                'confidence': 80,
                'description': f'Export function {export_name} appears to handle security-sensitive operations',
                'cwe_id': 'CWE-284',
                'remediation': 'Review authentication and cryptographic implementations for common vulnerabilities'
            }
        
        # Medium-risk patterns
        if any(pattern in export_lower for pattern in [
            'execute', 'exec', 'run', 'process', 'command', 'shell',
            'file', 'read', 'write', 'open', 'create', 'delete'
        ]):
            return {
                'risk_level': 'medium',
                'severity': 'LOW',
                'confidence': 60,
                'description': f'Export function {export_name} appears to perform system operations',
                'cwe_id': 'CWE-78',
                'remediation': 'Review input validation and access controls for system operations'
            }
        
        # Network-related patterns
        if any(pattern in export_lower for pattern in [
            'socket', 'connect', 'send', 'recv', 'http', 'url', 'web', 'net'
        ]):
            return {
                'risk_level': 'medium',
                'severity': 'LOW',
                'confidence': 65,
                'description': f'Export function {export_name} appears to handle network operations',
                'cwe_id': 'CWE-200',
                'remediation': 'Review network communication for proper encryption and validation'
            }
        
        return {
            'risk_level': 'low',
            'severity': 'INFO',
            'confidence': 30,
            'description': f'Export function {export_name} does not show obvious security patterns'
        }
    
    def _analyze_function_code_patterns(self, function: Function, context: str) -> List[Dict[str, Any]]:
        """Analyze decompiled function code for security patterns"""
        findings = []
        
        if not function.decompiled_code:
            return findings
        
        code = function.decompiled_code.lower()
        
        # Look for dangerous function calls
        dangerous_patterns = {
            'strcpy': {'severity': 'HIGH', 'cwe': 'CWE-120', 'desc': 'Buffer overflow risk'},
            'strcat': {'severity': 'HIGH', 'cwe': 'CWE-120', 'desc': 'Buffer overflow risk'},
            'sprintf': {'severity': 'HIGH', 'cwe': 'CWE-120', 'desc': 'Buffer overflow risk'},
            'gets': {'severity': 'CRITICAL', 'cwe': 'CWE-120', 'desc': 'Critical buffer overflow risk'},
            'system': {'severity': 'HIGH', 'cwe': 'CWE-78', 'desc': 'Command injection risk'},
            'exec': {'severity': 'HIGH', 'cwe': 'CWE-78', 'desc': 'Command injection risk'},
        }
        
        for pattern, info in dangerous_patterns.items():
            if re.search(rf'\b{pattern}\s*\(', code):
                finding = {
                    'title': f'{info["desc"]} in {context}',
                    'description': f'Function {function.name or function.address} contains call to {pattern}()',
                    'severity': info['severity'],
                    'confidence': 85,
                    'category': 'dangerous_function',
                    'cwe_id': info['cwe'],
                    'detection_methods': ['pattern_matching'],
                    'affected_code': self._extract_code_context(function.decompiled_code, pattern),
                    'address': function.address,
                    'risk_score': 85 if info['severity'] == 'CRITICAL' else 70
                }
                findings.append(finding)
        
        return findings
    
    def _analyze_strings_for_security(self, binary: Binary) -> Dict[str, Any]:
        """Analyze strings for security-relevant patterns using AI"""
        try:
            # Get strings from database
            strings_query = BinaryString.query.filter_by(binary_id=binary.id).all()
            strings_data = [string.to_dict() for string in strings_query]
            findings = []
            
            # Extract interesting strings
            security_strings = []
            for string_obj in strings_data:
                string_value = string_obj.get('value', '')
                
                # Check against security patterns
                for category, patterns in self.security_string_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, string_value, re.IGNORECASE):
                            security_strings.append({
                                'value': string_value,
                                'category': category,
                                'address': string_obj.get('address', ''),
                                'pattern': pattern
                            })
            
            # Use AI to analyze security strings if found
            if security_strings:
                ai_analysis = self._ai_analyze_security_strings(security_strings, binary)
                if ai_analysis.get('findings'):
                    findings.extend(ai_analysis['findings'])
            
            return {
                'findings': findings,
                'metadata': {
                    'total_strings': len(strings_data),
                    'security_relevant_strings': len(security_strings),
                    'findings_count': len(findings)
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing strings for security: {e}")
            return {'findings': [], 'metadata': {'error': str(e)}}
    
    def _ai_analyze_security_strings(self, security_strings: List[Dict], binary: Binary) -> Dict[str, Any]:
        """Use AI to analyze security-relevant strings"""
        # TODO: Implement dedicated string analysis AI method
        return {'findings': []}
    
    def _analyze_imports_and_symbols(self, binary: Binary) -> Dict[str, Any]:
        """Analyze imports and symbols for security patterns"""
        try:
            findings = []
            
            # Analyze imports
            imports_query = Import.query.filter_by(binary_id=binary.id).all()
            if imports_query:
                imports_data = [imp.to_dict() for imp in imports_query]
                
                for imp in imports_data:
                    function_name = imp.get('name', '')
                    library = imp.get('library', 'unknown')
                    
                    # Check against suspicious import patterns
                    for category, suspicious_funcs in self.suspicious_imports.items():
                        if function_name in suspicious_funcs:
                            finding = {
                                'title': f'Suspicious Import: {function_name}',
                                'description': f'Binary imports {function_name} from {library}, which is associated with {category}',
                                'severity': self._get_import_severity(category),
                                'confidence': 75,
                                'category': f'suspicious_import_{category}',
                                'cwe_id': self._get_import_cwe(category),
                                'detection_methods': ['import_analysis'],
                                'affected_code': f'Import: {function_name} from {library}',
                                'remediation': f'Review usage of {function_name} for proper security controls',
                                'risk_score': 70
                            }
                            findings.append(finding)
            
            return {
                'findings': findings,
                'metadata': {
                    'findings_count': len(findings)
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing imports and symbols: {e}")
            return {'findings': [], 'metadata': {'error': str(e)}}
    
    def _analyze_memory_layout(self, binary: Binary) -> Dict[str, Any]:
        """Analyze memory layout for security issues"""
        try:
            findings = []
            
            # Get memory regions from database
            memory_query = MemoryRegion.query.filter_by(binary_id=binary.id).all()
            if memory_query:
                memory_data = [mem.to_dict() for mem in memory_query]
                
                # Look for suspicious memory configurations
                for block in memory_data:
                    perms = block.get('permissions', {})
                    if isinstance(perms, dict):
                        # Writable and executable memory is dangerous
                        if perms.get('write', False) and perms.get('execute', False):
                            finding = {
                                'title': 'Writable and Executable Memory Block',
                                'description': f'Memory block {block.get("name", "unknown")} has both write and execute permissions',
                                'severity': 'HIGH',
                                'confidence': 90,
                                'category': 'memory_protection',
                                'cwe_id': 'CWE-119',
                                'detection_methods': ['memory_analysis'],
                                'affected_code': f'Memory block: {block.get("name")} ({block.get("start_address")} - {block.get("end_address")})',
                                'remediation': 'Implement proper memory protection (DEP/NX bit)',
                                'risk_score': 80
                            }
                            findings.append(finding)
            
            return {
                'findings': findings,
                'metadata': {
                    'findings_count': len(findings)
                }
            }
            
        except Exception as e:
            logger.error(f"Error analyzing memory layout: {e}")
            return {'findings': [], 'metadata': {'error': str(e)}}
    
    def _ai_comprehensive_analysis(self, binary: Binary) -> Dict[str, Any]:
        """Perform AI-driven comprehensive analysis using all available data"""
        try:
            # Prepare comprehensive data summary for AI
            summary = self._prepare_comprehensive_summary(binary)
            
            prompt = f"""
Perform a comprehensive security analysis of the binary '{binary.filename}' based on the following information:

{summary}

Identify potential security vulnerabilities and provide specific, actionable findings. Focus on:

1. **Architecture and Binary Type Analysis**
2. **Import/Export Security Assessment** 
3. **Memory Layout Security**
4. **Overall Attack Surface Analysis**

For each finding, provide:
- **Title**: Specific security issue
- **Severity**: CRITICAL, HIGH, MEDIUM, LOW, or INFO
- **Description**: Detailed explanation 
- **CWE ID**: Relevant weakness enumeration
- **Confidence**: Your confidence (0-100)
- **Remediation**: Specific mitigation steps

Respond in JSON format:
{{
  "findings": [
    {{
      "title": "Large Attack Surface via Exports",
      "severity": "MEDIUM",
      "description": "...", 
      "cwe_id": "CWE-400",
      "confidence": 75,
      "remediation": "..."
    }}
  ]
}}
"""
            
            # Use the comprehensive binary analysis method
            context = {
                'binary_name': binary.filename,
                'file_size': binary.file_size or 0,
                'architecture': binary.architecture or 'unknown',
                'total_functions': Function.query.filter_by(binary_id=binary.id).count(),
                'ai_analyzed_functions': 0,
                'function_analyses': [],
                'high_risk_functions': [],
                'statistics': {}
            }
            
            response = self.ai_service.analyze_binary_comprehensive(context)
            if response and response.get('success'):
                try:
                    # The comprehensive analysis returns structured data already
                    general_summary = response.get('general_summary', '')
                    vulnerability_summary = response.get('vulnerability_summary', '')
                    
                    # Create a basic finding from the summary
                    findings = []
                    if vulnerability_summary:
                        findings.append({
                            'title': 'AI Comprehensive Security Assessment',
                            'description': f"{general_summary}\n\nVulnerability Analysis:\n{vulnerability_summary}",
                            'severity': 'INFO',
                            'confidence': 70,
                            'category': 'ai_comprehensive',
                            'cwe_id': None,
                            'detection_methods': ['ai_analysis'],
                            'affected_code': 'Binary-wide analysis',
                            'remediation': response.get('technical_details', ''),
                            'risk_score': 70
                        })
                    
                    # Format findings for storage (findings were already created above)
                    formatted_findings = findings  # Use the findings we already formatted
                    
                    return {
                        'findings': formatted_findings,
                        'metadata': {'findings_count': len(formatted_findings)}
                    }
                    
                except Exception as e:
                    logger.error(f"Error processing AI comprehensive analysis response: {e}")
                    return {'findings': []}
            else:
                return {'findings': []}
                
        except Exception as e:
            logger.error(f"Error in AI comprehensive analysis: {e}")
            return {'findings': []}
    
    def _prepare_comprehensive_summary(self, binary: Binary) -> str:
        """Prepare a comprehensive summary of binary data for AI analysis"""
        summary_parts = []
        
        # Basic binary info
        summary_parts.append(f"**Binary**: {binary.filename}")
        summary_parts.append(f"**Size**: {binary.file_size} bytes")
        summary_parts.append(f"**Architecture**: {binary.architecture or 'Unknown'}")
        
        # Imports summary
        imports_query = Import.query.filter_by(binary_id=binary.id).all()
        if imports_query:
            import_libs = list(set(imp.library for imp in imports_query if imp.library))
            summary_parts.append(f"**Imports**: {len(imports_query)} functions from {len(import_libs)} libraries")
            summary_parts.append(f"**Key Libraries**: {', '.join(import_libs[:10])}")
        
        # Exports summary  
        exports_query = Export.query.filter_by(binary_id=binary.id).all()
        if exports_query:
            summary_parts.append(f"**Exports**: {len(exports_query)} functions")
            export_names = [exp.name[:30] for exp in exports_query[:10] if exp.name]
            summary_parts.append(f"**Key Exports**: {', '.join(export_names)}")
        
        # Memory blocks summary
        memory_query = MemoryRegion.query.filter_by(binary_id=binary.id).all()
        if memory_query:
            summary_parts.append(f"**Memory Blocks**: {len(memory_query)} blocks")
        
        # Strings summary
        strings_query = BinaryString.query.filter_by(binary_id=binary.id).all()
        if strings_query:
            summary_parts.append(f"**Strings**: {len(strings_query)} strings found")
        
        return '\n'.join(summary_parts)
    
    def _format_string_findings(self, ai_findings: List[Dict], security_strings: List[Dict]) -> List[Dict]:
        """Format AI string findings for storage"""
        formatted_findings = []
        
        for finding in ai_findings:
            formatted_finding = {
                'title': finding.get('title', 'Security String Finding'),
                'description': finding.get('description', ''),
                'severity': finding.get('severity', 'MEDIUM'),
                'confidence': finding.get('confidence', 50),
                'category': 'security_string',
                'cwe_id': finding.get('cwe_id'),
                'detection_methods': ['ai_string_analysis'],
                'affected_code': finding.get('affected_string', ''),
                'remediation': finding.get('remediation', ''),
                'risk_score': finding.get('confidence', 50)
            }
            formatted_findings.append(formatted_finding)
        
        return formatted_findings
    
    def _extract_code_context(self, code: str, pattern: str) -> str:
        """Extract code context around a pattern match"""
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if re.search(rf'\b{pattern}\b', line, re.IGNORECASE):
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                return '\n'.join(lines[start:end])
        return code[:200] + '...' if len(code) > 200 else code
    
    def _get_import_severity(self, category: str) -> str:
        """Get severity level for import categories"""
        severity_map = {
            'process_injection': 'HIGH',
            'privilege_escalation': 'HIGH', 
            'crypto_api': 'MEDIUM',
            'network_operations': 'MEDIUM'
        }
        return severity_map.get(category, 'LOW')
    
    def _get_import_cwe(self, category: str) -> str:
        """Get CWE ID for import categories"""
        cwe_map = {
            'process_injection': 'CWE-94',
            'privilege_escalation': 'CWE-269',
            'crypto_api': 'CWE-327',
            'network_operations': 'CWE-200'
        }
        return cwe_map.get(category, 'CWE-200')
    
    def _store_enhanced_findings(self, binary: Binary, findings: List[Dict]) -> List[Dict]:
        """Store enhanced security findings in database"""
        stored_findings = []
        
        try:
            for finding_data in findings:
                # Create unified security finding
                finding = UnifiedSecurityFinding(
                    binary_id=binary.id,
                    function_id=None,  # Binary-level findings
                    title=finding_data.get('title', 'Enhanced Security Finding'),
                    description=finding_data.get('description', ''),
                    severity=finding_data.get('severity', 'MEDIUM'),
                    confidence=finding_data.get('confidence', 50),
                    cwe_id=finding_data.get('cwe_id'),
                    category=finding_data.get('category', 'enhanced_analysis'),
                    ai_explanation=finding_data.get('description'),
                    detection_methods=finding_data.get('detection_methods', ['enhanced_analysis']),
                    address=finding_data.get('address'),
                    affected_code=finding_data.get('affected_code'),
                    remediation=finding_data.get('remediation'),
                    risk_score=finding_data.get('risk_score', 50),
                    exploit_difficulty='MEDIUM',
                    analysis_version='enhanced_1.0'
                )
                
                db.session.add(finding)
                db.session.flush()
                
                stored_findings.append({
                    'id': finding.id,
                    'title': finding.title,
                    'severity': finding.severity,
                    'confidence': finding.confidence,
                    'category': finding.category
                })
            
            db.session.commit()
            logger.info(f"Stored {len(stored_findings)} enhanced security findings")
            return stored_findings
            
        except Exception as e:
            logger.error(f"Error storing enhanced security findings: {e}")
            db.session.rollback()
            return []
    
    def _decompile_exports_for_security(self, binary: Binary) -> Dict[str, Any]:
        """Decompile exported functions using Ghidra headless analyzer"""
        try:
            import subprocess
            import tempfile
            import os
            from flask import current_app
            
            logger.info(f"Starting export decompilation for binary {binary.id}")
            
            # Get Ghidra path from environment or config
            ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
            if not ghidra_path or not os.path.exists(ghidra_path):
                logger.error("Ghidra installation not found")
                return {'success': False, 'error': 'Ghidra installation not found'}
            
            # Prepare paths
            if os.name == 'nt':
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
            else:
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless")
                
            if not os.path.exists(headless_path):
                logger.error(f"Ghidra headless analyzer not found: {headless_path}")
                return {'success': False, 'error': 'Ghidra headless analyzer not found'}
            
            # Get script path
            script_path = os.path.join(os.getcwd(), 'analysis_scripts', 'decompile_exports.py')
            if not os.path.exists(script_path):
                logger.error(f"Export decompilation script not found: {script_path}")
                return {'success': False, 'error': 'Export decompilation script not found'}
                
            # Create projects directory
            projects_dir = os.path.join(os.getcwd(), "ghidra_projects")
            os.makedirs(projects_dir, exist_ok=True)
            
            # Set up environment variables for the script
            env = os.environ.copy()
            env['GHIDRA_BINARY_ID'] = str(binary.id)
            env['GHIDRA_MAX_EXPORTS'] = str(self.max_exports_to_analyze)
            
            temp_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
            os.makedirs(temp_dir, exist_ok=True)
            env['GHIDRA_TEMP_DIR'] = temp_dir
            
            # Run headless analyzer with export decompilation script
            project_name = f"ExportDecompile_{binary.id}_{int(time.time())}"
            
            cmd = [
                headless_path,
                projects_dir,
                project_name,
                "-import", binary.file_path,
                "-scriptPath", os.path.dirname(script_path),
                "-postScript", os.path.basename(script_path)
            ]
            
            logger.info(f"Running export decompilation command: {' '.join(cmd)}")
            
            # Execute the command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=os.getcwd()
            )
            
            try:
                stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error("Export decompilation timed out")
                return {'success': False, 'error': 'Export decompilation timed out'}
            
            if process.returncode != 0:
                logger.error(f"Export decompilation failed with return code {process.returncode}")
                logger.error(f"STDERR: {stderr}")
                return {'success': False, 'error': f'Ghidra process failed: {stderr}'}
            
            # Read results from temp file
            output_file = os.path.join(temp_dir, "export_decompilation_results.json")
            if not os.path.exists(output_file):
                logger.error(f"Export decompilation results file not found: {output_file}")
                return {'success': False, 'error': 'Results file not found'}
            
            try:
                with open(output_file, 'r') as f:
                    decompilation_results = json.load(f)
            except Exception as e:
                logger.error(f"Error reading decompilation results: {e}")
                return {'success': False, 'error': f'Error reading results: {str(e)}'}
            
            if not decompilation_results.get('success'):
                logger.error(f"Export decompilation script failed: {decompilation_results.get('error')}")
                return decompilation_results
            
            # Store decompiled functions in database
            stored_count = self._store_decompiled_exports(binary, decompilation_results)
            
            result = {
                'success': True,
                'exports_found': decompilation_results.get('exports_found', 0),
                'exports_decompiled': decompilation_results.get('exports_decompiled', 0),
                'failed_exports': decompilation_results.get('failed_exports', 0),
                'functions_stored': stored_count,
                'analysis_time': decompilation_results.get('analysis_time', 0)
            }
            
            logger.info(f"Export decompilation completed: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error in export decompilation: {e}")
            return {'success': False, 'error': str(e)}
    
    def _store_decompiled_exports(self, binary: Binary, decompilation_results: Dict) -> int:
        """Store decompiled export functions in the database"""
        try:
            stored_count = 0
            decompiled_functions = decompilation_results.get('decompiled_functions', [])
            
            for func_data in decompiled_functions:
                # Check if function already exists
                existing_function = Function.query.filter_by(
                    binary_id=binary.id,
                    address=func_data['address']
                ).first()
                
                if existing_function:
                    # Update existing function with decompilation data
                    existing_function.decompiled_code = func_data.get('decompiled_code')
                    existing_function.is_decompiled = True
                    existing_function.signature = func_data.get('signature')
                    existing_function.parameter_count = func_data.get('parameter_count', 0)
                    existing_function.return_type = func_data.get('return_type')
                    existing_function.calling_convention = func_data.get('calling_convention')
                    existing_function.body_size = func_data.get('body_size', 0)
                    stored_count += 1
                else:
                    # Create new function
                    new_function = Function(
                        binary_id=binary.id,
                        name=func_data['name'],
                        address=func_data['address'],
                        size=func_data.get('body_size', 0),
                        signature=func_data.get('signature'),
                        decompiled_code=func_data.get('decompiled_code'),
                        is_decompiled=True,
                        is_external=False,
                        is_export=True,
                        parameter_count=func_data.get('parameter_count', 0),
                        return_type=func_data.get('return_type'),
                        calling_convention=func_data.get('calling_convention'),
                        body_size=func_data.get('body_size', 0)
                    )
                    db.session.add(new_function)
                    stored_count += 1
            
            # Commit all changes
            db.session.commit()
            logger.info(f"Stored {stored_count} decompiled export functions")
            return stored_count
            
        except Exception as e:
            logger.error(f"Error storing decompiled exports: {e}")
            db.session.rollback()
            return 0
    
    def _run_traditional_security_analysis(self, binary: Binary) -> Dict[str, Any]:
        """Run traditional function-based security analysis using the unified security analyzer"""
        try:
            from .unified_security_analyzer import UnifiedSecurityAnalyzer
            
            # Get decompiled functions
            functions = Function.query.filter_by(binary_id=binary.id, is_decompiled=True).all()
            
            if not functions:
                return {'findings': [], 'metadata': {'error': 'No decompiled functions available'}}
            
            logger.info(f"Running traditional analysis on {len(functions)} decompiled functions")
            
            # Use the unified security analyzer for function analysis
            analyzer = UnifiedSecurityAnalyzer()
            findings = []
            analyzed_count = 0
            failed_count = 0
            
            for function in functions:
                try:
                    result = analyzer.analyze_function_security(function)
                    if result.get('success'):
                        analyzed_count += 1
                        # Extract findings from the stored results
                        stored_findings = result.get('stored_findings', [])
                        for finding in stored_findings:
                            findings.append({
                                'title': finding.get('title', 'Function Security Finding'),
                                'description': f"Traditional analysis finding in function {function.name or function.address}",
                                'severity': finding.get('severity', 'MEDIUM'),
                                'confidence': finding.get('confidence', 70),
                                'category': 'traditional_function_analysis',
                                'cwe_id': finding.get('cwe_id'),
                                'detection_methods': ['traditional_analysis'],
                                'affected_code': f'Function: {function.name or function.address}',
                                'address': function.address,
                                'risk_score': finding.get('confidence', 70)
                            })
                    else:
                        failed_count += 1
                        logger.warning(f"Traditional analysis failed for function {function.id}: {result.get('error')}")
                        
                except Exception as e:
                    failed_count += 1
                    logger.error(f"Error analyzing function {function.id} with traditional analyzer: {e}")
            
            return {
                'findings': findings,
                'metadata': {
                    'functions_analyzed': analyzed_count,
                    'functions_failed': failed_count,
                    'total_functions': len(functions),
                    'findings_count': len(findings)
                }
            }
            
        except Exception as e:
            logger.error(f"Error in traditional security analysis: {e}")
            return {'findings': [], 'metadata': {'error': str(e)}}
    
    def _run_comprehensive_analysis(self, binary: Binary) -> Dict[str, Any]:
        """Run comprehensive analysis to extract basic binary data (exports, imports, strings, etc.)"""
        try:
            import subprocess
            import os
            from flask import current_app
            
            logger.info(f"Starting comprehensive analysis for binary {binary.id}")
            
            # Get Ghidra path from environment or config
            ghidra_path = os.environ.get('GHIDRA_INSTALL_DIR')
            if not ghidra_path or not os.path.exists(ghidra_path):
                logger.error("Ghidra installation not found")
                return {'success': False, 'error': 'Ghidra installation not found'}
            
            # Prepare paths
            if os.name == 'nt':
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless.bat")
            else:
                headless_path = os.path.join(ghidra_path, "support", "analyzeHeadless")
                
            if not os.path.exists(headless_path):
                logger.error(f"Ghidra headless analyzer not found: {headless_path}")
                return {'success': False, 'error': 'Ghidra headless analyzer not found'}
            
            # Get script path
            script_path = os.path.join(os.getcwd(), 'analysis_scripts', 'comprehensive_analysis_direct.py')
            if not os.path.exists(script_path):
                logger.error(f"Comprehensive analysis script not found: {script_path}")
                return {'success': False, 'error': 'Comprehensive analysis script not found'}
                
            # Create projects directory
            projects_dir = os.path.join(os.getcwd(), "ghidra_projects")
            os.makedirs(projects_dir, exist_ok=True)
            
            # Set up environment variables for the script
            env = os.environ.copy()
            env['GHIDRA_BINARY_ID'] = str(binary.id)
            env['GHIDRA_SKIP_FUNCTIONS'] = '1'  # Skip function decompilation for speed
            
            temp_dir = os.environ.get('GHIDRA_TEMP_DIR') or os.path.join(os.getcwd(), "temp", "ghidra_temp")
            os.makedirs(temp_dir, exist_ok=True)
            env['GHIDRA_TEMP_DIR'] = temp_dir
            
            # Run headless analyzer with comprehensive analysis script
            project_name = f"ComprehensiveAnalysis_{binary.id}_{int(time.time())}"
            
            cmd = [
                headless_path,
                projects_dir,
                project_name,
                "-import", binary.file_path,
                "-scriptPath", os.path.dirname(script_path),
                "-postScript", os.path.basename(script_path)
            ]
            
            logger.info(f"Running comprehensive analysis command: {' '.join(cmd)}")
            
            # Execute the command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=os.getcwd()
            )
            
            try:
                stdout, stderr = process.communicate(timeout=600)  # 10 minute timeout
            except subprocess.TimeoutExpired:
                process.kill()
                logger.error("Comprehensive analysis timed out")
                return {'success': False, 'error': 'Comprehensive analysis timed out'}
            
            if process.returncode != 0:
                logger.error(f"Comprehensive analysis failed with return code {process.returncode}")
                logger.error(f"STDERR: {stderr}")
                return {'success': False, 'error': f'Ghidra process failed: {stderr}'}
            
            # Read results from temp file
            output_file = os.path.join(temp_dir, f"comprehensive_analysis_{binary.id}.json")
            if not os.path.exists(output_file):
                logger.error(f"Comprehensive analysis results file not found: {output_file}")
                return {'success': False, 'error': 'Results file not found'}
            
            try:
                with open(output_file, 'r') as f:
                    analysis_results = json.load(f)
            except Exception as e:
                logger.error(f"Error reading comprehensive analysis results: {e}")
                return {'success': False, 'error': f'Error reading results: {str(e)}'}
            
            if not analysis_results.get('success'):
                logger.error(f"Comprehensive analysis script failed: {analysis_results.get('error')}")
                return analysis_results
            
            # Store comprehensive analysis data in database
            stored_count = self._store_comprehensive_data(binary, analysis_results)
            
            result = {
                'success': True,
                'exports_found': len(analysis_results.get('data', {}).get('exports', [])),
                'imports_found': len(analysis_results.get('data', {}).get('imports', [])),
                'strings_found': len(analysis_results.get('data', {}).get('strings', [])),
                'symbols_found': len(analysis_results.get('data', {}).get('symbols', [])),
                'memory_blocks': len(analysis_results.get('data', {}).get('memoryBlocks', [])),
                'records_stored': stored_count,
                'analysis_time': analysis_results.get('data', {}).get('statistics', {}).get('analysis_time', 0)
            }
            
            logger.info(f"Comprehensive analysis completed: {result}")
            return result
            
        except Exception as e:
            logger.error(f"Error in comprehensive analysis: {e}")
            return {'success': False, 'error': str(e)}
    
    def _store_comprehensive_data(self, binary: Binary, analysis_results: Dict) -> int:
        """Store comprehensive analysis data in the database"""
        try:
            stored_count = 0
            data = analysis_results.get('data', {})
            
            # Store exports
            exports = data.get('exports', [])
            for export_data in exports:
                existing = Export.query.filter_by(
                    binary_id=binary.id, 
                    name=export_data.get('name', ''),
                    address=export_data.get('address', '')
                ).first()
                
                if not existing:
                    new_export = Export(
                        binary_id=binary.id,
                        name=export_data.get('name', ''),
                        address=export_data.get('address', ''),
                        function_name=export_data.get('function_name', export_data.get('name', '')),
                        ordinal=None  # Not available in this analysis
                    )
                    db.session.add(new_export)
                    stored_count += 1
            
            # Store imports
            imports = data.get('imports', [])
            for import_data in imports:
                existing = Import.query.filter_by(
                    binary_id=binary.id,
                    name=import_data.get('name', ''),
                    address=import_data.get('address', '')
                ).first()
                
                if not existing:
                    new_import = Import(
                        binary_id=binary.id,
                        name=import_data.get('name', ''),
                        address=import_data.get('address', ''),
                        library=import_data.get('library', 'unknown'),
                        function_name=import_data.get('function_name', import_data.get('name', ''))
                    )
                    db.session.add(new_import)
                    stored_count += 1
            
            # Store strings
            strings = data.get('strings', [])
            for string_data in strings:
                existing = BinaryString.query.filter_by(
                    binary_id=binary.id,
                    address=string_data.get('address', '')
                ).first()
                
                if not existing:
                    new_string = BinaryString(
                        binary_id=binary.id,
                        address=string_data.get('address', ''),
                        content=string_data.get('value', ''),
                        encoding='ascii',  # Default encoding
                        length=string_data.get('length', len(string_data.get('value', '')))
                    )
                    db.session.add(new_string)
                    stored_count += 1
            
            # Store symbols
            symbols = data.get('symbols', [])
            for symbol_data in symbols:
                existing = Symbol.query.filter_by(
                    binary_id=binary.id,
                    name=symbol_data.get('name', ''),
                    address=symbol_data.get('address', '')
                ).first()
                
                if not existing:
                    new_symbol = Symbol(
                        binary_id=binary.id,
                        name=symbol_data.get('name', ''),
                        address=symbol_data.get('address', ''),
                        type=symbol_data.get('type', 'unknown'),
                        size=0  # Not available in this analysis
                    )
                    db.session.add(new_symbol)
                    stored_count += 1
            
            # Store memory regions
            memory_blocks = data.get('memoryBlocks', [])
            for block_data in memory_blocks:
                existing = MemoryRegion.query.filter_by(
                    binary_id=binary.id,
                    start_address=block_data.get('start', ''),
                    end_address=block_data.get('end', '')
                ).first()
                
                if not existing:
                    permissions = block_data.get('permissions', {})
                    new_memory = MemoryRegion(
                        binary_id=binary.id,
                        start_address=block_data.get('start', ''),
                        end_address=block_data.get('end', ''),
                        size=int(block_data.get('size', 0)),
                        permissions=f"{'r' if permissions.get('read', False) else '-'}"
                                  f"{'w' if permissions.get('write', False) else '-'}"
                                  f"{'x' if permissions.get('execute', False) else '-'}",
                        name=block_data.get('name', '')
                    )
                    db.session.add(new_memory)
                    stored_count += 1
            
            # Commit all changes
            db.session.commit()
            logger.info(f"Stored {stored_count} comprehensive analysis records")
            return stored_count
            
        except Exception as e:
            logger.error(f"Error storing comprehensive analysis data: {e}")
            db.session.rollback()
            return 0
    
    def _detect_forwarder_dll_simple(self, binary):
        """
        Simple forwarder DLL detection based on existing exports data
        Looks for characteristic patterns of API Set forwarder DLLs
        """
        try:
            from flask_app.models import Export
            
            # Get exports for this binary
            exports = Export.query.filter_by(binary_id=binary.id).all()
            
            if not exports:
                return {
                    'success': False,
                    'is_forwarder': False,
                    'reason': 'no_exports_data'
                }
            
            # Analyze export patterns
            forwarding_entries = []
            target_dlls = set()
            export_count = len(exports)
            
            # Check if exports look like forwarding entries
            forwarder_indicators = 0
            
            for exp in exports:
                export_name = exp.name or ''
                
                # Look for API Set DLL patterns in the filename
                if any(pattern in binary.filename.lower() for pattern in [
                    'api-ms-win-', 'ext-ms-win-', 'api-ms-', 'ext-ms-'
                ]):
                    forwarder_indicators += 1
                
                # Look for forwarding string patterns in export names/addresses
                # This is a simplified check - real forwarders would need Ghidra analysis
                if any(keyword in export_name.lower() for keyword in [
                    'eventing', 'trace', 'controller', 'consumer', 'legacy'
                ]):
                    # Create mock forwarding entry for API Set DLLs
                    target_dll = self._guess_target_dll(export_name, binary.filename)
                    target_dlls.add(target_dll)
                    
                    forwarding_entries.append({
                        'export_name': export_name,
                        'export_address': exp.address,
                        'target_dll': target_dll,
                        'target_function': export_name  # Same name typically
                    })
            
            # Determine if this is likely a forwarder DLL
            is_forwarder = (
                forwarder_indicators > 0 and  # Has API Set naming pattern
                any(pattern in binary.filename.lower() for pattern in [
                    'api-ms-win-', 'ext-ms-win-'  # Definite API Set patterns
                ]) and
                binary.file_size < 50000  # Small file size typical of forwarders
            )
            
            # If we detected it as forwarder but have no forwarding entries,
            # create them based on all exports
            if is_forwarder and not forwarding_entries:
                for exp in exports:
                    target_dll = self._guess_target_dll(exp.name, binary.filename)
                    target_dlls.add(target_dll)
                    forwarding_entries.append({
                        'export_name': exp.name,
                        'export_address': exp.address,
                        'target_dll': target_dll,
                        'target_function': exp.name
                    })
            
            return {
                'success': True,
                'is_forwarder': is_forwarder,
                'export_count': export_count,
                'function_count': 0 if is_forwarder else export_count,
                'forwarding_entries': forwarding_entries,
                'target_dlls': list(target_dlls),
                'analysis_method': 'simplified_pattern_matching'
            }
            
        except Exception as e:
            logger.error(f"Error in simple forwarder detection: {e}")
            return {
                'success': False,
                'is_forwarder': False,
                'error': str(e)
            }
    
    def _guess_target_dll(self, export_name, forwarder_filename):
        """
        Guess the target DLL based on export name and forwarder filename patterns
        """
        filename_lower = forwarder_filename.lower()
        
        # Common API Set to implementation DLL mappings
        if 'eventing-controller' in filename_lower:
            return 'api-ms-win-eventing-controller-l1-1-0'
        elif 'eventing-consumer' in filename_lower:
            return 'api-ms-win-eventing-consumer-l1-1-0'
        elif 'eventing-legacy' in filename_lower:
            return 'api-ms-win-eventing-legacy-l1-1-0'
        elif 'eventing-classicprovider' in filename_lower:
            return 'api-ms-win-eventing-classicprovider-l1-1-0'
        elif 'eventing-obsolete' in filename_lower:
            return 'api-ms-win-eventing-obsolete-l1-1-0'
        elif 'ntdll' in export_name.lower():
            return 'ntdll'
        elif 'wmi' in filename_lower:
            return 'wmiclnt'
        else:
            # Generic target DLL name
            return filename_lower.replace('api-ms-win-', '').replace('.dll', '')