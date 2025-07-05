"""
Simple Security Analyzer - Temporary implementation
"""

import logging
import re
from typing import Dict, Any, List
from flask_app.models import db, Function, UnifiedSecurityFinding, SecurityEvidence

logger = logging.getLogger(__name__)

class SimpleSecurityAnalyzer:
    """Simple security analyzer for basic vulnerability detection"""
    
    def __init__(self):
        """Initialize simple security analyzer"""
        self.dangerous_functions = {
            'strcpy': {
                'title': 'Buffer Overflow Risk - strcpy',
                'severity': 'HIGH',
                'cwe_id': 'CWE-120',
                'description': 'Use of strcpy() without bounds checking can lead to buffer overflow',
                'remediation': 'Use strncpy() or safer string handling functions'
            },
            'strcat': {
                'title': 'Buffer Overflow Risk - strcat', 
                'severity': 'HIGH',
                'cwe_id': 'CWE-120',
                'description': 'Use of strcat() without bounds checking can lead to buffer overflow',
                'remediation': 'Use strncat() or safer string handling functions'
            },
            'sprintf': {
                'title': 'Buffer Overflow Risk - sprintf',
                'severity': 'HIGH', 
                'cwe_id': 'CWE-120',
                'description': 'Use of sprintf() without bounds checking can lead to buffer overflow',
                'remediation': 'Use snprintf() with proper bounds checking'
            },
            'gets': {
                'title': 'Buffer Overflow Risk - gets',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-120', 
                'description': 'Use of gets() is extremely dangerous as it has no bounds checking',
                'remediation': 'Replace with fgets() or other safer input functions'
            },
            'printf': {
                'title': 'Format String Vulnerability',
                'severity': 'MEDIUM',
                'cwe_id': 'CWE-134',
                'description': 'Direct use of user input in printf() can lead to format string attacks',
                'remediation': 'Use printf with explicit format strings, never printf(user_input)'
            },
            'system': {
                'title': 'Command Injection Risk',
                'severity': 'HIGH',
                'cwe_id': 'CWE-78',
                'description': 'Use of system() with user input can lead to command injection',
                'remediation': 'Validate and sanitize input, use safer alternatives like execv()'
            }
        }
    
    def analyze_function_security(self, function: Function) -> Dict[str, Any]:
        """
        Perform simple security analysis on a function
        
        Args:
            function: Function object to analyze
            
        Returns:
            Dict containing security analysis results
        """
        if not function.decompiled_code:
            return {'error': 'Function must be decompiled before security analysis'}
        
        try:
            logger.info(f"Starting simple security analysis for function {function.address}")
            
            # Find dangerous function patterns
            findings = self._find_dangerous_patterns(function)
            
            # Store findings in database
            stored_findings = self._store_findings(function, findings)
            
            logger.info(f"Simple security analysis completed for {function.address}: {len(stored_findings)} findings")
            
            return {
                'success': True,
                'function_id': function.id,
                'total_findings': len(findings),
                'high_confidence_findings': len(findings),  # All simple findings are high confidence
                'stored_findings': len(stored_findings),
                'findings': stored_findings,
                'analysis_metadata': {
                    'analyzer': 'simple_security_analyzer',
                    'pattern_based': True,
                    'ai_enhanced': False
                }
            }
            
        except Exception as e:
            logger.error(f"Error in simple security analysis for {function.address}: {e}")
            return {'error': f'Simple security analysis failed: {str(e)}'}
    
    def _find_dangerous_patterns(self, function: Function) -> List[Dict]:
        """Find dangerous function patterns in code"""
        findings = []
        code = function.decompiled_code
        
        for func_name, vuln_info in self.dangerous_functions.items():
            # Simple pattern matching - look for function calls
            pattern = rf'\b{func_name}\s*\('
            
            if re.search(pattern, code):
                # Extract context around the dangerous function
                affected_code = self._extract_code_context(code, func_name)
                
                finding = {
                    'title': vuln_info['title'],
                    'description': vuln_info['description'],
                    'severity': vuln_info['severity'],
                    'confidence': 85,  # High confidence for pattern matching
                    'cwe_id': vuln_info['cwe_id'],
                    'category': 'pattern_detection',
                    'ai_explanation': f"Pattern-based detection found usage of {func_name}",
                    'pattern_matches': [func_name],
                    'detection_methods': ['pattern_matching'],
                    'affected_code': affected_code,
                    'remediation': vuln_info['remediation'],
                    'risk_score': self._calculate_risk_score(vuln_info['severity']),
                    'exploit_difficulty': 'MEDIUM',
                    'correlation_score': 0,
                    'evidence': [{
                        'type': 'pattern_match',
                        'source': 'simple_analyzer',
                        'confidence_impact': 35,
                        'description': f"Found usage of {func_name} in function code"
                    }]
                }
                
                findings.append(finding)
        
        return findings
    
    def _extract_code_context(self, code: str, function_name: str) -> str:
        """Extract code context around a dangerous function"""
        lines = code.split('\n')
        context_lines = []
        
        for i, line in enumerate(lines):
            if function_name in line:
                # Get 2 lines before and after for context
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                context_lines = lines[start:end]
                break
        
        if context_lines:
            return '\n'.join(context_lines)
        else:
            # Fallback to first 200 characters
            return code[:200] + '...' if len(code) > 200 else code
    
    def _calculate_risk_score(self, severity: str) -> int:
        """Calculate risk score based on severity"""
        severity_scores = {
            'CRITICAL': 95,
            'HIGH': 80,
            'MEDIUM': 60,
            'LOW': 40,
            'INFO': 20
        }
        return severity_scores.get(severity, 50)
    
    def _store_findings(self, function: Function, findings: List[Dict]) -> List[Dict]:
        """Store findings in database"""
        stored_findings = []
        
        try:
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
                        description=evidence_data.get('description')
                    )
                    db.session.add(evidence)
                
                stored_findings.append(finding.to_dict())
            
            db.session.commit()
            logger.info(f"Stored {len(stored_findings)} simple security findings")
            
        except Exception as e:
            logger.error(f"Error storing simple findings: {e}")
            db.session.rollback()
            raise
        
        return stored_findings 