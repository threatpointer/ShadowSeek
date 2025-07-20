"""
AI Service for Function Explanation
Provides AI-powered analysis and explanation of decompiled functions
"""

import os
import re
import json
import logging
from openai import OpenAI
from typing import Dict, Any, Optional
from flask import current_app

# Configure logging
logger = logging.getLogger(__name__)

class AIService:
    """AI service for analyzing and explaining functions"""
    
    def __init__(self, api_key: str = None, model: str = "gpt-3.5-turbo"):
        """
        Initialize AI service
        
        Args:
            api_key: OpenAI API key (if None, will try to get from environment)
            model: OpenAI model to use
        """
        # Force reload environment variables to get latest config
        if api_key is None:
            try:
                from dotenv import load_dotenv
                load_dotenv(override=True)  # Reload .env with override
                logger.debug("Reloaded environment variables from .env file")
            except ImportError:
                logger.debug("python-dotenv not available, using os.environ")
            except Exception as e:
                logger.debug(f"Error reloading .env file: {e}")
        
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.model = model
        self.client = None
        
        if self.api_key:
            try:
                self.client = OpenAI(api_key=self.api_key)
                logger.info(f"AI Service initialized successfully with model: {model}")
                logger.info(f"API key configured: {'*' * (len(self.api_key) - 10) + self.api_key[-4:] if len(self.api_key) > 10 else '***'}")
            except Exception as e:
                logger.error(f"Failed to initialize OpenAI client: {e}")
                self.client = None
        else:
            logger.warning("OpenAI API key not found. AI explanations will not work.")
            logger.debug("Make sure OPENAI_API_KEY is set in your .env file")
    
    def explain_function(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate AI explanation for a decompiled function
        
        Args:
            context: Dictionary containing function information
            
        Returns:
            Dictionary with explanation and risk assessment
        """
        if not self.client:
            return {
                "success": False,
                "error": "OpenAI client not initialized. Check API key configuration."
            }
        
        try:
            # Extract function information
            function_name = context.get("function_name", "unknown")
            function_address = context.get("function_address", "0x0")
            decompiled_code = context.get("decompiled_code", "")
            signature = context.get("signature", "")
            size = context.get("size", 0)
            
            # Validate we have decompiled code
            if not decompiled_code or len(decompiled_code.strip()) < 10:
                return {
                    "success": False,
                    "error": "No decompiled code available for analysis"
                }
            
            # Prepare prompt for AI
            prompt = self._build_analysis_prompt(
                function_name, function_address, decompiled_code, 
                signature, size
            )
            
            logger.info(f"Sending AI explanation request for function {function_name}")
            
            # Call OpenAI API with timeout
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior security researcher and reverse engineer with expertise in vulnerability analysis, exploitation techniques, and secure coding practices. Provide detailed technical analysis suitable for security professionals."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=3000,  # Increased for detailed technical analysis
                temperature=0.2,  # Lower temperature for more focused, technical responses
                timeout=45  # Increased timeout for longer responses
            )
            
            # Parse AI response
            ai_response = response.choices[0].message.content
            
            logger.info(f"Received AI response for function {function_name} ({len(ai_response)} chars)")
            
            # Extract structured information from response
            explanation, risk_score, vulnerabilities = self._parse_ai_response(ai_response)
            
            return {
                "success": True,
                "explanation": explanation,
                "risk_score": risk_score,
                "vulnerabilities": vulnerabilities,
                "raw_response": ai_response,
                "model_used": self.model
            }
            
        except Exception as e:
            logger.error(f"Error in AI explanation for function {function_name}: {e}")
            return {
                "success": False,
                "error": f"AI explanation failed: {str(e)}"
            }
    
    def _build_analysis_prompt(self, function_name: str, address: str, 
                             code: str, signature: str, size: int) -> str:
        """
        Build prompt for AI analysis
        
        Args:
            function_name: Name of the function
            address: Memory address
            code: Decompiled C code
            signature: Function signature
            size: Function size in bytes
            
        Returns:
            Formatted prompt string
        """
        prompt = f"""
You are a senior reverse engineer and vulnerability researcher. Analyze this decompiled function with extreme technical detail for a technical audience:

**Function Information:**
- Name: {function_name}
- Address: {address}
- Signature: {signature}
- Size: {size} bytes

**Decompiled Code:**
```c
{code}
```

**Provide comprehensive technical analysis:**

1. **FUNCTION SUMMARY** (2-3 sentences): Core purpose and primary functionality.

2. **TECHNICAL ANALYSIS**:
   - **Control Flow**: Analyze loops, conditionals, branching logic, and execution paths
   - **Data Types & Arguments**: Examine function parameters, local variables, their types, and usage patterns
   - **Memory Operations**: Detail malloc/free patterns, stack usage, heap operations, pointer arithmetic
   - **API/System Calls**: Identify external function calls, system APIs, library dependencies
   - **Algorithms**: Describe any cryptographic, compression, parsing, or mathematical algorithms
   - **String/Buffer Handling**: Analyze string operations, buffer manipulations, size calculations

3. **LOGICAL FLOW ANALYSIS**:
   - **Conditions**: Detail conditional checks, validation logic, error handling paths
   - **Input Processing**: How inputs are received, validated, transformed, and used
   - **Output Generation**: What data is produced, how it's formatted, and where it goes
   - **State Management**: Any global variables, static data, or persistent state handling

4. **ATTACK SURFACE ASSESSMENT**:
   - **Input Vectors**: Command-line args, file inputs, network data, user inputs, environment variables
   - **Trust Boundaries**: Where external data enters, privilege transitions, validation points
   - **Memory Corruption**: Buffer overflows, underflows, use-after-free, double-free opportunities
   - **Logic Flaws**: TOCTOU races, integer overflows, format string bugs, injection points
   - **Information Disclosure**: Potential data leaks, uninitialized memory, debug information
   - **Denial of Service**: Resource exhaustion, infinite loops, crash conditions

5. **VULNERABILITY ANALYSIS**:
   - **High-Risk Patterns**: Identify dangerous function calls, unchecked operations, unsafe casts
   - **Exploitation Scenarios**: Concrete attack vectors and exploitation techniques
   - **Bypass Potential**: Ways to circumvent security checks or validation logic
   - **Chaining Opportunities**: How this function could be used in multi-stage attacks

6. **RISK SCORING** (0-100):
   - **0-20**: Minimal risk - well-bounded, validated inputs, safe operations
   - **21-40**: Low risk - minor issues, hard to exploit, limited impact
   - **41-60**: Medium risk - exploitable vulnerabilities with moderate impact
   - **61-80**: High risk - easily exploitable, significant impact potential
   - **81-100**: Critical risk - remote code execution, privilege escalation, or system compromise

7. **TECHNICAL RECOMMENDATIONS**:
   - **Code Hardening**: Specific security improvements with code examples
   - **Input Validation**: Detailed validation requirements and implementation suggestions
   - **Memory Safety**: Bounds checking, allocation patterns, defensive programming
   - **Monitoring**: Logging, instrumentation, and detection opportunities

**Focus on:**
- Precise technical details, not generic descriptions
- Actual variable names, data types, and memory layouts from the code
- Specific line-by-line analysis where security-relevant
- Concrete exploitation techniques and mitigation strategies
- Real-world attack scenarios relevant to this function's context

Be thorough, technical, and actionable for security researchers and developers.
"""
        return prompt
    
    def _parse_ai_response(self, response: str) -> tuple:
        """
        Parse structured information from AI response
        
        Args:
            response: Raw AI response text
            
        Returns:
            Tuple of (explanation, risk_score, vulnerabilities)
        """
        try:
            # Extract function summary/explanation
            summary_patterns = [
                r'\*\*FUNCTION SUMMARY\*\*(.*?)(?=\*\*|$)',
                r'\*\*SUMMARY\*\*(.*?)(?=\*\*|$)',
                r'1\.\s*\*\*FUNCTION SUMMARY\*\*(.*?)(?=\d+\.\s*\*\*|$)'
            ]
            
            explanation = ""
            for pattern in summary_patterns:
                summary_match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
                if summary_match:
                    explanation = summary_match.group(1).strip()
                    break
            
            if not explanation:
                # Fallback: use first meaningful paragraph
                paragraphs = [p.strip() for p in response.split('\n\n') if p.strip()]
                explanation = paragraphs[0] if paragraphs else response[:500]
            
            # Extract risk score with improved patterns
            risk_score = 0
            risk_patterns = [
                r'\*\*RISK SCORING\*\*.*?(\d+)',
                r'\*\*RISK SCORE\*\*.*?(\d+)',
                r'Risk Score[:\s]*(\d+)',
                r'Score[:\s]*(\d+)\/100',
                r'(\d+)\/100'
            ]
            
            for pattern in risk_patterns:
                risk_match = re.search(pattern, response, re.IGNORECASE)
                if risk_match:
                    potential_score = int(risk_match.group(1))
                    if 0 <= potential_score <= 100:
                        risk_score = potential_score
                        break
            
            # Enhanced vulnerability extraction
            vulnerabilities = []
            
            # Search in multiple sections
            vuln_sections = [
                r'\*\*ATTACK SURFACE ASSESSMENT\*\*(.*?)(?=\*\*|$)',
                r'\*\*VULNERABILITY ANALYSIS\*\*(.*?)(?=\*\*|$)',
                r'\*\*SECURITY ANALYSIS\*\*(.*?)(?=\*\*|$)'
            ]
            
            vuln_text = ""
            for section_pattern in vuln_sections:
                section_match = re.search(section_pattern, response, re.DOTALL | re.IGNORECASE)
                if section_match:
                    vuln_text += " " + section_match.group(1).lower()
            
            # Enhanced vulnerability patterns
            vuln_patterns = {
                'buffer_overflow': ['buffer overflow', 'buffer overrun', 'stack overflow', 'heap overflow', 'strcpy', 'strcat', 'sprintf', 'gets', 'bounds check', 'array bounds'],
                'format_string': ['format string', 'printf', '%s', '%d', '%x', 'format specifier', 'fprintf', 'snprintf'],
                'integer_overflow': ['integer overflow', 'integer wraparound', 'arithmetic overflow', 'signed overflow', 'multiplication overflow', 'size calculation'],
                'use_after_free': ['use after free', 'dangling pointer', 'freed memory', 'double free'],
                'double_free': ['double free', 'double deallocation', 'free twice'],
                'null_pointer': ['null pointer', 'null dereference', 'nullptr', 'null check'],
                'memory_leak': ['memory leak', 'malloc', 'calloc', 'resource leak', 'allocation'],
                'race_condition': ['race condition', 'toctou', 'time-of-check', 'concurrency', 'thread safety'],
                'command_injection': ['command injection', 'code injection', 'script injection', 'system call', 'exec', 'shell command'],
                'path_traversal': ['path traversal', 'directory traversal', '../', 'file inclusion', 'path injection'],
                'privilege_escalation': ['privilege escalation', 'privilege elevation', 'setuid', 'permission bypass'],
                'denial_of_service': ['denial of service', 'dos', 'resource exhaustion', 'infinite loop', 'crash'],
                'information_disclosure': ['information disclosure', 'data leak', 'memory disclosure', 'uninitialized', 'sensitive data'],
                'crypto_weakness': ['cryptographic', 'encryption', 'hash', 'md5', 'sha1', 'weak algorithm', 'crypto'],
                'input_validation': ['input validation', 'sanitization', 'bounds check', 'parameter validation', 'user input']
            }
            
            for vuln_type, keywords in vuln_patterns.items():
                if any(keyword in vuln_text for keyword in keywords):
                    vulnerabilities.append(vuln_type)
            
            return explanation, risk_score, vulnerabilities
            
        except Exception as e:
            logger.error(f"Error parsing AI response: {e}")
            # Return first 1000 characters as fallback for longer technical responses
            return response[:1000], 0, []
    
    def analyze_vulnerability_patterns(self, code: str) -> Dict[str, Any]:
        """
        Analyze code for specific vulnerability patterns
        
        This method now uses the comprehensive dangerous functions database
        from the VulnerabilityEngine (60+ functions) to ensure consistency
        between AI analysis and formal vulnerability detection.
        
        Args:
            code: Decompiled C code
            
        Returns:
            Dictionary with vulnerability analysis
        """
        vulnerabilities = []
        risk_factors = []
        
        # Import the comprehensive dangerous functions from vulnerability engine
        try:
            from flask_app.vulnerability_engine import VulnerabilityEngine
            engine = VulnerabilityEngine()
            dangerous_functions = engine.dangerous_functions
        except ImportError:
            # Fallback to basic list if vulnerability engine is not available
            dangerous_functions = {
                'strcpy': 'Buffer overflow risk - no bounds checking',
                'strcat': 'Buffer overflow risk - no bounds checking', 
                'sprintf': 'Buffer overflow risk - no bounds checking',
                'gets': 'Buffer overflow risk - reads unlimited input',
                'scanf': 'Format string vulnerability if user input used as format',
                'printf': 'Format string vulnerability if user input used as format'
            }
        
        # Check for dangerous functions
        for func, description in dangerous_functions.items():
            if func in code:
                vulnerabilities.append({
                    'type': 'dangerous_function',
                    'function': func,
                    'description': description,
                    'severity': 'high' if func in ['gets', 'strcpy', 'system'] else 'medium'
                })
                risk_factors.append(func)
        
        # Check for malloc without free
        malloc_count = code.count('malloc')
        free_count = code.count('free')
        if malloc_count > free_count:
            vulnerabilities.append({
                'type': 'memory_leak',
                'description': f'Potential memory leak: {malloc_count} malloc calls, {free_count} free calls',
                'severity': 'medium'
            })
        
        # Calculate risk score based on findings
        base_score = 10  # Base risk
        risk_score = base_score + len(vulnerabilities) * 15
        risk_score = min(risk_score, 100)  # Cap at 100
        
        return {
            'vulnerabilities': vulnerabilities,
            'risk_factors': risk_factors,
            'risk_score': risk_score,
            'total_issues': len(vulnerabilities)
        }
    
    def analyze_binary(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate AI analysis for an entire binary
        
        Args:
            context: Dictionary containing binary information
            
        Returns:
            Dictionary with binary analysis and summary
        """
        if not self.client:
            return {
                "success": False,
                "error": "OpenAI client not initialized. Check API key configuration."
            }
        
        try:
            # Extract binary information
            binary_name = context.get("binary_name", "unknown")
            file_size = context.get("file_size", 0)
            architecture = context.get("architecture", "unknown")
            total_functions = context.get("total_functions", 0)
            analyzed_functions = context.get("analyzed_functions", 0)
            decompiled_functions = context.get("decompiled_functions", 0)
            external_functions = context.get("external_functions", 0)
            function_list = context.get("function_list", [])
            
            # Prepare prompt for AI
            prompt = self._build_binary_analysis_prompt(
                binary_name, file_size, architecture, 
                total_functions, analyzed_functions, decompiled_functions, 
                external_functions, function_list
            )
            
            logger.info(f"Sending AI binary analysis request for {binary_name}")
            
            # Call OpenAI API with timeout
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in malware analysis and reverse engineering. Analyze the provided binary information and provide clear, actionable insights."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=2000,
                temperature=0.3,
                timeout=45  # 45 second timeout for binary analysis
            )
            
            # Parse AI response
            ai_response = response.choices[0].message.content
            
            logger.info(f"Received AI binary analysis response ({len(ai_response)} chars)")
            
            # Extract structured information from response
            summary, analysis, risk_assessment, recommendations = self._parse_binary_analysis_response(ai_response)
            
            return {
                "success": True,
                "summary": summary,
                "analysis": analysis,
                "risk_assessment": risk_assessment,
                "recommendations": recommendations,
                "raw_response": ai_response,
                "model_used": self.model
            }
            
        except Exception as e:
            logger.error(f"Error in binary AI analysis for {binary_name}: {e}")
            return {
                "success": False,
                "error": f"Binary AI analysis failed: {str(e)}"
            }
    
    def _build_binary_analysis_prompt(self, binary_name: str, file_size: int, 
                                    architecture: str, total_functions: int,
                                    analyzed_functions: int, decompiled_functions: int,
                                    external_functions: int, function_list: list) -> str:
        """
        Build prompt for binary AI analysis
        
        Returns:
            Formatted prompt string
        """
        # Get top function names for context
        function_names = []
        for func in function_list[:20]:  # Limit to top 20 functions
            if func.get("name") and not func.get("is_external", False):
                function_names.append(func["name"])
        
        prompt = f"""
Please analyze this binary file and provide a comprehensive assessment:

**Binary Information:**
- Name: {binary_name}
- Size: {file_size:,} bytes
- Architecture: {architecture}
- Total Functions: {total_functions:,}
- Analyzed Functions: {analyzed_functions:,}
- Decompiled Functions: {decompiled_functions:,}
- External/Library Functions: {external_functions:,}

**Key Functions Found:**
{', '.join(function_names[:10]) if function_names else 'No significant function names identified'}

**Please provide:**

1. **SUMMARY** (2-3 sentences): What type of software is this and what does it likely do?

2. **DETAILED ANALYSIS**: 
   - Primary purpose and functionality
   - Software category (system utility, application, library, etc.)
   - Notable characteristics from function analysis
   - Architectural insights

3. **SECURITY ASSESSMENT**:
   - Potential security concerns
   - Suspicious patterns or behaviors
   - Code complexity and obfuscation level
   - Overall risk level

4. **RISK SCORE** (0-100): Rate the overall security risk
   - 0-20: Benign/Low risk
   - 21-40: Low-Medium risk
   - 41-60: Medium risk
   - 61-80: High risk
   - 81-100: Critical/Malicious

5. **RECOMMENDATIONS**: 
   - Analysis suggestions
   - Security considerations
   - Next steps for investigation

Format your response with clear section headers.
"""
        return prompt
    
    def _parse_binary_analysis_response(self, response: str) -> tuple:
        """
        Parse structured information from binary analysis response
        
        Args:
            response: Raw AI response text
            
        Returns:
            Tuple of (summary, analysis, risk_assessment, recommendations)
        """
        try:
            # Extract summary
            summary_match = re.search(r'\*\*SUMMARY\*\*(.*?)(?=\*\*|$)', response, re.DOTALL | re.IGNORECASE)
            summary = summary_match.group(1).strip() if summary_match else response[:300]
            
            # Extract detailed analysis
            analysis_match = re.search(r'\*\*DETAILED ANALYSIS\*\*(.*?)(?=\*\*|$)', response, re.DOTALL | re.IGNORECASE)
            analysis = analysis_match.group(1).strip() if analysis_match else ""
            
            # Extract security assessment
            security_match = re.search(r'\*\*SECURITY ASSESSMENT\*\*(.*?)(?=\*\*|$)', response, re.DOTALL | re.IGNORECASE)
            risk_assessment = security_match.group(1).strip() if security_match else ""
            
            # Extract recommendations
            rec_match = re.search(r'\*\*RECOMMENDATIONS\*\*(.*?)(?=\*\*|$)', response, re.DOTALL | re.IGNORECASE)
            recommendations = rec_match.group(1).strip() if rec_match else ""
            
            # Extract risk score
            risk_score = 0
            risk_match = re.search(r'\*\*RISK SCORE\*\*.*?(\d+)', response, re.IGNORECASE)
            if risk_match:
                risk_score = int(risk_match.group(1))
                risk_assessment = f"Risk Score: {risk_score}/100\n\n" + risk_assessment
            
            return summary, analysis, risk_assessment, recommendations
            
        except Exception as e:
            logger.error(f"Error parsing binary analysis response: {e}")
            # Return the response split into logical sections
            sections = response.split('\n\n')
            return (
                sections[0] if len(sections) > 0 else response[:200],
                sections[1] if len(sections) > 1 else "",
                sections[2] if len(sections) > 2 else "",
                sections[3] if len(sections) > 3 else ""
            )

    def analyze_binary_comprehensive(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive AI analysis for an entire binary using function analyses
        
        Args:
            context: Dictionary containing binary information and function analyses
            
        Returns:
            Dictionary with comprehensive binary analysis and summary
        """
        if not self.client:
            return {
                "success": False,
                "error": "OpenAI client not initialized. Check API key configuration."
            }
        
        try:
            # Extract binary information
            binary_name = context.get("binary_name", "unknown")
            file_size = context.get("file_size", 0)
            architecture = context.get("architecture", "unknown")
            total_functions = context.get("total_functions", 0)
            ai_analyzed_functions = context.get("ai_analyzed_functions", 0)
            function_analyses = context.get("function_analyses", [])
            high_risk_functions = context.get("high_risk_functions", [])
            statistics = context.get("statistics", {})
            
            # Prepare comprehensive prompt for AI
            prompt = self._build_comprehensive_binary_analysis_prompt(
                binary_name, file_size, architecture, 
                total_functions, ai_analyzed_functions, function_analyses,
                high_risk_functions, statistics
            )
            
            logger.info(f"Sending comprehensive AI binary analysis request for {binary_name} with {ai_analyzed_functions} function analyses")
            
            # Call OpenAI API with increased timeout for comprehensive analysis
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a senior cybersecurity expert and malware analyst with extensive experience in binary analysis, reverse engineering, and threat assessment. Provide comprehensive, technical analysis suitable for security professionals and threat hunters."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=4000,  # Increased for comprehensive analysis
                temperature=0.2,  # Lower temperature for more focused analysis
                timeout=60  # 60 second timeout for comprehensive analysis
            )
            
            # Parse AI response
            ai_response = response.choices[0].message.content
            
            logger.info(f"Received comprehensive AI binary analysis response ({len(ai_response)} chars)")
            
            # Extract structured information from response
            executive_summary, general_summary, vulnerability_summary, technical_details = self._parse_comprehensive_binary_response(ai_response)
            
            return {
                "success": True,
                "summary": executive_summary,
                "general_summary": general_summary,
                "vulnerability_summary": vulnerability_summary, 
                "technical_details": technical_details,
                "raw_response": ai_response,
                "model_used": self.model,
                "function_analyses_used": ai_analyzed_functions,
                # Legacy fields for backward compatibility
                "analysis": general_summary,
                "risk_assessment": vulnerability_summary,
                "recommendations": technical_details
            }
            
        except Exception as e:
            logger.error(f"Error in comprehensive binary AI analysis for {binary_name}: {e}")
            return {
                "success": False,
                "error": f"Comprehensive binary AI analysis failed: {str(e)}"
            }
    
    def _build_comprehensive_binary_analysis_prompt(self, binary_name: str, file_size: int, 
                                                  architecture: str, total_functions: int,
                                                  ai_analyzed_functions: int, function_analyses: list,
                                                  high_risk_functions: list, statistics: dict) -> str:
        """
        Build comprehensive prompt for binary AI analysis using function analyses
        Focused on reverse engineering professionals with technical depth
        
        Returns:
            Formatted prompt string
        """
        # Prepare function analysis summaries with technical details
        function_summaries = []
        for func in function_analyses[:20]:  # Top 20 function analyses
            if func.get("ai_summary"):
                calling_conv = func.get('calling_convention', 'unknown')
                size_info = f"{func.get('size', 0)} bytes" if func.get('size') else "unknown size"
                risk_info = f"Risk: {func.get('risk_score', 0)}/100" if func.get('risk_score') else "Risk: unknown"
                param_count = func.get('parameter_count', 0)
                
                function_summaries.append(
                    f"• {func.get('name', 'unknown')} @ {func.get('address', '0x0')} "
                    f"({size_info}, {calling_conv}, {param_count} params, {risk_info})\n"
                    f"  └─ {func.get('ai_summary', '')[:300]}..."
                )
        
        # Prepare detailed high-risk function analysis
        vulnerable_functions = []
        for func in high_risk_functions[:8]:  # Top 8 most critical functions
            calling_conv = func.get('calling_convention', '__fastcall')
            params = func.get('parameter_count', 0)
            summary = func.get('ai_summary', 'No analysis available')
            
            vulnerable_functions.append(
                f"📍 **{func.get('name', 'unknown')}** @ {func.get('address', '0x0')}\n"
                f"   • Calling Convention: {calling_conv}\n"
                f"   • Parameters: {params}\n"
                f"   • Risk Score: {func.get('risk_score', 0)}/100\n"
                f"   • Security Analysis: {summary[:400]}\n"
            )
        
        # Technical metadata extraction
        external_count = sum(1 for f in function_analyses if f.get('is_external', False))
        internal_count = ai_analyzed_functions - external_count
        
        # Get comprehensive statistics
        avg_risk = statistics.get('avg_risk_score', 0)
        critical_count = statistics.get('critical_risk_count', 0)
        high_risk_count = statistics.get('high_risk_count', 0)
        medium_risk_count = statistics.get('medium_risk_count', 0)
        low_risk_count = statistics.get('low_risk_count', 0)
        
        # Extract dangerous function patterns
        dangerous_patterns = []
        try:
            from flask_app.vulnerability_engine import VulnerabilityEngine
            engine = VulnerabilityEngine()
            for func in function_analyses[:15]:
                if func.get('ai_summary'):
                    summary_lower = func.get('ai_summary', '').lower()
                    for danger_func in ['strcpy', 'sprintf', 'gets', 'system', 'exec', 'malloc', 'free']:
                        if danger_func in summary_lower:
                            dangerous_patterns.append(f"{func.get('name', 'unknown')} uses {danger_func}")
        except:
            pass
        
        prompt = f"""
You are a senior reverse engineer and malware analyst. Analyze this binary comprehensively for a technical security audience.

**BINARY TECHNICAL PROFILE:**
📂 **File**: {binary_name} ({file_size:,} bytes)
🏗️ **Architecture**: {architecture}
⚙️ **Function Topology**: {total_functions:,} total ({internal_count} internal, {external_count} external)
🔍 **Analysis Coverage**: {ai_analyzed_functions}/{total_functions} functions analyzed ({(ai_analyzed_functions/total_functions*100):.1f}%)

**SECURITY POSTURE METRICS:**
🎯 **Average Risk Score**: {avg_risk:.1f}/100
🔴 **Critical Risk Functions (90+)**: {critical_count}
🟠 **High Risk Functions (70-89)**: {high_risk_count}  
🟡 **Medium Risk Functions (40-69)**: {medium_risk_count}
🟢 **Low Risk Functions (0-39)**: {low_risk_count}

**FUNCTION LANDSCAPE ANALYSIS:**
{chr(10).join(function_summaries) if function_summaries else "No detailed function analyses available for technical review"}

**DANGEROUS FUNCTION USAGE PATTERNS:**
{chr(10).join([f"⚠️ {pattern}" for pattern in dangerous_patterns[:8]]) if dangerous_patterns else "No immediately dangerous function patterns detected"}

**CRITICAL VULNERABILITY ASSESSMENT:**
{chr(10).join(vulnerable_functions) if vulnerable_functions else "No high-risk functions identified for detailed assessment"}

**PROVIDE STRUCTURED REVERSE ENGINEERING ANALYSIS:**

**1. GENERAL SUMMARY**
Infer the high-level purpose and classification of this binary based on:
- Function naming patterns and import signatures
- Code complexity and architectural patterns  
- Cross-references between functions and data flow
- Compiler hints and linking patterns visible in the function structure
- Operational context clues from system interactions

**2. VULNERABILITY SUMMARY**  
For each significant vulnerable function, provide:
- **Function Name & Entry Point**: Exact function name and memory address
- **Function Signature**: Parameters, calling convention, return type
- **Vulnerability Classification**: Specific CWE/OWASP category and technical description
- **Exploitation Vector**: How an attacker could trigger and exploit the vulnerability
- **Attack Complexity**: Technical requirements and constraints for successful exploitation
- **Impact Assessment**: Potential consequences (code execution, privilege escalation, data disclosure)
- **Exploit Primitives**: Memory corruption primitives, control flow hijacking opportunities

**3. TECHNICAL DETAILS**
- **Platform Analysis**: Target OS, compiler toolchain indicators, runtime dependencies
- **Architectural Patterns**: Code organization, modularity, obfuscation techniques
- **Control Flow Analysis**: Function call graphs, critical paths, trust boundaries
- **Data Flow Security**: Input validation patterns, sanitization gaps, tainted data propagation
- **Memory Management**: Allocation patterns, lifetime management, potential use-after-free conditions
- **Anti-Analysis Features**: Packing, encryption, anti-debugging, or evasion techniques detected
- **Binary Artifacts**: String constants, hardcoded values, configuration data that reveal intent

**ANALYSIS REQUIREMENTS:**
- Focus on **concrete technical findings** with specific memory addresses and function signatures
- Provide **exploitability assessments** with realistic attack scenarios
- Include **architectural context** about how functions interact and share data
- Correlate findings across functions to identify **chaining opportunities** 
- Consider **both local and remote attack vectors** based on the binary's apparent purpose
- Evaluate **defensive measures** already present in the code
- Assess **real-world threat landscape** relevance

**OUTPUT FORMAT:**
Structure your response with clear section headers matching the analysis requirements above. 
Be technically precise and include specific function names, addresses, and code patterns.
"""
        return prompt
    
    def _parse_comprehensive_binary_response(self, response: str) -> tuple:
        """
        Parse structured information from comprehensive binary analysis response
        Enhanced to extract new structured sections for reverse engineering professionals
        
        Args:
            response: Raw AI response text
            
        Returns:
            Tuple of (general_summary, vulnerability_summary, technical_details, original_summary)
        """
        try:
            # Extract General Summary (high-level purpose inference)
            general_summary_patterns = [
                r'\*\*1\.\s*GENERAL SUMMARY\*\*(.*?)(?=\*\*2\.|$)',
                r'\*\*GENERAL SUMMARY\*\*(.*?)(?=\*\*VULNERABILITY SUMMARY|$)',
                r'1\.\s*\*\*GENERAL SUMMARY\*\*(.*?)(?=\d+\.\s*\*\*|$)'
            ]
            
            general_summary = ""
            for pattern in general_summary_patterns:
                summary_match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
                if summary_match:
                    general_summary = summary_match.group(1).strip()
                    break
            
            # Extract Vulnerability Summary (detailed assessment of vulnerable functions)
            vulnerability_summary_patterns = [
                r'\*\*2\.\s*VULNERABILITY SUMMARY\*\*(.*?)(?=\*\*3\.|$)',
                r'\*\*VULNERABILITY SUMMARY\*\*(.*?)(?=\*\*TECHNICAL DETAILS|$)',
                r'2\.\s*\*\*VULNERABILITY SUMMARY\*\*(.*?)(?=\d+\.\s*\*\*|$)'
            ]
            
            vulnerability_summary = ""
            for pattern in vulnerability_summary_patterns:
                vuln_match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
                if vuln_match:
                    vulnerability_summary = vuln_match.group(1).strip()
                    break
            
            # Extract Technical Details (architectural context and technical analysis)
            technical_details_patterns = [
                r'\*\*3\.\s*TECHNICAL DETAILS\*\*(.*?)(?=\*\*|$)',
                r'\*\*TECHNICAL DETAILS\*\*(.*?)(?=\*\*|$)',
                r'3\.\s*\*\*TECHNICAL DETAILS\*\*(.*?)(?=\d+\.\s*\*\*|$)'
            ]
            
            technical_details = ""
            for pattern in technical_details_patterns:
                tech_match = re.search(pattern, response, re.DOTALL | re.IGNORECASE)
                if tech_match:
                    technical_details = tech_match.group(1).strip()
                    break
            
            # Create executive summary from the general summary or extract from beginning
            executive_summary = general_summary if general_summary else ""
            if not executive_summary:
                # Fallback: extract first meaningful paragraphs
                paragraphs = [p.strip() for p in response.split('\n\n') if p.strip() and len(p.strip()) > 50]
                executive_summary = paragraphs[0] if paragraphs else response[:400]
            
            # Validate that we got meaningful content
            if not general_summary and not vulnerability_summary and not technical_details:
                # Fallback parsing for different response formats
                sections = [s.strip() for s in response.split('\n\n') if s.strip() and len(s.strip()) > 30]
                
                general_summary = sections[0] if len(sections) > 0 else ""
                vulnerability_summary = sections[1] if len(sections) > 1 else ""
                technical_details = sections[2] if len(sections) > 2 else ""
                executive_summary = general_summary or response[:400]
            
            return executive_summary, general_summary, vulnerability_summary, technical_details
            
        except Exception as e:
            logger.error(f"Error parsing comprehensive binary analysis response: {e}")
            # Return the response split into logical sections as fallback
            sections = [s.strip() for s in response.split('\n\n') if s.strip()]
            return (
                sections[0] if len(sections) > 0 else response[:400],  # Executive summary
                sections[1] if len(sections) > 1 else "",              # General summary  
                sections[2] if len(sections) > 2 else "",              # Vulnerability summary
                sections[3] if len(sections) > 3 else ""               # Technical details
            )

    def analyze_function_security(self, decompiled_code: str, function_name: str, prompt: str) -> Dict[str, Any]:
        """
        Perform AI-powered security analysis on a function
        
        Args:
            decompiled_code: The decompiled C code
            function_name: Name of the function
            prompt: Security analysis prompt
            
        Returns:
            Dictionary with security analysis results
        """
        if not self.client:
            return {
                "success": False,
                "error": "OpenAI client not initialized. Check API key configuration."
            }
        
        try:
            logger.info(f"Performing AI security analysis for function {function_name}")
            
            # Call OpenAI API with structured response format
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert and vulnerability researcher. Analyze the provided function for security vulnerabilities and respond in the exact JSON format requested. Be precise, technical, and thorough in your analysis."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                max_tokens=3000,
                temperature=0.1,  # Very low temperature for consistent security analysis
                timeout=60
            )
            
            ai_response = response.choices[0].message.content
            
            # Try to parse JSON response
            try:
                # Extract JSON from response
                json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                    parsed_response = json.loads(json_str)
                    
                    # Validate required structure
                    if 'security_analysis' in parsed_response:
                        return {
                            "success": True,
                            "security_analysis": parsed_response['security_analysis'],
                            "raw_response": ai_response
                        }
                
                # Fallback parsing if JSON is malformed
                return self._parse_security_response_fallback(ai_response, function_name)
                
            except json.JSONDecodeError:
                # Fallback parsing
                return self._parse_security_response_fallback(ai_response, function_name)
                
        except Exception as e:
            logger.error(f"Error in AI security analysis for function {function_name}: {e}")
            return {
                "success": False,
                "error": f"AI security analysis failed: {str(e)}"
            }
    
    def _parse_security_response_fallback(self, response: str, function_name: str) -> Dict[str, Any]:
        """
        Fallback parser for security analysis when JSON parsing fails
        
        Args:
            response: Raw AI response
            function_name: Name of the function being analyzed
            
        Returns:
            Structured security analysis dictionary
        """
        try:
            issues = []
            
            # Extract vulnerability patterns from text
            vuln_patterns = {
                'Buffer Overflow': ['buffer overflow', 'strcpy', 'strcat', 'sprintf', 'gets', 'bounds check'],
                'Format String': ['format string', 'printf', 'fprintf', '%s', '%d'],
                'Command Injection': ['command injection', 'system', 'exec', 'shell'],
                'Integer Overflow': ['integer overflow', 'arithmetic overflow', 'size calculation'],
                'Memory Management': ['use after free', 'double free', 'memory leak', 'dangling pointer'],
                'Cryptographic Weakness': ['md5', 'sha1', 'weak hash', 'deprecated crypto']
            }
            
            response_lower = response.lower()
            
            for vuln_type, keywords in vuln_patterns.items():
                if any(keyword in response_lower for keyword in keywords):
                    # Extract severity from context
                    severity = 'MEDIUM'
                    if any(word in response_lower for word in ['critical', 'severe', 'high risk']):
                        severity = 'HIGH'
                    elif any(word in response_lower for word in ['critical', 'remote code', 'rce']):
                        severity = 'CRITICAL'
                    elif any(word in response_lower for word in ['low', 'minor', 'informational']):
                        severity = 'LOW'
                    
                    # Try to extract CWE
                    cwe_match = re.search(r'cwe[-\s]*(\d+)', response_lower)
                    cwe_id = f"CWE-{cwe_match.group(1)}" if cwe_match else None
                    
                    issues.append({
                        'title': f"{vuln_type} in {function_name}",
                        'severity': severity,
                        'cwe_id': cwe_id,
                        'description': f"Potential {vuln_type.lower()} vulnerability detected",
                        'confidence': 75
                    })
            
            # Extract overall risk assessment
            risk_assessment = {
                'overall_risk': 'MEDIUM',
                'exploit_difficulty': 'MEDIUM',
                'false_positive_risk': 'MEDIUM'
            }
            
            if any(word in response_lower for word in ['high risk', 'critical', 'severe']):
                risk_assessment['overall_risk'] = 'HIGH'
            elif any(word in response_lower for word in ['low risk', 'minimal', 'benign']):
                risk_assessment['overall_risk'] = 'LOW'
            
            return {
                "success": True,
                "security_analysis": {
                    "issues": issues,
                    "risk_assessment": risk_assessment,
                    "recommendations": ["Review identified security issues", "Implement input validation", "Use safer alternatives"]
                },
                "raw_response": response
            }
            
        except Exception as e:
            logger.error(f"Error in fallback security response parsing: {e}")
            return {
                "success": False,
                "error": f"Failed to parse security analysis response: {str(e)}"
            }
    
    def is_available(self) -> bool:
        """Check if AI service is available"""
        return self.client is not None 