"""
Multi-Provider AI Service for ShadowSeek
Supports OpenAI, Anthropic Claude, and Google Gemini
"""

import os
import re
import json
import logging
from typing import Dict, Any, Optional, Protocol, List
from abc import ABC, abstractmethod

# Configure logging
logger = logging.getLogger(__name__)

class AIProvider(ABC):
    """Abstract base class for AI providers"""
    
    def __init__(self, api_key: str, model: str):
        self.api_key = api_key
        self.model = model
        self.client = None
        
    @abstractmethod
    def initialize_client(self) -> bool:
        """Initialize the client for this provider"""
        pass
    
    @abstractmethod
    def generate_response(self, system_prompt: str, user_prompt: str, max_tokens: int = 3000, temperature: float = 0.2) -> str:
        """Generate a response using this provider"""
        pass
    
    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Test the connection to this provider"""
        pass


class OpenAIProvider(AIProvider):
    """OpenAI provider implementation"""
    
    def initialize_client(self) -> bool:
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=self.api_key)
            return True
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            return False
    
    def generate_response(self, system_prompt: str, user_prompt: str, max_tokens: int = 3000, temperature: float = 0.2) -> str:
        if not self.client:
            raise Exception("OpenAI client not initialized")
            
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            timeout=45
        )
        
        return response.choices[0].message.content
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            if not self.client:
                return {"success": False, "error": "Client not initialized"}
                
            # Simple test call
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Test"}],
                max_tokens=10
            )
            
            return {"success": True, "message": "OpenAI connection successful"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class ClaudeProvider(AIProvider):
    """Anthropic Claude provider implementation"""
    
    def initialize_client(self) -> bool:
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.api_key)
            return True
        except ImportError:
            logger.error("anthropic package not installed. Run: pip install anthropic")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize Claude client: {e}")
            return False
    
    def generate_response(self, system_prompt: str, user_prompt: str, max_tokens: int = 3000, temperature: float = 0.2) -> str:
        if not self.client:
            raise Exception("Claude client not initialized")
            
        # Claude uses a different format - system prompt is separate
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[
                {"role": "user", "content": user_prompt}
            ]
        )
        
        return response.content[0].text
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            if not self.client:
                return {"success": False, "error": "Client not initialized"}
                
            # Simple test call
            response = self.client.messages.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": "Test"}]
            )
            
            return {"success": True, "message": "Claude connection successful"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class GeminiProvider(AIProvider):
    """Google Gemini provider implementation"""
    
    def initialize_client(self) -> bool:
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self.client = genai.GenerativeModel(self.model)
            return True
        except ImportError:
            logger.error("google-generativeai package not installed. Run: pip install google-generativeai")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize Gemini client: {e}")
            return False
    
    def generate_response(self, system_prompt: str, user_prompt: str, max_tokens: int = 3000, temperature: float = 0.2) -> str:
        if not self.client:
            raise Exception("Gemini client not initialized")
            
        # Gemini combines system and user prompts
        combined_prompt = f"System: {system_prompt}\n\nUser: {user_prompt}"
        
        generation_config = {
            'max_output_tokens': max_tokens,
            'temperature': temperature,
        }
        
        response = self.client.generate_content(
            combined_prompt,
            generation_config=generation_config
        )
        
        return response.text
    
    def test_connection(self) -> Dict[str, Any]:
        try:
            if not self.client:
                return {"success": False, "error": "Client not initialized"}
                
            # Simple test call
            response = self.client.generate_content("Test")
            
            return {"success": True, "message": "Gemini connection successful"}
        except Exception as e:
            return {"success": False, "error": str(e)}


class MultiProviderAIService:
    """Multi-provider AI service that can use OpenAI, Claude, or Gemini"""
    
    def __init__(self, provider: str = None, api_key: str = None, model: str = None):
        """
        Initialize multi-provider AI service
        
        Args:
            provider: AI provider ('openai', 'claude', 'gemini')
            api_key: API key for the provider
            model: Model name for the provider
        """
        # Force reload environment variables
        try:
            from dotenv import load_dotenv
            load_dotenv(override=True)
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"Error reloading .env file: {e}")
        
        # Get configuration from environment if not provided
        self.provider_name = provider or os.getenv('LLM_PROVIDER', 'openai').lower()
        self.provider = None
        
        # Initialize the appropriate provider
        if self.provider_name == 'openai':
            api_key = api_key or os.getenv('OPENAI_API_KEY')
            model = model or os.getenv('OPENAI_MODEL', 'gpt-3.5-turbo')
            if api_key:
                self.provider = OpenAIProvider(api_key, model)
        
        elif self.provider_name == 'claude':
            api_key = api_key or os.getenv('CLAUDE_API_KEY')
            model = model or os.getenv('CLAUDE_MODEL', 'claude-3-5-sonnet-20241022')
            if api_key:
                self.provider = ClaudeProvider(api_key, model)
        
        elif self.provider_name == 'gemini':
            api_key = api_key or os.getenv('GEMINI_API_KEY')
            model = model or os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')
            if api_key:
                self.provider = GeminiProvider(api_key, model)
        
        else:
            logger.error(f"Unsupported provider: {self.provider_name}")
            return
        
        # Initialize the provider
        if self.provider:
            success = self.provider.initialize_client()
            if success:
                logger.info(f"AI Service initialized successfully with {self.provider_name} provider, model: {self.provider.model}")
                if hasattr(self.provider, 'api_key') and self.provider.api_key:
                    key_display = '*' * (len(self.provider.api_key) - 10) + self.provider.api_key[-4:] if len(self.provider.api_key) > 10 else '***'
                    logger.info(f"API key configured: {key_display}")
            else:
                logger.error(f"Failed to initialize {self.provider_name} provider")
                self.provider = None
        else:
            logger.warning(f"No API key found for {self.provider_name} provider. AI explanations will not work.")
    
    @property
    def client(self):
        """Compatibility property for existing code"""
        return self.provider.client if self.provider else None
    
    def is_available(self) -> bool:
        """Check if the AI service is available"""
        return self.provider is not None and self.provider.client is not None
    
    def explain_function(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate AI explanation for a decompiled function
        
        Args:
            context: Dictionary containing function information
            
        Returns:
            Dictionary with explanation and risk assessment
        """
        if not self.provider or not self.provider.client:
            return {
                "success": False,
                "error": f"{self.provider_name.title()} client not initialized. Check API key configuration."
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
            
            # Prepare prompts
            system_prompt = "You are a senior security researcher and reverse engineer with expertise in vulnerability analysis, exploitation techniques, and secure coding practices. Provide detailed technical analysis suitable for security professionals."
            
            user_prompt = self._build_analysis_prompt(
                function_name, function_address, decompiled_code, 
                signature, size
            )
            
            logger.info(f"Sending AI explanation request for function {function_name} using {self.provider_name}")
            
            # Generate response using the provider
            ai_response = self.provider.generate_response(system_prompt, user_prompt)
            
            logger.info(f"Received AI response for function {function_name} ({len(ai_response)} chars)")
            
            # Extract structured information from response
            explanation, risk_score, vulnerabilities = self._parse_ai_response(ai_response)
            
            return {
                "success": True,
                "explanation": explanation,
                "risk_score": risk_score,
                "vulnerabilities": vulnerabilities,
                "raw_response": ai_response,
                "model_used": self.provider.model,
                "provider_used": self.provider_name
            }
            
        except Exception as e:
            logger.error(f"Error in AI explanation for function {function_name}: {e}")
            return {
                "success": False,
                "error": f"AI explanation failed: {str(e)}"
            }
    
    def analyze_security_strings(self, security_strings: List[Dict], binary_name: str) -> Dict[str, Any]:
        """
        Perform AI-powered security analysis on binary strings
        
        Args:
            security_strings: List of security-relevant strings with their metadata
            binary_name: Name of the binary being analyzed
            
        Returns:
            Dictionary with string security analysis results
        """
        if not self.provider or not self.provider.client:
            return {
                "success": False,
                "error": f"{self.provider_name.title()} client not initialized. Check API key configuration."
            }
        
        try:
            # Prepare strings for AI analysis (limit to top 20)
            strings_text = '\n'.join([f"- {s.get('value', s.get('content', ''))[:100]} (Category: {s.get('category', 'unknown')})" for s in security_strings[:20]])
            
            system_prompt = "You are a cybersecurity expert specializing in static binary analysis and string-based vulnerability detection. Analyze strings for genuine security concerns and respond in the exact JSON format requested. Be precise and focus only on real security issues."
            
            user_prompt = f"""
Analyze these security-relevant strings found in the binary '{binary_name}' for potential security issues:

{strings_text}

For each string that represents a genuine security concern, provide:
1. **Title**: Brief security issue description
2. **Severity**: CRITICAL, HIGH, MEDIUM, LOW, or INFO  
3. **Description**: Detailed explanation of the security implication
4. **CWE ID**: Relevant Common Weakness Enumeration ID
5. **Confidence**: Your confidence level (0-100)
6. **Affected String**: The specific string that caused concern
7. **Remediation**: Specific mitigation recommendations

Focus on:
- Hardcoded credentials, passwords, or API keys
- Weak cryptographic algorithms or configurations
- Command injection vectors and shell execution patterns
- SQL injection patterns and database queries
- Path traversal risks and file system access
- Information disclosure and debug information
- Network endpoints and sensitive URLs
- Registry keys or system configuration strings

Respond in JSON format:
{{
  "findings": [
    {{
      "title": "Hardcoded Credential Found",
      "severity": "HIGH", 
      "description": "The binary contains what appears to be a hardcoded password or API key, which could allow unauthorized access if discovered.",
      "cwe_id": "CWE-798",
      "confidence": 85,
      "affected_string": "password=admin123",
      "remediation": "Remove hardcoded credentials and implement secure credential storage using environment variables or secure key management systems."
    }}
  ]
}}
"""
            
            logger.info(f"Performing AI string security analysis for binary {binary_name} with {len(security_strings)} strings using {self.provider_name}")
            
            # Generate response using the provider
            ai_response = self.provider.generate_response(system_prompt, user_prompt, max_tokens=2000, temperature=0.1)
            
            # Parse JSON response
            try:
                # Extract JSON from response
                import json
                import re
                json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                if json_match:
                    json_str = json_match.group(0)
                    parsed_response = json.loads(json_str)
                    
                    # Validate and format findings
                    if 'findings' in parsed_response and isinstance(parsed_response['findings'], list):
                        formatted_findings = []
                        for finding in parsed_response['findings']:
                            if isinstance(finding, dict) and 'title' in finding:
                                # Ensure all required fields are present
                                formatted_finding = {
                                    'title': finding.get('title', 'Security String Analysis'),
                                    'severity': finding.get('severity', 'INFO').upper(),
                                    'description': finding.get('description', 'Security-relevant string detected'),
                                    'cwe_id': finding.get('cwe_id'),
                                    'confidence': int(finding.get('confidence', 70)),
                                    'affected_string': finding.get('affected_string', ''),
                                    'remediation': finding.get('remediation', 'Review string usage for security implications'),
                                    'category': 'string_analysis',
                                    'detection_methods': ['ai_string_analysis'],
                                    'risk_score': min(100, max(0, int(finding.get('confidence', 70))))
                                }
                                formatted_findings.append(formatted_finding)
                        
                        return {
                            "success": True,
                            "findings": formatted_findings,
                            "raw_response": ai_response,
                            "provider_used": self.provider_name
                        }
                
                # If no valid findings structure, return empty
                logger.warning(f"AI string analysis for {binary_name} returned invalid structure")
                return {
                    "success": True,
                    "findings": [],
                    "raw_response": ai_response,
                    "provider_used": self.provider_name
                }
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON parsing error in string analysis for {binary_name}: {e}")
                return {
                    "success": False,
                    "error": f"Invalid JSON response from AI: {str(e)}",
                    "raw_response": ai_response
                }
                
        except Exception as e:
            logger.error(f"Error in AI string security analysis for {binary_name}: {e}")
            return {
                "success": False,
                "error": f"AI string analysis failed: {str(e)}"
            }

    def analyze_binary_comprehensive(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive AI analysis for an entire binary using function analyses
        
        Args:
            context: Dictionary containing binary information and function analyses
            
        Returns:
            Dictionary with comprehensive binary analysis and summary
        """
        if not self.provider or not self.provider.client:
            return {
                "success": False,
                "error": f"{self.provider_name.title()} client not initialized. Check API key configuration."
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
            
            logger.info(f"Sending comprehensive AI binary analysis request for {binary_name} with {ai_analyzed_functions} function analyses using {self.provider_name}")
            
            # Generate response using the provider
            system_prompt = "You are a senior cybersecurity expert and malware analyst with extensive experience in binary analysis, reverse engineering, and threat assessment. Provide comprehensive, technical analysis suitable for security professionals and threat hunters."
            
            ai_response = self.provider.generate_response(system_prompt, prompt, max_tokens=4000, temperature=0.2)
            
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
                "model_used": self.provider.model,
                "provider_used": self.provider_name,
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
    
    def test_connection(self) -> Dict[str, Any]:
        """Test the connection to the configured AI provider"""
        if not self.provider:
            return {
                "success": False,
                "error": f"No provider initialized for {self.provider_name}"
            }
        
        return self.provider.test_connection()
    
    def _build_analysis_prompt(self, function_name: str, address: str, 
                             code: str, signature: str, size: int) -> str:
        """Build prompt for AI analysis (brief format)"""
        prompt = f"""
You are a senior reverse engineer analyzing this decompiled function for security risks.

**Function Information:**
- Name: {function_name}
- Address: {address}
- Signature: {signature}
- Size: {size} bytes

**Decompiled Code:**
```c
{code}
```

**Provide a BRIEF security analysis (3-4 sentences maximum):**

1. FUNCTION SUMMARY: What does this function do and what is its primary purpose?

2. SECURITY RISK ASSESSMENT: What are the main security concerns? Look for buffer operations, memory management, input validation, dangerous API calls, or other potential vulnerabilities.

3. RISK SCORE (0-100): Assign a risk score based on the following criteria:
   - Only assign a score above 60 (High/Critical) if there is clear evidence of:
       - Remote code execution (RCE)
       - Memory corruption (e.g., buffer overflow, use-after-free)
       - Direct exposure of highly sensitive data (e.g., cryptographic keys, passwords)
       - Privilege escalation or system compromise
   - For simple getter functions that return a static value or memory address, default to Low (21-40) or Medium (41-60) risk unless you have strong evidence the returned value is highly sensitive or misused elsewhere.
   - If the function's risk depends on how its return value is used elsewhere, state this and assign a conservative (lower) risk score.

CONTEXTUAL ANALYSIS: If possible, consider:
- Where is this function called?
- How is its return value used?
- Is the returned value used in a security-sensitive context (e.g., authentication, cryptography, access control)?
If you cannot determine this, mention it in your assessment and avoid assigning a high/critical risk score.

Keep your response concise and focused on the most important security-relevant observations. Avoid lengthy technical details - just highlight key risks and concerns.
"""
        return prompt
    
    def _parse_ai_response(self, response: str) -> tuple:
        """Parse AI response to extract explanation, risk score, and vulnerabilities (same as original)"""
        explanation = response
        risk_score = 50  # Default
        vulnerabilities = []
        
        # Try to extract risk score
        risk_patterns = [
            r'(?:risk|score).*?(\d+)(?:/100|\%)',
            r'(\d+)(?:/100|\%).*?risk',
            r'risk.*?(\d+)',
            r'score.*?(\d+)'
        ]
        
        for pattern in risk_patterns:
            match = re.search(pattern, response.lower())
            if match:
                try:
                    risk_score = int(match.group(1))
                    risk_score = max(0, min(100, risk_score))  # Clamp to 0-100
                    break
                except ValueError:
                    continue
        
        # Try to extract vulnerability types
        vuln_keywords = [
            'buffer overflow', 'format string', 'sql injection', 'command injection',
            'path traversal', 'use after free', 'double free', 'memory leak',
            'integer overflow', 'race condition', 'toctou', 'privilege escalation'
        ]
        
        response_lower = response.lower()
        for keyword in vuln_keywords:
            if keyword in response_lower:
                vulnerabilities.append(keyword.replace(' ', '_'))
        
        return explanation, risk_score, vulnerabilities
    
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


def create_ai_service(provider: str = None, api_key: str = None, model: str = None) -> MultiProviderAIService:
    """Factory function to create AI service"""
    return MultiProviderAIService(provider, api_key, model)


# For backward compatibility, create an alias to the original AIService interface
AIService = MultiProviderAIService 