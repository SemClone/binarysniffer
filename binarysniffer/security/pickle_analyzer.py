"""
Enhanced Pickle Security Analyzer for ML Models

This module provides deep security analysis of pickle files,
detecting malicious code patterns, backdoors, and exploits.
"""

import pickle
import pickletools
import io
import logging
from typing import Set, Dict, List, Tuple, Optional, Any
from pathlib import Path

from .patterns import MaliciousPatterns, ThreatPattern
from .risk_scorer import RiskScorer, RiskAssessment

logger = logging.getLogger(__name__)


class PickleSecurityAnalyzer:
    """
    Advanced security analyzer for pickle files.
    Performs static analysis without executing code.
    """
    
    # Dangerous pickle opcodes that enable code execution
    DANGEROUS_OPCODES = {
        'GLOBAL': 'Can import arbitrary modules',
        'REDUCE': 'Can call arbitrary functions',
        'BUILD': 'Can call object methods',
        'INST': 'Can instantiate arbitrary classes',
        'OBJ': 'Can create arbitrary objects',
        'NEWOBJ': 'Can create new objects',
        'NEWOBJ_EX': 'Extended object creation',
        'STACK_GLOBAL': 'Stack-based module import',
    }
    
    # Common malicious module imports in exploits
    MALICIOUS_IMPORTS = {
        'os': ['system', 'popen', 'exec', 'spawn', 'fork'],
        'subprocess': ['Popen', 'run', 'call', 'check_output'],
        'commands': ['getoutput', 'getstatusoutput'],
        'pty': ['spawn'],
        'socket': ['socket', 'connect', 'bind'],
        'builtins': ['eval', 'exec', 'compile', '__import__'],
        'importlib': ['import_module', '__import__'],
        'code': ['interact', 'compile_command'],
        'webbrowser': ['open'],
        'tempfile': ['mktemp', 'NamedTemporaryFile'],
    }
    
    def __init__(self):
        """Initialize the pickle security analyzer"""
        self.risk_scorer = RiskScorer()
        self.patterns = MaliciousPatterns()
    
    def analyze_pickle(self, file_path: str) -> Tuple[RiskAssessment, Set[str]]:
        """
        Perform comprehensive security analysis on a pickle file
        
        Args:
            file_path: Path to the pickle file
            
        Returns:
            Tuple of (RiskAssessment, extracted_features)
        """
        features = set()
        suspicious_items = set()
        imports = set()
        dangerous_calls = set()
        
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Analyze opcodes
            opcode_features = self._analyze_opcodes(content)
            features.update(opcode_features['features'])
            suspicious_items.update(opcode_features['suspicious'])
            imports.update(opcode_features['imports'])
            dangerous_calls.update(opcode_features['dangerous_calls'])
            
            # Analyze strings
            string_features = self._analyze_strings(content)
            features.update(string_features)
            
            # Check for known exploits
            exploit_features = self._check_known_exploits(content)
            features.update(exploit_features)
            
            # Check for obfuscation
            if self._is_obfuscated(content):
                features.add("pickle_obfuscated")
                suspicious_items.add("obfuscation_detected")
            
            # Add categorized features
            for item in suspicious_items:
                features.add(f"suspicious:{item}")
            
            for imp in imports:
                features.add(f"import:{imp}")
                
            for call in dangerous_calls:
                features.add(f"dangerous_call:{call}")
            
            # Calculate risk assessment
            metadata = {
                'file_type': 'pickle',
                'imports': list(imports),
                'dangerous_calls': list(dangerous_calls),
                'suspicious_items': list(suspicious_items)
            }
            
            risk_assessment = self.risk_scorer.calculate_risk(
                features, 
                file_path,
                metadata
            )
            
            return risk_assessment, features
            
        except Exception as e:
            logger.error(f"Error analyzing pickle file {file_path}: {e}")
            features.add("pickle_analysis_error")
            features.add(f"error:{str(e)[:50]}")
            
            # Return error assessment
            risk_assessment = self.risk_scorer.calculate_risk(
                features,
                file_path,
                {'error': str(e)}
            )
            
            return risk_assessment, features
    
    def _analyze_opcodes(self, content: bytes) -> Dict[str, Any]:
        """Analyze pickle opcodes for security threats"""
        features = set()
        suspicious = set()
        imports = set()
        dangerous_calls = set()
        
        try:
            # Use pickletools for safe static analysis (dis is for display only)
            pickletools.dis(io.BytesIO(content), annotate=0)
            opcode_list = []
            
            # Parse opcodes
            for opcode, arg, pos in pickletools.genops(content):
                opcode_list.append((opcode.name, arg, pos))
                
                # Check for dangerous opcodes
                if opcode.name in self.DANGEROUS_OPCODES:
                    features.add(f"opcode:{opcode.name}")
                    
                    # Analyze GLOBAL imports
                    if opcode.name == 'GLOBAL' and arg:
                        if isinstance(arg, str):
                            if ' ' in arg:
                                module, name = arg.split(' ', 1)
                            else:
                                module, name = arg, ''
                        elif isinstance(arg, (tuple, list)) and len(arg) >= 2:
                            module, name = arg[0], arg[1]
                        else:
                            module, name = str(arg), ''
                        
                        import_str = f"{module}.{name}" if name else module
                        imports.add(import_str)
                        
                        # Check for malicious imports
                        if module in self.MALICIOUS_IMPORTS:
                            if not name or name in self.MALICIOUS_IMPORTS[module]:
                                dangerous_calls.add(import_str)
                                features.add(f"malicious_import:{import_str}")
                                suspicious.add(f"dangerous_import_{module}_{name}")
                    
                    # Analyze STACK_GLOBAL 
                    elif opcode.name == 'STACK_GLOBAL':
                        # STACK_GLOBAL builds module.name from the two strings on stack
                        if len(opcode_list) >= 2:
                            # Look for the two STRING opcodes before this
                            prev_strings = []
                            for i in range(len(opcode_list) - 1, -1, -1):
                                if opcode_list[i][0] in ['SHORT_BINUNICODE', 'BINUNICODE', 'STRING']:
                                    prev_strings.insert(0, opcode_list[i][1])
                                    if len(prev_strings) == 2:
                                        break
                            
                            if len(prev_strings) == 2:
                                module, name = prev_strings
                                import_str = f"{module}.{name}"
                                imports.add(import_str)
                                
                                # Check for malicious imports
                                if module in self.MALICIOUS_IMPORTS:
                                    if not name or name in self.MALICIOUS_IMPORTS[module]:
                                        dangerous_calls.add(import_str)
                                        features.add(f"malicious_import:{import_str}")
                                        suspicious.add(f"dangerous_import_{module}_{name}")
                    
                    # Analyze REDUCE calls
                    elif opcode.name == 'REDUCE' and len(opcode_list) > 1:
                        # Check previous opcode for function being called
                        prev_op = opcode_list[-2] if len(opcode_list) >= 2 else None
                        if prev_op and prev_op[0] == 'GLOBAL':
                            func = prev_op[1]
                            if any(danger in func.lower() for danger in 
                                  ['system', 'exec', 'eval', 'popen', 'spawn']):
                                dangerous_calls.add(func)
                                features.add(f"dangerous_reduce:{func}")
                                suspicious.add("code_execution_attempt")
            
            # Pattern detection in opcode sequences
            opcode_sequence = [op[0] for op in opcode_list]
            
            # Check for common exploit patterns
            if self._has_exploit_pattern(opcode_sequence):
                suspicious.add("exploit_pattern_detected")
                features.add("known_exploit_sequence")
            
            # Check for reverse shell patterns
            if self._has_reverse_shell_pattern(opcode_list):
                suspicious.add("reverse_shell_pattern")
                features.add("reverse_shell_detected")
                
        except Exception as e:
            logger.debug(f"Opcode analysis error: {e}")
            features.add("opcode_analysis_failed")
        
        return {
            'features': features,
            'suspicious': suspicious,
            'imports': imports,
            'dangerous_calls': dangerous_calls
        }
    
    def _analyze_strings(self, content: bytes) -> Set[str]:
        """Extract and analyze strings from pickle content"""
        features = set()
        
        try:
            # Extract printable strings
            strings = self._extract_strings(content)
            
            for string in strings:
                # Check against malicious patterns
                matches = MaliciousPatterns.check_pattern(string)
                for pattern, _ in matches:
                    features.add(f"string_pattern:{pattern.pattern}")
                    
                # Check for specific indicators
                if any(shell in string for shell in ['/bin/sh', '/bin/bash', 'cmd.exe']):
                    features.add("shell_path_found")
                    
                if any(net in string for net in ['0.0.0.0', '127.0.0.1', 'localhost']):
                    features.add("network_address_found")
                    
                if 'base64' in string.lower():
                    features.add("base64_encoding_found")
                    
        except Exception as e:
            logger.debug(f"String analysis error: {e}")
            
        return features
    
    def _check_known_exploits(self, content: bytes) -> Set[str]:
        """Check for known pickle exploit signatures"""
        features = set()
        content_str = str(content)
        
        # Known exploit signatures
        exploits = {
            'pickle_rce_classic': b'cos\\nsystem',
            'pickle_reverse_shell': b'reverse_tcp',
            'pickle_bind_shell': b'bind_tcp',
            'metasploit_payload': b'meterpreter',
            'python_reverse_shell': b'socket.socket',
            'subprocess_shell': b'subprocess.Popen',
        }
        
        for exploit_name, signature in exploits.items():
            if signature in content:
                features.add(f"exploit:{exploit_name}")
                
        return features
    
    def _is_obfuscated(self, content: bytes) -> bool:
        """Check if pickle content appears obfuscated"""
        # Calculate entropy
        entropy = self._calculate_entropy(content)
        
        # High entropy suggests compression/encryption
        if entropy > 7.5:
            return True
            
        # Check for obfuscation patterns
        obfusc_patterns = [b'exec(', b'eval(', b'compile(', b'marshal.loads']
        return any(pattern in content for pattern in obfusc_patterns)
    
    def _has_exploit_pattern(self, opcodes: List[str]) -> bool:
        """Check for common exploit opcode patterns"""
        exploit_patterns = [
            ['GLOBAL', 'MARK', 'TUPLE', 'REDUCE'],  # Classic RCE
            ['GLOBAL', 'GLOBAL', 'TUPLE', 'REDUCE'],  # Double import
            ['GLOBAL', 'INST'],  # Direct instantiation
            ['STACK_GLOBAL', 'REDUCE'],  # Stack-based RCE
        ]
        
        opcode_str = ' '.join(opcodes)
        for pattern in exploit_patterns:
            pattern_str = ' '.join(pattern)
            if pattern_str in opcode_str:
                return True
                
        return False
    
    def _has_reverse_shell_pattern(self, opcode_list: List[Tuple]) -> bool:
        """Check for reverse shell patterns in opcodes"""
        suspicious_strings = set()
        
        for op_name, arg, _ in opcode_list:
            if op_name in ['SHORT_BINSTRING', 'BINSTRING', 'BINUNICODE']:
                if arg and isinstance(arg, (str, bytes)):
                    arg_str = arg.decode() if isinstance(arg, bytes) else arg
                    suspicious_strings.add(arg_str.lower())
        
        # Check for reverse shell indicators
        shell_indicators = [
            'socket', 'connect', 'dup2', 'exec',
            '/bin/sh', '/bin/bash', 'cmd.exe',
            '0.0.0.0', 'LHOST', 'LPORT'
        ]
        
        for indicator in shell_indicators:
            if any(indicator.lower() in s for s in suspicious_strings):
                return True
                
        return False
    
    def _extract_strings(self, content: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary content"""
        strings = []
        current = []
        
        for byte in content:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []
                
        if len(current) >= min_length:
            strings.append(''.join(current))
            
        return strings
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
            
        import math
        entropy = 0.0
        data_len = len(data)
        
        # Count byte frequencies
        frequencies = {}
        for byte in data:
            frequencies[byte] = frequencies.get(byte, 0) + 1
            
        # Calculate entropy using Shannon entropy formula
        for count in frequencies.values():
            if count > 0:
                probability = float(count) / float(data_len)
                entropy -= probability * math.log2(probability)
                
        return entropy