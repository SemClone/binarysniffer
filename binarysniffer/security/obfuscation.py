"""
Obfuscation Detection Module for ML Model Security

This module detects various obfuscation techniques used to hide
malicious code in ML models.
"""

import re
import math
import base64
import zlib
from typing import Set, Dict, List, Tuple, Optional
from collections import Counter
import logging

logger = logging.getLogger(__name__)


class ObfuscationDetector:
    """
    Detects obfuscation techniques in ML model files
    """
    
    # Entropy thresholds
    HIGH_ENTROPY_THRESHOLD = 7.5  # Likely encrypted/compressed
    MEDIUM_ENTROPY_THRESHOLD = 6.0  # Possibly obfuscated
    
    # Common obfuscation patterns
    OBFUSCATION_PATTERNS = [
        # Base64 encoding patterns
        (r'^[A-Za-z0-9+/]{20,}={0,2}$', 'base64_encoded'),
        # Hex encoding patterns  
        (r'^[0-9a-fA-F]{20,}$', 'hex_encoded'),
        # URL encoding
        (r'%[0-9a-fA-F]{2}', 'url_encoded'),
        # Unicode escape sequences
        (r'\\u[0-9a-fA-F]{4}', 'unicode_escaped'),
        # Octal sequences
        (r'\\[0-7]{3}', 'octal_encoded'),
        # Variable name obfuscation
        (r'\b[oO0]{5,}\b|\b[Il1]{5,}\b', 'variable_obfuscation'),
        # Packed/minified code
        (r'[^\s]{200,}', 'packed_code'),
    ]
    
    # Encoding function indicators
    ENCODING_FUNCTIONS = [
        'base64.b64decode',
        'base64.b64encode',
        'base64.b85decode',
        'base64.b32decode',
        'zlib.decompress',
        'zlib.compress',
        'gzip.decompress',
        'bz2.decompress',
        'lzma.decompress',
        'marshal.loads',
        'marshal.dumps',
        'pickle.loads',
        'codecs.decode',
        'codecs.encode',
        'binascii.unhexlify',
        'binascii.hexlify',
        'urllib.parse.unquote',
        'json.loads',
        'ast.literal_eval',
    ]
    
    # Cryptographic indicators
    CRYPTO_INDICATORS = [
        'Crypto.Cipher',
        'cryptography.fernet',
        'AES.new',
        'DES.new',
        'RSA.generate',
        'hashlib.md5',
        'hashlib.sha256',
        'hmac.new',
        'pbkdf2',
        'scrypt',
    ]
    
    # Anti-analysis techniques
    ANTI_ANALYSIS = [
        'sys.exit',
        'os._exit',
        'signal.alarm',
        'threading.Timer',
        'time.sleep',
        'random.seed',
        'inspect.stack',
        'inspect.currentframe',
        'traceback.extract_stack',
        '__debug__',
        'sys.gettrace',
        'sys.settrace',
    ]
    
    def __init__(self):
        """Initialize the obfuscation detector"""
        self.patterns = [
            (re.compile(pattern), name) 
            for pattern, name in self.OBFUSCATION_PATTERNS
        ]
    
    def detect_obfuscation(self, content: bytes, features: Set[str] = None) -> Dict[str, any]:
        """
        Detect obfuscation in file content
        
        Args:
            content: Raw file content
            features: Optional extracted features to analyze
            
        Returns:
            Dictionary with obfuscation analysis results
        """
        results = {
            'is_obfuscated': False,
            'confidence': 0.0,
            'techniques': [],
            'indicators': [],
            'entropy': 0.0,
            'recommendations': []
        }
        
        # Calculate entropy
        entropy = self._calculate_entropy(content)
        results['entropy'] = entropy
        
        # Check entropy levels
        if entropy > self.HIGH_ENTROPY_THRESHOLD:
            results['is_obfuscated'] = True
            results['techniques'].append('high_entropy')
            results['indicators'].append(f'Very high entropy: {entropy:.2f}')
            results['confidence'] = 0.9
            
        elif entropy > self.MEDIUM_ENTROPY_THRESHOLD:
            results['techniques'].append('medium_entropy')
            results['indicators'].append(f'Elevated entropy: {entropy:.2f}')
            results['confidence'] = 0.5
        
        # Check for encoding patterns
        content_str = self._safe_decode(content)
        encoding_results = self._detect_encoding_patterns(content_str)
        if encoding_results['found']:
            results['is_obfuscated'] = True
            results['techniques'].extend(encoding_results['techniques'])
            results['indicators'].extend(encoding_results['indicators'])
            results['confidence'] = max(results['confidence'], encoding_results['confidence'])
        
        # Check for encoding functions in features
        if features:
            function_results = self._detect_encoding_functions(features)
            if function_results['found']:
                results['is_obfuscated'] = True
                results['techniques'].extend(function_results['techniques'])
                results['indicators'].extend(function_results['indicators'])
                results['confidence'] = max(results['confidence'], function_results['confidence'])
            
            # Check for anti-analysis techniques
            anti_results = self._detect_anti_analysis(features)
            if anti_results['found']:
                results['techniques'].extend(anti_results['techniques'])
                results['indicators'].extend(anti_results['indicators'])
                
            # Check for crypto usage
            crypto_results = self._detect_cryptography(features)
            if crypto_results['found']:
                results['is_obfuscated'] = True
                results['techniques'].extend(crypto_results['techniques'])
                results['indicators'].extend(crypto_results['indicators'])
                results['confidence'] = max(results['confidence'], 0.8)
        
        # Check for layered obfuscation
        if self._has_layered_obfuscation(content):
            results['is_obfuscated'] = True
            results['techniques'].append('layered_obfuscation')
            results['indicators'].append('Multiple encoding layers detected')
            results['confidence'] = 0.95
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        # Remove duplicates
        results['techniques'] = list(set(results['techniques']))
        results['indicators'] = list(set(results['indicators']))
        
        return results
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        frequencies = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in frequencies.values():
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _safe_decode(self, content: bytes) -> str:
        """Safely decode bytes to string"""
        try:
            return content.decode('utf-8', errors='ignore')
        except:
            return str(content)
    
    def _detect_encoding_patterns(self, content: str) -> Dict[str, any]:
        """Detect encoding patterns in content"""
        results = {
            'found': False,
            'techniques': [],
            'indicators': [],
            'confidence': 0.0
        }
        
        # Check each line/chunk
        chunks = content.split('\n') if '\n' in content else [content[:1000]]
        
        for chunk in chunks[:100]:  # Limit analysis
            for pattern, name in self.patterns:
                if pattern.search(chunk):
                    results['found'] = True
                    results['techniques'].append(name)
                    results['indicators'].append(f'Pattern {name} detected')
                    
        if results['found']:
            results['confidence'] = 0.7
            
        return results
    
    def _detect_encoding_functions(self, features: Set[str]) -> Dict[str, any]:
        """Detect encoding function usage"""
        results = {
            'found': False,
            'techniques': [],
            'indicators': [],
            'confidence': 0.0
        }
        
        features_str = ' '.join(features).lower()
        
        for func in self.ENCODING_FUNCTIONS:
            if func.lower() in features_str:
                results['found'] = True
                results['techniques'].append('encoding_function')
                results['indicators'].append(f'Encoding function: {func}')
                
        if results['found']:
            count = len(results['indicators'])
            results['confidence'] = min(0.5 + (count * 0.1), 0.9)
            
        return results
    
    def _detect_anti_analysis(self, features: Set[str]) -> Dict[str, any]:
        """Detect anti-analysis techniques"""
        results = {
            'found': False,
            'techniques': [],
            'indicators': [],
            'confidence': 0.0
        }
        
        features_str = ' '.join(features).lower()
        
        for technique in self.ANTI_ANALYSIS:
            if technique.lower() in features_str:
                results['found'] = True
                results['techniques'].append('anti_analysis')
                results['indicators'].append(f'Anti-analysis: {technique}')
                
        return results
    
    def _detect_cryptography(self, features: Set[str]) -> Dict[str, any]:
        """Detect cryptographic usage"""
        results = {
            'found': False,
            'techniques': [],
            'indicators': [],
            'confidence': 0.0
        }
        
        features_str = ' '.join(features).lower()
        
        for crypto in self.CRYPTO_INDICATORS:
            if crypto.lower() in features_str:
                results['found'] = True
                results['techniques'].append('cryptography')
                results['indicators'].append(f'Crypto usage: {crypto}')
                
        return results
    
    def _has_layered_obfuscation(self, content: bytes) -> bool:
        """Check for multiple layers of obfuscation"""
        indicators = 0
        
        # Check for base64 inside base64
        try:
            decoded = base64.b64decode(content[:1000], validate=True)
            if self._is_base64(decoded):
                indicators += 1
        except:
            pass
        
        # Check for compressed then encoded
        if b'eJy' in content or b'eJx' in content:  # zlib markers
            indicators += 1
            
        # Check for multiple encoding indicators
        encoding_markers = [b'base64', b'zlib', b'gzip', b'marshal']
        if sum(1 for marker in encoding_markers if marker in content) >= 2:
            indicators += 1
            
        return indicators >= 2
    
    def _is_base64(self, data: bytes) -> bool:
        """Check if data appears to be base64 encoded"""
        try:
            if len(data) < 20:
                return False
            # Check if it's valid base64
            decoded = base64.b64decode(data[:100], validate=True)
            return True
        except:
            return False
    
    def _generate_recommendations(self, results: Dict[str, any]) -> List[str]:
        """Generate recommendations based on obfuscation analysis"""
        recommendations = []
        
        if results['is_obfuscated']:
            recommendations.append("Model appears obfuscated - exercise extreme caution")
            
            if 'high_entropy' in results['techniques']:
                recommendations.append("Very high entropy suggests encryption or compression")
                
            if 'encoding_function' in results['techniques']:
                recommendations.append("Multiple encoding functions detected - possible malware")
                
            if 'cryptography' in results['techniques']:
                recommendations.append("Cryptographic functions present - may hide payloads")
                
            if 'anti_analysis' in results['techniques']:
                recommendations.append("Anti-analysis techniques detected - likely malicious")
                
            if 'layered_obfuscation' in results['techniques']:
                recommendations.append("Multiple obfuscation layers - highly suspicious")
                
            recommendations.append("Do not load without thorough security review")
            recommendations.append("Consider running in isolated sandbox environment")
            
        elif results['confidence'] > 0.3:
            recommendations.append("Some obfuscation indicators present")
            recommendations.append("Review model source and purpose before loading")
            
        return recommendations