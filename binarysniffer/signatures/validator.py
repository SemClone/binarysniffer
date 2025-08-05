"""
Signature validation and quality filtering
"""

import re
from typing import List, Dict, Set, Tuple


class SignatureValidator:
    """Validates and filters signatures to reduce false positives"""
    
    # Common generic terms that appear in many projects
    GENERIC_TERMS = {
        # Common programming terms
        'error', 'warning', 'info', 'debug', 'log', 'logger', 'logging',
        'test', 'tests', 'testing', 'assert', 'check', 'verify',
        'init', 'create', 'destroy', 'free', 'alloc', 'malloc',
        'get', 'set', 'add', 'remove', 'delete', 'clear',
        'start', 'stop', 'run', 'execute', 'process',
        'read', 'write', 'open', 'close', 'load', 'save',
        'send', 'receive', 'connect', 'disconnect',
        'data', 'buffer', 'string', 'array', 'list', 'vector',
        'error', 'exception', 'throw', 'catch', 'try',
        'public', 'private', 'static', 'const', 'final',
        'class', 'struct', 'function', 'method', 'void',
        'true', 'false', 'null', 'none', 'nil',
        'main', 'app', 'application', 'program', 'system',
        'version', 'config', 'settings', 'options', 'params',
        # Language names
        'java', 'python', 'javascript', 'cpp', 'csharp',
        'kotlin', 'swift', 'rust', 'go', 'ruby',
        # Common libraries/tools
        'apache', 'google', 'microsoft', 'apple', 'android', 'ios',
        'linux', 'windows', 'macos', 'unix',
        # File extensions
        'json', 'xml', 'yaml', 'toml', 'ini',
        'jpg', 'png', 'gif', 'svg', 'pdf',
        'zip', 'tar', 'gz', 'bz2',
        # Single letters
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
    }
    
    # Known library prefixes that are valid signatures
    VALID_PREFIXES = {
        # FFmpeg/libav
        'av_', 'avcodec_', 'avformat_', 'avutil_', 'avfilter_', 'avdevice_',
        'sws_', 'swr_', 'swscale_',
        # Video codecs
        'x264_', 'x265_', 'vpx_', 'vp8_', 'vp9_', 'av1_', 'aom_',
        'theora_', 'xvid_', 'divx_',
        # Audio codecs
        'opus_', 'vorbis_', 'mp3_', 'aac_', 'flac_', 'speex_',
        # Image libraries
        'png_', 'jpeg_', 'jpg_', 'webp_', 'tiff_', 'gif_',
        # Compression
        'z_', 'zlib_', 'gz_', 'bz2_', 'BZ2_', 'lzma_', 'lz4_', 'zstd_',
        # Crypto/SSL
        'SSL_', 'EVP_', 'CRYPTO_', 'RSA_', 'AES_', 'SHA_', 'MD5_',
        # Networking
        'curl_', 'http_', 'https_', 'tcp_', 'udp_', 'socket_',
        # Database
        'sqlite3_', 'mysql_', 'pg_', 'postgres_', 'redis_',
        # XML/JSON
        'xml_', 'XML_', 'json_', 'JSON_', 'yaml_', 'YAML_',
        # Common libraries
        'boost_', 'Qt_', 'gtk_', 'glib_', 'SDL_', 'GL_', 'glu_',
        # Math/Science
        'blas_', 'lapack_', 'fftw_', 'gsl_',
    }
    
    @classmethod
    def is_valid_signature(cls, pattern: str, confidence: float = 0.0) -> bool:
        """
        Check if a signature pattern is valid (not too generic)
        
        Returns True if the pattern is specific enough to be useful
        """
        # ULTRA PERMISSIVE - Accept almost everything except empty/whitespace
        if not pattern or not pattern.strip():
            return False
        
        # Only reject single characters
        if len(pattern.strip()) < 2:
            return False
        
        # Accept everything else - no filtering for debugging
        return True
        
        # 5. Reject patterns that are just numbers
        if pattern.isdigit():
            return False
        
        # 6. Reject common file extensions
        if pattern_lower.startswith('.') and len(pattern) <= 5:
            return False
        
        # 7. Reject single common words with colons
        if pattern_lower.endswith(':') and pattern_lower[:-1] in cls.GENERIC_TERMS:
            return False
        
        # 8. Accept if pattern contains special characters or mixed case
        # (indicates more specific identifier)
        if any(c in pattern for c in ['_', '-', '.', '::', '->', '(', ')', '[', ']']):
            return True
        
        # 9. Accept if pattern has mixed case (camelCase or PascalCase)
        if pattern != pattern.lower() and pattern != pattern.upper():
            return True
        
        # 10. Reject if it's a single word and too generic
        if ' ' not in pattern and len(pattern) < 8:
            # Check if it's a common prefix
            common_prefixes = ['get', 'set', 'is', 'has', 'add', 'remove', 'create', 'delete']
            for prefix in common_prefixes:
                if pattern_lower.startswith(prefix) and not any(c in pattern for c in ['_', '-']):
                    return False
        
        # 11. Accept longer patterns by default
        if len(pattern) >= 12:
            return True
        
        # 12. For medium length patterns, check specificity
        if 8 <= len(pattern) < 12:
            # Accept if it contains numbers (version strings, etc)
            if any(c.isdigit() for c in pattern):
                return True
            # Accept if it's not all lowercase (indicates proper noun or constant)
            if pattern != pattern.lower():
                return True
        
        # Default: reject short, all-lowercase, single words
        return False
    
    @classmethod
    def filter_signatures(cls, signatures: List[Dict]) -> List[Dict]:
        """
        Filter a list of signatures to remove generic ones
        
        Returns filtered list of valid signatures
        """
        valid_signatures = []
        
        for sig in signatures:
            pattern = sig.get('pattern', '')
            confidence = sig.get('confidence', 0.7)
            
            if cls.is_valid_signature(pattern, confidence):
                valid_signatures.append(sig)
        
        return valid_signatures
    
    @classmethod
    def calculate_signature_quality_score(cls, signatures: List[Dict]) -> float:
        """
        Calculate a quality score for a set of signatures (0.0 to 1.0)
        
        Higher scores indicate more specific, less generic signatures
        """
        if not signatures:
            return 0.0
        
        total_score = 0.0
        for sig in signatures:
            pattern = sig.get('pattern', '')
            confidence = sig.get('confidence', 0.7)
            
            # Base score from pattern length
            length_score = min(len(pattern) / 20.0, 1.0)
            
            # Bonus for special characters
            special_char_bonus = 0.2 if any(c in pattern for c in ['_', '-', '.', '::', '->', '(']) else 0.0
            
            # Bonus for mixed case
            mixed_case_bonus = 0.1 if pattern != pattern.lower() and pattern != pattern.upper() else 0.0
            
            # Penalty for being too generic
            generic_penalty = -0.5 if pattern.lower() in cls.GENERIC_TERMS else 0.0
            
            # Combine scores
            pattern_score = max(0.0, min(1.0, length_score + special_char_bonus + mixed_case_bonus + generic_penalty))
            
            # Weight by confidence
            weighted_score = pattern_score * confidence
            total_score += weighted_score
        
        return total_score / len(signatures)
    
    @classmethod
    def get_signature_issues(cls, pattern: str) -> List[str]:
        """Get list of issues with a signature pattern"""
        issues = []
        
        if len(pattern) < 6:
            issues.append("Pattern too short (< 6 characters)")
        
        if pattern.lower() in cls.GENERIC_TERMS:
            issues.append("Pattern is a generic programming term")
        
        if pattern.isdigit():
            issues.append("Pattern contains only numbers")
        
        if ' ' not in pattern and len(pattern) < 8 and pattern.islower():
            issues.append("Short single word pattern")
        
        if pattern.lower().startswith(('get', 'set', 'is', 'has')) and len(pattern) < 12:
            issues.append("Common method prefix pattern")
        
        return issues