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
        'error', 'warning', 'info', 'debug', 'log', 'logger', 'logging', 'trace',
        'test', 'tests', 'testing', 'assert', 'check', 'verify', 'validate',
        'init', 'create', 'destroy', 'free', 'alloc', 'malloc', 'new', 'delete',
        'get', 'set', 'add', 'remove', 'delete', 'clear', 'reset', 'update',
        'start', 'stop', 'run', 'execute', 'process', 'handle', 'manage',
        'read', 'write', 'open', 'close', 'load', 'save', 'store', 'fetch',
        'send', 'receive', 'connect', 'disconnect', 'bind', 'listen',
        'data', 'buffer', 'string', 'array', 'list', 'vector', 'map', 'dict',
        'error', 'exception', 'throw', 'catch', 'try', 'finally', 'raise',
        'public', 'private', 'static', 'const', 'final', 'abstract', 'virtual',
        'class', 'struct', 'function', 'method', 'void', 'return', 'break',
        'true', 'false', 'null', 'none', 'nil', 'undefined', 'empty',
        'main', 'app', 'application', 'program', 'system', 'service', 'daemon',
        'version', 'config', 'settings', 'options', 'params', 'args', 'flags',
        'user', 'admin', 'root', 'guest', 'default', 'custom', 'global',
        'input', 'output', 'result', 'response', 'request', 'query', 'command',
        'key', 'value', 'pair', 'item', 'element', 'node', 'object', 'instance',
        'count', 'size', 'length', 'index', 'offset', 'position', 'range',
        'begin', 'end', 'first', 'last', 'next', 'prev', 'current', 'head', 'tail',
        'parent', 'child', 'root', 'leaf', 'branch', 'tree', 'graph',
        'file', 'path', 'dir', 'directory', 'folder', 'name', 'extension',
        'http', 'https', 'url', 'uri', 'host', 'port', 'protocol', 'scheme',
        'success', 'fail', 'failure', 'ok', 'cancel', 'abort', 'retry',
        'enable', 'disable', 'active', 'inactive', 'valid', 'invalid',
        'push', 'pop', 'peek', 'enqueue', 'dequeue', 'insert', 'append',
        'copy', 'move', 'clone', 'duplicate', 'merge', 'split', 'join',
        'lock', 'unlock', 'mutex', 'semaphore', 'thread', 'async', 'sync',
        'client', 'server', 'request', 'response', 'session', 'connection',
        'parse', 'format', 'encode', 'decode', 'serialize', 'deserialize',
        'print', 'printf', 'println', 'console', 'stdout', 'stderr', 'stdin',
        # Common variable names
        'i', 'j', 'k', 'n', 'm', 'x', 'y', 'z', 'tmp', 'temp', 'var', 'val',
        'str', 'num', 'int', 'float', 'bool', 'char', 'byte', 'obj', 'ptr',
        'src', 'dst', 'dest', 'source', 'target', 'from', 'to', 'in', 'out',
        # Language names
        'java', 'python', 'javascript', 'cpp', 'csharp', 'cplus', 'cplusplus',
        'kotlin', 'swift', 'rust', 'go', 'ruby', 'php', 'perl', 'scala',
        # Common libraries/tools (without specific versions)
        'apache', 'google', 'microsoft', 'apple', 'android', 'ios', 'oracle',
        'linux', 'windows', 'macos', 'unix', 'ubuntu', 'debian', 'fedora',
        # File extensions
        'json', 'xml', 'yaml', 'toml', 'ini', 'conf', 'cfg', 'properties',
        'jpg', 'png', 'gif', 'svg', 'pdf', 'ico', 'bmp', 'tiff',
        'zip', 'tar', 'gz', 'bz2', 'rar', '7z', 'iso', 'dmg',
        'txt', 'log', 'md', 'rst', 'doc', 'docx', 'html', 'css', 'js',
        # HTTP methods and status codes
        'get', 'post', 'put', 'patch', 'delete', 'head', 'options',
        # Common acronyms
        'api', 'sdk', 'ui', 'gui', 'cli', 'id', 'uid', 'pid', 'tid',
        # Single letters
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'l', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w'
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
        # Check for empty or whitespace
        if not pattern or not pattern.strip():
            return False
        
        pattern_lower = pattern.lower().strip()
        
        # 1. Reject very short patterns
        if len(pattern.strip()) < 4:
            return False
        
        # 2. Accept patterns with known library prefixes
        for prefix in cls.VALID_PREFIXES:
            if pattern.startswith(prefix):
                return True
        
        # 3. Reject exact matches of generic terms
        if pattern_lower in cls.GENERIC_TERMS:
            return False
        
        # 4. Reject patterns that are all uppercase generic terms
        if pattern.isupper() and pattern_lower in cls.GENERIC_TERMS:
            return False
        
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
        
        # 10. Reject common method prefixes with generic suffixes (check before mixed case)
        common_prefixes = ['get', 'set', 'is', 'has', 'add', 'remove', 'create', 'delete']
        for prefix in common_prefixes:
            if pattern_lower.startswith(prefix):
                # Extract the suffix after the prefix
                suffix = pattern[len(prefix):]
                # Reject if suffix is too short or generic
                if len(suffix) < 8 or suffix.lower() in ['item', 'data', 'value', 'name', 'type', 'id', 'key', 'val', 'valid']:
                    return False
        
        # 9. Accept if pattern has mixed case (camelCase or PascalCase) - but check after prefix rejection
        if pattern != pattern.lower() and pattern != pattern.upper():
            return True
        
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
            # Accept if it has special characters
            if any(c in pattern for c in ['_', '-', '.', '/']):
                return True
        
        # 13. For short patterns (4-7 chars), be more strict
        if 4 <= len(pattern) < 8:
            # Must have special characters, mixed case, or numbers to be valid
            has_special = any(c in pattern for c in ['_', '-', '.', '/', ':'])
            has_mixed_case = pattern != pattern.lower() and pattern != pattern.upper()
            has_numbers = any(c.isdigit() for c in pattern)
            
            if has_special or has_mixed_case or has_numbers:
                return True
            else:
                return False
        
        # Default: reject
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