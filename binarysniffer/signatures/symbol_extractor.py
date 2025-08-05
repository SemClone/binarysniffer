"""
Symbol extraction from binaries for signature generation
"""

import re
import subprocess
import logging
from pathlib import Path
from typing import Set, List, Dict, Optional, Tuple
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)


class SymbolExtractor:
    """Extract symbols from binaries for signature generation"""
    
    # Generic symbols to exclude (common in many binaries)
    GENERIC_SYMBOLS = {
        # C runtime
        'main', 'init', 'fini', 'exit', 'abort', 'atexit',
        'malloc', 'free', 'calloc', 'realloc', 'memcpy', 'memset', 'memmove',
        'strlen', 'strcpy', 'strncpy', 'strcmp', 'strncmp', 'strcat', 'strchr',
        'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
        'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell',
        'open', 'close', 'read', 'write', 'lseek',
        # C++ runtime
        'new', 'delete', 'throw', 'catch',
        # POSIX
        'pthread_create', 'pthread_join', 'pthread_mutex_lock', 'pthread_mutex_unlock',
        'signal', 'sigaction', 'kill', 'raise',
        # Math
        'sin', 'cos', 'tan', 'sqrt', 'pow', 'exp', 'log',
        # Common prefixes that are too generic
        '_Z', '__', '_GLOBAL_', '.L', '.LC', '.LFB', '.LFE'
    }
    
    # Common library prefixes that indicate specific components
    LIBRARY_PREFIXES = {
        'av_': 'ffmpeg',
        'avcodec_': 'ffmpeg',
        'avformat_': 'ffmpeg',
        'avutil_': 'ffmpeg',
        'x264_': 'x264',
        'x265_': 'x265',
        'vpx_': 'libvpx',
        'opus_': 'opus',
        'vorbis_': 'vorbis',
        'png_': 'libpng',
        'jpeg_': 'libjpeg',
        'z_': 'zlib',
        'BZ2_': 'bzip2',
        'lzma_': 'lzma',
        'SSL_': 'openssl',
        'EVP_': 'openssl',
        'CRYPTO_': 'openssl',
        'curl_': 'curl',
        'sqlite3_': 'sqlite',
        'xml_': 'libxml2',
        'json_': 'json-c',
        'pcre_': 'pcre',
        'boost_': 'boost',
        'Qt': 'qt',
        'gtk_': 'gtk',
        'glib_': 'glib',
        'SDL_': 'sdl',
    }
    
    @classmethod
    def extract_symbols_from_binary(cls, binary_path: Path) -> Dict[str, Set[str]]:
        """
        Extract symbols from a binary file using various tools
        
        Returns dict with keys: 'functions', 'objects', 'all'
        """
        symbols = {
            'functions': set(),
            'objects': set(),
            'all': set()
        }
        
        # Try readelf first (most detailed for ELF files)
        if cls._is_elf(binary_path):
            readelf_symbols = cls._extract_with_readelf(binary_path)
            symbols['functions'].update(readelf_symbols.get('functions', set()))
            symbols['objects'].update(readelf_symbols.get('objects', set()))
            symbols['all'].update(readelf_symbols.get('all', set()))
        
        # Try nm as fallback or for additional symbols
        nm_symbols = cls._extract_with_nm(binary_path)
        symbols['functions'].update(nm_symbols.get('functions', set()))
        symbols['objects'].update(nm_symbols.get('objects', set()))
        symbols['all'].update(nm_symbols.get('all', set()))
        
        # Extract strings as well
        string_symbols = cls._extract_strings(binary_path)
        symbols['all'].update(string_symbols)
        
        # Filter out generic symbols
        for key in symbols:
            symbols[key] = cls._filter_generic_symbols(symbols[key])
        
        return symbols
    
    @classmethod
    def _is_elf(cls, file_path: Path) -> bool:
        """Check if file is an ELF binary"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except:
            return False
    
    @classmethod
    def _extract_with_readelf(cls, binary_path: Path) -> Dict[str, Set[str]]:
        """Extract symbols using readelf"""
        symbols = {
            'functions': set(),
            'objects': set(),
            'all': set()
        }
        
        try:
            # readelf -sW shows all symbols with wide format
            result = subprocess.run(
                ['readelf', '-sW', str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse readelf output
                # Format: Num: Value Size Type Bind Vis Ndx Name
                for line in result.stdout.split('\n'):
                    if 'FUNC' in line or 'OBJECT' in line:
                        parts = line.split()
                        if len(parts) >= 8:
                            symbol_name = parts[-1]
                            symbol_type = parts[3]
                            
                            # Skip versioned symbols like symbol@@GLIBC_2.2.5
                            if '@@' in symbol_name:
                                symbol_name = symbol_name.split('@@')[0]
                            
                            symbols['all'].add(symbol_name)
                            
                            if 'FUNC' in symbol_type:
                                symbols['functions'].add(symbol_name)
                            elif 'OBJECT' in symbol_type:
                                symbols['objects'].add(symbol_name)
        
        except Exception as e:
            logger.debug(f"readelf failed: {e}")
        
        return symbols
    
    @classmethod
    def _extract_with_nm(cls, binary_path: Path) -> Dict[str, Set[str]]:
        """Extract symbols using nm"""
        symbols = {
            'functions': set(),
            'objects': set(),
            'all': set()
        }
        
        try:
            # nm -D shows dynamic symbols, -U excludes undefined symbols
            result = subprocess.run(
                ['nm', '-D', str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        symbol_type = parts[1]
                        symbol_name = parts[2]
                        
                        symbols['all'].add(symbol_name)
                        
                        # T/t = text (code) section
                        if symbol_type in ['T', 't']:
                            symbols['functions'].add(symbol_name)
                        # D/d = initialized data, B/b = uninitialized data
                        elif symbol_type in ['D', 'd', 'B', 'b']:
                            symbols['objects'].add(symbol_name)
        
        except Exception as e:
            logger.debug(f"nm failed: {e}")
        
        return symbols
    
    @classmethod
    def _extract_strings(cls, binary_path: Path, min_length: int = 6) -> Set[str]:
        """Extract printable strings that look like symbols"""
        strings = set()
        
        try:
            # Use strings command
            result = subprocess.run(
                ['strings', '-n', str(min_length), str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    # Look for strings that resemble function/symbol names
                    if cls._looks_like_symbol(line):
                        strings.add(line)
        
        except Exception as e:
            logger.debug(f"strings extraction failed: {e}")
        
        return strings
    
    @classmethod
    def _looks_like_symbol(cls, s: str) -> bool:
        """Check if a string looks like a symbol name"""
        if not s or len(s) < 4 or len(s) > 100:
            return False
        
        # Common patterns for symbols
        patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # C identifier
            r'^[a-zA-Z_][a-zA-Z0-9_]*::[a-zA-Z_][a-zA-Z0-9_]*$',  # C++ method
            r'^[A-Z][a-zA-Z0-9_]*_[a-z][a-zA-Z0-9_]*$',  # Mixed case with underscore
        ]
        
        for pattern in patterns:
            if re.match(pattern, s):
                return True
        
        # Check for known library prefixes
        for prefix in cls.LIBRARY_PREFIXES:
            if s.startswith(prefix):
                return True
        
        return False
    
    @classmethod
    def _filter_generic_symbols(cls, symbols: Set[str]) -> Set[str]:
        """Filter out generic symbols"""
        filtered = set()
        
        for symbol in symbols:
            # Skip empty or very short
            if not symbol or len(symbol) < 3:
                continue
            
            # Skip generic symbols
            if symbol in cls.GENERIC_SYMBOLS:
                continue
            
            # Skip symbols starting with generic prefixes
            skip = False
            for prefix in ['_Z', '__', '_GLOBAL_', '.L', '.LC', '.LFB', '.LFE']:
                if symbol.startswith(prefix):
                    skip = True
                    break
            
            if not skip:
                filtered.add(symbol)
        
        return filtered
    
    @classmethod
    def identify_component_symbols(cls, symbols: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
        """
        Group symbols by likely component based on prefixes
        
        Returns dict mapping component name to set of symbols
        """
        components = defaultdict(set)
        all_symbols = symbols.get('all', set())
        
        for symbol in all_symbols:
            # Check known prefixes
            component_found = False
            for prefix, component in cls.LIBRARY_PREFIXES.items():
                if symbol.startswith(prefix):
                    components[component].add(symbol)
                    component_found = True
                    break
            
            # If no known prefix, try to identify by pattern
            if not component_found:
                # Look for namespace patterns like "namespace::function"
                if '::' in symbol:
                    namespace = symbol.split('::')[0]
                    if namespace and len(namespace) > 2:
                        components[namespace.lower()].add(symbol)
                # Look for consistent prefixes (e.g., "mylib_function")
                elif '_' in symbol:
                    parts = symbol.split('_')
                    if len(parts) >= 2 and len(parts[0]) > 2:
                        potential_prefix = parts[0]
                        # Check if this prefix appears multiple times
                        prefix_count = sum(1 for s in all_symbols if s.startswith(potential_prefix + '_'))
                        if prefix_count >= 3:  # At least 3 symbols with same prefix
                            components[potential_prefix.lower()].add(symbol)
        
        return dict(components)
    
    @classmethod
    def find_common_patterns(cls, symbols: List[str], min_length: int = 5) -> List[Tuple[str, int]]:
        """
        Find common substrings in symbols using LCS approach
        
        Returns list of (pattern, count) tuples sorted by frequency
        """
        if len(symbols) < 2:
            return []
        
        # Find all substrings of reasonable length
        substring_counts = Counter()
        
        for symbol in symbols:
            # Extract all substrings
            for i in range(len(symbol)):
                for j in range(i + min_length, min(i + 50, len(symbol)) + 1):
                    substring = symbol[i:j]
                    # Only consider meaningful substrings
                    if cls._is_meaningful_substring(substring):
                        substring_counts[substring] += 1
        
        # Filter patterns that appear in multiple symbols
        patterns = [(pattern, count) for pattern, count in substring_counts.items() 
                   if count >= 2]
        
        # Sort by count (descending) and length (descending)
        patterns.sort(key=lambda x: (x[1], len(x[0])), reverse=True)
        
        # Remove redundant patterns (substrings of other patterns with same count)
        filtered_patterns = []
        for pattern, count in patterns:
            is_redundant = False
            for other_pattern, other_count in filtered_patterns:
                if count == other_count and pattern in other_pattern:
                    is_redundant = True
                    break
            if not is_redundant:
                filtered_patterns.append((pattern, count))
        
        return filtered_patterns[:50]  # Return top 50 patterns
    
    @classmethod
    def _is_meaningful_substring(cls, s: str) -> bool:
        """Check if substring is meaningful for signature"""
        # Must contain at least one letter
        if not any(c.isalpha() for c in s):
            return False
        
        # Should not be all uppercase or all lowercase (unless short)
        if len(s) > 8 and (s.isupper() or s.islower()):
            return False
        
        # Should not be just numbers and underscores
        if s.replace('_', '').isdigit():
            return False
        
        return True
    
    @classmethod
    def generate_signatures_from_binary(cls, binary_path: Path, component_name: str = None) -> Dict[str, List[str]]:
        """
        Generate high-quality signatures from a binary
        
        Returns dict mapping component names to list of signature patterns
        """
        # Extract symbols
        symbols = cls.extract_symbols_from_binary(binary_path)
        
        # Group by component
        components = cls.identify_component_symbols(symbols)
        
        # If specific component requested, filter
        if component_name:
            if component_name in components:
                components = {component_name: components[component_name]}
            else:
                # Try to find all symbols that might belong to this component
                component_symbols = set()
                for symbol in symbols['all']:
                    if component_name.lower() in symbol.lower():
                        component_symbols.add(symbol)
                if component_symbols:
                    components = {component_name: component_symbols}
        
        # Generate signatures for each component
        signatures = {}
        
        for comp_name, comp_symbols in components.items():
            if len(comp_symbols) < 3:
                continue
            
            # Find common patterns
            symbol_list = sorted(list(comp_symbols))
            patterns = cls.find_common_patterns(symbol_list)
            
            # Select best patterns as signatures
            selected_patterns = []
            
            # 1. Include highly specific full symbol names
            for symbol in comp_symbols:
                if len(symbol) > 10 and symbol.count('_') >= 2:
                    selected_patterns.append(symbol)
                    if len(selected_patterns) >= 5:
                        break
            
            # 2. Include common patterns
            for pattern, count in patterns[:10]:
                if pattern not in selected_patterns:
                    selected_patterns.append(pattern)
            
            # 3. Include characteristic prefixes
            prefixes = Counter()
            for symbol in comp_symbols:
                if '_' in symbol:
                    prefix = symbol.split('_')[0] + '_'
                    if len(prefix) > 3:
                        prefixes[prefix] += 1
            
            for prefix, count in prefixes.most_common(5):
                if count >= 3 and prefix not in selected_patterns:
                    selected_patterns.append(prefix)
            
            signatures[comp_name] = selected_patterns[:20]  # Limit to 20 signatures
        
        return signatures