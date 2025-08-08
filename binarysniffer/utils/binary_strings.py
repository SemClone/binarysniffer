"""
Shared utilities for binary string extraction
"""

import re
import logging
from pathlib import Path
from typing import Set, List

logger = logging.getLogger(__name__)


class BinaryStringExtractor:
    """Shared utility for extracting strings from binary files"""
    
    def __init__(self, min_length: int = 4, max_strings: int = 10000):
        """Initialize extractor
        
        Args:
            min_length: Minimum string length to extract
            max_strings: Maximum number of strings to extract
        """
        self.min_length = min_length
        self.max_strings = max_strings
        # Pattern for extracting ASCII strings
        self.ascii_pattern = re.compile(
            rb'[\x20-\x7e]{' + str(min_length).encode() + b',}'
        )
        # Pattern for extracting UTF-16 strings (common in Windows binaries)
        self.utf16_pattern = re.compile(
            rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + b',}'
        )
    
    def extract_strings(self, file_path: Path, chunk_size: int = 1024 * 1024) -> Set[str]:
        """Extract strings from binary file
        
        Args:
            file_path: Path to binary file
            chunk_size: Size of chunks to read (default 1MB)
            
        Returns:
            Set of extracted strings
        """
        strings = set()
        
        try:
            with open(file_path, 'rb') as f:
                overlap = b''
                
                while len(strings) < self.max_strings:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Include overlap from previous chunk to catch strings at boundaries
                    data = overlap + chunk
                    
                    # Extract ASCII strings
                    for match in self.ascii_pattern.finditer(data):
                        if len(strings) >= self.max_strings:
                            break
                        try:
                            string = match.group().decode('ascii', errors='ignore').strip()
                            if self._is_valid_string(string):
                                strings.add(string)
                        except Exception:
                            continue
                    
                    # Extract UTF-16 strings (if we haven't hit the limit)
                    if len(strings) < self.max_strings:
                        for match in self.utf16_pattern.finditer(data):
                            if len(strings) >= self.max_strings:
                                break
                            try:
                                # Decode UTF-16 LE
                                string = match.group().decode('utf-16le', errors='ignore').strip()
                                if self._is_valid_string(string):
                                    strings.add(string)
                            except Exception:
                                continue
                    
                    # Keep last part of chunk as overlap for next iteration
                    overlap = chunk[-256:] if len(chunk) > 256 else chunk
        
        except Exception as e:
            logger.error(f"Error extracting strings from {file_path}: {e}")
        
        return strings
    
    def extract_functions(self, strings: Set[str]) -> List[str]:
        """Extract function-like strings
        
        Args:
            strings: Set of strings to filter
            
        Returns:
            List of function-like strings
        """
        function_patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # C-style identifiers
            r'^[A-Z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*$',  # CamelCase
            r'^[a-z]+_[a-z]+(?:_[a-z]+)*$',  # snake_case
            r'^[a-zA-Z0-9_]+::[a-zA-Z0-9_]+$',  # C++ namespaced
        ]
        
        functions = []
        for string in strings:
            if len(string) < 3 or len(string) > 100:
                continue
            
            for pattern in function_patterns:
                if re.match(pattern, string):
                    functions.append(string)
                    break
        
        return functions[:1000]  # Limit to 1000 functions
    
    def extract_constants(self, strings: Set[str]) -> List[str]:
        """Extract constant-like strings
        
        Args:
            strings: Set of strings to filter
            
        Returns:
            List of constant-like strings
        """
        constants = []
        
        for string in strings:
            # Look for all-caps constants
            if string.isupper() and '_' in string and len(string) > 3:
                constants.append(string)
            # Look for version-like strings
            elif re.match(r'^\d+\.\d+(?:\.\d+)?(?:-\w+)?$', string):
                constants.append(string)
            # Look for paths
            elif '/' in string or '\\' in string:
                if len(string) > 5 and len(string) < 200:
                    constants.append(string)
        
        return constants[:500]  # Limit to 500 constants
    
    def extract_imports(self, strings: Set[str]) -> List[str]:
        """Extract import/library references
        
        Args:
            strings: Set of strings to filter
            
        Returns:
            List of import-like strings
        """
        imports = []
        
        for string in strings:
            # Library names (*.dll, *.so, *.dylib)
            if re.match(r'^[\w\-\.]+\.(dll|so|dylib)(?:[\.\d]+)?$', string.lower()):
                imports.append(string)
            # Package imports (e.g., com.example.package)
            elif re.match(r'^[a-z]+(?:\.[a-z]+)+$', string):
                imports.append(string)
        
        return imports[:200]  # Limit to 200 imports
    
    def _is_valid_string(self, string: str) -> bool:
        """Check if a string is valid for extraction
        
        Args:
            string: String to validate
            
        Returns:
            True if string is valid
        """
        if len(string) < self.min_length:
            return False
        
        # Skip strings that are all whitespace
        if not string or string.isspace():
            return False
        
        # Always keep MIME types and codec-related strings
        if self._is_mime_or_codec_string(string):
            return True
        
        # Skip strings with too many special characters
        special_count = sum(1 for c in string if not c.isalnum() and c not in '._-/:@')
        if special_count > len(string) * 0.5:
            return False
        
        # Skip binary garbage that looks like strings
        if any(ord(c) < 32 or ord(c) > 126 for c in string):
            return False
        
        return True
    
    def _is_mime_or_codec_string(self, string: str) -> bool:
        """Check if string is a MIME type or codec-related string
        
        Args:
            string: String to check
            
        Returns:
            True if string is MIME type or codec-related
        """
        string_lower = string.lower()
        
        # MIME types (audio/*, video/*, application/*, etc.)
        if re.match(r'^(audio|video|application|text|image|font|model|message)/[\w\-\+\.]+$', string_lower):
            return True
        
        # Codec names and identifiers
        codec_patterns = [
            r'^(h264|h265|hevc|avc|av1|vp8|vp9|opus|vorbis|aac|mp3|ac3|eac3|dolby)',
            r'(codec|encoder|decoder|muxer|demuxer|parse|parser)$',
            r'^(mpeg|mp4|mkv|webm|ogg|flac|wav|m4a)',
            r'^lib(x264|x265|vpx|opus|vorbis|aac|mp3)',
            r'^(video|audio)/([\w\-]+)$',
            r'^MIME_',
            r'Profile[A-Z]',  # For Dolby Vision profiles
        ]
        
        for pattern in codec_patterns:
            if re.search(pattern, string_lower):
                return True
        
        # Also keep strings that look like codec configurations
        if 'codec' in string_lower or 'mime' in string_lower:
            return True
        
        return False