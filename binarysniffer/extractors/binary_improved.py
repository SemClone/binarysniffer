"""
Improved binary file feature extractor that preserves all potential signatures
"""

import re
import logging
from pathlib import Path
from typing import List, Set

from .base import BaseExtractor, ExtractedFeatures


logger = logging.getLogger(__name__)


class ImprovedBinaryExtractor(BaseExtractor):
    """Extract features from binary files without aggressive filtering"""
    
    # Binary file extensions
    BINARY_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib', '.o', '.obj',
        '.a', '.lib', '.ko', '.elf', '.bin', '.dat'
    }
    
    def __init__(self, min_string_length: int = 4, max_strings: int = 50000):
        """
        Initialize extractor with more permissive defaults.
        
        Args:
            min_string_length: Minimum length for extracted strings (lowered to 4)
            max_strings: Maximum number of strings to extract (increased to 50000)
        """
        super().__init__(min_string_length, max_strings)
    
    def can_handle(self, file_path: Path) -> bool:
        """Check if file is a binary"""
        # Check extension
        if file_path.suffix.lower() in self.BINARY_EXTENSIONS:
            return True
        
        # Check if file is binary by reading first bytes
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                # Check for null bytes (common in binaries)
                if b'\x00' in chunk:
                    return True
                # Check for common binary signatures
                if chunk.startswith((b'MZ', b'\x7fELF', b'\xfe\xed\xfa', b'\xce\xfa\xed\xfe')):
                    return True
        except Exception:
            pass
        
        return False
    
    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract strings and symbols from binary"""
        logger.debug(f"Extracting features from binary: {file_path}")
        
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type="binary"
        )
        
        try:
            # Extract printable strings with minimal filtering
            all_strings = self._extract_strings(file_path)
            
            # Keep ALL strings for matching (important!)
            features.strings = all_strings
            
            # Also categorize strings for backward compatibility
            features.functions = self._extract_functions(all_strings)
            features.constants = self._extract_constants(all_strings)
            features.imports = self._extract_imports(all_strings)
            
            # Extract additional symbols that might be signatures
            features.symbols = self._extract_symbols(all_strings)
            
            # Set metadata
            features.metadata = {
                'size': file_path.stat().st_size,
                'total_strings': len(all_strings),
                'unique_strings': len(set(all_strings))
            }
            
        except Exception as e:
            logger.error(f"Error extracting from {file_path}: {e}")
        
        return features
    
    def _extract_strings(self, file_path: Path) -> List[str]:
        """Extract printable ASCII strings from binary"""
        strings = []
        
        # Pattern for printable ASCII strings (lowered minimum to 4)
        pattern = rb'[\x20-\x7e]{4,}'
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB chunks
                overlap = 100  # Overlap to catch strings split across chunks
                
                previous_tail = b''
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Combine with tail of previous chunk
                    search_data = previous_tail + chunk
                    
                    # Find strings in chunk
                    for match in re.finditer(pattern, search_data):
                        try:
                            string = match.group().decode('ascii', errors='ignore')
                            if string and len(string) >= self.min_string_length:
                                strings.append(string)
                        except Exception:
                            continue
                    
                    # Keep tail for next iteration
                    previous_tail = chunk[-overlap:] if len(chunk) > overlap else chunk
                    
                    # Limit total strings
                    if len(strings) > self.max_strings:
                        break
        
        except Exception as e:
            logger.error(f"Error reading binary file {file_path}: {e}")
        
        return strings
    
    def _extract_symbols(self, strings: List[str]) -> List[str]:
        """Extract potential symbol names including library functions"""
        symbols = []
        
        # Patterns that indicate symbols/functions
        symbol_patterns = [
            # Standard library functions
            r'^(str|mem|std|lib|pthread|malloc|free|open|close|read|write)',
            # Common prefixes
            r'^(SSL_|EVP_|RSA_|SHA|MD5_|AES_)',
            r'^(png_|jpeg_|jpg_|gif_|bmp_)',
            r'^(xml|XML|json|JSON)',
            r'^(sqlite3_|mysql_|pg_)',
            r'^(curl_|http_|https_)',
            r'^(z_|gz_|zip_|compress|deflate|inflate)',
            # Common suffixes
            r'_(init|create|destroy|free|alloc|open|close|read|write)$',
            # Version strings
            r'(version|Version|VERSION)',
            # Library identifiers
            r'(copyright|Copyright|LICENSE|library|Library)'
        ]
        
        for string in strings:
            # Check if string matches any symbol pattern
            for pattern in symbol_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    symbols.append(string)
                    break
            
            # Also include strings that look like function names
            if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', string) and 3 <= len(string) <= 100:
                if string not in symbols:  # Avoid duplicates
                    symbols.append(string)
        
        return symbols[:5000]  # More generous limit
    
    def _extract_functions(self, strings: List[str]) -> List[str]:
        """Extract function-like symbols"""
        functions = []
        
        # More inclusive patterns for function names
        patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # C-style identifiers
            r'^[a-zA-Z_][a-zA-Z0-9_]*::[a-zA-Z_][a-zA-Z0-9_]*$',  # C++ methods
            r'^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$',  # Object methods
            r'^[a-zA-Z_][a-zA-Z0-9_]*\$[a-zA-Z0-9_]*$',  # Mangled names
        ]
        
        for string in strings:
            # More permissive length check
            if len(string) < 2 or len(string) > 200:
                continue
            
            # Check patterns
            for pattern in patterns:
                if re.match(pattern, string):
                    functions.append(string)
                    break
        
        return functions[:5000]  # Increased limit
    
    def _extract_constants(self, strings: List[str]) -> List[str]:
        """Extract constant-like symbols"""
        constants = []
        
        for string in strings:
            # Constants are often uppercase with underscores
            if re.match(r'^[A-Z][A-Z0-9_]+$', string) and len(string) >= 3:
                constants.append(string)
            # Also version-like strings
            elif re.match(r'^\d+\.\d+(\.\d+)?', string):
                constants.append(string)
        
        return constants[:2000]  # Increased limit
    
    def _extract_imports(self, strings: List[str]) -> List[str]:
        """Extract import/library references"""
        imports = []
        
        # Common library patterns
        lib_patterns = [
            r'\.dll$', r'\.so(\.\d+)?$', r'\.dylib$',  # Libraries
            r'^lib[a-z0-9_-]+', r'[a-z0-9_-]+\.h$',  # Headers
            r'\.jar$', r'\.class$',  # Java
            r'\.framework',  # macOS/iOS
        ]
        
        for string in strings:
            for pattern in lib_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    imports.append(string)
                    break
        
        return imports[:1000]  # Increased limit