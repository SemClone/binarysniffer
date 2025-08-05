"""
Binary file feature extractor
"""

import re
import logging
from pathlib import Path
from typing import List, Set

from .base import BaseExtractor, ExtractedFeatures


logger = logging.getLogger(__name__)


class BinaryExtractor(BaseExtractor):
    """Extract features from binary files"""
    
    # Binary file extensions
    BINARY_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib', '.o', '.obj',
        '.a', '.lib', '.ko', '.elf', '.bin', '.dat'
    }
    
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
            # Extract printable strings
            strings = self._extract_strings(file_path)
            features.strings = self._filter_strings(strings)
            
            # Extract function-like symbols
            features.functions = self._extract_functions(features.strings)
            
            # Extract constant-like symbols
            features.constants = self._extract_constants(features.strings)
            
            # Extract import-like strings
            features.imports = self._extract_imports(features.strings)
            
            # Set metadata
            features.metadata = {
                'size': file_path.stat().st_size,
                'total_strings': len(strings),
                'filtered_strings': len(features.strings)
            }
            
        except Exception as e:
            logger.error(f"Error extracting from {file_path}: {e}")
        
        return features
    
    def _extract_strings(self, file_path: Path) -> List[str]:
        """Extract printable ASCII strings from binary"""
        strings = []
        
        # Pattern for printable ASCII strings
        pattern = rb'[\x20-\x7e]{5,}'
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                chunk_size = 1024 * 1024  # 1MB chunks
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Find strings in chunk
                    for match in re.finditer(pattern, chunk):
                        try:
                            string = match.group().decode('ascii', errors='ignore')
                            if string:
                                strings.append(string)
                        except Exception:
                            continue
                    
                    # Limit total strings
                    if len(strings) > self.max_strings * 2:
                        break
        
        except Exception as e:
            logger.error(f"Error reading binary file {file_path}: {e}")
        
        return strings
    
    def _extract_functions(self, strings: List[str]) -> List[str]:
        """Extract function-like symbols"""
        functions = []
        
        # Patterns for function names
        patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # C-style identifiers
            r'^[a-zA-Z_][a-zA-Z0-9_]*::[a-zA-Z_][a-zA-Z0-9_]*$',  # C++ methods
            r'^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$',  # Object methods
        ]
        
        for string in strings:
            # Skip if too short or too long
            if len(string) < 3 or len(string) > 100:
                continue
            
            # Check patterns
            for pattern in patterns:
                if re.match(pattern, string):
                    functions.append(string)
                    break
        
        return functions[:1000]  # Limit functions
    
    def _extract_constants(self, strings: List[str]) -> List[str]:
        """Extract constant-like symbols"""
        constants = []
        
        for string in strings:
            # Constants are often uppercase with underscores
            if re.match(r'^[A-Z][A-Z0-9_]+$', string) and len(string) >= 5:
                constants.append(string)
        
        return constants[:500]  # Limit constants
    
    def _extract_imports(self, strings: List[str]) -> List[str]:
        """Extract import/library references"""
        imports = []
        
        # Common library patterns
        lib_patterns = [
            r'\.dll$', r'\.so(\.\d+)?$', r'\.dylib$',  # Libraries
            r'^lib[a-z0-9_-]+', r'[a-z0-9_-]+\.h$',  # Headers
        ]
        
        for string in strings:
            for pattern in lib_patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    imports.append(string)
                    break
        
        return imports[:200]  # Limit imports