"""
Enhanced binary extractor using LIEF library for better component detection
"""

import logging
import re
from pathlib import Path
from typing import List, Set
import subprocess

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

from .base import BaseExtractor, ExtractedFeatures

logger = logging.getLogger(__name__)


class LiefBinaryExtractor(BaseExtractor):
    """Extract features from binary files using LIEF for enhanced analysis"""
    
    def __init__(self, min_string_length: int = 4, max_strings: int = 100000):
        """
        Initialize extractor with LIEF support.
        
        Args:
            min_string_length: Minimum length for extracted strings
            max_strings: Maximum number of strings to extract
        """
        super().__init__(min_string_length, max_strings)
        self.has_lief = HAS_LIEF
        
    def can_handle(self, file_path: Path) -> bool:
        """Check if file is a binary"""
        # Handle common binary extensions
        binary_extensions = {'.so', '.dll', '.exe', '.dylib', '.a', '.lib', '.o'}
        if file_path.suffix.lower() in binary_extensions:
            return True
            
        # Check magic bytes for ELF, PE, Mach-O
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                # ELF: 0x7f454c46
                if magic.startswith(b'\x7fELF'):
                    return True
                # PE: MZ header
                if magic.startswith(b'MZ'):
                    return True
                # Mach-O: Various magic numbers
                if magic in [b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', 
                           b'\xfe\xed\xfa\xcf', b'\xcf\xfa\xed\xfe']:
                    return True
        except Exception:
            pass
            
        return False
    
    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from binary file using LIEF when available"""
        logger.debug(f"Extracting features from binary: {file_path}")
        
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type="binary"
        )
        
        # First, extract strings using traditional method
        all_strings = self._extract_strings_traditional(file_path)
        
        # Then enhance with LIEF if available
        if self.has_lief:
            try:
                binary = lief.parse(str(file_path))
                if binary:
                    # Extract additional features based on binary type
                    if binary.format == lief.Binary.FORMATS.ELF:
                        self._extract_elf_features(binary, features, all_strings)
                    elif binary.format == lief.Binary.FORMATS.PE:
                        self._extract_pe_features(binary, features, all_strings)
                    elif binary.format == lief.Binary.FORMATS.MACHO:
                        self._extract_macho_features(binary, features, all_strings)
            except Exception as e:
                logger.debug(f"LIEF parsing failed for {file_path}: {e}")
        
        # Store all extracted strings
        features.strings = list(all_strings)[:self.max_strings]
        
        # Categorize strings
        features.functions = self._extract_functions(features.strings)
        features.constants = self._extract_constants(features.strings)
        features.imports = list(dict.fromkeys(features.imports))[:5000]  # Limit imports
        features.symbols = self._extract_symbols(features.strings)
        
        # Set metadata
        features.metadata = {
            'size': file_path.stat().st_size,
            'has_lief': self.has_lief,
            'total_strings': len(all_strings),
            'unique_strings': len(set(all_strings))
        }
        
        return features
    
    def _extract_strings_traditional(self, file_path: Path) -> Set[str]:
        """Extract strings using traditional method (fast and comprehensive)"""
        strings = set()
        
        try:
            # Use the strings command if available (fastest method)
            result = subprocess.run(
                ['strings', '-n', str(self.min_string_length), str(file_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line and len(line) >= self.min_string_length:
                        strings.add(line.strip())
                return strings
        except Exception:
            pass
        
        # Fallback to Python-based extraction
        pattern = rb'[\x20-\x7e]{' + str(self.min_string_length).encode() + rb',}'
        
        try:
            with open(file_path, 'rb') as f:
                # Read in chunks
                chunk_size = 1024 * 1024  # 1MB chunks
                while len(strings) < self.max_strings:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Find strings in chunk
                    for match in re.finditer(pattern, chunk):
                        try:
                            string = match.group().decode('ascii', errors='ignore')
                            if string and len(string) >= self.min_string_length:
                                strings.add(string)
                        except Exception:
                            continue
        except Exception as e:
            logger.error(f"Error extracting strings from {file_path}: {e}")
        
        return strings
    
    def _extract_elf_features(self, binary, features: ExtractedFeatures, existing_strings: Set[str]):
        """Extract ELF-specific features using LIEF"""
        try:
            # Extract imported functions
            for func in binary.imported_functions:
                features.imports.append(func.name)
                existing_strings.add(func.name)
            
            # Extract exported functions
            for func in binary.exported_functions:
                features.functions.append(func.name)
                existing_strings.add(func.name)
            
            # Extract dynamic symbols
            for symbol in binary.dynamic_symbols:
                if symbol.name and symbol.is_function:
                    features.symbols.append(symbol.name)
                    existing_strings.add(symbol.name)
            
            # Extract static symbols
            for symbol in binary.static_symbols:
                if symbol.name and symbol.is_function:
                    features.symbols.append(symbol.name)
                    existing_strings.add(symbol.name)
            
            # Extract section names (can reveal libraries)
            for section in binary.sections:
                if section.name:
                    existing_strings.add(section.name)
            
            # Extract library dependencies
            for lib in binary.libraries:
                features.imports.append(lib)
                existing_strings.add(lib)
                
        except Exception as e:
            logger.debug(f"Error extracting ELF features: {e}")
    
    def _extract_pe_features(self, binary, features: ExtractedFeatures, existing_strings: Set[str]):
        """Extract PE-specific features using LIEF"""
        try:
            # Extract imports
            for imported in binary.imports:
                features.imports.append(imported.name)
                for func in imported.functions:
                    features.imports.append(func.name)
                    existing_strings.add(func.name)
            
            # Extract exports
            if hasattr(binary, 'exported_functions'):
                for func in binary.exported_functions:
                    features.functions.append(func.name)
                    existing_strings.add(func.name)
                    
        except Exception as e:
            logger.debug(f"Error extracting PE features: {e}")
    
    def _extract_macho_features(self, binary, features: ExtractedFeatures, existing_strings: Set[str]):
        """Extract Mach-O specific features using LIEF"""
        try:
            # Extract imported functions
            for func in binary.imported_functions:
                features.imports.append(func.name)
                existing_strings.add(func.name)
            
            # Extract exported functions  
            for func in binary.exported_functions:
                features.functions.append(func.name)
                existing_strings.add(func.name)
                
            # Extract libraries
            for lib in binary.libraries:
                features.imports.append(lib.name)
                existing_strings.add(lib.name)
                
        except Exception as e:
            logger.debug(f"Error extracting Mach-O features: {e}")
    
    def _extract_symbols(self, strings: List[str]) -> List[str]:
        """Extract potential symbol names"""
        symbols = []
        
        # Common patterns for symbols
        symbol_patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*$',  # C-style identifiers
            r'^[A-Z][a-zA-Z0-9_]*_[a-z]+$',  # Constant-like patterns
            r'^lib[a-zA-Z0-9_]+$',  # Library names
        ]
        
        for string in strings:
            if len(string) < 50:  # Skip very long strings
                for pattern in symbol_patterns:
                    if re.match(pattern, string):
                        symbols.append(string)
                        break
        
        return symbols[:10000]  # Limit symbols
    
    def _extract_functions(self, strings: List[str]) -> List[str]:
        """Extract function-like strings"""
        functions = []
        
        # Patterns that indicate functions
        func_patterns = [
            r'^[a-zA-Z_][a-zA-Z0-9_]*_(?:init|create|destroy|open|close|read|write|get|set)$',
            r'^[a-zA-Z_][a-zA-Z0-9_]*(?:Init|Create|Destroy|Open|Close|Read|Write|Get|Set)$',
            r'^(?:png|jpeg|jpg|gif|webp|tiff|bmp)_[a-zA-Z0-9_]+$',  # Image library functions
            r'^(?:ssl|tls|crypto|aes|rsa|sha|md5)_[a-zA-Z0-9_]+$',  # Crypto functions
            r'^(?:xml|json|yaml|toml)_[a-zA-Z0-9_]+$',  # Parser functions
        ]
        
        for string in strings:
            if 3 < len(string) < 100:
                for pattern in func_patterns:
                    if re.match(pattern, string, re.IGNORECASE):
                        functions.append(string)
                        break
        
        return functions[:10000]  # Limit functions
    
    def _extract_constants(self, strings: List[str]) -> List[str]:
        """Extract constant-like strings"""
        constants = []
        
        # Patterns for constants
        const_patterns = [
            r'^[A-Z][A-Z0-9_]*$',  # ALL_CAPS
            r'^k[A-Z][a-zA-Z0-9]*$',  # kConstantName
            r'^[A-Z]+_[A-Z]+(?:_[A-Z0-9]+)*$',  # MULTI_WORD_CONSTANT
        ]
        
        for string in strings:
            if 2 < len(string) < 50:
                for pattern in const_patterns:
                    if re.match(pattern, string):
                        constants.append(string)
                        break
        
        return constants[:5000]  # Limit constants