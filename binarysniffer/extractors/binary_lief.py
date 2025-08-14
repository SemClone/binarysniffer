"""
Enhanced binary extractor using LIEF library for better component detection
"""

import logging
import re
from pathlib import Path
from typing import List, Set

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

from ..utils.binary_strings import BinaryStringExtractor
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

        # Initialize string extractor
        string_extractor = BinaryStringExtractor(min_length=self.min_string_length, max_strings=self.max_strings)

        # First, extract strings using the shared utility
        all_strings = string_extractor.extract_strings(file_path)

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

        # Categorize strings using shared utility
        features.functions = string_extractor.extract_functions(all_strings)
        features.constants = string_extractor.extract_constants(all_strings)
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

