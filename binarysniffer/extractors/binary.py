"""
Binary file feature extractor
"""

import logging
from pathlib import Path

from ..utils.binary_strings import BinaryStringExtractor
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
            # Initialize string extractor with default settings
            string_extractor = BinaryStringExtractor(min_length=5, max_strings=self.max_strings * 2)

            # Extract printable strings
            raw_strings = string_extractor.extract_strings(file_path)
            features.strings = self._filter_strings(list(raw_strings))

            # Extract categorized strings using the shared utility
            features.functions = string_extractor.extract_functions(raw_strings)
            features.constants = string_extractor.extract_constants(raw_strings)
            features.imports = string_extractor.extract_imports(raw_strings)

            # Set metadata
            features.metadata = {
                'size': file_path.stat().st_size,
                'total_strings': len(raw_strings),
                'filtered_strings': len(features.strings)
            }

        except Exception as e:
            logger.error(f"Error extracting from {file_path}: {e}")

        return features

