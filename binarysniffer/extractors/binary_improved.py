"""
Improved binary file feature extractor that preserves all potential signatures
"""

import logging
import re
from pathlib import Path
from typing import List

from ..utils.binary_strings import BinaryStringExtractor
from .base import BaseExtractor, ExtractedFeatures

logger = logging.getLogger(__name__)


class ImprovedBinaryExtractor(BaseExtractor):
    """Extract features from binary files without aggressive filtering"""

    # Binary file extensions
    BINARY_EXTENSIONS = {
        '.exe', '.dll', '.so', '.dylib', '.o', '.obj',
        '.a', '.lib', '.ko', '.elf', '.bin', '.dat'
    }

    def __init__(self, min_string_length: int = 4, max_strings: int = 100000):
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

        # Explicitly reject known text/metadata files
        rejected_extensions = {
            '.txt', '.md', '.rst', '.json', '.xml', '.yml', '.yaml',
            '.plist', '.xcprivacy', '.xcconfig',  # Apple metadata
            '.html', '.htm', '.css', '.scss', '.less',
            '.ini', '.cfg', '.conf', '.config',
            '.log', '.gitignore', '.gitattributes',
            '.properties', '.toml', '.svg', '.strings',
            '.js', '.ts', '.jsx', '.tsx',  # JavaScript/TypeScript
            '.py', '.rb', '.go', '.rs',  # Other source code
            '.java', '.kt', '.swift', '.m', '.mm', '.h', '.hpp', '.cpp', '.c',
        }
        if file_path.suffix.lower() in rejected_extensions:
            return False

        # Check if file is binary by reading first bytes
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)

                # Reject if it starts with XML declaration
                if chunk.startswith(b'<?xml') or chunk.startswith(b'<!DOCTYPE'):
                    return False

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
            # Initialize string extractor with improved settings
            string_extractor = BinaryStringExtractor(min_length=self.min_string_length, max_strings=self.max_strings)

            # Extract printable strings with minimal filtering
            raw_strings = string_extractor.extract_strings(file_path)

            # Keep ALL strings for matching (important!)
            features.strings = list(raw_strings)

            # Also categorize strings using shared utility
            features.functions = string_extractor.extract_functions(raw_strings)
            features.constants = string_extractor.extract_constants(raw_strings)
            features.imports = string_extractor.extract_imports(raw_strings)

            # Extract additional symbols that might be signatures
            features.symbols = self._extract_symbols(features.strings)

            # Set metadata
            features.metadata = {
                'size': file_path.stat().st_size,
                'total_strings': len(raw_strings),
                'unique_strings': len(set(raw_strings))
            }

        except Exception as e:
            logger.error(f"Error extracting from {file_path}: {e}")

        return features


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
            # Codec-related prefixes
            r'^(h264|h265|hevc|avc|av1|vp8|vp9)',
            r'^(aac|mp3|opus|vorbis|ac3|eac3)',
            r'^(audio|video|codec|encoder|decoder)',
            r'^(gst_|GST_)',  # GStreamer
            r'^(av_|ff_|avcodec_|avformat_)',  # FFmpeg
            # Common suffixes
            r'_(init|create|destroy|free|alloc|open|close|read|write)$',
            r'_(encode|decode|parse|mux|demux)$',
            # Version strings
            r'(version|Version|VERSION)',
            # Library identifiers
            r'(copyright|Copyright|LICENSE|library|Library)',
            # MIME types
            r'^(audio|video|application|text)/',
            # Dolby patterns
            r'Dolby|DOLBY|dolby',
            r'Profile[A-Z]'
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

