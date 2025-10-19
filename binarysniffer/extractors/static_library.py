"""
Static library (.a) archive extractor for analyzing individual object files.

This module handles AR archives (static libraries) which contain multiple
object files (.o). It extracts and analyzes each object file separately,
providing better attribution and component detection.
"""

import logging
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Tuple

from binarysniffer.extractors.base import BaseExtractor, ExtractedFeatures
from binarysniffer.extractors.binary import BinaryExtractor

logger = logging.getLogger(__name__)

# AR archive constants
AR_MAGIC = b'!<arch>\n'
AR_HEADER_SIZE = 60
AR_END_MARKER = b'`\n'


class ARMember:
    """Represents a single member (object file) in an AR archive"""

    def __init__(self, name: str, size: int, offset: int, data: bytes = None):
        self.name = name
        self.size = size
        self.offset = offset
        self.data = data

    def __repr__(self):
        return f"ARMember(name={self.name}, size={self.size}, offset={self.offset})"


class StaticLibraryExtractor(BaseExtractor):
    """
    Extractor for static library (.a) files.
    
    Static libraries are AR archives containing multiple object files.
    This extractor:
    1. Parses the AR archive structure
    2. Extracts each object file
    3. Analyzes each object separately using BinaryExtractor
    4. Aggregates results with source tracking
    """

    SUPPORTED_EXTENSIONS = {'.a', '.lib'}

    def __init__(self):
        super().__init__()
        self.binary_extractor = BinaryExtractor()

    def can_handle(self, file_path: Path) -> bool:
        """Check if this extractor can handle the file"""
        # Check extension
        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            return False

        # Verify AR magic
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
                return magic == AR_MAGIC
        except Exception:
            return False

    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from static library"""
        logger.info(f"Extracting features from static library: {file_path}")

        # Initialize features
        all_strings = []
        all_symbols = []
        all_functions = []
        all_constants = []
        all_imports = []
        metadata = {
            'file_type': 'static_library',
            'members': [],
            'total_objects': 0,
            'components_per_object': {}
        }

        try:
            # Parse AR archive
            members = self._parse_ar_archive(file_path)
            metadata['total_objects'] = len(members)

            logger.info(f"Found {len(members)} members in {file_path.name}")

            # Analyze each object file
            for member in members:
                # Skip non-object files and symbol tables
                if not self._is_object_file(member.name):
                    continue

                logger.debug(f"Analyzing member: {member.name}")

                # Extract features from object file
                member_features = self._analyze_object_file(member)

                if member_features:
                    # Track which object contains which features
                    metadata['members'].append({
                        'name': member.name,
                        'size': member.size,
                        'features_extracted': len(member_features.get('strings', [])) +
                                            len(member_features.get('symbols', [])),
                    })

                    # Aggregate features with source tracking
                    for string in member_features.get('strings', []):
                        # Add source context to important strings
                        if self._is_significant_string(string):
                            all_strings.append(f"{string}@{member.name}")
                        else:
                            all_strings.append(string)

                    all_symbols.extend(member_features.get('symbols', []))
                    all_functions.extend(member_features.get('functions', []))
                    all_constants.extend(member_features.get('constants', []))
                    all_imports.extend(member_features.get('imports', []))

        except Exception as e:
            logger.error(f"Error extracting from static library {file_path}: {e}")
            # Fall back to basic binary extraction
            return self.binary_extractor.extract(file_path)

        # Create ExtractedFeatures
        return ExtractedFeatures(
            file_path=str(file_path),
            file_type='static_library',
            strings=list(set(all_strings))[:10000],  # Limit total strings
            symbols=list(set(all_symbols))[:5000],
            functions=list(set(all_functions))[:2000],
            constants=list(set(all_constants))[:2000],
            imports=list(set(all_imports))[:1000],
            metadata=metadata
        )

    def _parse_ar_archive(self, file_path: Path) -> List[ARMember]:
        """Parse AR archive and return list of members"""
        members = []

        with open(file_path, 'rb') as f:
            # Check magic
            magic = f.read(8)
            if magic != AR_MAGIC:
                raise ValueError(f"Not a valid AR archive: {file_path}")

            # Read members
            while True:
                # Read header
                header_data = f.read(AR_HEADER_SIZE)
                if len(header_data) < AR_HEADER_SIZE:
                    break

                # Parse header
                name, size, name_len = self._parse_ar_header(header_data)

                # Handle BSD extended names
                if name is None and name_len > 0:
                    # Name is at beginning of data
                    name_bytes = f.read(name_len)
                    # Remove null terminators and decode
                    name = name_bytes.rstrip(b'\x00').decode('ascii', errors='ignore')
                    # Size is already adjusted by _parse_ar_header
                    actual_data_size = size
                elif name:
                    actual_data_size = size
                else:
                    # No name found, try to continue
                    if size > 0:
                        f.read(size)
                        if size % 2 != 0:
                            f.read(1)
                    continue

                # Read member data
                current_pos = f.tell()
                member_data = f.read(actual_data_size)

                # Create member only if we have a valid name
                if name:
                    member = ARMember(
                        name=name,
                        size=actual_data_size,
                        offset=current_pos,
                        data=member_data
                    )
                    members.append(member)

                # Align to 2-byte boundary (using original size, not actual_data_size)
                if (size & 1) == 1:
                    f.read(1)

        return members

    def _parse_ar_header(self, header: bytes) -> Tuple[str, int, int]:
        """Parse AR archive member header"""
        if len(header) != AR_HEADER_SIZE:
            return None, 0, 0

        # AR header format:
        # name(16), mtime(12), uid(6), gid(6), mode(8), size(10), end(2)
        try:
            name = header[0:16].rstrip()
            size_str = header[48:58].strip()
            end_marker = header[58:60]

            # Verify end marker
            if end_marker != AR_END_MARKER:
                return None, 0, 0

            # Parse size
            size = int(size_str)

            # Handle BSD-style extended names (#1/length)
            name_str = name.decode('ascii', errors='ignore').strip()
            if name_str.startswith('#1/'):
                # Extended name length follows #1/
                name_len = int(name_str[3:])
                # Name is stored at beginning of data
                return None, size - name_len, name_len

            # Handle GNU-style extended names (//)
            if name_str.startswith('//'):
                # This is the string table itself
                return '__string_table__', size, 0

            # Handle references to string table (/digit)
            if name_str.startswith('/') and name_str[1:].isdigit():
                # This references the string table
                # For now, use the reference as name
                return f'__ref_{name_str[1:]}__', size, 0

            # Regular name (may end with /)
            if name_str.endswith('/'):
                name_str = name_str[:-1]

            return name_str, size, 0

        except (ValueError, UnicodeDecodeError) as e:
            logger.debug(f"Error parsing AR header: {e}")
            return None, 0, 0

    def _is_object_file(self, name: str) -> bool:
        """Check if member is an object file"""
        # Skip special entries
        if name.startswith('__'):
            return False

        # Check for object file extensions
        return name.endswith('.o') or name.endswith('.obj')

    def _analyze_object_file(self, member: ARMember) -> Dict[str, List[str]]:
        """Analyze a single object file from the archive"""
        try:
            # Create a temporary file-like object
            temp_file = BytesIO(member.data)

            # Use BinaryExtractor to analyze the object file
            # We'll extract strings and symbols directly
            features = {
                'strings': [],
                'symbols': [],
                'functions': [],
                'constants': [],
                'imports': []
            }

            # Extract strings (simplified - just looking for ASCII strings)
            strings = self._extract_strings_from_bytes(member.data)
            features['strings'] = strings

            # Try to identify symbols (looking for common patterns)
            for s in strings:
                if self._looks_like_symbol(s):
                    features['symbols'].append(s)
                elif self._looks_like_function(s):
                    features['functions'].append(s)
                elif self._looks_like_constant(s):
                    features['constants'].append(s)

            return features

        except Exception as e:
            logger.debug(f"Error analyzing object file {member.name}: {e}")
            return {}

    def _extract_strings_from_bytes(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = bytearray()

        for byte in data:
            # Check if printable ASCII
            if 32 <= byte <= 126:
                current_string.append(byte)
            else:
                # End of string
                if len(current_string) >= min_length:
                    try:
                        s = current_string.decode('ascii', errors='ignore')
                        if s and not s.isspace():
                            strings.append(s)
                    except:
                        pass
                current_string = bytearray()

        # Don't forget the last string
        if len(current_string) >= min_length:
            try:
                s = current_string.decode('ascii', errors='ignore')
                if s and not s.isspace():
                    strings.append(s)
            except:
                pass

        return strings[:5000]  # Limit per object

    def _is_significant_string(self, s: str) -> bool:
        """Check if a string is significant enough to track its source"""
        # Track source for function names, version strings, etc.
        if len(s) < 8:
            return False

        indicators = ['version', 'copyright', 'license', '_init', '_fini',
                     'main', 'lib', 'ssl', 'crypto', 'compress']

        s_lower = s.lower()
        return any(ind in s_lower for ind in indicators)

    def _looks_like_symbol(self, s: str) -> bool:
        """Check if string looks like a symbol"""
        # Symbols often have underscores or colons
        return ('_' in s or '::' in s) and len(s) > 3

    def _looks_like_function(self, s: str) -> bool:
        """Check if string looks like a function name"""
        # Functions often end with common suffixes
        suffixes = ['_init', '_exit', '_open', '_close', '_read', '_write',
                   '_free', '_alloc', '_create', '_destroy', '_get', '_set']
        return any(s.endswith(suf) for suf in suffixes)

    def _looks_like_constant(self, s: str) -> bool:
        """Check if string looks like a constant"""
        # Constants are often all caps with underscores
        return s.isupper() and '_' in s and len(s) > 4

    def get_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Get metadata about the static library"""
        metadata = {
            'file_type': 'static_library',
            'file_path': str(file_path),
            'file_name': file_path.name
        }

        try:
            members = self._parse_ar_archive(file_path)
            object_files = [m for m in members if self._is_object_file(m.name)]

            metadata.update({
                'total_members': len(members),
                'object_files': len(object_files),
                'member_names': [m.name for m in object_files[:20]],  # First 20
                'total_size': sum(m.size for m in members)
            })
        except Exception as e:
            logger.debug(f"Error getting metadata for {file_path}: {e}")

        return metadata
