"""
Hermes bytecode extractor for React Native bundles

This module provides native Python extraction of features from Hermes bytecode files.
Based on the Hermes bytecode format specification.
"""

import logging
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from binarysniffer.extractors.base import BaseExtractor

logger = logging.getLogger(__name__)

# Hermes bytecode magic number: 0xC61FBC03 (little-endian)
HERMES_MAGIC = b'\xc6\x1f\xbc\x03'
HERMES_MAGIC_INT = 0x03BC1FC6

@dataclass
class HermesHeader:
    """Hermes bytecode file header structure"""
    magic: int
    version: int
    sha1: bytes
    file_length: int
    global_code_index: int
    function_count: int
    string_kind: int
    identifier_count: int
    string_count: int
    overflow_string_count: int
    string_storage_size: int
    regexp_table_offset: int
    regexp_count: int
    array_buffer_size: int
    obj_key_buffer_size: int
    obj_value_buffer_size: int
    segment_id: int
    cjs_module_count: int
    cjs_module_offset: int
    function_source_count: int
    debug_info_offset: int

    @property
    def is_valid(self) -> bool:
        """Check if this is a valid Hermes header"""
        return self.magic == HERMES_MAGIC_INT


class HermesExtractor(BaseExtractor):
    """
    Extractor for Hermes bytecode files used in React Native applications.
    
    Hermes is a JavaScript engine optimized for React Native that compiles
    JavaScript to bytecode for faster startup and lower memory usage.
    """

    SUPPORTED_EXTENSIONS = {'.hbc', '.bundle'}

    def __init__(self):
        super().__init__()
        self.min_string_length = 4
        self.max_strings = 10000

    def can_handle(self, file_path: Path) -> bool:
        """Check if this extractor can handle the file"""
        return self.can_extract(file_path)

    def extract(self, file_path: Path):
        """Extract features from file"""
        from binarysniffer.extractors.base import ExtractedFeatures
        features = self.extract_features(file_path)
        metadata = self.get_metadata(file_path)

        # Split features into appropriate categories
        strings = []
        symbols = []
        functions = []
        constants = []

        for feature in features:
            if 'hermes::' in feature or 'Hermes' in feature:
                symbols.append(feature)
            elif 'function' in feature.lower() or '_functions_' in feature:
                functions.append(feature)
            elif feature.upper() == feature and '_' in feature:  # Likely constants
                constants.append(feature)
            else:
                strings.append(feature)

        return ExtractedFeatures(
            file_path=str(file_path),
            file_type='hermes_bytecode',
            strings=strings,
            symbols=symbols,
            functions=functions,
            constants=constants,
            imports=[],
            metadata=metadata
        )

    def can_extract(self, file_path: Path) -> bool:
        """Check if file is a Hermes bytecode file"""
        if not file_path.is_file():
            return False

        # Check extension
        if file_path.suffix.lower() not in self.SUPPORTED_EXTENSIONS:
            # Also check magic bytes for files without standard extension
            try:
                with open(file_path, 'rb') as f:
                    magic = f.read(4)
                    return magic == HERMES_MAGIC
            except Exception:
                return False

        # Check magic bytes
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == HERMES_MAGIC
        except Exception:
            return False

    def extract_features(self, file_path: Path) -> List[str]:
        """Extract features from Hermes bytecode file"""
        features = set()

        try:
            with open(file_path, 'rb') as f:
                # Read and parse header
                header = self._parse_header(f)
                if not header or not header.is_valid:
                    logger.warning(f"Invalid Hermes header in {file_path}")
                    return []

                # Add header-based features
                features.add("HermesInternal")
                features.add(f"Hermes_v{header.version}")
                features.add("hermes::vm")
                features.add("HermesRuntime")
                features.add("HBC_VERSION")

                # Extract metadata features
                if header.function_count > 0:
                    features.add(f"hermes_functions_{header.function_count}")
                    features.add("hermes::Function")

                if header.string_count > 0:
                    features.add("hermes::StringTable")
                    # Extract ALL strings for better library detection
                    strings = self._extract_all_strings(f, header)
                    features.update(strings)  # Add all extracted strings

                if header.regexp_count > 0:
                    features.add("hermes::RegExp")
                    features.add("HermesRegExp")

                if header.cjs_module_count > 0:
                    features.add("hermes::CJSModule")
                    features.add("CommonJS")

                if header.debug_info_offset > 0:
                    features.add("hermes::DebugInfo")
                    features.add("HermesDebugger")

                # Add common Hermes runtime features
                features.update([
                    "hermes_create_runtime",
                    "hermes_execute_bytecode",
                    "facebook::hermes",
                    "ReactNativeHermes",
                    "JSI/Hermes",
                    "Hermes-GC",
                    "HermesValue",
                    "hermesLog"
                ])

                # Try to identify React Native specific patterns
                if self._has_react_native_patterns(f, header):
                    features.update([
                        "React.createElement",
                        "ReactNative",
                        "Metro",
                        "__fbBatchedBridge",
                        "NativeModules"
                    ])

        except Exception as e:
            logger.error(f"Error extracting Hermes features from {file_path}: {e}")
            # Still return the magic signature as a feature
            features.add("Hermes_bytecode")

        return list(features)

    def _parse_header(self, f) -> Optional[HermesHeader]:
        """Parse Hermes bytecode header"""
        try:
            # Read the fixed-size header (version 89-96 format)
            # This is a simplified version - actual format varies by version
            f.seek(0)

            # Basic header structure (first 88 bytes typically)
            data = f.read(88)
            if len(data) < 88:
                return None

            # Parse using little-endian format
            # Note: This is simplified - actual format depends on version
            magic = struct.unpack('<I', data[0:4])[0]
            version = struct.unpack('<I', data[4:8])[0]
            sha1 = data[8:28]  # 20 bytes SHA1
            file_length = struct.unpack('<I', data[28:32])[0]
            global_code_index = struct.unpack('<I', data[32:36])[0]
            function_count = struct.unpack('<I', data[36:40])[0]
            string_kind = struct.unpack('<I', data[40:44])[0]
            identifier_count = struct.unpack('<I', data[44:48])[0]
            string_count = struct.unpack('<I', data[48:52])[0]
            overflow_string_count = struct.unpack('<I', data[52:56])[0]
            string_storage_size = struct.unpack('<I', data[56:60])[0]
            regexp_table_offset = struct.unpack('<I', data[60:64])[0]
            regexp_count = struct.unpack('<I', data[64:68])[0]
            array_buffer_size = struct.unpack('<I', data[68:72])[0]
            obj_key_buffer_size = struct.unpack('<I', data[72:76])[0]
            obj_value_buffer_size = struct.unpack('<I', data[76:80])[0]

            # Additional fields for newer versions
            segment_id = 0
            cjs_module_count = 0
            cjs_module_offset = 0
            function_source_count = 0
            debug_info_offset = 0

            if len(data) >= 88:
                segment_id = struct.unpack('<I', data[80:84])[0]
                cjs_module_count = struct.unpack('<I', data[84:88])[0]

            return HermesHeader(
                magic=magic,
                version=version,
                sha1=sha1,
                file_length=file_length,
                global_code_index=global_code_index,
                function_count=function_count,
                string_kind=string_kind,
                identifier_count=identifier_count,
                string_count=string_count,
                overflow_string_count=overflow_string_count,
                string_storage_size=string_storage_size,
                regexp_table_offset=regexp_table_offset,
                regexp_count=regexp_count,
                array_buffer_size=array_buffer_size,
                obj_key_buffer_size=obj_key_buffer_size,
                obj_value_buffer_size=obj_value_buffer_size,
                segment_id=segment_id,
                cjs_module_count=cjs_module_count,
                cjs_module_offset=cjs_module_offset,
                function_source_count=function_source_count,
                debug_info_offset=debug_info_offset
            )

        except Exception as e:
            logger.debug(f"Failed to parse Hermes header: {e}")
            return None

    def _extract_strings(self, f, header: HermesHeader) -> List[str]:
        """Extract readable strings from the string table"""
        strings = []

        try:
            # String table typically follows the header
            # This is a simplified extraction - actual format is complex
            f.seek(88)  # Skip header

            # Read string storage area
            if header.string_storage_size > 0 and header.string_storage_size < 10*1024*1024:  # Sanity check: < 10MB
                string_data = f.read(min(header.string_storage_size, 100000))  # Limit to 100KB

                # Extract ASCII strings (simplified approach)
                current_string = bytearray()
                for byte in string_data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string.append(byte)
                    elif current_string and len(current_string) >= self.min_string_length:
                        try:
                            s = current_string.decode('ascii', errors='ignore')
                            if s and not s.isspace():
                                strings.append(s)
                        except:
                            pass
                        current_string = bytearray()

                # Don't forget the last string
                if current_string and len(current_string) >= self.min_string_length:
                    try:
                        s = current_string.decode('ascii', errors='ignore')
                        if s and not s.isspace():
                            strings.append(s)
                    except:
                        pass

        except Exception as e:
            logger.debug(f"Failed to extract strings: {e}")

        return strings[:self.max_strings]

    def _extract_all_strings(self, f, header: HermesHeader) -> List[str]:
        """Extract ALL readable strings from the entire bytecode file for library detection"""
        strings = []

        try:
            # Read the entire file
            f.seek(0)
            data = f.read()

            # Extract longer strings that might be library signatures
            current_string = bytearray()
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string.append(byte)
                elif current_string and len(current_string) >= 10:  # Longer strings for library detection
                    try:
                        s = current_string.decode('ascii', errors='ignore')
                        # Only add strings that might be library indicators
                        if s and not s.isspace() and self._is_library_indicator(s):
                            strings.append(s)
                    except:
                        pass
                    current_string = bytearray()

            # Don't forget the last string
            if current_string and len(current_string) >= 10:
                try:
                    s = current_string.decode('ascii', errors='ignore')
                    if s and not s.isspace() and self._is_library_indicator(s):
                        strings.append(s)
                except:
                    pass

        except Exception as e:
            logger.debug(f"Failed to extract all strings: {e}")

        # Limit to reasonable number
        return strings[:5000]

    def _is_library_indicator(self, s: str) -> bool:
        """Check if a string might be a library indicator"""
        # Look for patterns that indicate library code
        indicators = [
            '__', 'lodash', 'core-js', 'prop', 'types', 'metro',
            'module', 'exports', 'require', 'esModule', 'webpack',
            'react', 'native', 'bundle', 'DEV', 'proto',
            'Symbol', 'iterator', 'toString', 'hasOwn', 'define',
            'async', 'await', 'promise', 'callback', 'error',
            'warning', 'assert', 'check', 'validate', 'transform',
            'compile', 'parse', 'serialize', 'decode', 'encode'
        ]

        s_lower = s.lower()
        return any(ind in s_lower for ind in indicators)

    def _has_react_native_patterns(self, f, header: HermesHeader) -> bool:
        """Check if the bytecode contains React Native patterns"""
        try:
            # Look for common React Native strings in the file
            f.seek(0)
            data = f.read(min(header.file_length, 1024*1024))  # Read up to 1MB

            # Common React Native markers
            rn_markers = [
                b'ReactNative',
                b'__fbBatchedBridge',
                b'NativeModules',
                b'DeviceEventEmitter',
                b'AppRegistry',
                b'renderApplication',
                b'requireNativeComponent'
            ]

            for marker in rn_markers:
                if marker in data:
                    return True

        except Exception as e:
            logger.debug(f"Failed to check React Native patterns: {e}")

        return False

    def get_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from Hermes bytecode file"""
        metadata = {
            'file_type': 'hermes_bytecode',
            'file_path': str(file_path),
            'file_name': file_path.name
        }

        try:
            with open(file_path, 'rb') as f:
                header = self._parse_header(f)
                if header and header.is_valid:
                    metadata.update({
                        'hermes_version': header.version,
                        'function_count': header.function_count,
                        'string_count': header.string_count,
                        'identifier_count': header.identifier_count,
                        'regexp_count': header.regexp_count,
                        'cjs_module_count': header.cjs_module_count,
                        'has_debug_info': header.debug_info_offset > 0,
                        'file_size': header.file_length
                    })
        except Exception as e:
            logger.debug(f"Failed to extract Hermes metadata: {e}")

        return metadata
