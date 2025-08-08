"""
Tests for the static library (.a) extractor
"""

import pytest
import tempfile
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

from binarysniffer.extractors.static_library import (
    StaticLibraryExtractor, 
    ARMember,
    AR_MAGIC,
    AR_HEADER_SIZE,
    AR_END_MARKER
)
from binarysniffer.extractors.base import ExtractedFeatures


class TestStaticLibraryExtractor:
    """Test static library extractor functionality"""
    
    @pytest.fixture
    def extractor(self):
        """Create extractor instance"""
        return StaticLibraryExtractor()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def create_simple_ar_archive(self, path: Path, members: list) -> None:
        """Create a simple AR archive for testing"""
        with open(path, 'wb') as f:
            # Write magic
            f.write(AR_MAGIC)
            
            for name, content in members:
                # Prepare name (pad to 16 bytes)
                name_bytes = name.encode('ascii')[:15] + b'/'
                name_field = name_bytes.ljust(16, b' ')
                
                # Other fields (simplified)
                mtime = b'0           '  # 12 bytes
                uid = b'0     '          # 6 bytes  
                gid = b'0     '          # 6 bytes
                mode = b'100644  '       # 8 bytes
                
                # Size field (10 bytes)
                size = len(content)
                size_field = str(size).encode('ascii').ljust(10, b' ')
                
                # Build header
                header = name_field + mtime + uid + gid + mode + size_field + AR_END_MARKER
                assert len(header) == AR_HEADER_SIZE
                
                # Write header and content
                f.write(header)
                f.write(content)
                
                # Add padding for alignment
                if size % 2 != 0:
                    f.write(b'\n')
    
    def test_can_handle_valid_archive(self, extractor, temp_dir):
        """Test can_handle with valid AR archive"""
        ar_file = temp_dir / "test.a"
        self.create_simple_ar_archive(ar_file, [
            ("test.o", b"fake object file content")
        ])
        
        assert extractor.can_handle(ar_file) == True
    
    def test_can_handle_invalid_file(self, extractor, temp_dir):
        """Test can_handle with non-AR file"""
        non_ar = temp_dir / "test.txt"
        non_ar.write_text("not an archive")
        
        assert extractor.can_handle(non_ar) == False
    
    def test_can_handle_wrong_extension(self, extractor, temp_dir):
        """Test can_handle checks magic even with wrong extension"""
        ar_file = temp_dir / "test.txt"
        self.create_simple_ar_archive(ar_file, [
            ("test.o", b"object file")
        ])
        
        # Should return False due to extension check
        assert extractor.can_handle(ar_file) == False
    
    def test_parse_ar_archive(self, extractor, temp_dir):
        """Test parsing AR archive structure"""
        ar_file = temp_dir / "test.a"
        members_data = [
            ("first.o", b"first object file"),
            ("second.o", b"second object file content"),
            ("third.o", b"third")
        ]
        self.create_simple_ar_archive(ar_file, members_data)
        
        members = extractor._parse_ar_archive(ar_file)
        
        assert len(members) == 3
        assert members[0].name == "first.o"
        assert members[0].size == len(members_data[0][1])
        assert members[1].name == "second.o"
        assert members[2].name == "third.o"
    
    def test_is_object_file(self, extractor):
        """Test object file identification"""
        assert extractor._is_object_file("test.o") == True
        assert extractor._is_object_file("libfoo.o") == True
        assert extractor._is_object_file("test.obj") == True
        assert extractor._is_object_file("__.SYMDEF") == False
        assert extractor._is_object_file("__string_table__") == False
        assert extractor._is_object_file("test.c") == False
    
    def test_extract_strings_from_bytes(self, extractor):
        """Test string extraction from binary data"""
        data = b'\x00\x01Hello World\x00\x02OpenSSL_version\x00test123\xff'
        strings = extractor._extract_strings_from_bytes(data, min_length=4)
        
        assert "Hello World" in strings
        assert "OpenSSL_version" in strings
        assert "test123" in strings
        assert len([s for s in strings if len(s) < 4]) == 0
    
    def test_looks_like_symbol(self, extractor):
        """Test symbol detection heuristic"""
        assert extractor._looks_like_symbol("crypto_malloc") == True
        assert extractor._looks_like_symbol("EVP_DigestInit") == True
        assert extractor._looks_like_symbol("std::string") == True
        assert extractor._looks_like_symbol("ab") == False  # Too short
        assert extractor._looks_like_symbol("hello") == False  # No special chars
    
    def test_looks_like_function(self, extractor):
        """Test function name detection"""
        assert extractor._looks_like_function("ssl_init") == True
        assert extractor._looks_like_function("mem_free") == True
        assert extractor._looks_like_function("ctx_create") == True
        assert extractor._looks_like_function("random_name") == False
    
    def test_looks_like_constant(self, extractor):
        """Test constant detection"""
        assert extractor._looks_like_constant("SSL_VERSION") == True
        assert extractor._looks_like_constant("MAX_BUFFER_SIZE") == True
        assert extractor._looks_like_constant("OPENSSL") == False  # No underscore
        assert extractor._looks_like_constant("test") == False  # Not uppercase
    
    def test_is_significant_string(self, extractor):
        """Test significant string detection"""
        assert extractor._is_significant_string("OpenSSL version 1.1.1") == True
        assert extractor._is_significant_string("Copyright (c) 2023") == True
        assert extractor._is_significant_string("libcrypto.so.1.1") == True
        assert extractor._is_significant_string("main") == False  # Too short
        assert extractor._is_significant_string("test") == False
    
    def test_extract_features(self, extractor, temp_dir):
        """Test feature extraction from archive"""
        ar_file = temp_dir / "test.a"
        
        # Create test content with recognizable strings
        obj1_content = b'\x00SSL_CTX_new\x00EVP_DigestInit\x00OPENSSL_VERSION\x00'
        obj2_content = b'\x00crypto_malloc\x00BN_free\x00SHA256_Init\x00'
        
        self.create_simple_ar_archive(ar_file, [
            ("crypto.o", obj1_content),
            ("ssl.o", obj2_content)
        ])
        
        features = extractor.extract(ar_file)
        
        assert features.file_type == "static_library"
        assert len(features.strings) > 0
        assert len(features.symbols) > 0
        
        # Check metadata
        assert features.metadata['total_objects'] == 2
        assert len(features.metadata['members']) == 2
        
        # Check for specific strings
        all_strings = ' '.join(features.strings)
        assert 'SSL_CTX_new' in all_strings or 'SSL_CTX_new@crypto.o' in all_strings
    
    def test_extract_with_invalid_archive(self, extractor, temp_dir):
        """Test extraction falls back gracefully on invalid archive"""
        invalid_file = temp_dir / "invalid.a"
        invalid_file.write_bytes(b'Not an AR archive at all')
        
        # Should fall back to binary extractor
        features = extractor.extract(invalid_file)
        
        # Should return some result (from binary extractor fallback)
        assert features is not None
        assert features.file_type in ['static_library', 'binary']
    
    def test_get_metadata(self, extractor, temp_dir):
        """Test metadata extraction"""
        ar_file = temp_dir / "libtest.a"
        self.create_simple_ar_archive(ar_file, [
            ("first.o", b"x" * 100),
            ("second.o", b"y" * 200),
            ("third.o", b"z" * 150)
        ])
        
        metadata = extractor.get_metadata(ar_file)
        
        assert metadata['file_type'] == 'static_library'
        assert metadata['file_name'] == 'libtest.a'
        assert metadata['total_members'] == 3
        assert metadata['object_files'] == 3
        assert metadata['total_size'] == 450  # 100 + 200 + 150
        assert len(metadata['member_names']) == 3
    
    def test_bsd_extended_names(self, extractor, temp_dir):
        """Test handling of BSD-style extended names"""
        ar_file = temp_dir / "bsd.a"
        
        with open(ar_file, 'wb') as f:
            # Write magic
            f.write(AR_MAGIC)
            
            # BSD-style extended name
            name = "very_long_object_file_name.o"
            content = b"test content"
            
            # BSD format: #1/length in name field, actual name at start of data
            name_len = len(name)
            total_size = name_len + len(content)
            
            # Build header with BSD-style name
            name_field = f"#1/{name_len}".encode('ascii').ljust(16, b' ')
            mtime = b'0           '
            uid = b'0     '
            gid = b'0     '
            mode = b'100644  '
            size_field = str(total_size).encode('ascii').ljust(10, b' ')
            
            header = name_field + mtime + uid + gid + mode + size_field + AR_END_MARKER
            
            f.write(header)
            f.write(name.encode('ascii'))
            f.write(content)
        
        members = extractor._parse_ar_archive(ar_file)
        
        assert len(members) == 1
        assert members[0].name == name
        assert members[0].data == content
    
    @patch('binarysniffer.extractors.static_library.logger')
    def test_analyze_object_file_error_handling(self, mock_logger, extractor):
        """Test error handling in object file analysis"""
        member = ARMember("bad.o", 100, 0, b'\xff\xfe\xfd')
        
        result = extractor._analyze_object_file(member)
        
        # Should return empty dict on error but not crash
        assert isinstance(result, dict)
    
    def test_feature_limits(self, extractor, temp_dir):
        """Test that feature extraction respects limits"""
        ar_file = temp_dir / "large.a"
        
        # Create object with many strings
        large_content = b''.join(f'string_{i}\x00'.encode() for i in range(20000))
        
        self.create_simple_ar_archive(ar_file, [
            ("large.o", large_content)
        ])
        
        features = extractor.extract(ar_file)
        
        # Check limits are enforced
        assert len(features.strings) <= 10000
        assert len(features.symbols) <= 5000
        assert len(features.functions) <= 2000