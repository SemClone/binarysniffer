"""
Tests for feature extractors
"""

import pytest
import tempfile
from pathlib import Path

from binarysniffer.extractors import ExtractorFactory, BaseExtractor, ExtractedFeatures
from binarysniffer.extractors.binary import BinaryExtractor


class TestExtractedFeatures:
    """Test ExtractedFeatures data class"""
    
    def test_features_creation(self):
        """Test creating ExtractedFeatures"""
        features = ExtractedFeatures(
            file_path="/test/file",
            file_type="binary",
            strings=["str1", "str2"],
            symbols=["sym1"],
            functions=["func1"],
            constants=["CONST1"],
            imports=["lib.so"]
        )
        
        assert features.file_path == "/test/file"
        assert features.file_type == "binary"
        assert len(features.strings) == 2
        assert len(features.all_features) == 6
    
    def test_unique_features(self):
        """Test unique features extraction"""
        features = ExtractedFeatures(
            file_path="/test",
            file_type="test",
            strings=["dup", "unique1"],
            symbols=["dup", "unique2"]
        )
        
        unique = features.unique_features
        assert len(unique) == 3
        assert "dup" in unique
        assert "unique1" in unique
        assert "unique2" in unique
    
    def test_filter_by_length(self):
        """Test filtering features by length"""
        features = ExtractedFeatures(
            file_path="/test",
            file_type="test",
            strings=["a", "ab", "abcde", "abcdef"],
            symbols=["x", "xyz", "xyzabc"]
        )
        
        filtered = features.filter_by_length(min_length=3)
        
        assert len(filtered.strings) == 2  # "abcde", "abcdef"
        assert len(filtered.symbols) == 2  # "xyz", "xyzabc"
        assert "a" not in filtered.strings
        assert "x" not in filtered.symbols


class TestBinaryExtractor:
    """Test binary file extractor"""
    
    @pytest.fixture
    def extractor(self):
        """Create binary extractor"""
        return BinaryExtractor(min_string_length=5)
    
    def test_can_handle_by_extension(self, extractor):
        """Test file type detection by extension"""
        assert extractor.can_handle(Path("test.exe"))
        assert extractor.can_handle(Path("test.dll"))
        assert extractor.can_handle(Path("test.so"))
        assert extractor.can_handle(Path("test.dylib"))
        assert not extractor.can_handle(Path("test.txt"))
    
    def test_can_handle_by_content(self, extractor, tmp_path):
        """Test file type detection by content"""
        # Create file with null bytes
        binary_file = tmp_path / "binary"
        binary_file.write_bytes(b'text\x00binary\x00content')
        assert extractor.can_handle(binary_file)
        
        # Create file with ELF header
        elf_file = tmp_path / "elf"
        elf_file.write_bytes(b'\x7fELF' + b'rest of file')
        assert extractor.can_handle(elf_file)
        
        # Create text file
        text_file = tmp_path / "text"
        text_file.write_text("just plain text")
        assert not extractor.can_handle(text_file)
    
    def test_extract_strings(self, extractor, tmp_path):
        """Test string extraction from binary"""
        # Create binary with embedded strings
        test_file = tmp_path / "test.bin"
        with open(test_file, 'wb') as f:
            f.write(b'\x00\x01\x02\x03')
            f.write(b'HelloWorld')
            f.write(b'\x00' * 10)
            f.write(b'AnotherString123')
            f.write(b'\xff\xfe\xfd')
            f.write(b'libtest.so.1')
        
        features = extractor.extract(test_file)
        
        assert "HelloWorld" in features.strings
        assert "AnotherString123" in features.strings
        assert "libtest.so.1" in features.strings
        assert features.file_type == "binary"
    
    def test_extract_functions(self, extractor, tmp_path):
        """Test function name extraction"""
        test_file = tmp_path / "test.bin"
        content = b'\x00'.join([
            b'main',
            b'calculate_sum',
            b'MyClass::method',
            b'object.property',
            b'not_a_function!',
            b'_internal_func'
        ])
        test_file.write_bytes(content)
        
        features = extractor.extract(test_file)
        
        assert "calculate_sum" in features.functions
        assert "MyClass::method" in features.functions
        assert "_internal_func" in features.functions
        assert "not_a_function!" not in features.functions
    
    def test_extract_constants(self, extractor, tmp_path):
        """Test constant extraction"""
        test_file = tmp_path / "test.bin"
        content = b'\x00'.join([
            b'MAX_SIZE',
            b'DEFAULT_TIMEOUT',
            b'API_VERSION_1_0',
            b'not_constant',
            b'SOME'  # Too short
        ])
        test_file.write_bytes(content)
        
        features = extractor.extract(test_file)
        
        assert "MAX_SIZE" in features.constants
        assert "DEFAULT_TIMEOUT" in features.constants
        assert "API_VERSION_1_0" in features.constants
        assert "not_constant" not in features.constants
        assert "SOME" not in features.constants  # Too short
    
    def test_extract_imports(self, extractor, tmp_path):
        """Test import/library extraction"""
        test_file = tmp_path / "test.bin"
        content = b'\x00'.join([
            b'kernel32.dll',
            b'libcrypto.so.1.1',
            b'libm.dylib',
            b'stdlib.h',
            b'regular_string'
        ])
        test_file.write_bytes(content)
        
        features = extractor.extract(test_file)
        
        assert "kernel32.dll" in features.imports
        assert "libcrypto.so.1.1" in features.imports
        assert "libm.dylib" in features.imports
        assert "stdlib.h" in features.imports
        assert "regular_string" not in features.imports
    
    def test_large_file_handling(self, extractor, tmp_path):
        """Test handling of large files"""
        test_file = tmp_path / "large.bin"
        
        # Create 5MB file with repeated pattern
        with open(test_file, 'wb') as f:
            pattern = b'LongString1234567890' + b'\x00' * 100
            for _ in range(50000):
                f.write(pattern)
        
        features = extractor.extract(test_file)
        
        # Should extract strings but limit them
        assert len(features.strings) <= extractor.max_strings
        assert "LongString1234567890" in features.strings


class TestExtractorFactory:
    """Test extractor factory"""
    
    def test_factory_creation(self):
        """Test creating factory"""
        factory = ExtractorFactory()
        assert len(factory.extractors) > 0
    
    def test_get_extractor(self, tmp_path):
        """Test getting appropriate extractor"""
        factory = ExtractorFactory()
        
        # Binary file
        binary_file = tmp_path / "test.exe"
        binary_file.write_bytes(b'MZ\x00\x01')
        
        extractor = factory.get_extractor(binary_file)
        # Can be either BinaryExtractor or LiefBinaryExtractor (if LIEF is available)
        from binarysniffer.extractors.binary_lief import LiefBinaryExtractor
        from binarysniffer.extractors.binary_improved import ImprovedBinaryExtractor
        assert isinstance(extractor, (BinaryExtractor, LiefBinaryExtractor, ImprovedBinaryExtractor))
    
    def test_extract_via_factory(self, tmp_path):
        """Test extraction through factory"""
        factory = ExtractorFactory()
        
        # Create test file
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b'TestString123\x00MoreData')
        
        features = factory.extract(test_file)
        
        assert isinstance(features, ExtractedFeatures)
        assert features.file_path == str(test_file)
        assert len(features.strings) > 0