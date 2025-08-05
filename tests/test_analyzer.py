"""
Tests for the core analyzer module
"""

import pytest
import tempfile
from pathlib import Path

from binarysniffer import BinarySniffer, Config, AnalysisResult


class TestBinarySniffer:
    """Test BinarySniffer core functionality"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    @pytest.fixture
    def config(self, temp_dir):
        """Create test configuration"""
        return Config(
            data_dir=temp_dir / ".binarysniffer",
            min_confidence=0.5,
            auto_update=False
        )
    
    @pytest.fixture
    def sniffer(self, config):
        """Create BinarySniffer instance"""
        return BinarySniffer(config)
    
    def test_initialization(self, sniffer, config):
        """Test analyzer initialization"""
        assert sniffer.config == config
        assert sniffer.db is not None
        assert sniffer.matcher is not None
        assert config.data_dir.exists()
    
    def test_analyze_missing_file(self, sniffer):
        """Test analyzing non-existent file"""
        with pytest.raises(FileNotFoundError):
            sniffer.analyze_file("/path/to/nonexistent/file")
    
    def test_analyze_text_file(self, sniffer, temp_dir):
        """Test analyzing a simple text file"""
        # Create test file
        test_file = temp_dir / "test.txt"
        test_file.write_text("Hello, World! This is a test file.")
        
        # Analyze
        result = sniffer.analyze_file(test_file)
        
        # Verify result structure
        assert isinstance(result, AnalysisResult)
        assert result.file_path == str(test_file)
        assert result.file_size > 0
        assert result.file_type == "binary"  # Default extractor
        assert isinstance(result.matches, list)
        assert result.error is None
    
    def test_analyze_binary_with_strings(self, sniffer, temp_dir):
        """Test analyzing binary file with embedded strings"""
        # Create binary file with strings
        test_file = temp_dir / "test.bin"
        with open(test_file, 'wb') as f:
            f.write(b'\x00\x01\x02')
            f.write(b'libcrypto.so.1.1\x00')
            f.write(b'\x03\x04\x05')
            f.write(b'OpenSSL_version_num\x00')
            f.write(b'\x06\x07\x08')
        
        # Analyze
        result = sniffer.analyze_file(test_file)
        
        # Verify
        assert result.file_type == "binary"
        assert result.features_extracted > 0
    
    def test_analyze_directory(self, sniffer, temp_dir):
        """Test analyzing directory"""
        # Create test files
        (temp_dir / "file1.bin").write_bytes(b'Test file 1')
        (temp_dir / "file2.bin").write_bytes(b'\x00\x01\x02test\x00')
        
        # Analyze directory
        results = sniffer.analyze_directory(temp_dir, recursive=False)
        
        # Verify
        assert len(results) == 2
        assert all(isinstance(r, AnalysisResult) for r in results.values())
    
    def test_analyze_with_patterns(self, sniffer, temp_dir):
        """Test analyzing with file patterns"""
        # Create test files
        (temp_dir / "test.exe").write_bytes(b'MZ\x00\x01')
        (temp_dir / "test.txt").write_text("text")
        (temp_dir / "test.so").write_bytes(b'\x7fELF')
        
        # Analyze only .exe and .so files
        results = sniffer.analyze_directory(
            temp_dir,
            file_patterns=["*.exe", "*.so"]
        )
        
        # Verify
        assert len(results) == 2
        assert str(temp_dir / "test.txt") not in results
    
    def test_batch_analysis(self, sniffer, temp_dir):
        """Test batch analysis"""
        # Create test files
        files = []
        for i in range(3):
            file_path = temp_dir / f"file{i}.bin"
            file_path.write_bytes(b'test' + str(i).encode())
            files.append(file_path)
        
        # Analyze batch
        results = sniffer.analyze_batch(files)
        
        # Verify
        assert len(results) == 3
        for file_path in files:
            assert str(file_path) in results
    
    def test_parallel_processing(self, sniffer, temp_dir):
        """Test parallel vs sequential processing"""
        # Create multiple files
        for i in range(10):
            (temp_dir / f"file{i}.bin").write_bytes(b'test' * 100)
        
        # Test parallel
        results_parallel = sniffer.analyze_directory(
            temp_dir,
            parallel=True
        )
        
        # Test sequential
        results_sequential = sniffer.analyze_directory(
            temp_dir,
            parallel=False
        )
        
        # Results should be the same
        assert len(results_parallel) == len(results_sequential)
        assert set(results_parallel.keys()) == set(results_sequential.keys())
    
    def test_confidence_threshold(self, sniffer, temp_dir):
        """Test confidence threshold filtering"""
        # Create test file
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b'test_signature_data')
        
        # Analyze with different thresholds
        result_low = sniffer.analyze_file(test_file, confidence_threshold=0.1)
        result_high = sniffer.analyze_file(test_file, confidence_threshold=0.9)
        
        # High threshold should have fewer or equal matches
        assert len(result_high.matches) <= len(result_low.matches)
    
    def test_signature_stats(self, sniffer):
        """Test getting signature statistics"""
        stats = sniffer.get_signature_stats()
        
        assert isinstance(stats, dict)
        assert 'component_count' in stats
        assert 'signature_count' in stats
        assert 'database_size' in stats