"""
Test Zstandard archive support
"""

import io
import tarfile
import tempfile
from pathlib import Path
import pytest
import zstandard as zstd

from binarysniffer.extractors.archive import ArchiveExtractor
from binarysniffer.utils.inventory import extract_package_inventory


class TestZstandardSupport:
    """Test Zstandard compression support"""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory"""
        with tempfile.TemporaryDirectory() as tmp:
            yield Path(tmp)
    
    def create_tar_zst(self, temp_dir: Path, files: dict) -> Path:
        """Create a .tar.zst archive with given files"""
        # Create tar archive in memory
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            for filename, content in files.items():
                if isinstance(content, str):
                    content = content.encode('utf-8')
                
                info = tarfile.TarInfo(name=filename)
                info.size = len(content)
                tar.addfile(tarinfo=info, fileobj=io.BytesIO(content))
        
        # Compress with zstandard
        tar_data = tar_buffer.getvalue()
        compressor = zstd.ZstdCompressor(level=3)
        compressed_data = compressor.compress(tar_data)
        
        # Save to file
        archive_path = temp_dir / "test.tar.zst"
        archive_path.write_bytes(compressed_data)
        
        return archive_path
    
    def create_plain_zst(self, temp_dir: Path, content: bytes) -> Path:
        """Create a plain .zst file"""
        compressor = zstd.ZstdCompressor(level=3)
        compressed_data = compressor.compress(content)
        
        zst_path = temp_dir / "test.txt.zst"
        zst_path.write_bytes(compressed_data)
        
        return zst_path
    
    def test_tar_zst_extraction(self, temp_dir):
        """Test extracting .tar.zst archives"""
        # Create test archive
        files = {
            "readme.txt": "This is a test",
            "lib/binary.so": b"\x7fELF\x02\x01\x01\x00binary data",
            "src/code.py": "def hello():\n    print('world')"
        }
        archive_path = self.create_tar_zst(temp_dir, files)
        
        # Extract features
        extractor = ArchiveExtractor()
        features = extractor.extract(archive_path)
        
        # Verify extraction
        assert features is not None
        assert features.file_type == "tar"
        assert len(features.strings) > 0  # Changed from features_extracted
        # Check that we extracted some content from the archive
        all_strings = ' '.join(features.strings).lower()
        assert 'test' in all_strings or 'hello' in all_strings or 'world' in all_strings
    
    def test_plain_zst_extraction(self, temp_dir):
        """Test extracting plain .zst files"""
        # Create plain compressed file
        content = b"This is compressed text content with some data"
        zst_path = self.create_plain_zst(temp_dir, content)
        
        # Extract features
        extractor = ArchiveExtractor()
        features = extractor.extract(zst_path)
        
        # Verify extraction
        assert features is not None
        assert len(features.strings) > 0
        assert any("compressed text" in s for s in features.strings)
    
    def test_inventory_tar_zst(self, temp_dir):
        """Test inventory extraction from .tar.zst"""
        # Create test archive
        files = {
            "file1.txt": "content 1",
            "file2.py": "import sys",
            "dir/file3.so": b"binary\x00data"
        }
        archive_path = self.create_tar_zst(temp_dir, files)
        
        # Extract inventory
        inventory = extract_package_inventory(str(archive_path))
        
        # Verify inventory
        assert inventory is not None
        assert inventory["package_type"] == "tar.zst"
        assert inventory["summary"]["total_files"] == 3
        assert inventory["summary"]["total_directories"] == 0  # tar doesn't create directory entries
        assert ".txt" in inventory["summary"]["file_types"]
        assert ".py" in inventory["summary"]["file_types"]
        assert ".so" in inventory["summary"]["file_types"]
        
        # Check files
        assert len(inventory["files"]) == 3
        file_paths = [f["path"] for f in inventory["files"]]
        assert "file1.txt" in file_paths
        assert "file2.py" in file_paths
        assert "dir/file3.so" in file_paths
    
    def test_inventory_plain_zst(self, temp_dir):
        """Test inventory extraction from plain .zst"""
        # Create plain compressed file
        content = b"Large content " * 1000  # Make it large to show compression
        zst_path = self.create_plain_zst(temp_dir, content)
        
        # Extract inventory
        inventory = extract_package_inventory(str(zst_path))
        
        # Verify inventory
        assert inventory is not None
        assert inventory["package_type"] == "zstd"
        assert inventory["summary"]["total_files"] == 1
        assert len(inventory["files"]) == 1
        
        file_entry = inventory["files"][0]
        assert file_entry["path"] == "test.txt"  # .zst removed
        assert file_entry["compression_method"] == "zstd"
        assert file_entry["size"] == len(content)  # Uncompressed size
        assert file_entry["compressed_size"] < file_entry["size"]  # Should be compressed
        assert file_entry["compression_ratio"] > 0  # Should show compression
    
    def test_nested_archives_with_zst(self, temp_dir):
        """Test handling nested archives with Zstandard"""
        # Create inner archive
        inner_files = {"inner.txt": "nested content"}
        inner_tar = io.BytesIO()
        with tarfile.open(fileobj=inner_tar, mode='w') as tar:
            for name, content in inner_files.items():
                info = tarfile.TarInfo(name=name)
                data = content.encode() if isinstance(content, str) else content
                info.size = len(data)
                tar.addfile(tarinfo=info, fileobj=io.BytesIO(data))
        
        # Create outer archive with inner archive
        outer_files = {
            "outer.txt": "outer content",
            "nested.tar": inner_tar.getvalue()
        }
        archive_path = self.create_tar_zst(temp_dir, outer_files)
        
        # Extract features
        extractor = ArchiveExtractor()
        features = extractor.extract(archive_path)
        
        # Should extract from both outer and inner archives
        assert features is not None
        assert any("outer content" in s for s in features.strings)
        # Inner archive content might be extracted if nested extraction is enabled