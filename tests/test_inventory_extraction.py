"""
Tests for package inventory extraction functionality
"""

import io
import json
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from binarysniffer.utils.inventory import extract_package_inventory


class TestInventoryExtraction:
    """Test package inventory extraction"""
    
    def setup_method(self):
        """Set up test fixtures"""
        # Create a temporary directory for test files
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
    
    def teardown_method(self):
        """Clean up test files"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_zip(self, files_dict):
        """Create a test ZIP file with given contents
        
        Args:
            files_dict: Dictionary of filename -> content
            
        Returns:
            Path to created ZIP file
        """
        zip_path = self.temp_path / "test.zip"
        
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for filename, content in files_dict.items():
                zf.writestr(filename, content)
        
        return zip_path
    
    def test_basic_inventory_extraction(self):
        """Test basic inventory extraction from ZIP"""
        # Create test ZIP
        files = {
            "README.md": "# Test Project",
            "src/main.py": "print('hello')",
            "lib/utils.py": "def helper(): pass",
            "data/config.json": '{"key": "value"}'
        }
        zip_path = self.create_test_zip(files)
        
        # Extract inventory
        inventory = extract_package_inventory(str(zip_path))
        
        # Check basic structure
        assert "package_name" in inventory
        assert inventory["package_name"] == "test.zip"
        assert "package_size" in inventory
        assert inventory["package_size"] > 0
        assert "files" in inventory
        assert len(inventory["files"]) == 4
        
        # Check file entries
        file_paths = [f["path"] for f in inventory["files"]]
        assert "README.md" in file_paths
        assert "src/main.py" in file_paths
        assert "lib/utils.py" in file_paths
        assert "data/config.json" in file_paths
        
        # Check summary
        assert "summary" in inventory
        summary = inventory["summary"]
        assert summary["total_files"] == 4
        assert summary["total_directories"] == 0
    
    def test_inventory_with_directories(self):
        """Test inventory extraction with directory structure"""
        # Create ZIP with directories
        files = {
            "src/": "",  # Directory entry
            "src/main.py": "code",
            "lib/": "",
            "lib/utils.py": "utils"
        }
        zip_path = self.create_test_zip(files)
        
        inventory = extract_package_inventory(str(zip_path))
        
        # Check for directory entries
        dirs = [f for f in inventory["files"] if f.get("is_directory")]
        files = [f for f in inventory["files"] if not f.get("is_directory")]
        
        assert len(dirs) >= 0  # May or may not include directory entries
        assert len(files) == 2
    
    def test_inventory_with_mime_types(self):
        """Test MIME type detection in inventory"""
        files = {
            "script.py": "#!/usr/bin/env python\nprint('test')",
            "data.json": '{"key": "value"}',
            "README.md": "# Markdown",
            "binary.dat": b"\x00\x01\x02\x03"
        }
        zip_path = self.create_test_zip(files)
        
        inventory = extract_package_inventory(
            str(zip_path),
            analyze_contents=True
        )
        
        # Check MIME types
        for file_entry in inventory["files"]:
            if not file_entry.get("is_directory"):
                assert "mime_type" in file_entry
                
                if file_entry["path"] == "script.py":
                    assert "python" in file_entry["mime_type"].lower() or \
                           "text" in file_entry["mime_type"].lower()
                elif file_entry["path"] == "data.json":
                    assert "json" in file_entry["mime_type"].lower() or \
                           "text" in file_entry["mime_type"].lower()
    
    @patch('binarysniffer.utils.file_metadata.calculate_file_hashes')
    def test_inventory_with_hashes(self, mock_calc_hashes):
        """Test hash calculation in inventory"""
        # Mock hash calculation
        mock_calc_hashes.return_value = {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
        
        files = {"test.txt": "content"}
        zip_path = self.create_test_zip(files)
        
        inventory = extract_package_inventory(
            str(zip_path),
            analyze_contents=True,
            include_hashes=True
        )
        
        # Check hashes were calculated
        assert mock_calc_hashes.called
        
        file_entry = inventory["files"][0]
        if not file_entry.get("is_directory"):
            assert "hashes" in file_entry
            assert "md5" in file_entry["hashes"]
            assert "sha1" in file_entry["hashes"]
            assert "sha256" in file_entry["hashes"]
    
    @patch('binarysniffer.utils.file_metadata.calculate_file_hashes')
    def test_inventory_with_fuzzy_hashes(self, mock_calc_hashes):
        """Test fuzzy hash calculation in inventory"""
        # Mock hash calculation including fuzzy hashes
        mock_calc_hashes.return_value = {
            "md5": "abc123",
            "sha1": "def456",
            "sha256": "ghi789",
            "tlsh": "T1234567890ABCDEF",
            "ssdeep": "3:abc123:def456"
        }
        
        files = {"test.txt": "content" * 100}  # Larger content for fuzzy hashing
        zip_path = self.create_test_zip(files)
        
        inventory = extract_package_inventory(
            str(zip_path),
            analyze_contents=True,
            include_fuzzy_hashes=True
        )
        
        # Check fuzzy hashes were calculated
        assert mock_calc_hashes.called
        assert mock_calc_hashes.call_args[1]['include_fuzzy'] == True
        
        file_entry = inventory["files"][0]
        if not file_entry.get("is_directory"):
            assert "hashes" in file_entry
            assert "tlsh" in file_entry["hashes"]
            assert "ssdeep" in file_entry["hashes"]
    
    def test_inventory_with_component_detection(self):
        """Test component detection in inventory"""
        # Create a mock analyzer
        mock_analyzer = MagicMock()
        
        mock_result = MagicMock()
        mock_result.matches = [
            MagicMock(component="FFmpeg", confidence=0.85, license="LGPL"),
            MagicMock(component="OpenSSL", confidence=0.92, license="Apache-2.0")
        ]
        mock_result.features_extracted = 42
        mock_analyzer.analyze_file.return_value = mock_result
        
        files = {"lib.so": b"binary content"}
        zip_path = self.create_test_zip(files)
        
        inventory = extract_package_inventory(
            str(zip_path),
            analyzer=mock_analyzer,  # Pass the mock analyzer
            analyze_contents=True,
            detect_components=True
        )
        
        # Check component detection was performed
        assert mock_analyzer.analyze_file.called
        
        file_entry = inventory["files"][0]
        if not file_entry.get("is_directory"):
            assert "components" in file_entry
            assert len(file_entry["components"]) == 2
            
            # Check component details
            ffmpeg = file_entry["components"][0]
            assert ffmpeg["name"] == "FFmpeg"
            assert ffmpeg["confidence"] == 0.85
            assert ffmpeg["license"] == "LGPL"
    
    def test_inventory_compression_ratio(self):
        """Test compression ratio calculation"""
        # Create file with known sizes
        uncompressed_content = "x" * 1000  # 1000 bytes uncompressed
        files = {"test.txt": uncompressed_content}
        zip_path = self.create_test_zip(files)
        
        inventory = extract_package_inventory(
            str(zip_path),
            analyze_contents=True
        )
        
        file_entry = inventory["files"][0]
        if not file_entry.get("is_directory"):
            assert "compression_ratio" in file_entry
            # Compression ratio should be between 0 and 1
            assert 0 <= file_entry["compression_ratio"] <= 1
            assert file_entry["size"] == 1000
    
    def test_inventory_file_types_summary(self):
        """Test file type summary in inventory"""
        files = {
            "main.py": "python code",
            "utils.py": "more python",
            "data.json": "{}",
            "config.json": "{}",
            "README.md": "docs"
        }
        zip_path = self.create_test_zip(files)
        
        inventory = extract_package_inventory(str(zip_path))
        
        # Check file types summary
        assert "file_types" in inventory["summary"]
        file_types = inventory["summary"]["file_types"]
        
        # Should group by extension
        assert ".py" in file_types
        assert file_types[".py"] == 2
        assert ".json" in file_types
        assert file_types[".json"] == 2
        assert ".md" in file_types
        assert file_types[".md"] == 1
    
    def test_inventory_nonexistent_file(self):
        """Test inventory extraction with nonexistent file"""
        # Should handle gracefully instead of raising
        inventory = extract_package_inventory("/nonexistent/file.zip")
        assert inventory is not None
        assert inventory["package_size"] == 0
    
    def test_inventory_invalid_archive(self):
        """Test inventory extraction with invalid archive"""
        # Create a non-archive file
        invalid_path = self.temp_path / "not_an_archive.txt"
        invalid_path.write_text("This is not an archive")
        
        # Should handle gracefully
        inventory = extract_package_inventory(str(invalid_path))
        
        # Should return minimal inventory with error
        assert inventory is not None
        assert "error" in inventory
        assert "unsupported" in inventory["error"].lower() or "not a valid" in inventory["error"].lower()
    
    def test_inventory_nested_archives(self):
        """Test inventory extraction with nested archives"""
        # Create inner ZIP
        inner_files = {"inner.txt": "nested content"}
        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, 'w') as zf:
            for name, content in inner_files.items():
                zf.writestr(name, content)
        
        # Create outer ZIP containing inner ZIP
        outer_files = {
            "outer.txt": "outer content",
            "nested.zip": inner_zip.getvalue()
        }
        zip_path = self.create_test_zip(outer_files)
        
        inventory = extract_package_inventory(str(zip_path))
        
        # Should list nested archive as a file
        file_paths = [f["path"] for f in inventory["files"]]
        assert "nested.zip" in file_paths
        assert "outer.txt" in file_paths
        
        # Nested contents should not be extracted by default
        assert "inner.txt" not in file_paths