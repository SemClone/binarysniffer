"""
Tests for archive extractor
"""

import pytest
import zipfile
import tarfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from binarysniffer.extractors.archive import ArchiveExtractor
from binarysniffer.extractors.base import ExtractedFeatures


class TestArchiveExtractor:
    """Test archive file extraction"""
    
    def test_can_handle_archives(self):
        """Test archive detection"""
        extractor = ArchiveExtractor()
        
        # Should handle archives
        assert extractor.can_handle(Path("test.zip"))
        assert extractor.can_handle(Path("test.jar"))
        assert extractor.can_handle(Path("test.apk"))
        assert extractor.can_handle(Path("test.ipa"))
        assert extractor.can_handle(Path("test.tar.gz"))
        
        # Should not handle non-archives
        assert not extractor.can_handle(Path("test.txt"))
        assert not extractor.can_handle(Path("test.exe"))
    
    def test_extract_simple_zip(self, tmp_path):
        """Test extracting simple ZIP file"""
        # Create test ZIP
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("test.txt", "Hello World")
            zf.writestr("code.py", "def hello():\n    print('Hello')")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(zip_path)
        
        assert features.file_type == "zip"
        assert features.metadata["archive_type"] == "generic"
        assert features.metadata["file_count"] > 0
    
    def test_extract_apk(self, tmp_path):
        """Test extracting Android APK"""
        # Create test APK (ZIP structure)
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, 'w') as zf:
            zf.writestr("AndroidManifest.xml", "<manifest>")
            zf.writestr("classes.dex", "dex\n035")
            zf.writestr("lib/arm64-v8a/libnative.so", "ELF")
            zf.writestr("com/example/MainActivity.class", "cafebabe")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(apk_path)
        
        assert features.file_type == "android"
        assert features.metadata["archive_type"] == "android"
        assert features.metadata.get("has_android_manifest") == True
        assert features.metadata.get("dex_files") == 1
        # Native libs are stored in metadata, not imports
        assert "libnative.so" in features.metadata.get("native_libs", [])
    
    def test_extract_ipa(self, tmp_path):
        """Test extracting iOS IPA"""
        # Create test IPA (ZIP structure)
        ipa_path = tmp_path / "test.ipa"
        with zipfile.ZipFile(ipa_path, 'w') as zf:
            zf.writestr("Payload/TestApp.app/Info.plist", "<plist>")
            zf.writestr("Payload/TestApp.app/TestApp", "MachO")
            zf.writestr("Payload/TestApp.app/Frameworks/Test.framework/Test", "Framework")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(ipa_path)
        
        assert features.file_type == "ios"
        assert features.metadata["archive_type"] == "ios"
        assert features.metadata.get("has_info_plist") == True
        assert "Test.framework" in features.imports
    
    def test_extract_jar(self, tmp_path):
        """Test extracting Java JAR"""
        # Create test JAR
        jar_path = tmp_path / "test.jar"
        with zipfile.ZipFile(jar_path, 'w') as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: com.example.Main")
            zf.writestr("com/example/Main.class", "cafebabe")
            zf.writestr("com/example/Utils.class", "cafebabe")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(jar_path)
        
        assert features.file_type == "java"
        assert features.metadata["archive_type"] == "java"
        assert features.metadata.get("main_class") == "com.example.Main"
        assert "com.example.Main" in features.symbols
    
    def test_extract_python_wheel(self, tmp_path):
        """Test extracting Python wheel"""
        # Create test wheel
        wheel_path = tmp_path / "test.whl"
        with zipfile.ZipFile(wheel_path, 'w') as zf:
            zf.writestr("test_package-1.0.0.dist-info/METADATA", 
                       "Name: test-package\nVersion: 1.0.0")
            zf.writestr("test_package/__init__.py", "# Package")
            zf.writestr("test_package/module.py", "def function(): pass")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(wheel_path)
        
        assert features.file_type == "python_wheel"
        assert features.metadata["archive_type"] == "python_wheel"
        assert features.metadata.get("package_name") == "test-package"
        assert features.metadata.get("version") == "1.0.0"
    
    def test_extract_tar(self, tmp_path):
        """Test extracting TAR archive"""
        # Create test TAR
        tar_path = tmp_path / "test.tar.gz"
        with tarfile.open(tar_path, 'w:gz') as tf:
            # Create temp files to add
            temp_file = tmp_path / "temp.txt"
            temp_file.write_text("content")
            tf.add(temp_file, arcname="test.txt")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(tar_path)
        
        assert features.file_type == "tar"
        assert features.metadata["archive_type"] == "generic"
    
    def test_nested_extraction(self, tmp_path):
        """Test extraction processes nested files"""
        # Create nested structure
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            # Add various file types
            zf.writestr("source.py", "import os\ndef main():\n    print('test')")
            zf.writestr("binary.exe", b"MZ\x90\x00" + b"test string in binary")
            zf.writestr("doc.txt", "Documentation file")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(zip_path)
        
        # Debug: print what we got
        print(f"Functions: {features.functions}")
        print(f"Imports: {features.imports}")
        print(f"Strings: {features.strings}")
        
        # Should have extracted features from nested files
        assert len(features.imports) > 0    # From Python file - we see os is imported
        assert len(features.strings) > 0    # From all files
    
    def test_large_archive_limit(self, tmp_path):
        """Test that large archives are limited"""
        # Create archive with many files
        zip_path = tmp_path / "large.zip"
        with zipfile.ZipFile(zip_path, 'w') as zf:
            for i in range(200):
                zf.writestr(f"file{i}.txt", f"Content {i}")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(zip_path)
        
        # Should process only first 100 files
        assert features.metadata["file_count"] == 200
        # But strings should be limited
        assert len(features.strings) <= extractor.max_strings
    
    def test_corrupted_archive(self, tmp_path):
        """Test handling corrupted archives"""
        # Create corrupted ZIP
        zip_path = tmp_path / "corrupted.zip"
        zip_path.write_bytes(b"PK\x03\x04corrupted data")
        
        extractor = ArchiveExtractor()
        features = extractor.extract(zip_path)
        
        # Should return empty features without crashing
        assert features.file_type == "zip"
        assert len(features.strings) == 0
        assert len(features.functions) == 0