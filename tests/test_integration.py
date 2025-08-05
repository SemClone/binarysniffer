"""
Integration tests for BinarySniffer
"""

import pytest
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from binarysniffer.core.analyzer import BinarySniffer
from binarysniffer.core.results import AnalysisResult


class TestIntegration:
    """Test full integration scenarios"""
    
    def test_analyze_apk_file(self, tmp_path):
        """Test analyzing an APK file end-to-end"""
        # Create test APK
        apk_path = tmp_path / "test.apk"
        with zipfile.ZipFile(apk_path, 'w') as zf:
            zf.writestr("AndroidManifest.xml", "<manifest>")
            zf.writestr("classes.dex", "dex\n035")
            zf.writestr("lib/arm64-v8a/libnative.so", "ELF binary content")
            zf.writestr("res/values/strings.xml", '<string name="app_name">TestApp</string>')
        
        # Analyze with BinarySniffer
        analyzer = BinarySniffer()
        result = analyzer.analyze_file(str(apk_path))
        
        assert isinstance(result, AnalysisResult)
        assert result.error is None
        assert result.file_path == str(apk_path)
        
        # Should detect it as an archive (file_type will be "archive" or similar)
        # The features get processed through the matching system
        assert result.file_type in ["archive", "zip", "android"]
        assert result.features_extracted > 0
        
        # Even if no matches found, should have processed features
        assert result.analysis_time > 0
    
    def test_analyze_ipa_file(self, tmp_path):
        """Test analyzing an IPA file end-to-end"""
        # Create test IPA
        ipa_path = tmp_path / "test.ipa"
        with zipfile.ZipFile(ipa_path, 'w') as zf:
            zf.writestr("Payload/TestApp.app/Info.plist", "<plist><key>CFBundleIdentifier</key>")
            zf.writestr("Payload/TestApp.app/TestApp", "Mach-O binary")
            zf.writestr("Payload/TestApp.app/Frameworks/UIKit.framework/UIKit", "Framework")
        
        # Analyze with BinarySniffer
        analyzer = BinarySniffer()
        result = analyzer.analyze_file(str(ipa_path))
        
        assert isinstance(result, AnalysisResult)
        assert result.error is None
        
        # Should detect it as an archive
        assert result.file_type in ["archive", "zip", "ios"]
        assert result.features_extracted > 0
        assert result.analysis_time > 0
    
    def test_analyze_jar_with_manifest(self, tmp_path):
        """Test analyzing a JAR file with manifest"""
        # Create test JAR
        jar_path = tmp_path / "library.jar"
        with zipfile.ZipFile(jar_path, 'w') as zf:
            zf.writestr("META-INF/MANIFEST.MF", 
                       "Manifest-Version: 1.0\n"
                       "Main-Class: com.example.Main\n"
                       "Implementation-Title: Test Library\n")
            zf.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe")  # Java class magic
            zf.writestr("com/example/Utils.class", b"\xca\xfe\xba\xbe")
        
        # Analyze
        analyzer = BinarySniffer()
        result = analyzer.analyze_file(str(jar_path))
        
        assert result.error is None
        assert result.file_type in ["archive", "zip", "java"]
        assert result.features_extracted > 0
    
    def test_analyze_nested_archives(self, tmp_path):
        """Test analyzing archives within archives"""
        # Create inner JAR
        inner_jar = tmp_path / "inner.jar"
        with zipfile.ZipFile(inner_jar, 'w') as zf:
            zf.writestr("com/inner/Class.class", b"\xca\xfe\xba\xbe")
        
        # Create outer ZIP containing the JAR
        outer_zip = tmp_path / "outer.zip"
        with zipfile.ZipFile(outer_zip, 'w') as zf:
            zf.write(inner_jar, "libs/inner.jar")
            zf.writestr("README.txt", "This contains a JAR file")
        
        # Clean up temp file
        inner_jar.unlink()
        
        # Analyze outer archive
        analyzer = BinarySniffer()
        result = analyzer.analyze_file(str(outer_zip))
        
        assert result.error is None
        assert result.file_type in ["archive", "zip"]
        assert result.features_extracted > 0
    
    def test_ctags_integration(self, tmp_path):
        """Test CTags integration if available"""
        # Create a C source file
        c_file = tmp_path / "test.c"
        c_file.write_text("""
#include <stdio.h>

typedef struct {
    int x;
    int y;
} Point;

int add(int a, int b) {
    return a + b;
}

void main() {
    printf("Hello World\\n");
    Point p = {1, 2};
}
""")
        
        # Analyze with CTags potentially enabled
        analyzer = BinarySniffer()
        result = analyzer.analyze_file(str(c_file))
        
        assert result.error is None
        assert result.file_type == "source"
        assert result.features_extracted > 0
        
        # Should have processed the source file
        assert result.analysis_time > 0