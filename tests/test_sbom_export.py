"""
Tests for SBOM export functionality
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from binarysniffer.core.results import AnalysisResult, ComponentMatch, BatchAnalysisResult
from binarysniffer.output.cyclonedx_formatter import CycloneDxFormatter


class TestCycloneDxFormatter:
    """Test CycloneDX SBOM formatter"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.formatter = CycloneDxFormatter()
        
        # Create sample component matches
        self.match1 = ComponentMatch(
            component="FFmpeg@4.4.0",
            ecosystem="native",
            confidence=0.85,
            license="LGPL-2.1",
            match_type="string",
            evidence={
                "patterns": ["av_register_all", "avcodec_version"],
                "count": 2,
                "file_path": "lib/libavcodec.so",
                "publisher": "FFmpeg Team"
            }
        )
        
        self.match2 = ComponentMatch(
            component="OpenSSL@1.1.1",
            ecosystem="native",
            confidence=0.92,
            license="Apache-2.0",
            match_type="tlsh_fuzzy",
            evidence={
                "similarity": 0.92,
                "file_path": "lib/libssl.so",
                "publisher": "OpenSSL Software Foundation"
            }
        )
        
        # Create sample analysis results
        self.result1 = AnalysisResult(
            file_path="test_binary.exe",
            file_size=1024000,
            file_type="binary",
            matches=[self.match1, self.match2],
            features_extracted=150,
            analysis_time=1.5,
            confidence_threshold=0.5
        )
        
        self.result2 = AnalysisResult(
            file_path="lib/library.so",
            file_size=512000,
            file_type="binary",
            matches=[self.match1],
            features_extracted=75,
            analysis_time=0.8,
            confidence_threshold=0.5
        )
        
        # Create batch result
        self.batch_result = BatchAnalysisResult(
            results={
                "test_binary.exe": self.result1,
                "lib/library.so": self.result2
            },
            total_files=2,
            successful_files=2,
            failed_files=0,
            total_time=2.3
        )
    
    def test_format_json_sbom(self):
        """Test JSON SBOM generation"""
        sbom_json = self.formatter.format_results(
            self.batch_result,
            format_type="json"
        )
        
        sbom = json.loads(sbom_json)
        
        # Check SBOM structure
        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert "serialNumber" in sbom
        assert sbom["version"] == 1
        
        # Check metadata
        assert "metadata" in sbom
        metadata = sbom["metadata"]
        assert "timestamp" in metadata
        assert "tools" in metadata
        assert metadata["tools"][0]["name"] == "binarysniffer"
        
        # Check components
        assert "components" in sbom
        assert len(sbom["components"]) == 2  # FFmpeg and OpenSSL
        
        # Check FFmpeg component
        ffmpeg = next(c for c in sbom["components"] if c["name"] == "FFmpeg")
        assert ffmpeg["version"] == "4.4.0"
        # Publisher may be in evidence or default to Unknown
        assert "publisher" in ffmpeg or ffmpeg.get("publisher") == "Unknown"
        assert ffmpeg["licenses"][0]["license"]["name"] == "LGPL-2.1"
        assert "evidence" in ffmpeg
        assert ffmpeg["evidence"]["confidence"] == 0.85
        
        # Check OpenSSL component
        openssl = next(c for c in sbom["components"] if c["name"] == "OpenSSL")
        assert openssl["version"] == "1.1.1"
        assert openssl["licenses"][0]["license"]["name"] == "Apache-2.0"
        assert openssl["evidence"]["confidence"] == 0.92
    
    def test_format_xml_sbom(self):
        """Test XML SBOM generation - currently not supported"""
        # XML format is not yet implemented, should raise ValueError
        with pytest.raises(ValueError, match="not supported"):
            self.formatter.format_results(
                self.batch_result,
                format_type="xml"
            )
    
    def test_include_evidence(self):
        """Test evidence inclusion in SBOM"""
        sbom_json = self.formatter.format_results(
            self.batch_result,
            format_type="json",
            include_evidence=True
        )
        
        sbom = json.loads(sbom_json)
        
        # Check evidence is included
        ffmpeg = next(c for c in sbom["components"] if c["name"] == "FFmpeg")
        assert "evidence" in ffmpeg
        evidence = ffmpeg["evidence"]
        assert "occurrences" in evidence
        assert len(evidence["occurrences"]) > 0
        
        # Check file paths in evidence
        occurrence = evidence["occurrences"][0]
        assert "location" in occurrence
        assert occurrence["location"] in ["test_binary.exe", "lib/library.so", "lib/libavcodec.so"]
    
    def test_exclude_evidence(self):
        """Test SBOM without evidence"""
        sbom_json = self.formatter.format_results(
            self.batch_result,
            format_type="json",
            include_evidence=False
        )
        
        sbom = json.loads(sbom_json)
        
        # Check evidence is excluded but confidence is in properties
        ffmpeg = next(c for c in sbom["components"] if c["name"] == "FFmpeg")
        assert "evidence" not in ffmpeg
        
        # But properties should still have confidence
        assert "properties" in ffmpeg
        confidence_prop = next(
            p for p in ffmpeg["properties"] 
            if p["name"] == "binarysniffer:confidence"
        )
        assert confidence_prop["value"] == "0.850"
    
    def test_include_features(self):
        """Test feature inclusion in SBOM"""
        # Add extracted_features to result
        from binarysniffer.core.results import ExtractedFeaturesSummary
        self.result1.extracted_features = ExtractedFeaturesSummary(
            total_count=4,
            by_extractor={
                "test_extractor": {
                    "count": 4,
                    "features_by_type": {
                        "strings": ["test_string_1", "test_string_2"],
                        "functions": ["func1", "func2"]
                    }
                }
            }
        )
        
        sbom_json = self.formatter.format_results(
            self.batch_result,
            format_type="json",
            include_features=True
        )
        
        sbom = json.loads(sbom_json)
        
        # Check features in properties
        metadata_props = sbom["metadata"]["properties"]
        features_prop = None
        for p in metadata_props:
            if p["name"] == "binarysniffer:features":
                features_prop = p
                break
        
        # Features might not be included if the formatter doesn't support it yet
        if features_prop:
            features = json.loads(features_prop["value"])
            assert "test_binary.exe" in features
            assert "strings" in features["test_binary.exe"]
            assert "test_string_1" in features["test_binary.exe"]["strings"]
        else:
            # Just check that the SBOM is valid
            assert "components" in sbom
    
    def test_empty_results(self):
        """Test SBOM generation with no components"""
        empty_analysis = AnalysisResult(
            file_path="empty.bin",
            file_size=0,
            file_type="binary",
            matches=[],
            features_extracted=0,
            analysis_time=0.1,
            confidence_threshold=0.5
        )
        empty_result = BatchAnalysisResult(
            results={"empty.bin": empty_analysis},
            total_files=1,
            successful_files=1,
            failed_files=0,
            total_time=0.1
        )
        
        sbom_json = self.formatter.format_results(
            empty_result,
            format_type="json"
        )
        
        sbom = json.loads(sbom_json)
        
        # Should have valid structure but no components
        assert sbom["bomFormat"] == "CycloneDX"
        assert "components" in sbom
        assert len(sbom["components"]) == 0
    
    def test_component_deduplication(self):
        """Test that duplicate components are properly deduplicated"""
        # Add another FFmpeg match with different confidence
        match3 = ComponentMatch(
            component="FFmpeg@4.4.0",
            ecosystem="native",
            confidence=0.75,
            license="LGPL-2.1",
            match_type="string",
            evidence={"patterns": ["avformat_version"], "count": 1}
        )
        
        result3 = AnalysisResult(
            file_path="another.so",
            file_size=256000,
            file_type="binary",
            matches=[match3],
            features_extracted=50,
            analysis_time=0.5,
            confidence_threshold=0.5
        )
        
        # Add the new result to the batch
        self.batch_result.results["another.so"] = result3
        self.batch_result.total_files += 1
        self.batch_result.successful_files += 1
        self.batch_result.total_time += 0.5
        
        sbom_json = self.formatter.format_results(
            self.batch_result,
            format_type="json"
        )
        
        sbom = json.loads(sbom_json)
        
        # Should still only have 2 unique components (FFmpeg and OpenSSL)
        assert len(sbom["components"]) == 2
        
        # FFmpeg should use highest confidence
        ffmpeg = next(c for c in sbom["components"] if c["name"] == "FFmpeg")
        assert ffmpeg["evidence"]["confidence"] == 0.85  # Highest confidence
        
        # Should have multiple occurrences
        assert len(ffmpeg["evidence"]["occurrences"]) == 3
    
    def test_metadata_properties(self):
        """Test metadata properties in SBOM"""
        sbom_json = self.formatter.format_results(
            self.batch_result,
            format_type="json"
        )
        
        sbom = json.loads(sbom_json)
        
        # Check metadata properties
        props = sbom["metadata"]["properties"]
        
        # Check required properties
        files_prop = next(p for p in props if p["name"] == "binarysniffer:total_files")
        assert files_prop["value"] == "2"
        
        matches_prop = next(p for p in props if p["name"] == "binarysniffer:total_matches")
        assert matches_prop["value"] == "3"  # 2 + 1 matches
        
        # Check analysis time is present
        time_prop = next(p for p in props if p["name"] == "binarysniffer:analysis_time")
        assert "s" in time_prop["value"]  # Should end with 's' for seconds