"""
Comprehensive tests for the ML security module
"""

import pytest
import tempfile
import pickle
import json
from pathlib import Path
from unittest.mock import Mock, patch

from binarysniffer.security.patterns import MaliciousPatterns, ThreatPattern, ThreatSeverity
from binarysniffer.security.risk_scorer import RiskScorer, RiskLevel, RiskAssessment
from binarysniffer.security.pickle_analyzer import PickleSecurityAnalyzer
from binarysniffer.security.obfuscation import ObfuscationDetector
from binarysniffer.security.validators import ModelIntegrityValidator, ValidationStatus


class TestMaliciousPatterns:
    """Test malicious pattern database"""
    
    def test_get_all_patterns(self):
        """Test retrieving all patterns"""
        patterns = MaliciousPatterns.get_all_patterns()
        assert len(patterns) > 0
        assert all(isinstance(p, ThreatPattern) for p in patterns)
    
    def test_critical_patterns_exist(self):
        """Test that critical patterns exist"""
        all_patterns = MaliciousPatterns.get_all_patterns()
        critical = [p for p in all_patterns if p.severity == ThreatSeverity.CRITICAL]
        assert len(critical) > 0
        assert all(p.severity == ThreatSeverity.CRITICAL for p in critical)
    
    def test_check_pattern_detection(self):
        """Test pattern detection in text"""
        test_cases = [
            ("import os.system", ["os.system"]),
            ("subprocess.Popen('/bin/bash')", ["subprocess.Popen", "/bin/bash"]),
            ("base64.b64decode(data)", ["base64.b64decode"]),
            ("innocent text", []),
        ]
        
        for text, expected_patterns in test_cases:
            matches = MaliciousPatterns.check_pattern(text)
            found_patterns = [m[0].pattern for m in matches]
            for expected in expected_patterns:
                assert any(expected in p for p in found_patterns), f"Expected {expected} in {found_patterns}"
    
    def test_patterns_have_categories(self):
        """Test that patterns have valid categories"""
        all_patterns = MaliciousPatterns.get_all_patterns()
        categories = ['code_execution', 'network', 'shell', 'obfuscation']
        
        for category in categories:
            patterns = [p for p in all_patterns if p.category == category]
            assert len(patterns) > 0, f"No patterns found for category {category}"
            assert all(p.category == category for p in patterns)


class TestRiskScorer:
    """Test risk scoring engine"""
    
    def test_safe_model_assessment(self):
        """Test assessment of safe model"""
        scorer = RiskScorer()
        features = {
            "ml_framework:pytorch",
            "pickle_string:torch.nn.Module",
            "pickle_import:torch.tensor"
        }
        
        assessment = scorer.calculate_risk(features)
        assert assessment.level in [RiskLevel.SAFE, RiskLevel.LOW]
        assert assessment.score < 40
    
    def test_malicious_model_assessment(self):
        """Test assessment of malicious model"""
        scorer = RiskScorer()
        features = {
            "import:os.system",
            "dangerous_call:subprocess.Popen",
            "suspicious:reverse_shell_pattern",
            "string_pattern:/bin/bash"
        }
        
        assessment = scorer.calculate_risk(features)
        assert assessment.level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert assessment.score >= 60
        assert len(assessment.indicators) > 0
        assert len(assessment.recommendations) > 0
    
    def test_malformed_file_assessment(self):
        """Test assessment of malformed file"""
        scorer = RiskScorer()
        features = {
            "pickle_parse_error",
            "malformed_pickle:invalid_opcode"
        }
        
        assessment = scorer.calculate_risk(features)
        assert assessment.level == RiskLevel.MALFORMED
        assert "malformed" in assessment.summary.lower()
    
    def test_risk_level_calculation(self):
        """Test risk level thresholds"""
        scorer = RiskScorer()
        
        test_cases = [
            (0, RiskLevel.SAFE),
            (15, RiskLevel.SAFE),  # Below 20 threshold
            (20, RiskLevel.LOW),   # At LOW threshold
            (25, RiskLevel.LOW),
            (40, RiskLevel.MEDIUM), # At MEDIUM threshold
            (45, RiskLevel.MEDIUM),
            (60, RiskLevel.HIGH),   # At HIGH threshold
            (65, RiskLevel.HIGH),
            (80, RiskLevel.CRITICAL), # At CRITICAL threshold
            (85, RiskLevel.CRITICAL),
            (100, RiskLevel.CRITICAL),
        ]
        
        for score, expected_level in test_cases:
            level = scorer._calculate_risk_level(score)
            assert level == expected_level, f"Score {score} should be {expected_level}, got {level}"


class TestPickleSecurityAnalyzer:
    """Test pickle security analyzer"""
    
    def test_safe_pickle_analysis(self):
        """Test analysis of safe pickle file"""
        # Create a safe pickle file with some ML framework indicators
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Include some torch-like data to trigger feature extraction
            safe_data = {
                'model': 'test',
                'weights': [1, 2, 3],
                'torch.nn.Module': 'fake_module',
                'sklearn_model': 'test'
            }
            pickle.dump(safe_data, f)
            temp_path = f.name
        
        try:
            analyzer = PickleSecurityAnalyzer()
            risk_assessment, features = analyzer.analyze_pickle(temp_path)
            
            assert risk_assessment.level in [RiskLevel.SAFE, RiskLevel.LOW]
            # For a completely safe file with ML indicators, we should get some features
            # If no suspicious features found, that's also valid
            assert risk_assessment.level == RiskLevel.SAFE or len(features) > 0
        finally:
            Path(temp_path).unlink()
    
    def test_malicious_pickle_detection(self):
        """Test detection of malicious pickle patterns"""
        analyzer = PickleSecurityAnalyzer()
        
        # Test dangerous opcode detection
        opcodes = analyzer._analyze_opcodes(b'\x80\x04\x95\x15\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94\x8c\x06system\x94\x93\x94.')
        
        # Should detect either GLOBAL or STACK_GLOBAL
        assert 'opcode:GLOBAL' in opcodes['features'] or 'opcode:STACK_GLOBAL' in opcodes['features']
        assert any('os.system' in imp for imp in opcodes['imports'])
        assert len(opcodes['dangerous_calls']) > 0
    
    def test_string_extraction(self):
        """Test string extraction from binary content"""
        analyzer = PickleSecurityAnalyzer()
        
        test_content = b'Hello\x00World\x01TestString123\xff'
        strings = analyzer._extract_strings(test_content)
        
        assert 'Hello' in strings
        assert 'World' in strings
        assert 'TestString123' in strings
    
    def test_entropy_calculation(self):
        """Test entropy calculation for obfuscation detection"""
        analyzer = PickleSecurityAnalyzer()
        
        # Low entropy (repetitive)
        low_entropy_data = b'A' * 100
        low_entropy = analyzer._calculate_entropy(low_entropy_data)
        assert low_entropy < 2
        
        # High entropy (random)
        import os
        high_entropy_data = os.urandom(100)
        high_entropy = analyzer._calculate_entropy(high_entropy_data)
        assert high_entropy > 5


class TestObfuscationDetector:
    """Test obfuscation detection"""
    
    def test_entropy_detection(self):
        """Test entropy-based obfuscation detection"""
        detector = ObfuscationDetector()
        
        # High entropy content
        import os
        random_content = os.urandom(1000)
        result = detector.detect_obfuscation(random_content)
        
        assert result['is_obfuscated'] == True
        assert 'high_entropy' in result['techniques']
        assert result['confidence'] >= 0.9
    
    def test_base64_detection(self):
        """Test base64 encoding detection"""
        detector = ObfuscationDetector()
        
        import base64
        encoded = base64.b64encode(b"test data" * 10)
        result = detector.detect_obfuscation(encoded)
        
        assert any('base64' in tech for tech in result['techniques'])
    
    def test_encoding_function_detection(self):
        """Test detection of encoding functions"""
        detector = ObfuscationDetector()
        
        features = {
            "import:base64.b64decode",
            "import:zlib.decompress",
            "string:marshal.loads"
        }
        
        result = detector.detect_obfuscation(b"", features)
        assert result['is_obfuscated'] == True
        assert 'encoding_function' in result['techniques']
    
    def test_layered_obfuscation(self):
        """Test detection of multiple obfuscation layers"""
        detector = ObfuscationDetector()
        
        # Test with high entropy data (random bytes) - need more bytes for higher entropy
        import os
        high_entropy_content = os.urandom(1000)  # Larger sample for higher entropy
        
        result = detector.detect_obfuscation(high_entropy_content)
        assert result['is_obfuscated'] == True
        assert 'high_entropy' in result['techniques']
        
        # Also test with encoding function features
        features = {'import:base64.b64decode', 'import:zlib.decompress'}
        result2 = detector.detect_obfuscation(b"some data", features)
        assert result2['is_obfuscated'] == True
        assert 'encoding_function' in result2['techniques']


class TestModelIntegrityValidator:
    """Test model integrity validation"""
    
    def test_file_existence_check(self):
        """Test file existence validation"""
        validator = ModelIntegrityValidator()
        
        # Non-existent file
        result = validator.validate_model("/nonexistent/file.pkl")
        assert result.status == ValidationStatus.INVALID
        assert any(c.check_type == 'file_existence' for c in result.checks)
    
    def test_file_size_validation(self):
        """Test file size validation"""
        validator = ModelIntegrityValidator()
        
        # Create test file
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            f.write(b'A' * 1000)
            temp_path = f.name
        
        try:
            result = validator.validate_model(temp_path, 'pickle')
            size_check = next((c for c in result.checks if c.check_type == 'file_size'), None)
            assert size_check is not None
            assert size_check.status == ValidationStatus.VALID
        finally:
            Path(temp_path).unlink()
    
    def test_hash_verification(self):
        """Test file hash verification"""
        validator = ModelIntegrityValidator()
        
        # Create test file
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            f.write(b'test content')
            temp_path = f.name
        
        try:
            import hashlib
            with open(temp_path, 'rb') as f:
                expected_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Test with correct hash
            result = validator.validate_model(temp_path, expected_hash=expected_hash)
            hash_check = next((c for c in result.checks if c.check_type == 'hash_verification'), None)
            assert hash_check.status == ValidationStatus.VALID
            
            # Test with wrong hash
            wrong_hash = 'a' * 64
            result = validator.validate_model(temp_path, expected_hash=wrong_hash)
            hash_check = next((c for c in result.checks if c.check_type == 'hash_verification'), None)
            assert hash_check.status == ValidationStatus.INVALID
        finally:
            Path(temp_path).unlink()
    
    def test_format_validation(self):
        """Test file format validation"""
        validator = ModelIntegrityValidator()
        
        # Test pickle format
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            f.write(b'\x80\x04')  # Pickle protocol 4 header
            temp_path = f.name
        
        try:
            result = validator.validate_model(temp_path, 'pickle')
            format_check = next((c for c in result.checks if c.check_type == 'format_validation'), None)
            assert format_check.status == ValidationStatus.VALID
        finally:
            Path(temp_path).unlink()
    
    def test_suspicious_filename_detection(self):
        """Test detection of suspicious filenames"""
        validator = ModelIntegrityValidator()
        
        # Create file with suspicious name
        with tempfile.NamedTemporaryFile(suffix='_backdoor.pkl', delete=False) as f:
            f.write(b'data')
            temp_path = f.name
        
        try:
            result = validator.validate_model(temp_path)
            supply_check = next((c for c in result.checks if c.check_type == 'supply_chain'), None)
            assert supply_check.status == ValidationStatus.SUSPICIOUS
        finally:
            Path(temp_path).unlink()


class TestIntegration:
    """Integration tests for the security module"""
    
    def test_end_to_end_pickle_analysis(self):
        """Test complete pickle file analysis workflow"""
        # Create a suspicious pickle file
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # This would be a real malicious pickle in production tests
            # For safety, we just create a normal pickle
            data = {'model': 'test', 'command': 'os.system'}
            pickle.dump(data, f)
            temp_path = f.name
        
        try:
            # Analyze with all components
            pickle_analyzer = PickleSecurityAnalyzer()
            obfusc_detector = ObfuscationDetector()
            validator = ModelIntegrityValidator()
            
            # Run analysis
            risk_assessment, features = pickle_analyzer.analyze_pickle(temp_path)
            
            with open(temp_path, 'rb') as f:
                content = f.read()
            obfusc_results = obfusc_detector.detect_obfuscation(content, features)
            
            integrity_results = validator.validate_model(temp_path, 'pickle')
            
            # Verify results
            assert risk_assessment is not None
            assert features is not None
            assert obfusc_results is not None
            assert integrity_results is not None
            
        finally:
            Path(temp_path).unlink()
    
    def test_risk_assessment_serialization(self):
        """Test risk assessment JSON serialization"""
        scorer = RiskScorer()
        features = {"test_feature", "ml_framework:pytorch"}
        
        assessment = scorer.calculate_risk(features)
        json_data = assessment.to_dict()
        
        # Verify JSON structure
        assert 'risk_assessment' in json_data
        assert 'indicators' in json_data
        assert 'recommendations' in json_data
        
        # Verify it's JSON serializable
        json_str = json.dumps(json_data)
        assert json_str is not None
    
    def test_validation_result_serialization(self):
        """Test validation result JSON serialization"""
        validator = ModelIntegrityValidator()
        
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            result = validator.validate_model(temp_path)
            json_data = result.to_dict()
            
            # Verify JSON structure
            assert 'status' in json_data
            assert 'checks' in json_data
            assert 'risk_factors' in json_data
            assert 'recommendations' in json_data
            
            # Verify it's JSON serializable
            json_str = json.dumps(json_data)
            assert json_str is not None
            
        finally:
            Path(temp_path).unlink()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])