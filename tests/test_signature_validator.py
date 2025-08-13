"""
Test signature validation and filtering
"""

import pytest
from binarysniffer.signatures.validator import SignatureValidator


class TestSignatureValidator:
    """Test the SignatureValidator class"""
    
    def test_reject_empty_patterns(self):
        """Test that empty or whitespace patterns are rejected"""
        assert not SignatureValidator.is_valid_signature("")
        assert not SignatureValidator.is_valid_signature("   ")
        assert not SignatureValidator.is_valid_signature("\n")
        assert not SignatureValidator.is_valid_signature("\t")
    
    def test_reject_short_patterns(self):
        """Test that very short patterns are rejected"""
        assert not SignatureValidator.is_valid_signature("a")
        assert not SignatureValidator.is_valid_signature("ab")
        assert not SignatureValidator.is_valid_signature("abc")
        # 4 character generic strings should be rejected
        assert not SignatureValidator.is_valid_signature("abcd")
        # But 4 chars with special chars/mixed case should be accepted
        assert SignatureValidator.is_valid_signature("ab_c")
        assert SignatureValidator.is_valid_signature("AbCd")
    
    def test_reject_generic_terms(self):
        """Test that generic programming terms are rejected"""
        generic_terms = [
            'error', 'test', 'init', 'data', 'get', 'set',
            'main', 'config', 'true', 'false', 'null',
            'open', 'close', 'read', 'write', 'debug',
            'info', 'warning', 'start', 'stop', 'run'
        ]
        for term in generic_terms:
            assert not SignatureValidator.is_valid_signature(term), f"Should reject '{term}'"
            # Also test uppercase versions
            assert not SignatureValidator.is_valid_signature(term.upper()), f"Should reject '{term.upper()}'"
    
    def test_accept_library_prefixes(self):
        """Test that known library prefixes are accepted"""
        valid_patterns = [
            'av_codec_init',      # FFmpeg
            'sqlite3_open',       # SQLite
            'curl_easy_init',     # cURL
            'SSL_connect',        # OpenSSL
            'png_create_read',    # libpng
            'jpeg_start_compress', # libjpeg
            'z_stream',           # zlib
            'xml_parse',          # XML
            'boost_system',       # Boost
            'Qt_version'          # Qt
        ]
        for pattern in valid_patterns:
            assert SignatureValidator.is_valid_signature(pattern), f"Should accept '{pattern}'"
    
    def test_reject_pure_numbers(self):
        """Test that pure number strings are rejected"""
        assert not SignatureValidator.is_valid_signature("12345")
        assert not SignatureValidator.is_valid_signature("0000")
        assert not SignatureValidator.is_valid_signature("42")
    
    def test_reject_file_extensions(self):
        """Test that common file extensions are rejected"""
        extensions = ['.txt', '.jpg', '.png', '.xml', '.json', '.zip']
        for ext in extensions:
            assert not SignatureValidator.is_valid_signature(ext), f"Should reject '{ext}'"
    
    def test_accept_special_characters(self):
        """Test that patterns with special characters are accepted"""
        valid_patterns = [
            'my_function_name',
            'MyClass::method',
            'package.ClassName',
            'lib-name-v2',
            'function()',
            'array[index]',
            'pointer->member'
        ]
        for pattern in valid_patterns:
            assert SignatureValidator.is_valid_signature(pattern), f"Should accept '{pattern}'"
    
    def test_accept_mixed_case(self):
        """Test that mixed case patterns are accepted"""
        valid_patterns = [
            'MyClassName',
            'camelCaseFunction',
            'HTTPSConnection',
            'XMLParser',
            'iOS_Version'
        ]
        for pattern in valid_patterns:
            assert SignatureValidator.is_valid_signature(pattern), f"Should accept '{pattern}'"
    
    def test_filter_signatures_list(self):
        """Test filtering a list of signatures"""
        signatures = [
            {'pattern': 'test', 'confidence': 0.8},         # Should be rejected (generic)
            {'pattern': 'av_codec_open', 'confidence': 0.9}, # Should be accepted (library prefix)
            {'pattern': 'a', 'confidence': 0.7},            # Should be rejected (too short)
            {'pattern': 'MyUniqueClass', 'confidence': 0.85}, # Should be accepted (mixed case)
            {'pattern': '12345', 'confidence': 0.6},        # Should be rejected (pure numbers)
            {'pattern': 'unique_library_function', 'confidence': 0.8} # Should be accepted
        ]
        
        filtered = SignatureValidator.filter_signatures(signatures)
        
        # Check that only valid signatures remain
        assert len(filtered) == 3
        patterns = [sig['pattern'] for sig in filtered]
        assert 'av_codec_open' in patterns
        assert 'MyUniqueClass' in patterns
        assert 'unique_library_function' in patterns
        assert 'test' not in patterns
        assert 'a' not in patterns
        assert '12345' not in patterns
    
    def test_signature_quality_score(self):
        """Test calculation of signature quality scores"""
        # High quality signatures
        high_quality = [
            {'pattern': 'unique_library_specific_function', 'confidence': 0.9},
            {'pattern': 'MyVerySpecificClassName', 'confidence': 0.85},
            {'pattern': 'component::detailed::method', 'confidence': 0.95}
        ]
        high_score = SignatureValidator.calculate_signature_quality_score(high_quality)
        assert high_score > 0.7, "High quality signatures should have high score"
        
        # Low quality signatures
        low_quality = [
            {'pattern': 'test', 'confidence': 0.5},
            {'pattern': 'data', 'confidence': 0.4},
            {'pattern': 'init', 'confidence': 0.6}
        ]
        low_score = SignatureValidator.calculate_signature_quality_score(low_quality)
        assert low_score < 0.3, "Low quality signatures should have low score"
    
    def test_get_signature_issues(self):
        """Test getting issues with signature patterns"""
        # Test short pattern
        issues = SignatureValidator.get_signature_issues("ab")
        assert any("too short" in issue.lower() for issue in issues)
        
        # Test generic term
        issues = SignatureValidator.get_signature_issues("test")
        assert any("generic" in issue.lower() for issue in issues)
        
        # Test number-only pattern
        issues = SignatureValidator.get_signature_issues("12345")
        assert any("number" in issue.lower() for issue in issues)
        
        # Test valid pattern (should have no issues)
        issues = SignatureValidator.get_signature_issues("unique_library_function_v2")
        assert len(issues) == 0, "Valid pattern should have no issues"
    
    def test_reject_common_prefixes(self):
        """Test that common method prefixes are rejected when too generic"""
        # These should be rejected (too generic)
        assert not SignatureValidator.is_valid_signature("getItem")
        assert not SignatureValidator.is_valid_signature("setName")
        assert not SignatureValidator.is_valid_signature("isValid")
        assert not SignatureValidator.is_valid_signature("hasData")
        
        # But longer, more specific versions should be accepted
        assert SignatureValidator.is_valid_signature("getComplexDataStructure")
        assert SignatureValidator.is_valid_signature("setDatabaseConnectionParams")
    
    def test_accept_version_strings(self):
        """Test that version strings and patterns with numbers are accepted"""
        valid_patterns = [
            'version_2_0_1',
            'libname_v3',
            'component2',
            'feature_20230101',
            'build_12345'
        ]
        for pattern in valid_patterns:
            assert SignatureValidator.is_valid_signature(pattern), f"Should accept '{pattern}'"
    
    def test_reject_single_words(self):
        """Test that single common words are rejected"""
        common_words = ['client', 'server', 'parse', 'format', 'encode', 'decode']
        for word in common_words:
            assert not SignatureValidator.is_valid_signature(word), f"Should reject '{word}'"
    
    def test_accept_long_patterns(self):
        """Test that long patterns are generally accepted"""
        long_patterns = [
            'this_is_a_very_specific_function_name',
            'ComponentManagerFactoryInstance',
            'extremely_detailed_error_message_handler'
        ]
        for pattern in long_patterns:
            assert SignatureValidator.is_valid_signature(pattern), f"Should accept long pattern '{pattern}'"