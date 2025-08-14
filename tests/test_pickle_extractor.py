"""
Tests for pickle file parser/extractor
"""

import pickle
import pytest
import tempfile
from pathlib import Path

from binarysniffer.extractors.pickle_model import PickleModelExtractor

# Try to import numpy but don't fail if not available
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False


@pytest.fixture
def extractor():
    """Create extractor instance"""
    return PickleModelExtractor()


@pytest.fixture
def safe_pickle_file():
    """Create a safe pickle file with ML model-like data"""
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        # Create a simple "model" dictionary
        model_data = {
            'weights': [1.0, 2.0, 3.0],
            'bias': 0.5,
            'model_type': 'linear_regression',
            'version': '1.0.0'
        }
        pickle.dump(model_data, f)
        return Path(f.name)


@pytest.fixture
def sklearn_like_pickle():
    """Create a pickle that looks like sklearn model"""
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        # Simulate sklearn-like data structure
        model_data = {
            '__module__': 'sklearn.linear_model._base',
            '__class__': 'LinearRegression',
            'coef_': [1.0, 2.0, 3.0],
            'intercept_': 0.5,
            'n_iter_': 100,
            'fit_intercept': True
        }
        pickle.dump(model_data, f, protocol=2)
        return Path(f.name)


@pytest.fixture
def numpy_pickle_file():
    """Create a pickle with numpy arrays"""
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        if HAS_NUMPY:
            # Use numpy if available
            data = {
                'array': np.array([1, 2, 3, 4, 5]),
                'matrix': np.array([[1, 2], [3, 4]]),
                'dtype': np.float32
            }
        else:
            # Fallback if numpy not available
            data = {
                'array': [1, 2, 3, 4, 5],
                'matrix': [[1, 2], [3, 4]],
                'dtype': 'float32'
            }
        pickle.dump(data, f)
        return Path(f.name)


def create_malicious_pickle(command):
    """
    Create a malicious pickle file (for testing only!)
    This creates a pickle that would execute a command when loaded.
    DO NOT UNPICKLE THIS!
    """
    import os
    import tempfile
    
    class Exploit:
        def __reduce__(self):
            # This would execute when unpickled - dangerous!
            return (os.system, (command,))
    
    with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
        pickle.dump(Exploit(), f)
        return Path(f.name)


class TestPickleModelExtractor:
    
    def test_can_handle_pickle_extensions(self, extractor):
        """Test recognition of pickle file extensions"""
        assert extractor.can_handle(Path("model.pkl"))
        assert extractor.can_handle(Path("model.pickle"))
        assert extractor.can_handle(Path("model.p"))
        assert extractor.can_handle(Path("model.pth"))
        assert not extractor.can_handle(Path("model.txt"))
        assert not extractor.can_handle(Path("model.json"))
    
    def test_extract_safe_pickle(self, extractor, safe_pickle_file):
        """Test extraction from safe pickle file"""
        features = extractor.extract(safe_pickle_file)
        
        assert features is not None
        assert features.file_type == 'pickle'
        assert len(features.strings) > 0
        
        # Should detect as likely safe or unknown
        risk_features = [s for s in features.strings if s.startswith('pickle_risk:')]
        assert any('safe' in s or 'unknown' in s for s in risk_features)
        
        # Cleanup
        safe_pickle_file.unlink()
    
    def test_extract_sklearn_like(self, extractor, sklearn_like_pickle):
        """Test extraction from sklearn-like pickle"""
        features = extractor.extract(sklearn_like_pickle)
        
        assert features is not None
        assert features.file_type == 'pickle'
        
        # Should detect sklearn patterns
        assert any('sklearn' in s for s in features.strings)
        
        # Cleanup
        sklearn_like_pickle.unlink()
    
    def test_extract_numpy_pickle(self, extractor, numpy_pickle_file):
        """Test extraction from pickle with numpy data"""
        features = extractor.extract(numpy_pickle_file)
        
        assert features is not None
        assert features.file_type == 'pickle'
        
        # May detect numpy if it's actually imported
        strings_lower = [s.lower() for s in features.strings]
        # At minimum should extract some features
        assert len(features.strings) > 0
        
        # Cleanup
        numpy_pickle_file.unlink()
    
    def test_detect_malicious_os_system(self, extractor):
        """Test detection of malicious pickle with os.system"""
        # Create a malicious pickle (safely, for testing only)
        malicious_file = create_malicious_pickle("echo 'test'")
        
        features = extractor.extract(malicious_file)
        
        assert features is not None
        assert features.file_type == 'pickle'
        
        # Should detect dangerous patterns
        assert any('dangerous_import:os.system' in s for s in features.strings)
        assert any('pickle_risk:dangerous' in s for s in features.strings)
        
        # Should NOT be safe to unpickle
        assert not extractor.validate_safe_unpickle(malicious_file)
        
        # Cleanup
        malicious_file.unlink()
    
    def test_detect_reduce_opcode(self, extractor):
        """Test detection of REDUCE opcode"""
        malicious_file = create_malicious_pickle("ls")
        
        features = extractor.extract(malicious_file)
        
        # Should detect REDUCE opcode
        assert any('pickle_opcode:REDUCE' in s for s in features.strings)
        
        # Cleanup
        malicious_file.unlink()
    
    def test_validate_safe_unpickle(self, extractor, safe_pickle_file):
        """Test safe unpickle validation"""
        # Safe pickle should pass validation
        assert extractor.validate_safe_unpickle(safe_pickle_file) == True
        
        # Malicious pickle should fail validation
        malicious_file = create_malicious_pickle("whoami")
        assert extractor.validate_safe_unpickle(malicious_file) == False
        
        # Cleanup
        safe_pickle_file.unlink()
        malicious_file.unlink()
    
    def test_suspicious_strings_detection(self, extractor):
        """Test detection of suspicious string patterns"""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            # Create pickle with suspicious strings
            data = {
                'cmd': '/bin/sh',
                'payload': 'reverse_tcp',
                'encoded': 'base64.b64decode'
            }
            pickle.dump(data, f)
            test_file = Path(f.name)
        
        features = extractor.extract(test_file)
        
        # Should detect suspicious patterns
        assert any('suspicious_string' in s for s in features.strings)
        assert any('/bin/sh' in s.lower() for s in features.strings)
        
        # Cleanup
        test_file.unlink()
    
    def test_protocol_versions(self, extractor):
        """Test handling of different pickle protocol versions"""
        for protocol in range(3):  # Test protocols 0, 1, 2
            with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
                data = {'protocol': protocol, 'test': True}
                pickle.dump(data, f, protocol=protocol)
                test_file = Path(f.name)
            
            # Should handle all protocol versions
            assert extractor.can_handle(test_file)
            features = extractor.extract(test_file)
            assert features is not None
            assert len(features.strings) > 0
            
            # Cleanup
            test_file.unlink()
    
    def test_empty_pickle(self, extractor):
        """Test handling of empty/minimal pickle file"""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            pickle.dump(None, f)
            test_file = Path(f.name)
        
        features = extractor.extract(test_file)
        assert features is not None
        assert features.file_type == 'pickle'
        # Even empty pickle should have some structure opcodes
        assert len(features.strings) > 0
        
        # Cleanup
        test_file.unlink()
    
    def test_corrupted_pickle(self, extractor):
        """Test handling of corrupted pickle file"""
        with tempfile.NamedTemporaryFile(suffix='.pkl', delete=False) as f:
            f.write(b'\x80\x03corrupted data here')
            test_file = Path(f.name)
        
        # Should handle corrupted file gracefully
        features = extractor.extract(test_file)
        assert features is not None
        assert 'pickle_parse_error' in features.strings
        
        # Cleanup
        test_file.unlink()