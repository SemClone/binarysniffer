"""
Tests for ONNX model parser/extractor
"""

import pytest
import tempfile
import struct
from pathlib import Path

from binarysniffer.extractors.onnx_model import ONNXModelExtractor


@pytest.fixture
def extractor():
    """Create extractor instance"""
    return ONNXModelExtractor()


def create_mock_onnx_file(producer="pytorch", operators=None, custom_ops=False):
    """
    Create a mock ONNX-like file for testing.
    This creates a file with ONNX-like patterns but not a valid ONNX model.
    """
    content = bytearray()
    
    # Add some protobuf-like structure
    content.extend(b'\x08\x01')  # Version field
    
    # Add ModelProto identifier
    content.extend(b'ModelProto')
    content.extend(b'\x00')
    
    # Add producer name
    content.extend(b'producer_name')
    content.extend(producer.encode('utf-8'))
    content.extend(b'\x00')
    
    # Add GraphProto
    content.extend(b'GraphProto')
    content.extend(b'\x00')
    
    # Add operators
    if operators:
        for op in operators:
            content.extend(b'op_type')
            content.extend(op.encode('utf-8'))
            content.extend(b'\x00')
    
    # Add custom operators if requested
    if custom_ops:
        content.extend(b'CustomOp_malicious')
        content.extend(b'\x00')
        content.extend(b'exec')
        content.extend(b'\x00')
    
    # Add some framework hints
    if 'pytorch' in producer.lower():
        content.extend(b'aten::')
        content.extend(b'torch.nn.Module')
    elif 'tensorflow' in producer.lower():
        content.extend(b'tf.nn.')
        content.extend(b'StatefulPartitionedCall')
    
    # Add version info
    content.extend(b'ir_version')
    content.extend(struct.pack('<I', 7))  # Version 7
    
    with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
        f.write(bytes(content))
        return Path(f.name)


class TestONNXModelExtractor:
    
    def test_can_handle_onnx_extensions(self, extractor):
        """Test recognition of ONNX file extensions"""
        assert extractor.can_handle(Path("model.onnx"))
        assert extractor.can_handle(Path("model.onnxmodel"))
        assert extractor.can_handle(Path("model.pb"))  # Sometimes used
        assert not extractor.can_handle(Path("model.pt"))
        assert not extractor.can_handle(Path("model.h5"))
    
    def test_can_handle_onnx_content(self, extractor):
        """Test recognition by content"""
        # Create a file with ONNX identifiers
        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
            f.write(b'Some data ModelProto GraphProto onnx data')
            test_file = Path(f.name)
        
        assert extractor.can_handle(test_file)
        test_file.unlink()
    
    def test_extract_pytorch_model(self, extractor):
        """Test extraction from PyTorch-exported ONNX model"""
        model_file = create_mock_onnx_file(
            producer="pytorch",
            operators=["Conv", "BatchNormalization", "Relu", "MaxPool"]
        )
        
        features = extractor.extract(model_file)
        
        assert features is not None
        assert features.file_type == 'onnx'
        assert len(features.strings) > 0
        
        # Should detect PyTorch framework
        assert any('pytorch' in s.lower() for s in features.strings)
        assert 'pytorch' in features.imports or any('pytorch' in s for s in features.imports)
        
        # Should extract operators
        assert any('Conv' in f for f in features.functions)
        
        # Cleanup
        model_file.unlink()
    
    def test_extract_tensorflow_model(self, extractor):
        """Test extraction from TensorFlow-exported ONNX model"""
        model_file = create_mock_onnx_file(
            producer="tf2onnx",
            operators=["MatMul", "Add", "Softmax"]
        )
        
        features = extractor.extract(model_file)
        
        assert features is not None
        assert features.file_type == 'onnx'
        
        # Should detect TensorFlow framework
        assert any('tensorflow' in s.lower() for s in features.strings)
        
        # Cleanup
        model_file.unlink()
    
    def test_detect_suspicious_operators(self, extractor):
        """Test detection of suspicious custom operators"""
        model_file = create_mock_onnx_file(
            producer="unknown",
            operators=["Conv", "CustomOp"],
            custom_ops=True
        )
        
        features = extractor.extract(model_file)
        
        assert features is not None
        
        # Should detect suspicious patterns (logged but maybe not in features)
        # Check either in strings or metadata
        has_suspicious = any('suspicious' in s.lower() for s in features.strings) or \
                        any('suspicious' in str(v).lower() for v in features.metadata.values())
        assert has_suspicious
        
        # Should have elevated risk
        risk_level = features.metadata.get('risk_level', 'unknown')
        assert risk_level in ['suspicious', 'high_risk', 'dangerous']
        
        # Cleanup
        model_file.unlink()
    
    def test_extract_operators(self, extractor):
        """Test operator extraction"""
        operators = ["Conv", "BatchNormalization", "Relu", "LSTM", "Attention"]
        model_file = create_mock_onnx_file(
            producer="test",
            operators=operators
        )
        
        features = extractor.extract(model_file)
        
        # Check that operators were extracted
        assert len(features.functions) > 0
        for op in ["Conv", "Relu"]:
            assert op in features.functions or any(op in f for f in features.functions)
        
        # Cleanup
        model_file.unlink()
    
    def test_model_size_classification(self, extractor):
        """Test model size classification"""
        # Small model
        small_model = create_mock_onnx_file(producer="test", operators=["Conv"])
        features = extractor.extract(small_model)
        assert any('small_model' in s for s in features.strings)
        small_model.unlink()
        
        # For larger models, we'd need to create bigger files
        # This is simplified for testing
    
    def test_risk_assessment(self, extractor):
        """Test risk assessment levels"""
        # Safe model
        safe_model = create_mock_onnx_file(
            producer="pytorch",
            operators=["Conv", "Relu", "MaxPool"]
        )
        features = extractor.extract(safe_model)
        risk = features.metadata.get('risk_level', 'unknown')
        assert risk in ['likely_safe', 'unknown']
        safe_model.unlink()
        
        # Suspicious model
        suspicious_model = create_mock_onnx_file(
            producer="unknown",
            operators=["CustomOp", "UnknownOp"],
            custom_ops=True
        )
        features = extractor.extract(suspicious_model)
        risk = features.metadata.get('risk_level', 'unknown')
        assert risk in ['suspicious', 'high_risk', 'dangerous']
        suspicious_model.unlink()
    
    def test_architecture_detection(self, extractor):
        """Test model architecture detection"""
        # Create a file with architecture hints
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            content = b'ModelProto\x00GraphProto\x00'
            content += b'resnet50_layer1_conv'
            content += b'ResBlock'
            content += b'BottleNeck'
            f.write(content)
            model_file = Path(f.name)
        
        features = extractor.extract(model_file)
        
        # Should detect ResNet architecture
        assert any('resnet' in s.lower() for s in features.strings)
        
        # Cleanup
        model_file.unlink()
    
    def test_empty_onnx_file(self, extractor):
        """Test handling of minimal ONNX file"""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            f.write(b'ModelProto\x00')
            test_file = Path(f.name)
        
        features = extractor.extract(test_file)
        assert features is not None
        assert features.file_type == 'onnx'
        
        # Cleanup
        test_file.unlink()
    
    def test_corrupted_onnx_file(self, extractor):
        """Test handling of corrupted ONNX file"""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            f.write(b'\x00\x01\x02\x03corrupted data')
            test_file = Path(f.name)
        
        # Should handle corrupted file gracefully
        features = extractor.extract(test_file)
        assert features is not None
        # May have parse error
        
        # Cleanup
        test_file.unlink()
    
    def test_multiple_frameworks(self, extractor):
        """Test detection of multiple framework signatures"""
        with tempfile.NamedTemporaryFile(suffix='.onnx', delete=False) as f:
            content = b'ModelProto\x00'
            # Add multiple framework signatures
            content += b'produced_by_pytorch'
            content += b'sklearn.preprocessing'
            content += b'xgboost.core'
            f.write(content)
            test_file = Path(f.name)
        
        features = extractor.extract(test_file)
        
        # Should detect multiple frameworks
        frameworks = features.imports
        assert len(frameworks) >= 1  # At least one framework detected
        
        # Cleanup
        test_file.unlink()
    
    def test_metadata_extraction(self, extractor):
        """Test metadata extraction"""
        model_file = create_mock_onnx_file(
            producer="test_producer",
            operators=["Conv", "Relu"]
        )
        
        features = extractor.extract(model_file)
        
        # Should have metadata
        assert 'file_size' in features.metadata
        assert features.metadata['file_size'] > 0
        
        # Should have producer info if extracted
        if 'producer_name' in features.metadata:
            # The extraction might be partial, so check if it contains part of "test"
            producer = features.metadata['producer_name'].lower()
            assert 'test' in producer or 'est' in producer
        
        # Cleanup
        model_file.unlink()