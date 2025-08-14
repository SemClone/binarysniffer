"""
Tests for TensorFlow native format extractor
"""

import tempfile
from pathlib import Path

import pytest

from binarysniffer.extractors.tensorflow_native import TensorFlowNativeExtractor


@pytest.fixture
def extractor():
    """Create TensorFlow native extractor instance."""
    return TensorFlowNativeExtractor()


def create_mock_pb_file() -> bytes:
    """Create a mock TensorFlow protobuf file."""
    content = b''
    # Add TensorFlow markers
    content += b'\x12\x0atensorflow'
    content += b'\x1a\x0bsaved_model'
    content += b'\x22\x08graph_def'
    
    # Add operations
    ops = [b'Conv2D', b'MatMul', b'BiasAdd', b'Relu']
    for op in ops:
        content += b'\x2a' + bytes([len(op)]) + op
    
    # Add variable names
    vars = [b'model/conv1/kernel:0', b'model/conv1/bias:0']
    for var in vars:
        content += b'\x32' + bytes([len(var)]) + var
    
    return content


def create_mock_h5_file() -> bytes:
    """Create a mock HDF5/Keras file."""
    # HDF5 magic number
    content = b'\x89HDF\r\n\x1a\n'
    content += b'\x00' * 100
    
    # Add Keras markers
    markers = [
        b'keras_version',
        b'2.11.0',
        b'model_config',
        b'dense',
        b'conv2d',
        b'dropout'
    ]
    
    for marker in markers:
        content += bytes([len(marker)]) + marker
        content += b'\x00' * 10
    
    return content


def test_can_handle_pb_file(extractor, tmp_path):
    """Test detection of .pb files."""
    pb_file = tmp_path / "model.pb"
    pb_file.write_bytes(create_mock_pb_file())
    
    assert extractor.can_handle(pb_file)


def test_can_handle_h5_file(extractor, tmp_path):
    """Test detection of .h5 files."""
    h5_file = tmp_path / "model.h5"
    h5_file.write_bytes(create_mock_h5_file())
    
    assert extractor.can_handle(h5_file)


def test_can_handle_keras_file(extractor, tmp_path):
    """Test detection of .keras files."""
    keras_file = tmp_path / "model.keras"
    keras_file.write_bytes(create_mock_h5_file())
    
    assert extractor.can_handle(keras_file)


def test_cannot_handle_non_tensorflow(extractor, tmp_path):
    """Test rejection of non-TensorFlow files."""
    # Wrong extension
    txt_file = tmp_path / "file.txt"
    txt_file.write_text("not a tensorflow file")
    assert not extractor.can_handle(txt_file)
    
    # Wrong content for .pb
    bad_pb = tmp_path / "bad.pb"
    bad_pb.write_bytes(b"not a protobuf")
    assert not extractor.can_handle(bad_pb)
    
    # Wrong content for .h5
    bad_h5 = tmp_path / "bad.h5"
    bad_h5.write_bytes(b"not an hdf5 file")
    assert not extractor.can_handle(bad_h5)


def test_extract_pb_operations(extractor, tmp_path):
    """Test extraction of operations from .pb file."""
    pb_file = tmp_path / "model.pb"
    pb_file.write_bytes(create_mock_pb_file())
    
    features = extractor.extract(pb_file)
    
    assert features.file_type == 'tensorflow'
    assert features.metadata['format'] == 'tensorflow_pb'
    assert features.metadata['op_count'] > 0
    assert 'Conv2D' in features.functions
    assert 'MatMul' in features.functions
    assert '__tensorflow__' in features.strings


def test_extract_pb_variables(extractor, tmp_path):
    """Test extraction of variables from .pb file."""
    pb_file = tmp_path / "model.pb"
    pb_file.write_bytes(create_mock_pb_file())
    
    features = extractor.extract(pb_file)
    
    assert len(features.constants) > 0
    variables = features.metadata.get('variables', [])
    assert any('kernel' in var for var in variables)
    assert any('bias' in var for var in variables)


def test_extract_h5_format(extractor, tmp_path):
    """Test extraction from .h5 file."""
    h5_file = tmp_path / "model.h5"
    h5_file.write_bytes(create_mock_h5_file())
    
    features = extractor.extract(h5_file)
    
    assert features.file_type == 'tensorflow'
    assert features.metadata['format'] == 'tensorflow_h5'
    assert features.metadata.get('format_type') == 'Keras'
    assert 'keras_model' in features.strings


def test_extract_h5_layers(extractor, tmp_path):
    """Test extraction of layer types from .h5 file."""
    h5_file = tmp_path / "model.h5"
    h5_file.write_bytes(create_mock_h5_file())
    
    features = extractor.extract(h5_file)
    
    # Check that layer types were detected
    assert 'dense' in features.functions
    assert 'conv2d' in features.functions
    assert 'dropout' in features.functions


def test_detect_suspicious_pb_operations(extractor, tmp_path):
    """Test detection of suspicious operations in .pb file."""
    # Create a pb with suspicious operations
    content = b'\x12\x0atensorflow'
    content += b'\x1a\x08py_func'  # Suspicious operation
    content += b'\x22\x0dnumpy_function'  # Another suspicious op
    
    pb_file = tmp_path / "suspicious.pb"
    pb_file.write_bytes(content)
    
    features = extractor.extract(pb_file)
    
    assert features.metadata.get('risk_level') == 'suspicious'
    assert 'suspicious_operations' in features.metadata


def test_detect_mobilenet_architecture(extractor, tmp_path):
    """Test detection of MobileNet architecture."""
    content = b'\x12\x0atensorflow'
    # Add MobileNet-specific operations
    content += b'\x1a\x09mobilenet'
    content += b'\x22\x18DepthwiseConv2dNative'
    content += b'\x2a\x09pointwise'
    content += b'\x32\x11inverted_residual'
    
    pb_file = tmp_path / "mobilenet.pb"
    pb_file.write_bytes(content)
    
    features = extractor.extract(pb_file)
    
    assert features.metadata.get('architecture') == 'mobilenet'


def test_savedmodel_vs_graphdef(extractor, tmp_path):
    """Test differentiation between SavedModel and GraphDef."""
    # SavedModel
    saved_content = b'\x12\x0atensorflow'
    saved_content += b'\x1a\x0bsaved_model'
    
    saved_file = tmp_path / "saved.pb"
    saved_file.write_bytes(saved_content)
    
    features = extractor.extract(saved_file)
    assert features.metadata['format_type'] == 'SavedModel'
    
    # GraphDef
    graph_content = b'\x12\x0atensorflow'
    graph_content += b'\x1a\x08graph_def'
    
    graph_file = tmp_path / "graph.pb"
    graph_file.write_bytes(graph_content)
    
    features = extractor.extract(graph_file)
    assert features.metadata['format_type'] == 'GraphDef'