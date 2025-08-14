"""
Tests for SafeTensors model extractor
"""

import json
import struct
import tempfile
from pathlib import Path

import pytest

from binarysniffer.extractors.safetensors import SafeTensorsExtractor


@pytest.fixture
def extractor():
    """Create SafeTensors extractor instance."""
    return SafeTensorsExtractor()


def create_safetensors_file(metadata: dict) -> bytes:
    """Create a valid SafeTensors file with given metadata."""
    metadata_bytes = json.dumps(metadata).encode('utf-8')
    header_size = len(metadata_bytes)
    
    # SafeTensors format: 8-byte header (size) + JSON metadata + tensor data
    file_content = struct.pack('<Q', header_size) + metadata_bytes
    
    # Add dummy tensor data if offsets are specified
    max_offset = 0
    for tensor_name, tensor_info in metadata.items():
        if tensor_name != '__metadata__' and isinstance(tensor_info, dict):
            if 'data_offsets' in tensor_info:
                end_offset = tensor_info['data_offsets'][1]
                max_offset = max(max_offset, end_offset)
    
    # Add dummy data to match offsets
    if max_offset > 0:
        file_content += b'\x00' * max_offset
    
    return file_content


def test_can_handle_safetensors_file(extractor, tmp_path):
    """Test detection of SafeTensors files."""
    # Valid SafeTensors file
    metadata = {
        "weight": {
            "dtype": "F32",
            "shape": [10, 20],
            "data_offsets": [0, 800]
        }
    }
    
    safetensors_file = tmp_path / "model.safetensors"
    safetensors_file.write_bytes(create_safetensors_file(metadata))
    
    assert extractor.can_handle(safetensors_file)
    
    # Also test .st extension
    st_file = tmp_path / "model.st"
    st_file.write_bytes(create_safetensors_file(metadata))
    assert extractor.can_handle(st_file)


def test_cannot_handle_non_safetensors(extractor, tmp_path):
    """Test rejection of non-SafeTensors files."""
    # Wrong extension
    txt_file = tmp_path / "file.txt"
    txt_file.write_text("not a safetensors file")
    assert not extractor.can_handle(txt_file)
    
    # Invalid header
    bad_file = tmp_path / "bad.safetensors"
    bad_file.write_bytes(b"invalid header")
    assert not extractor.can_handle(bad_file)
    
    # Invalid JSON in header
    invalid_json = tmp_path / "invalid.safetensors"
    invalid_json.write_bytes(struct.pack('<Q', 10) + b"not json!!")
    assert not extractor.can_handle(invalid_json)


def test_extract_pytorch_model(extractor, tmp_path):
    """Test extraction from PyTorch SafeTensors model."""
    metadata = {
        "__metadata__": {
            "format": "pt",
            "pt_version": "2.0.0"
        },
        "model.layers.0.weight": {
            "dtype": "F32",
            "shape": [512, 768],
            "data_offsets": [0, 1572864]
        },
        "model.layers.0.bias": {
            "dtype": "F32",
            "shape": [512],
            "data_offsets": [1572864, 1574912]
        },
        "model.layers.1.weight": {
            "dtype": "F32",
            "shape": [256, 512],
            "data_offsets": [1574912, 2099200]
        }
    }
    
    model_file = tmp_path / "pytorch_model.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    # Check metadata
    assert features.metadata['format'] == 'safetensors'
    assert features.metadata['tensor_count'] == 3
    assert features.metadata['framework'] == 'pytorch'
    assert 'weight' in features.strings
    assert 'bias' in features.strings
    assert '__safetensors__' in features.strings


def test_extract_transformers_model(extractor, tmp_path):
    """Test extraction from Transformers SafeTensors model."""
    metadata = {
        "__metadata__": {
            "format": "pt",
            "torch_version": "2.0.0"
        },
        "embeddings.word_embeddings.weight": {
            "dtype": "F16",
            "shape": [50000, 768],
            "data_offsets": [0, 76800000]
        },
        "encoder.layer.0.attention.self.query.weight": {
            "dtype": "F16",
            "shape": [768, 768],
            "data_offsets": [76800000, 77976576]
        },
        "encoder.layer.0.attention.self.key.weight": {
            "dtype": "F16",
            "shape": [768, 768],
            "data_offsets": [77976576, 79153152]
        },
        "lm_head.weight": {
            "dtype": "F16",
            "shape": [50000, 768],
            "data_offsets": [79153152, 155953152]
        }
    }
    
    model_file = tmp_path / "bert_model.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    # Check detection
    assert features.metadata['framework'] == 'transformers'
    assert features.metadata['architecture'] in ['bert', 'transformer']
    assert 'embeddings' in features.strings
    assert 'attention' in features.strings
    assert 'encoder' in features.strings


def test_detect_llama_architecture(extractor, tmp_path):
    """Test detection of LLaMA architecture."""
    metadata = {
        "model.layers.0.self_attn.q_proj.weight": {
            "dtype": "BF16",
            "shape": [4096, 4096],
            "data_offsets": [0, 33554432]
        },
        "model.layers.0.mlp.gate_proj.weight": {
            "dtype": "BF16",
            "shape": [11008, 4096],
            "data_offsets": [33554432, 123731968]
        }
    }
    
    model_file = tmp_path / "llama.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    assert features.metadata['architecture'] == 'llama'


def test_detect_tampering_invalid_dtype(extractor, tmp_path):
    """Test detection of invalid dtype (tampering indicator)."""
    metadata = {
        "weight": {
            "dtype": "INVALID_TYPE",  # Invalid dtype
            "shape": [10, 10],
            "data_offsets": [0, 400]
        }
    }
    
    model_file = tmp_path / "tampered.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    assert 'suspicious_patterns' in features.metadata
    assert any('invalid-dtype' in p for p in features.metadata['suspicious_patterns'])


def test_detect_injection_attempt(extractor, tmp_path):
    """Test detection of injection attempts via extra keys."""
    metadata = {
        "weight": {
            "dtype": "F32",
            "shape": [10, 10],
            "data_offsets": [0, 400],
            "malicious_code": "exec('evil')"  # Injection attempt
        }
    }
    
    model_file = tmp_path / "injected.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    assert 'suspicious_patterns' in features.metadata
    assert any('injection-attempt' in p for p in features.metadata['suspicious_patterns'])


def test_detect_data_exfiltration(extractor, tmp_path):
    """Test detection of potential data exfiltration via oversized tensors."""
    metadata = {
        "hidden_data": {
            "dtype": "U8",
            "shape": [100000, 100000],  # 10 billion elements!
            "data_offsets": [0, 10000000000]
        }
    }
    
    model_file = tmp_path / "exfiltration.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    assert 'suspicious_patterns' in features.metadata
    assert any('oversized-tensor' in p for p in features.metadata['suspicious_patterns'])


def test_detect_suspicious_tensor_names(extractor, tmp_path):
    """Test detection of suspicious tensor names."""
    metadata = {
        "model.weight": {
            "dtype": "F32",
            "shape": [100, 100],
            "data_offsets": [0, 40000]
        },
        "backdoor_trigger": {  # Suspicious name
            "dtype": "F32",
            "shape": [10, 10],
            "data_offsets": [40000, 40400]
        },
        "YmFzZTY0X2VuY29kZWRfbmFtZQ==": {  # Base64-like name
            "dtype": "I32",
            "shape": [5, 5],
            "data_offsets": [40400, 40500]
        }
    }
    
    model_file = tmp_path / "suspicious.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    assert 'suspicious_patterns' in features.metadata
    patterns = features.metadata['suspicious_patterns']
    assert any('suspicious-name' in p for p in patterns)
    assert any('base64-like-name' in p for p in patterns)


def test_valid_clean_model(extractor, tmp_path):
    """Test that clean, valid models don't trigger false positives."""
    metadata = {
        "__metadata__": {
            "format": "pt",
            "pt_version": "2.0.0"
        },
        "conv1.weight": {
            "dtype": "F32",
            "shape": [64, 3, 7, 7],
            "data_offsets": [0, 37632]
        },
        "bn1.weight": {
            "dtype": "F32",
            "shape": [64],
            "data_offsets": [37632, 37888]
        },
        "bn1.bias": {
            "dtype": "F32",
            "shape": [64],
            "data_offsets": [37888, 38144]
        }
    }
    
    model_file = tmp_path / "clean_model.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    # Should not have suspicious patterns
    assert 'suspicious_patterns' not in features.metadata or \
           len(features.metadata['suspicious_patterns']) == 0


def test_tensorflow_model(extractor, tmp_path):
    """Test extraction from TensorFlow SafeTensors model."""
    metadata = {
        "__metadata__": {
            "format": "tf",
            "tf_version": "2.12.0"
        },
        "dense/kernel:0": {
            "dtype": "F32",
            "shape": [784, 128],
            "data_offsets": [0, 401408]
        },
        "dense/bias:0": {
            "dtype": "F32",
            "shape": [128],
            "data_offsets": [401408, 401920]
        }
    }
    
    model_file = tmp_path / "tf_model.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    assert features.metadata['framework'] == 'tensorflow'
    assert 'kernel' in features.strings
    assert 'dense' in features.strings


def test_parameter_counting(extractor, tmp_path):
    """Test accurate parameter counting."""
    metadata = {
        "layer1": {
            "dtype": "F32",
            "shape": [10, 20],  # 200 params
            "data_offsets": [0, 800]
        },
        "layer2": {
            "dtype": "F32", 
            "shape": [20, 30],  # 600 params
            "data_offsets": [800, 3200]
        },
        "bias": {
            "dtype": "F32",
            "shape": [30],  # 30 params
            "data_offsets": [3200, 3320]
        }
    }
    
    model_file = tmp_path / "counted.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    assert features.metadata['tensor_count'] == 3
    assert features.metadata['total_parameters'] == 830  # 200 + 600 + 30


def test_missing_required_fields(extractor, tmp_path):
    """Test detection of missing required fields."""
    metadata = {
        "broken_tensor": {
            "dtype": "F32",
            "shape": [10, 10]
            # Missing data_offsets!
        }
    }
    
    model_file = tmp_path / "broken.safetensors"
    model_file.write_bytes(create_safetensors_file(metadata))
    
    features = extractor.extract(model_file)
    
    assert 'suspicious_patterns' in features.metadata
    assert any('missing-required' in p for p in features.metadata['suspicious_patterns'])