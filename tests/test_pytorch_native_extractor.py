"""
Tests for PyTorch native format extractor
"""

import pickle
import tempfile
from pathlib import Path

import pytest

from binarysniffer.extractors.pytorch_native import PyTorchNativeExtractor


@pytest.fixture
def extractor():
    """Create PyTorch native extractor instance."""
    return PyTorchNativeExtractor()


def create_pytorch_file(data: dict, protocol: int = 4) -> bytes:
    """Create a PyTorch pickle file."""
    return pickle.dumps(data, protocol=protocol)


def test_can_handle_pt_file(extractor, tmp_path):
    """Test detection of .pt files."""
    # Create a valid PyTorch file
    model_data = {
        'state_dict': {'layer1.weight': b'tensor_data'},
        'torch_version': '2.0.0'
    }
    
    pt_file = tmp_path / "model.pt"
    with open(pt_file, 'wb') as f:
        pickle.dump(model_data, f, protocol=4)
    
    assert extractor.can_handle(pt_file)


def test_can_handle_pth_file(extractor, tmp_path):
    """Test detection of .pth files."""
    checkpoint_data = {
        'model_state_dict': {'fc.weight': b'data'},
        'optimizer_state_dict': {'state': {}},
        'epoch': 10
    }
    
    pth_file = tmp_path / "checkpoint.pth"
    with open(pth_file, 'wb') as f:
        pickle.dump(checkpoint_data, f, protocol=4)
    
    assert extractor.can_handle(pth_file)


def test_cannot_handle_non_pytorch(extractor, tmp_path):
    """Test rejection of non-PyTorch files."""
    # Wrong extension
    txt_file = tmp_path / "file.txt"
    txt_file.write_text("not a pytorch file")
    assert not extractor.can_handle(txt_file)
    
    # Pickle file but wrong extension
    pkl_file = tmp_path / "file.pkl"
    with open(pkl_file, 'wb') as f:
        pickle.dump({'data': 'test'}, f)
    assert not extractor.can_handle(pkl_file)


def test_extract_state_dict(extractor, tmp_path):
    """Test extraction from model with state_dict."""
    model_data = {
        'state_dict': {
            'conv1.weight': b'conv_weights',
            'conv1.bias': b'conv_bias',
            'bn1.running_mean': b'running_mean',
            'bn1.running_var': b'running_var',
            'fc.weight': b'fc_weights'
        },
        'epoch': 100
    }
    
    pt_file = tmp_path / "model.pt"
    with open(pt_file, 'wb') as f:
        pickle.dump(model_data, f)
    
    features = extractor.extract(pt_file)
    
    assert features.file_type == 'pytorch'
    assert features.metadata['has_state_dict'] == True
    assert features.metadata['parameter_keys'] > 0
    assert 'state_dict' in features.strings
    assert '__pytorch__' in features.strings


def test_extract_optimizer_state(extractor, tmp_path):
    """Test extraction from checkpoint with optimizer."""
    checkpoint_data = {
        'model_state_dict': {'layer1.weight': b'weights'},
        'optimizer_state_dict': {
            'state': {0: {'momentum_buffer': b'momentum'}},
            'param_groups': [{'lr': 0.001}]
        },
        'epoch': 50
    }
    
    pth_file = tmp_path / "checkpoint.pth"
    with open(pth_file, 'wb') as f:
        pickle.dump(checkpoint_data, f)
    
    features = extractor.extract(pth_file)
    
    assert features.metadata['has_optimizer'] == True
    assert 'optimizer_state' in features.strings


def test_detect_resnet_architecture(extractor, tmp_path):
    """Test detection of ResNet architecture."""
    model_data = {
        'state_dict': {
            'layer1.0.conv1.weight': b'data',
            'layer2.0.conv1.weight': b'data',
            'layer3.0.conv1.weight': b'data',
            'layer4.0.conv1.weight': b'data',
            'fc.weight': b'data'
        }
    }
    
    pt_file = tmp_path / "resnet.pt"
    with open(pt_file, 'wb') as f:
        pickle.dump(model_data, f)
    
    features = extractor.extract(pt_file)
    
    assert features.metadata.get('architecture') == 'resnet'
    assert 'architecture:resnet' in features.strings


def test_detect_transformer_architecture(extractor, tmp_path):
    """Test detection of Transformer architecture."""
    model_data = {
        'state_dict': {
            'encoder.layer.0.attention.self.query.weight': b'data',
            'encoder.layer.0.attention.self.key.weight': b'data',
            'encoder.layer.0.attention.self.value.weight': b'data',
            'decoder.layer.0.attention.self.query.weight': b'data'
        }
    }
    
    pt_file = tmp_path / "transformer.pt"
    with open(pt_file, 'wb') as f:
        pickle.dump(model_data, f)
    
    features = extractor.extract(pt_file)
    
    assert features.metadata.get('architecture') == 'transformer'


def test_detect_suspicious_operations(extractor, tmp_path):
    """Test detection of suspicious operations."""
    # Create a file that imports dangerous modules
    import os
    
    class DangerousOp:
        def __reduce__(self):
            return (os.system, ('ls',))
    
    malicious_data = {
        'state_dict': {'weight': b'data'},
        'backdoor': DangerousOp()
    }
    
    pt_file = tmp_path / "malicious.pt"
    with open(pt_file, 'wb') as f:
        pickle.dump(malicious_data, f)
    
    features = extractor.extract(pt_file)
    
    assert features.metadata.get('risk_level') == 'dangerous'
    assert 'suspicious_operations' in features.metadata
    assert any('os.system' in op for op in features.metadata['suspicious_operations'])


def test_layer_counting(extractor, tmp_path):
    """Test layer counting functionality."""
    model_data = {
        'state_dict': {
            'layer1.weight': b'data',
            'layer2.weight': b'data',
            'layer3.weight': b'data',
            'layer4.weight': b'data',
            'layer5.weight': b'data'
        }
    }
    
    pt_file = tmp_path / "multilayer.pt"
    with open(pt_file, 'wb') as f:
        pickle.dump(model_data, f)
    
    features = extractor.extract(pt_file)
    
    assert features.metadata['layer_count'] == 5


def test_pytorch_modules_tracking(extractor, tmp_path):
    """Test tracking of PyTorch module imports."""
    # This would be in a real PyTorch file with tensor rebuild functions
    model_data = {
        'state_dict': {'weight': b'data'},
        '_metadata': {
            'torch_functions': [
                'torch.nn.modules.linear.Linear',
                'torch.nn.modules.conv.Conv2d',
                'torch.optim.adam.Adam'
            ]
        }
    }
    
    pt_file = tmp_path / "modules.pt"
    with open(pt_file, 'wb') as f:
        pickle.dump(model_data, f)
    
    features = extractor.extract(pt_file)
    
    assert features.file_type == 'pytorch'
    assert 'pytorch_native_format' in features.strings