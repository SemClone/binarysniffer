"""
TensorFlow native format extractor for .pb and .h5 files.

Supports:
- SavedModel format (.pb files with protobuf)
- HDF5/Keras format (.h5, .keras files)
"""

import json
import logging
from pathlib import Path
from typing import List, Optional

from .base import BaseExtractor, ExtractedFeatures

logger = logging.getLogger(__name__)


class TensorFlowNativeExtractor(BaseExtractor):
    """Extractor for TensorFlow native format files."""

    # TensorFlow operation types commonly found in .pb files
    TF_OPS = {
        'Conv2D', 'MatMul', 'Add', 'Relu', 'MaxPool', 'BatchNorm',
        'Dropout', 'Softmax', 'Dense', 'Flatten', 'Reshape',
        'Concat', 'Split', 'Pad', 'Transpose', 'Mean', 'Sum',
        'Identity', 'Placeholder', 'Variable', 'Const', 'Assign',
        'BiasAdd', 'FusedBatchNorm', 'DepthwiseConv2dNative'
    }

    # Keras/TensorFlow layer names in H5 files
    KERAS_LAYERS = {
        'dense', 'conv2d', 'conv1d', 'lstm', 'gru', 'embedding',
        'batch_normalization', 'dropout', 'flatten', 'max_pooling',
        'average_pooling', 'global_max_pooling', 'global_average_pooling',
        'concatenate', 'add', 'multiply', 'attention', 'layer_normalization'
    }

    # Model architectures
    ARCHITECTURES = {
        'resnet': ['resnet', 'residual', 'identity_block', 'conv_block'],
        'mobilenet': ['mobilenet', 'depthwise', 'pointwise', 'inverted_residual'],
        'efficientnet': ['efficientnet', 'mbconv', 'se_block'],
        'inception': ['inception', 'mixed', 'branch'],
        'densenet': ['densenet', 'dense_block', 'transition'],
        'vgg': ['vgg', 'block1', 'block2', 'block3', 'block4', 'block5'],
        'transformer': ['transformer', 'multi_head_attention', 'position'],
        'bert': ['bert', 'encoder', 'embeddings', 'pooler'],
    }

    def can_handle(self, file_path: Path) -> bool:
        """Check if file is a TensorFlow native format file."""
        suffix = file_path.suffix.lower()

        # Check extensions
        if suffix not in ['.pb', '.h5', '.keras', '.tf']:
            return False

        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)

                # Check for Protocol Buffer (.pb)
                if suffix == '.pb':
                    # TensorFlow SavedModel has specific protobuf markers
                    # Look for common TF protobuf fields
                    content = f.read(min(5000, file_path.stat().st_size - 16))
                    content_str = (header + content).decode('latin-1', errors='ignore')

                    # Check for TensorFlow markers
                    tf_markers = ['tensorflow', 'tf.', 'saved_model', 'graph_def', 'node_def']
                    return any(marker in content_str.lower() for marker in tf_markers)

                # Check for HDF5 (.h5, .keras)
                if suffix in ['.h5', '.keras']:
                    # HDF5 magic number
                    return header[:8] == b'\x89HDF\r\n\x1a\n'

        except Exception as e:
            logger.debug(f"Error checking TensorFlow file {file_path}: {e}")

        return False

    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from TensorFlow native file."""
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type='tensorflow',
            strings=[],
            functions=[],
            constants=[],
            metadata={}
        )

        suffix = file_path.suffix.lower()

        try:
            if suffix == '.pb':
                self._extract_pb_features(file_path, features)
            elif suffix in ['.h5', '.keras']:
                self._extract_h5_features(file_path, features)

            # Add TensorFlow identifiers
            features.strings.append('tensorflow_native_format')
            features.strings.append('__tensorflow__')

            logger.info(f"Extracted {len(features.strings)} features from TensorFlow file")

        except Exception as e:
            logger.error(f"Error extracting from TensorFlow file: {e}")
            features.metadata['extraction_error'] = str(e)

        return features

    def _extract_pb_features(self, file_path: Path, features: ExtractedFeatures):
        """Extract features from Protocol Buffer (.pb) file."""
        with open(file_path, 'rb') as f:
            content = f.read()

        # Convert to string for pattern matching
        content_str = content.decode('latin-1', errors='ignore')

        # Extract operation types
        ops_found = set()
        for op in self.TF_OPS:
            if op in content_str:
                ops_found.add(op)
                features.functions.append(op)

        features.metadata['operations'] = list(ops_found)
        features.metadata['op_count'] = len(ops_found)

        # Look for layer names and variables
        # In protobuf, strings are often prefixed with their length
        strings_found = self._extract_protobuf_strings(content)

        # Filter for relevant TensorFlow patterns
        layers = []
        variables = []
        for s in strings_found:
            if any(layer in s.lower() for layer in self.KERAS_LAYERS):
                layers.append(s)
                features.constants.append(s)
            elif any(pattern in s for pattern in ['kernel', 'bias', 'weight', 'gamma', 'beta']):
                variables.append(s)
                features.constants.append(s)

        features.metadata['layers'] = layers[:20]  # Limit for metadata
        features.metadata['variables'] = variables[:20]

        # Detect architecture
        architecture = self._detect_architecture(strings_found)
        if architecture:
            features.metadata['architecture'] = architecture
            features.strings.append(f'architecture:{architecture}')

        # Add format info
        features.metadata['format'] = 'tensorflow_pb'
        features.metadata['format_type'] = 'SavedModel' if 'saved_model' in content_str.lower() else 'GraphDef'

        # Security check - look for suspicious operations
        suspicious = []
        danger_ops = ['py_func', 'py_function', 'numpy_function', 'script']
        for op in danger_ops:
            if op in content_str.lower():
                suspicious.append(op)

        if suspicious:
            features.metadata['suspicious_operations'] = suspicious
            features.metadata['risk_level'] = 'suspicious'
        else:
            features.metadata['risk_level'] = 'safe'

    def _extract_h5_features(self, file_path: Path, features: ExtractedFeatures):
        """Extract features from HDF5 (.h5, .keras) file."""
        try:
            # Try to use h5py if available
            import h5py

            with h5py.File(file_path, 'r') as f:
                # Extract model configuration if present
                if 'model_config' in f.attrs:
                    config = json.loads(f.attrs['model_config'])
                    features.metadata['model_class'] = config.get('class_name', 'Unknown')

                    # Extract layers
                    if 'config' in config and 'layers' in config['config']:
                        layers = config['config']['layers']
                        layer_types = [layer.get('class_name', '') for layer in layers]
                        features.metadata['layer_types'] = list(set(layer_types))
                        features.metadata['layer_count'] = len(layers)

                        for layer_type in set(layer_types):
                            features.functions.append(layer_type)

                # Extract keras version
                if 'keras_version' in f.attrs:
                    features.metadata['keras_version'] = f.attrs['keras_version'].decode('utf-8')
                    features.strings.append(f"keras_{f.attrs['keras_version'].decode('utf-8')}")

                # Extract layer names and weights
                def extract_names(name, obj):
                    if isinstance(obj, h5py.Group):
                        features.constants.append(name.split('/')[-1])

                f.visititems(extract_names)

                # Check for optimizer weights
                has_optimizer = 'optimizer_weights' in f
                features.metadata['has_optimizer'] = has_optimizer
                if has_optimizer:
                    features.strings.append('optimizer_weights')

                features.metadata['format'] = 'tensorflow_h5'
                features.metadata['format_type'] = 'Keras'

        except ImportError:
            # Fallback if h5py is not available
            self._extract_h5_fallback(file_path, features)

    def _extract_h5_fallback(self, file_path: Path, features: ExtractedFeatures):
        """Fallback H5 extraction without h5py."""
        with open(file_path, 'rb') as f:
            content = f.read(min(100000, file_path.stat().st_size))

        content_str = content.decode('latin-1', errors='ignore')

        # Look for Keras/TensorFlow markers
        if 'keras' in content_str.lower():
            features.metadata['format_type'] = 'Keras'
            features.strings.append('keras_model')

        # Extract layer names from strings
        for layer in self.KERAS_LAYERS:
            if layer in content_str.lower():
                features.functions.append(layer)

        features.metadata['format'] = 'tensorflow_h5'
        features.metadata['fallback_extraction'] = True

    def _extract_protobuf_strings(self, content: bytes) -> List[str]:
        """Extract strings from protobuf content."""
        strings = []
        i = 0
        while i < len(content) - 1:
            # Look for length-prefixed strings (common in protobuf)
            if i < len(content) - 1:
                length = content[i]
                if 0 < length < 128 and i + length + 1 <= len(content):
                    try:
                        potential_string = content[i+1:i+1+length].decode('utf-8')
                        if all(c.isprintable() or c.isspace() for c in potential_string):
                            if len(potential_string) > 2:  # Minimum meaningful length
                                strings.append(potential_string)
                    except:
                        pass
            i += 1

        return strings

    def _detect_architecture(self, strings: List[str]) -> Optional[str]:
        """Detect model architecture from strings."""
        all_strings = ' '.join(strings).lower()

        for arch_name, patterns in self.ARCHITECTURES.items():
            matches = sum(1 for pattern in patterns if pattern.lower() in all_strings)
            if matches >= 2:
                return arch_name

        return None
