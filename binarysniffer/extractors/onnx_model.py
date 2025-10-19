"""
ONNX model parser for ML model analysis.

This module extracts features from ONNX (Open Neural Network Exchange) models,
which use protobuf serialization for cross-framework interoperability.
"""

import logging
from pathlib import Path
from typing import Any, Dict, Set

from binarysniffer.extractors.base import BaseExtractor, ExtractedFeatures

logger = logging.getLogger(__name__)

# ONNX magic bytes and identifiers
ONNX_MAGIC = b'\x08\x01'  # Common start of ONNX protobuf files
ONNX_IDENTIFIERS = [b'onnx', b'ONNX', b'model_version', b'ir_version']

# Known ONNX operators by domain
ONNX_OPERATORS = {
    # Standard ONNX operators
    'ai.onnx': [
        'Conv', 'BatchNormalization', 'Relu', 'MaxPool', 'AveragePool',
        'Gemm', 'MatMul', 'Add', 'Sub', 'Mul', 'Div', 'Concat',
        'Dropout', 'Softmax', 'LogSoftmax', 'Sigmoid', 'Tanh',
        'LSTM', 'GRU', 'RNN', 'Attention', 'MultiHeadAttention',
        'LayerNormalization', 'InstanceNormalization', 'GroupNormalization',
        'Pad', 'Resize', 'Upsample', 'GlobalAveragePool',
        'ReduceMean', 'ReduceSum', 'ReduceMax', 'ReduceMin',
        'Cast', 'Shape', 'Reshape', 'Transpose', 'Squeeze', 'Unsqueeze',
        'Gather', 'Scatter', 'Slice', 'Split', 'Concat',
    ],
    # ML-specific operators
    'ai.onnx.ml': [
        'TreeEnsembleClassifier', 'TreeEnsembleRegressor',
        'LinearClassifier', 'LinearRegressor',
        'SVMClassifier', 'SVMRegressor',
        'Scaler', 'Normalizer', 'LabelEncoder',
        'OneHotEncoder', 'Imputer', 'FeatureVectorizer',
    ],
    # Microsoft custom operators
    'com.microsoft': [
        'FusedConv', 'QuantizeLinear', 'DequantizeLinear',
        'QLinearConv', 'QLinearMatMul', 'DynamicQuantizeLinear',
        'FusedMatMul', 'FusedGemm', 'BiasGelu', 'FastGelu',
        'SkipLayerNormalization', 'EmbedLayerNormalization',
    ],
    # Custom/suspicious operators
    'custom': [],
}

# Framework signatures in ONNX models
FRAMEWORK_SIGNATURES = {
    'pytorch': [
        'aten::', 'torch.', '_caffe2::', 'torch::jit',
        'pytorch', 'PyTorch', 'torchvision',
        'prim::', 'onnx::Conv_', 'produced_by_pytorch',
    ],
    'tensorflow': [
        'tf.', 'tensorflow::', 'TensorFlow', 'tensorflow',
        'tf2onnx', 'produced_by_tensorflow', 'tf_',
        'StatefulPartitionedCall', 'PartitionedCall',
    ],
    'sklearn': [
        'sklearn.', 'SklearnTransform', 'sklearn-onnx',
        'skl2onnx', 'produced_by_sklearn',
    ],
    'keras': [
        'keras.', 'Keras', 'keras2onnx', 'produced_by_keras',
    ],
    'xgboost': [
        'xgboost.', 'XGBoost', 'produced_by_xgboost',
    ],
    'lightgbm': [
        'lightgbm.', 'LightGBM', 'produced_by_lightgbm',
    ],
    'paddlepaddle': [
        'paddle.', 'PaddlePaddle', 'paddle2onnx',
    ],
    'mxnet': [
        'mxnet.', 'MXNet', 'produced_by_mxnet',
    ],
}

# Model architecture signatures
MODEL_ARCHITECTURES = {
    'resnet': ['ResNet', 'resnet', 'res2net', 'ResBlock', 'BottleNeck'],
    'bert': ['BERT', 'bert', 'attention', 'transformer', 'position_embedding'],
    'yolo': ['YOLO', 'yolo', 'darknet', 'detection', 'anchor'],
    'efficientnet': ['EfficientNet', 'efficientnet', 'mbconv', 'se_module'],
    'mobilenet': ['MobileNet', 'mobilenet', 'depthwise', 'pointwise'],
    'vgg': ['VGG', 'vgg16', 'vgg19', 'vgg_'],
    'inception': ['Inception', 'inception', 'inception_module'],
    'densenet': ['DenseNet', 'densenet', 'dense_block', 'transition'],
    'unet': ['UNet', 'unet', 'up_conv', 'down_conv'],
    'gan': ['Generator', 'Discriminator', 'gan', 'adversarial'],
    'vae': ['Encoder', 'Decoder', 'vae', 'variational'],
    'transformer': ['Transformer', 'MultiHeadAttention', 'position_encoding'],
}

# Suspicious patterns that might indicate tampering or malicious content
SUSPICIOUS_PATTERNS = {
    'exec', 'eval', '__import__', 'compile',
    'subprocess', 'os.system', 'shell',
    'base64', 'decode', 'encrypt', 'decrypt',
    'reverse_tcp', 'bind_shell', '/bin/sh',
    'CustomOp', 'UnknownOp', 'PrivateOp',
}


class ONNXModelExtractor(BaseExtractor):
    """Extract features from ONNX model files."""

    def __init__(self):
        """Initialize the ONNX model extractor."""
        super().__init__()
        self.has_onnx = self._check_onnx_available()

    def _check_onnx_available(self) -> bool:
        """Check if onnx library is available."""
        try:
            import onnx
            return True
        except ImportError:
            logger.debug("ONNX library not available, using fallback pattern matching")
            return False

    def can_handle(self, file_path: Path) -> bool:
        """Check if file is an ONNX model."""
        # Check extension
        # Note: .pb files can be used for ONNX models (sometimes)
        if file_path.suffix.lower() in ['.onnx', '.onnxmodel', '.pb']:
            return True

        # Check for ONNX identifiers in file
        try:
            with open(file_path, 'rb') as f:
                # Read first 1KB
                header = f.read(1024)

                # Check for ONNX identifiers
                for identifier in ONNX_IDENTIFIERS:
                    if identifier in header:
                        return True

                # Check for protobuf structure with ONNX-like content
                if b'GraphProto' in header or b'ModelProto' in header:
                    return True

        except Exception:
            pass

        return False

    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from ONNX model file."""
        features = set()
        operators = set()
        frameworks = set()
        architectures = set()
        metadata = {}
        suspicious_items = set()

        try:
            if self.has_onnx:
                # Use ONNX library for full parsing
                features_extracted = self._extract_with_onnx(
                    file_path, features, operators, frameworks,
                    architectures, metadata, suspicious_items
                )
            else:
                # Fallback to pattern matching
                features_extracted = self._extract_with_patterns(
                    file_path, features, operators, frameworks,
                    architectures, metadata, suspicious_items
                )

            # Assess security risk
            risk_level = self._assess_risk(suspicious_items, operators)
            features.add(f"onnx_risk:{risk_level}")
            metadata['risk_level'] = risk_level

            # Add detected components
            for framework in frameworks:
                features.add(f"detected_framework:{framework}")

            for arch in architectures:
                features.add(f"model_architecture:{arch}")

            # Add suspicious items to features
            for suspicious in suspicious_items:
                features.add(suspicious)

            # Add operator statistics
            if operators:
                features.add(f"operator_count:{len(operators)}")
                metadata['operators'] = list(operators)[:20]  # First 20 operators

            # Log findings
            if suspicious_items:
                logger.warning(f"ONNX model {file_path.name} contains suspicious patterns: {list(suspicious_items)}")

            logger.info(f"Extracted {len(features)} features from ONNX model {file_path.name}")

        except Exception as e:
            logger.error(f"Error parsing ONNX model {file_path}: {e}")
            features.add("onnx_parse_error")
            metadata['error'] = str(e)

        return ExtractedFeatures(
            file_path=str(file_path),
            file_type='onnx',
            strings=list(features),
            functions=list(operators),  # Use functions for operators
            imports=list(frameworks),   # Use imports for frameworks
            constants=list(architectures),  # Use constants for architectures
            symbols=[],
            metadata=metadata
        )

    def _extract_with_onnx(self, file_path: Path, features: Set[str],
                           operators: Set[str], frameworks: Set[str],
                           architectures: Set[str], metadata: Dict[str, Any],
                           suspicious_items: Set[str]) -> bool:
        """Extract features using ONNX library."""
        try:
            import onnx

            # Load the model
            model = onnx.load(str(file_path))

            # Extract model metadata
            metadata['ir_version'] = model.ir_version
            metadata['producer_name'] = model.producer_name
            metadata['producer_version'] = model.producer_version
            metadata['domain'] = model.domain
            metadata['model_version'] = model.model_version

            # Add producer as feature
            if model.producer_name:
                features.add(f"onnx_producer:{model.producer_name}")

                # Check for framework
                producer_lower = model.producer_name.lower()
                for fw, patterns in FRAMEWORK_SIGNATURES.items():
                    if fw in producer_lower:
                        frameworks.add(fw)
                        break

            # Extract graph information
            if model.graph:
                graph = model.graph
                metadata['graph_name'] = graph.name
                features.add(f"onnx_graph:{graph.name}")

                # Extract operators from nodes
                for node in graph.node:
                    op_type = node.op_type
                    operators.add(op_type)
                    features.add(f"onnx_operator:{op_type}")

                    # Check for suspicious operators
                    if op_type in SUSPICIOUS_PATTERNS or 'Custom' in op_type:
                        suspicious_items.add(f"suspicious_operator:{op_type}")

                    # Check node names for framework hints
                    node_name = node.name.lower() if node.name else ""
                    for fw, patterns in FRAMEWORK_SIGNATURES.items():
                        for pattern in patterns:
                            if pattern.lower() in node_name:
                                frameworks.add(fw)
                                break

                    # Check for architecture patterns
                    for arch, patterns in MODEL_ARCHITECTURES.items():
                        for pattern in patterns:
                            if pattern.lower() in node_name or pattern.lower() in op_type.lower():
                                architectures.add(arch)
                                break

                # Extract input/output information
                metadata['num_inputs'] = len(graph.input)
                metadata['num_outputs'] = len(graph.output)
                features.add(f"onnx_inputs:{len(graph.input)}")
                features.add(f"onnx_outputs:{len(graph.output)}")

                # Extract initializer (weights) information
                metadata['num_weights'] = len(graph.initializer)
                total_params = 0
                for init in graph.initializer:
                    if init.dims:
                        params = 1
                        for dim in init.dims:
                            params *= dim
                        total_params += params

                metadata['total_parameters'] = total_params
                features.add(f"onnx_parameters:{total_params}")

            # Extract metadata properties
            for prop in model.metadata_props:
                key = prop.key.lower()
                value = prop.value

                # Check for framework signatures
                for fw, patterns in FRAMEWORK_SIGNATURES.items():
                    for pattern in patterns:
                        if pattern.lower() in key or pattern.lower() in value.lower():
                            frameworks.add(fw)
                            break

                # Check for suspicious content
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern in value.lower():
                        suspicious_items.add(f"suspicious_metadata:{key}={value[:50]}")

                # Store important metadata
                if any(k in key for k in ['license', 'author', 'description', 'framework']):
                    metadata[key] = value

            # Extract opset information
            for opset in model.opset_import:
                features.add(f"onnx_opset:{opset.domain}:{opset.version}")
                metadata[f'opset_{opset.domain}'] = opset.version

            return True

        except Exception as e:
            logger.debug(f"ONNX library extraction failed: {e}, falling back to patterns")
            return False

    def _extract_with_patterns(self, file_path: Path, features: Set[str],
                               operators: Set[str], frameworks: Set[str],
                               architectures: Set[str], metadata: Dict[str, Any],
                               suspicious_items: Set[str]) -> bool:
        """Extract features using pattern matching (fallback)."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            # Convert to string for pattern matching (ignore errors)
            text_content = content.decode('utf-8', errors='ignore')

            # Extract operators
            for domain, ops in ONNX_OPERATORS.items():
                for op in ops:
                    if op in text_content:
                        operators.add(op)
                        features.add(f"onnx_operator:{op}")

            # Extract framework signatures
            for fw, patterns in FRAMEWORK_SIGNATURES.items():
                for pattern in patterns:
                    if pattern in text_content or pattern.encode() in content:
                        frameworks.add(fw)
                        features.add(f"framework_hint:{pattern}")
                        break

            # Extract architecture patterns
            for arch, patterns in MODEL_ARCHITECTURES.items():
                for pattern in patterns:
                    if pattern.lower() in text_content.lower():
                        architectures.add(arch)
                        break

            # Look for suspicious patterns
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern in text_content.lower():
                    suspicious_items.add(f"suspicious_pattern:{pattern}")

            # Extract basic metadata from protobuf structure
            if b'producer_name' in content:
                try:
                    idx = content.index(b'producer_name')
                    # Try to extract the value (simplified)
                    producer = content[idx+14:idx+50].split(b'\x00')[0]
                    if producer and len(producer) < 30:
                        producer_str = producer.decode('utf-8', errors='ignore')
                        metadata['producer_name'] = producer_str
                        features.add(f"onnx_producer:{producer_str}")
                except:
                    pass

            # Look for model size indicators
            metadata['file_size'] = len(content)
            features.add(f"onnx_size:{len(content)}")

            # Estimate if it's a large model
            if len(content) > 100_000_000:  # >100MB
                features.add("large_model")
            elif len(content) > 10_000_000:  # >10MB
                features.add("medium_model")
            else:
                features.add("small_model")

            return True

        except Exception as e:
            logger.error(f"Pattern extraction failed: {e}")
            return False

    def _assess_risk(self, suspicious_items: Set[str], operators: Set[str]) -> str:
        """Assess the security risk level of the ONNX model."""
        # Check for highly suspicious items
        if any('exec' in s or 'eval' in s or 'shell' in s for s in suspicious_items):
            return "dangerous"

        # Check for custom operators (potential hiding place for malicious code)
        custom_ops = [op for op in operators if 'Custom' in op or 'Unknown' in op]
        if len(custom_ops) > 2:
            return "suspicious"

        # Check for any suspicious patterns
        if len(suspicious_items) > 3:
            return "high_risk"
        if len(suspicious_items) > 0:
            return "suspicious"

        # Check if it's a known safe model type
        if operators and not suspicious_items:
            return "likely_safe"

        return "unknown"
