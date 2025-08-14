"""
SafeTensors model extractor for secure model weight storage format.

SafeTensors is a simple, secure format for storing tensors safely
(no code execution) while being fast to load.
"""

import json
import logging
import struct
from pathlib import Path
from typing import Dict, List, Optional

from .base import BaseExtractor, ExtractedFeatures

logger = logging.getLogger(__name__)


class SafeTensorsExtractor(BaseExtractor):
    """Extractor for SafeTensors format model files."""

    def can_handle(self, file_path: Path) -> bool:
        """Check if file is a SafeTensors file."""
        if file_path.suffix.lower() not in ['.safetensors', '.st']:
            return False

        try:
            with open(file_path, 'rb') as f:
                # SafeTensors starts with an 8-byte header containing
                # the size of the JSON metadata
                header = f.read(8)
                if len(header) < 8:
                    return False

                # Try to parse the header size (little-endian uint64)
                header_size = struct.unpack('<Q', header)[0]

                # Sanity check: header shouldn't be larger than 100MB
                if header_size > 100 * 1024 * 1024:
                    return False

                # Try to read and parse the JSON metadata
                metadata_bytes = f.read(header_size)
                if len(metadata_bytes) != header_size:
                    return False

                try:
                    json.loads(metadata_bytes)
                    return True
                except (json.JSONDecodeError, UnicodeDecodeError):
                    return False

        except Exception as e:
            logger.debug(f"Error checking SafeTensors file {file_path}: {e}")
            return False

    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from SafeTensors file."""
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type='safetensors',
            strings=[],
            functions=[],
            constants=[],
            metadata={}
        )

        try:
            with open(file_path, 'rb') as f:
                # Read header size
                header_size = struct.unpack('<Q', f.read(8))[0]

                # Read metadata JSON
                metadata_bytes = f.read(header_size)
                metadata = json.loads(metadata_bytes)

                # Extract tensor information
                tensor_info = self._parse_tensor_metadata(metadata)

                # Add metadata to features
                features.metadata['format'] = 'safetensors'
                features.metadata['tensor_count'] = tensor_info['count']
                features.metadata['total_parameters'] = tensor_info['total_params']
                features.metadata['dtypes'] = list(tensor_info['dtypes'])
                features.metadata['shapes'] = tensor_info['shapes']

                # Extract framework hints from tensor names
                framework = self._detect_framework(tensor_info['names'])
                if framework:
                    features.metadata['framework'] = framework
                    features.strings.append(f"framework:{framework}")

                # Extract architecture from layer names
                architecture = self._detect_architecture(tensor_info['names'])
                if architecture:
                    features.metadata['architecture'] = architecture
                    features.strings.append(f"architecture:{architecture}")

                # Add tensor names as features for matching
                for name in tensor_info['names']:
                    # Add layer name components
                    parts = name.replace('.', '_').replace('/', '_').replace(':', '_').split('_')
                    for part in parts:
                        if len(part) > 3 and not part.isdigit():  # Skip very short parts and numbers
                            features.strings.append(part)

                    # Add full tensor name for specific patterns
                    if any(pattern in name for pattern in [
                        'attention', 'transformer', 'embedding', 'conv',
                        'linear', 'norm', 'pool', 'dropout', 'activation'
                    ]):
                        features.constants.append(name)

                # Add metadata signatures
                features.strings.append(f"safetensors_v{self._get_format_version(metadata)}")
                features.strings.append(f"params:{tensor_info['total_params']}")
                features.strings.append(f"tensors:{tensor_info['count']}")

                # Check for suspicious patterns (should be none in SafeTensors)
                suspicious = self._check_suspicious_patterns(metadata)
                if suspicious:
                    features.metadata['suspicious_patterns'] = suspicious
                    for pattern in suspicious:
                        features.strings.append(f"suspicious:{pattern}")

                # Add SafeTensors format identifier
                features.strings.append("__safetensors__")
                features.strings.append("safetensors_format")

                logger.info(f"Extracted {len(features.strings)} features from SafeTensors file")

        except Exception as e:
            logger.error(f"Error extracting from SafeTensors file: {e}")
            features.metadata['extraction_error'] = str(e)

        return features

    def _parse_tensor_metadata(self, metadata: Dict) -> Dict:
        """Parse tensor metadata from SafeTensors header."""
        tensor_info = {
            'names': [],
            'shapes': [],
            'dtypes': set(),
            'count': 0,
            'total_params': 0
        }

        # SafeTensors metadata has special __metadata__ key
        if '__metadata__' in metadata:
            # Skip the metadata entry
            metadata = {k: v for k, v in metadata.items() if k != '__metadata__'}

        for tensor_name, tensor_data in metadata.items():
            if isinstance(tensor_data, dict):
                tensor_info['names'].append(tensor_name)
                tensor_info['count'] += 1

                # Extract dtype
                if 'dtype' in tensor_data:
                    tensor_info['dtypes'].add(tensor_data['dtype'])

                # Extract and store shape
                if 'shape' in tensor_data:
                    shape = tensor_data['shape']
                    tensor_info['shapes'].append(shape)

                    # Calculate number of parameters
                    params = 1
                    for dim in shape:
                        params *= dim
                    tensor_info['total_params'] += params

        return tensor_info

    def _detect_framework(self, tensor_names: List[str]) -> Optional[str]:
        """Detect ML framework from tensor naming patterns."""
        # Convert all names to lowercase for matching
        names_lower = [name.lower() for name in tensor_names]
        all_names = ' '.join(names_lower)

        # PyTorch patterns
        pytorch_patterns = [
            '.weight', '.bias', 'running_mean', 'running_var',
            'num_batches_tracked', 'module.', '_orig_mod.', 'layers.'
        ]
        pytorch_score = sum(1 for p in pytorch_patterns if p in all_names)

        # TensorFlow/Keras patterns
        tf_patterns = [
            'kernel:0', 'bias:0', 'moving_mean:0', 'moving_variance:0',
            'beta:0', 'gamma:0', '/kernel', '/bias'
        ]
        tf_score = sum(1 for p in tf_patterns if p in all_names)

        # JAX/Flax patterns
        jax_patterns = [
            'params/', 'opt_state/', 'batch_stats/',
            'params/Dense', 'params/Conv'
        ]
        jax_score = sum(1 for p in jax_patterns if p in all_names)

        # Hugging Face Transformers patterns
        hf_patterns = [
            'transformer.', 'embeddings.', 'encoder.', 'decoder.',
            'lm_head.', 'cls.', 'pooler.', 'word_embeddings.'
        ]
        hf_score = sum(1 for p in hf_patterns if p in all_names)

        # Determine framework
        scores = {
            'pytorch': pytorch_score,
            'tensorflow': tf_score,
            'jax': jax_score,
            'transformers': hf_score
        }

        if max(scores.values()) > 2:
            return max(scores, key=scores.get)

        return None

    def _detect_architecture(self, tensor_names: List[str]) -> Optional[str]:
        """Detect model architecture from layer names."""
        names_lower = [name.lower() for name in tensor_names]
        all_names = ' '.join(names_lower)

        # Common architectures
        architectures = {
            'bert': ['bert', 'attention.self', 'attention.output', 'intermediate.dense'],
            'gpt': ['gpt', 'transformer.h.', 'attn.c_attn', 'mlp.c_fc'],
            'llama': ['llama', 'model.layers', 'self_attn.q_proj', 'mlp.gate_proj'],
            'resnet': ['resnet', 'layer1', 'layer2', 'layer3', 'layer4', 'conv1', 'bn1'],
            'vit': ['vit', 'vision_transformer', 'patch_embed', 'cls_token'],
            'clip': ['clip', 'text_projection', 'visual_projection', 'logit_scale'],
            'diffusion': ['unet', 'time_embed', 'down_blocks', 'up_blocks', 'mid_block'],
            't5': ['t5', 'encoder.block', 'decoder.block', 'relative_attention_bias'],
            'whisper': ['whisper', 'encoder.conv', 'decoder.token_embedding'],
            'stable_diffusion': ['vae', 'unet', 'text_encoder', 'down_blocks', 'up_blocks']
        }

        for arch_name, patterns in architectures.items():
            if any(pattern in all_names for pattern in patterns):
                return arch_name

        # Check for generic transformer
        if 'transformer' in all_names or 'attention' in all_names:
            return 'transformer'

        # Check for CNN
        if 'conv' in all_names and 'pool' in all_names:
            return 'cnn'

        return None

    def _get_format_version(self, metadata: Dict) -> str:
        """Get SafeTensors format version."""
        if '__metadata__' in metadata:
            meta = metadata['__metadata__']
            if isinstance(meta, dict) and 'format' in meta:
                return meta.get('format', '1.0')
        return '1.0'  # Default version

    def _check_suspicious_patterns(self, metadata: Dict) -> List[str]:
        """Check for format violations and suspicious patterns indicating tampering."""
        suspicious = []

        # Check for format violations that could indicate tampering
        for key, value in metadata.items():
            if key == '__metadata__':
                # Check metadata structure
                if isinstance(value, dict):
                    # Look for unexpected metadata keys
                    meta_keys = set(value.keys())
                    suspicious_meta = meta_keys - {'format', 'pt_version', 'torch_version',
                                                   'tf_version', 'jax_version'}
                    if suspicious_meta:
                        suspicious.append(f"unexpected-metadata:{','.join(suspicious_meta)}")
                continue

            # Tensor entries must be dictionaries
            if not isinstance(value, dict):
                suspicious.append(f"invalid-tensor-type:{key}:{type(value).__name__}")
                continue

            # Check for required and allowed keys in tensor metadata
            required_keys = {'dtype', 'shape', 'data_offsets'}
            allowed_keys = required_keys

            tensor_keys = set(value.keys())

            # Missing required keys indicates corruption/tampering
            missing = required_keys - tensor_keys
            if missing:
                suspicious.append(f"missing-required:{key}:{','.join(missing)}")

            # Extra keys could indicate injection attempts
            extra = tensor_keys - allowed_keys
            if extra:
                suspicious.append(f"injection-attempt:{key}:{','.join(extra)}")

            # Validate dtype values
            if 'dtype' in value:
                valid_dtypes = {'F32', 'F16', 'BF16', 'F64', 'I64', 'I32', 'I16', 'I8', 'U8', 'BOOL'}
                if value['dtype'] not in valid_dtypes:
                    suspicious.append(f"invalid-dtype:{key}:{value['dtype']}")

            # Check for suspiciously large tensors (potential data hiding)
            if 'shape' in value and isinstance(value['shape'], list):
                total_elements = 1
                for dim in value['shape']:
                    if not isinstance(dim, int) or dim < 0:
                        suspicious.append(f"invalid-shape:{key}")
                        break
                    total_elements *= dim

                # Flag tensors over 1 billion elements (potential data exfiltration)
                if total_elements > 1_000_000_000:
                    suspicious.append(f"oversized-tensor:{key}:{total_elements}")

            # Check data_offsets format
            if 'data_offsets' in value:
                offsets = value['data_offsets']
                if not isinstance(offsets, list) or len(offsets) != 2:
                    suspicious.append(f"invalid-offsets:{key}")
                elif not all(isinstance(x, int) and x >= 0 for x in offsets):
                    suspicious.append(f"invalid-offset-values:{key}")

        # Check for tensor names that might indicate hidden data
        tensor_names = [k for k in metadata if k != '__metadata__']
        for name in tensor_names:
            # Look for non-standard naming patterns
            if any(pattern in name.lower() for pattern in [
                'hidden', 'secret', 'payload', 'data', 'exfil',
                'backdoor', 'trigger', 'malicious'
            ]):
                suspicious.append(f"suspicious-name:{name}")

            # Check for base64-like names (potential obfuscation)
            if len(name) > 20 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in name):
                suspicious.append(f"base64-like-name:{name}")

        return suspicious
