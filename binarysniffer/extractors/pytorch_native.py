"""
PyTorch native format extractor for .pt and .pth files.

PyTorch native formats are essentially pickle files with a specific structure
containing model state dictionaries, optimizer states, and metadata.
"""

import logging
import pickletools
from pathlib import Path
from typing import Optional, Set

from .base import BaseExtractor, ExtractedFeatures

logger = logging.getLogger(__name__)


class PyTorchNativeExtractor(BaseExtractor):
    """Extractor for PyTorch native format files (.pt, .pth)."""

    # PyTorch-specific pickle protocol markers
    PYTORCH_MARKERS = {
        'torch._utils._rebuild_tensor',
        'torch._utils._rebuild_tensor_v2',
        'torch._utils._rebuild_parameter',
        'torch._tensor._rebuild_from_type_v2',
        'torch.nn.modules',
        'torch.optim',
        'torch.cuda',
        'torch.FloatStorage',
        'torch.LongStorage',
        'torch.ByteStorage',
        'torch.HalfStorage',
        'torch.DoubleStorage',
        'torch.IntStorage',
        'torch.ShortStorage',
        'torch.CharStorage',
        'torch.BoolStorage',
    }

    # Common PyTorch model architectures
    ARCHITECTURES = {
        'resnet': ['resnet', 'ResNet', 'layer1', 'layer2', 'layer3', 'layer4'],
        'vgg': ['vgg', 'VGG', 'features', 'classifier'],
        'densenet': ['densenet', 'DenseNet', 'denseblock', 'transition'],
        'mobilenet': ['mobilenet', 'MobileNet', 'inverted_residual'],
        'efficientnet': ['efficientnet', 'EfficientNet', '_blocks'],
        'transformer': ['transformer', 'Transformer', 'encoder', 'decoder', 'attention'],
        'bert': ['bert', 'BERT', 'embeddings', 'encoder', 'pooler'],
        'gpt': ['gpt', 'GPT', 'transformer', 'lm_head'],
        'vit': ['vit', 'ViT', 'patch_embed', 'cls_token'],
        'unet': ['unet', 'UNet', 'down', 'up', 'middle'],
    }

    def can_handle(self, file_path: Path) -> bool:
        """Check if file is a PyTorch native format file."""
        # Check extension
        if file_path.suffix.lower() not in ['.pt', '.pth']:
            return False

        try:
            # PyTorch files are pickle files, check magic number
            with open(file_path, 'rb') as f:
                header = f.read(2)
                # Pickle protocol headers
                if header in [b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05']:
                    # Try to check for PyTorch-specific content
                    f.seek(0)
                    content = f.read(min(10000, file_path.stat().st_size))

                    # Look for PyTorch markers in the content
                    content_str = content.decode('latin-1', errors='ignore')
                    return any(marker in content_str for marker in ['torch', 'cuda', 'state_dict'])

        except Exception as e:
            logger.debug(f"Error checking PyTorch file {file_path}: {e}")

        return False

    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from PyTorch native file."""
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type='pytorch',
            strings=[],
            functions=[],
            constants=[],
            imports=[],
            metadata={}
        )

        try:
            # Extract pickle opcodes for analysis
            with open(file_path, 'rb') as f:
                content = f.read()

            # Analyze pickle structure
            opcodes = list(pickletools.genops(content))

            # Track imports and state
            imports = set()
            keys = set()
            tensor_info = []
            has_optimizer = False
            has_state_dict = False
            suspicious_ops = []
            stack = []  # For tracking stack operations

            for opcode, arg, pos in opcodes:
                # Track imports
                if opcode.name in ['GLOBAL', 'STACK_GLOBAL']:
                    if opcode.name == 'GLOBAL':
                        # Handle different GLOBAL formats
                        if isinstance(arg, (tuple, list)) and len(arg) >= 2:
                            import_str = f"{arg[0]}.{arg[1]}"
                        elif isinstance(arg, str):
                            import_str = arg
                        else:
                            import_str = str(arg).replace('\n', '.')
                    else:
                        # STACK_GLOBAL builds module.attribute from stack
                        if len(stack) >= 2:
                            module_name = stack[-2]
                            attr_name = stack[-1]
                            import_str = f"{module_name}.{attr_name}"
                            stack = stack[:-2]  # Remove the two items used

                            # Normalize posix.system to os.system
                            if import_str == 'posix.system' or import_str == 'nt.system':
                                import_str = 'os.system'
                        else:
                            import_str = "stack_global_incomplete"

                    imports.add(import_str)
                    features.imports.append(import_str)

                    # Check for PyTorch modules
                    if 'torch' in import_str:
                        features.strings.append(import_str.replace('.', '_'))

                    # Check for optimizer
                    if 'optim' in import_str:
                        has_optimizer = True

                    # Check for dangerous operations
                    if any(danger in import_str for danger in [
                        'os.system', 'subprocess', 'eval', 'exec',
                        'compile', '__import__', 'open'
                    ]):
                        suspicious_ops.append(import_str)

                # Track string keys (likely layer names)
                elif opcode.name in ['SHORT_BINSTRING', 'BINSTRING', 'BINUNICODE', 'UNICODE', 'STRING', 'SHORT_BINUNICODE']:
                    if isinstance(arg, (bytes, str)):
                        key = arg.decode('utf-8') if isinstance(arg, bytes) else arg
                        keys.add(key)
                        stack.append(key)  # Add to stack for STACK_GLOBAL resolution

                        # Check for state_dict variations
                        if key in ['state_dict', 'model_state_dict']:
                            has_state_dict = True

                        # Check for optimizer variations
                        if key in ['optimizer_state_dict', 'optimizer']:
                            has_optimizer = True

                        # Extract layer names and parameter names
                        if any(pattern in key for pattern in [
                            'weight', 'bias', 'running_mean', 'running_var',
                            'num_batches_tracked', 'layer', 'conv', 'bn', 'fc',
                            'attention', 'encoder', 'decoder', 'query', 'key', 'value'
                        ]):
                            features.constants.append(key)

                # Track tensor rebuild operations
                elif opcode.name == 'REDUCE':
                    if arg and len(arg) > 0:
                        func = str(arg[0])
                        if 'rebuild_tensor' in func:
                            tensor_info.append('tensor_rebuild')

            # Detect architecture
            architecture = self._detect_architecture(keys)
            if architecture:
                features.metadata['architecture'] = architecture
                features.strings.append(f'architecture:{architecture}')

            # Add metadata
            features.metadata['format'] = 'pytorch_native'
            features.metadata['has_state_dict'] = has_state_dict
            features.metadata['has_optimizer'] = has_optimizer
            features.metadata['layer_count'] = len([k for k in keys if 'layer' in k.lower()])
            features.metadata['parameter_keys'] = len([k for k in keys if any(
                p in k for p in ['weight', 'bias', 'running_mean', 'running_var']
            )])

            # Security assessment
            if suspicious_ops:
                features.metadata['suspicious_operations'] = suspicious_ops
                features.metadata['risk_level'] = 'dangerous'
                for op in suspicious_ops:
                    features.strings.append(f'dangerous:{op}')
            else:
                features.metadata['risk_level'] = 'safe'

            # Add PyTorch identifiers
            features.strings.append('pytorch_native_format')
            features.strings.append('__pytorch__')
            if has_state_dict:
                features.strings.append('state_dict')
            if has_optimizer:
                features.strings.append('optimizer_state')

            # Add import signatures
            pytorch_imports = [imp for imp in imports if 'torch' in imp]
            features.metadata['pytorch_modules'] = list(pytorch_imports)

            logger.info(f"Extracted {len(features.strings)} features from PyTorch file")

        except Exception as e:
            logger.error(f"Error extracting from PyTorch file: {e}")
            features.metadata['extraction_error'] = str(e)

        return features

    def _detect_architecture(self, keys: Set[str]) -> Optional[str]:
        """Detect model architecture from layer keys."""
        keys_lower = {k.lower() for k in keys}
        all_keys = ' '.join(keys_lower)

        for arch_name, patterns in self.ARCHITECTURES.items():
            matches = sum(1 for pattern in patterns if pattern.lower() in all_keys)
            if matches >= 2:  # Need at least 2 pattern matches
                return arch_name

        # Check for generic patterns
        if 'conv' in all_keys and 'pool' in all_keys:
            return 'cnn'
        if 'attention' in all_keys or 'transformer' in all_keys:
            return 'transformer'
        if 'lstm' in all_keys or 'gru' in all_keys or 'rnn' in all_keys:
            return 'rnn'

        return None
