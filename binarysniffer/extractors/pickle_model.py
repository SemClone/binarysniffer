"""
Pickle file parser for ML model security analysis.

This module extracts features from pickle files without executing them,
focusing on detecting potentially malicious operations and ML framework signatures.
"""

import logging
import pickletools
from pathlib import Path
from typing import Set

from binarysniffer.extractors.base import BaseExtractor, ExtractedFeatures

logger = logging.getLogger(__name__)

# Pickle opcodes that can execute code
DANGEROUS_OPCODES = {
    'GLOBAL',     # Import a module/class
    'REDUCE',     # Call a function
    'BUILD',      # Call __setstate__ or similar
    'INST',       # Instantiate a class (protocol 0)
    'OBJ',        # Build a class instance
    'NEWOBJ',     # New-style class instance
    'NEWOBJ_EX',  # New-style class with kwargs
    'STACK_GLOBAL',  # Import via stack
}

# Known dangerous imports
DANGEROUS_IMPORTS = {
    'os.system', 'os.popen', 'os.execv', 'os.execve', 'os.spawnv',
    'subprocess.call', 'subprocess.run', 'subprocess.Popen', 'subprocess.check_output',
    'eval', 'exec', '__import__', 'compile', 'execfile',
    'socket.socket', 'socket.create_connection', 'socket.AddressFamily', 'socket.SocketKind',
    'requests.get', 'requests.post', 'urllib.request.urlopen', 'urllib.urlopen',
    'webbrowser.open', 'antigravity',  # Yes, antigravity can open browser
    'builtins.eval', 'builtins.exec', 'builtins.__import__',
    'importlib.import_module', 'importlib.__import__',
    'code.interact', 'code.compile_command',
    'commands.getoutput', 'commands.getstatusoutput',
    'pty.spawn', 'pty.fork',
    'multiprocessing.Process', 'threading.Thread',
}

# Suspicious string patterns
SUSPICIOUS_PATTERNS = {
    # Shell indicators
    '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell.exe',
    'reverse_tcp', 'bind_shell', 'meterpreter',

    # Network indicators
    'LHOST=', 'LPORT=', '0.0.0.0', '127.0.0.1',
    'nc -e', 'ncat ', 'socat ',

    # Encoding/obfuscation
    'base64.b64decode', 'zlib.decompress', 'codecs.decode',
    'marshal.loads', 'pickle.loads',

    # Common exploit patterns
    '__reduce__', '__setstate__', '__getstate__',
    'os._wrap_close', 'subprocess._wrap_close',
}

# ML framework signatures
ML_FRAMEWORK_SIGNATURES = {
    'sklearn': {
        'sklearn.', 'sklearn.tree._tree.Tree', 'sklearn.ensemble',
        'sklearn.linear_model', 'sklearn.svm', 'sklearn.neural_network',
        'sklearn.preprocessing', 'sklearn.pipeline',
    },
    'torch': {
        'torch.', 'torch.nn', 'torch.tensor', 'torch.cuda',
        'torch.jit', 'torch.onnx', 'torch.optim',
        'torch._utils._rebuild_tensor',
    },
    'tensorflow': {
        'tensorflow.', 'tf.', 'tensorflow.keras', 'tensorflow.lite',
        'tensorflow.saved_model', 'tensorflow.estimator',
    },
    'numpy': {
        'numpy.', 'numpy.ndarray', 'numpy.core.multiarray',
        'numpy.dtype', 'numpy.random',
    },
    'pandas': {
        'pandas.', 'pandas.core', 'pandas.DataFrame',
        'pandas.Series', 'pandas.Index',
    },
    'xgboost': {
        'xgboost.', 'xgboost.core', 'xgboost.sklearn',
        'xgboost.Booster', 'xgboost.DMatrix',
    },
    'lightgbm': {
        'lightgbm.', 'lightgbm.sklearn', 'lightgbm.Booster',
        'lightgbm.Dataset', 'lightgbm.LGBMClassifier',
    },
}


class PickleModelExtractor(BaseExtractor):
    """Extract features from pickle files for security analysis."""

    def can_handle(self, file_path: Path) -> bool:
        """Check if file is a pickle file."""
        # Check extension
        # Note: .pth files can be pickled PyTorch models
        if file_path.suffix.lower() in ['.pkl', '.pickle', '.p', '.pth']:
            return True

        # Check magic bytes for pickle protocol
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)  # Read more bytes for better identification
                # Protocol 3: b'\x80\x03'
                # Protocol 4: b'\x80\x04'
                # Protocol 5: b'\x80\x05'
                if len(header) >= 2 and header[:2] in [b'\x80\x03', b'\x80\x04', b'\x80\x05']:
                    return True

                # Protocol 0-2 are ASCII-based and more complex to detect
                # Only check for specific known patterns, not just any single character
                if len(header) >= 1:
                    first_byte = header[0:1]
                    # More restrictive checks for pickle protocol 0-2
                    if first_byte == b'(':
                        # Likely a tuple start in protocol 0
                        return True
                    elif first_byte == b'c' and len(header) >= 4:
                        # Check for pickle GLOBAL opcode pattern: c<module>\n<name>\n
                        # Look for newline characters which indicate pickle format
                        if b'\n' in header[1:4] or b'\r' in header[1:4]:
                            return True
                    elif first_byte in [b'}', b']'] and len(header) >= 2:
                        # Dict/list end markers - check if followed by reasonable pickle data
                        # This is quite rare as a file start, so be more careful
                        if header[1:2] in [b'q', b'p', b'(', b'.']: # Common pickle opcodes
                            return True
        except Exception:
            pass

        return False

    def extract(self, file_path: Path, use_advanced_security: bool = False) -> ExtractedFeatures:
        """Extract features from pickle file without executing it.
        
        Args:
            file_path: Path to pickle file
            use_advanced_security: Use advanced security module for deep analysis
        """
        # If advanced security is requested, use the security module
        if use_advanced_security:
            try:
                from binarysniffer.security.pickle_analyzer import PickleSecurityAnalyzer
                analyzer = PickleSecurityAnalyzer()
                risk_assessment, security_features = analyzer.analyze_pickle(str(file_path))
                
                # Convert security features to standard format
                features = security_features
                imports = {f for f in features if f.startswith('import:')}
                imports = {f.replace('import:', '') for f in imports}
                
                ml_frameworks = {f.replace('ml_framework:', '') 
                               for f in features if f.startswith('ml_framework:')}
                
                suspicious_items = {f for f in features if f.startswith('suspicious:')}
                
                return ExtractedFeatures(
                    file_path=str(file_path),
                    file_type='pickle',
                    strings=list(features),
                    imports=list(imports),
                    functions=[],
                    constants=list(ml_frameworks),
                    symbols=[],
                    metadata={
                        'risk_assessment': risk_assessment.to_dict(),
                        'frameworks': list(ml_frameworks),
                        'suspicious_items': list(suspicious_items) if suspicious_items else None
                    }
                )
            except ImportError:
                logger.debug("Advanced security module not available, using standard extraction")
            except Exception as e:
                logger.error(f"Error in advanced security analysis: {e}")
        
        # Standard extraction
        features = set()
        imports = set()
        suspicious_items = set()
        ml_frameworks = set()
        risk_indicators = []
        risk_level = "unknown"  # Initialize risk_level

        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            # Parse opcodes using pickletools (safe, no execution)
            opcodes = list(pickletools.genops(content))

            # Track stack for STACK_GLOBAL resolution
            stack = []

            for opcode, arg, pos in opcodes:
                opname = opcode.name


                # Track dangerous opcodes
                if opname in DANGEROUS_OPCODES:
                    features.add(f"pickle_opcode:{opname}")

                    # Handle STACK_GLOBAL (builds name from stack)
                    if opname == 'STACK_GLOBAL':
                        if len(stack) >= 2:
                            module_name = stack[-2]
                            attr_name = stack[-1]
                            import_str = f"{module_name}.{attr_name}"
                            stack = stack[:-2]

                            # Normalize posix.system to os.system
                            if import_str == 'posix.system' or import_str == 'nt.system':
                                import_str = 'os.system'

                            imports.add(import_str)
                            features.add(f"pickle_import:{import_str}")

                            # Check for dangerous imports
                            for dangerous in DANGEROUS_IMPORTS:
                                if dangerous in import_str or import_str.startswith(dangerous):
                                    suspicious_items.add(f"dangerous_import:{import_str}")
                                    risk_indicators.append(f"DANGEROUS: {import_str}")

                            # Check for ML frameworks
                            for framework, signatures in ML_FRAMEWORK_SIGNATURES.items():
                                for sig in signatures:
                                    if import_str.startswith(sig):
                                        ml_frameworks.add(framework)
                                        features.add(f"ml_framework:{framework}")
                                        break

                    # Handle regular GLOBAL opcodes
                    elif opname == 'GLOBAL' and arg:
                        # Handle different formats of GLOBAL arguments
                        if isinstance(arg, str):
                            import_str = arg
                        elif isinstance(arg, (list, tuple)) and len(arg) >= 2:
                            import_str = f"{arg[0]}.{arg[1]}"
                        else:
                            import_str = str(arg).replace('\n', '.')

                        imports.add(import_str)
                        features.add(f"pickle_import:{import_str}")

                        # Check for dangerous imports
                        for dangerous in DANGEROUS_IMPORTS:
                            if dangerous in import_str or import_str.startswith(dangerous):
                                suspicious_items.add(f"dangerous_import:{import_str}")
                                risk_indicators.append(f"DANGEROUS: {import_str}")

                        # Check for ML frameworks
                        for framework, signatures in ML_FRAMEWORK_SIGNATURES.items():
                            for sig in signatures:
                                if import_str.startswith(sig):
                                    ml_frameworks.add(framework)
                                    features.add(f"ml_framework:{framework}")
                                    break

                # Extract string constants (also track for STACK_GLOBAL)
                elif opname in ['STRING', 'BINSTRING', 'SHORT_BINSTRING',
                               'UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE']:
                    if arg and isinstance(arg, (str, bytes)):
                        string_val = arg.decode('utf-8', errors='ignore') if isinstance(arg, bytes) else arg

                        # Add to stack for STACK_GLOBAL resolution
                        stack.append(string_val)

                        # Check for suspicious patterns
                        for pattern in SUSPICIOUS_PATTERNS:
                            if pattern in string_val.lower():
                                suspicious_items.add(f"suspicious_string:{pattern}")
                                risk_indicators.append(f"SUSPICIOUS: Found '{pattern}'")

                        # Add significant strings as features
                        if len(string_val) > 4 and len(string_val) < 100:
                            # Clean the string for feature extraction
                            clean_str = ''.join(c for c in string_val if c.isalnum() or c in '._-')
                            if clean_str:
                                features.add(f"pickle_string:{clean_str[:50]}")

                # Track other interesting opcodes
                elif opname in ['MARK', 'STOP', 'FRAME', 'MEMOIZE']:
                    features.add(f"pickle_structure:{opname}")

            # Add risk assessment
            risk_level = self._assess_risk(imports, suspicious_items, ml_frameworks)
            features.add(f"pickle_risk:{risk_level}")

            # Add detected frameworks
            for framework in ml_frameworks:
                features.add(f"detected_framework:{framework}")

            # Add all suspicious items as features
            features.update(suspicious_items)

            # Log findings
            if risk_indicators:
                logger.debug(f"Pickle file {file_path.name} contains risky operations: {risk_indicators}")

            logger.debug(f"Extracted {len(features)} features from pickle file {file_path.name}")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error parsing pickle file {file_path}: {e}")
            features.add("pickle_parse_error")
            
            # Provide more specific error information
            if "unknown" in error_msg.lower() and "opcode" in error_msg.lower():
                features.add("malformed_pickle:invalid_opcode")
                risk_level = "malformed"
                suspicious_items.add("invalid_pickle_structure")
            elif "position" in error_msg.lower():
                features.add("malformed_pickle:truncated")
                risk_level = "malformed"
                suspicious_items.add("truncated_pickle_file")
            else:
                features.add("malformed_pickle:unknown_error")
                risk_level = "error"

        return ExtractedFeatures(
            file_path=str(file_path),
            file_type='pickle',
            strings=list(features),
            imports=list(imports),
            functions=[],  # Pickle doesn't have traditional functions
            constants=list(ml_frameworks),  # Use constants for detected frameworks
            symbols=[],
            metadata={'risk_level': risk_level, 'frameworks': list(ml_frameworks), 
                     'suspicious_items': list(suspicious_items) if suspicious_items else None}
        )

    def _assess_risk(self, imports: Set[str], suspicious: Set[str], frameworks: Set[str]) -> str:
        """Assess the risk level of the pickle file."""
        # Count dangerous indicators
        dangerous_count = sum(1 for i in imports for d in DANGEROUS_IMPORTS if d in i)
        suspicious_count = len(suspicious)

        # If it's a known ML framework with no dangerous operations, it's probably safe
        if frameworks and dangerous_count == 0 and suspicious_count == 0:
            return "safe"

        # Determine risk level
        if dangerous_count > 0:
            return "dangerous"
        if suspicious_count > 2:
            return "high_risk"
        if suspicious_count > 0:
            return "suspicious"
        if frameworks:
            return "likely_safe"
        return "unknown"

    def validate_safe_unpickle(self, file_path: Path) -> bool:
        """Validate if a pickle file is safe to unpickle.

        Args:
            file_path: Path to the pickle file

        Returns:
            True if safe to unpickle, False if dangerous
        """
        try:
            features = self.extract(file_path)

            # Check for dangerous imports in features
            dangerous_features = [
                f for f in features.strings
                if 'dangerous_import:' in f or 'pickle_risk:dangerous' in f
            ]

            # Check for suspicious items in metadata
            metadata = features.metadata or {}
            suspicious_items = metadata.get('suspicious_items', [])
            risk_level = metadata.get('risk_level', 'unknown')

            # File is NOT safe if:
            # 1. Contains dangerous imports
            # 2. Has suspicious items
            # 3. Risk level is dangerous or high_risk
            if dangerous_features or suspicious_items or risk_level in ['dangerous', 'high_risk']:
                return False

            # File is safe if:
            # 1. Risk level is safe or likely_safe
            # 2. Contains ML frameworks (indicates legitimate model)
            # 3. No dangerous patterns detected
            if risk_level in ['safe', 'likely_safe']:
                return True

            # For unknown/suspicious but not dangerous files, err on the side of caution
            return risk_level not in ['suspicious', 'malformed', 'error']

        except Exception as e:
            logger.error(f"Error validating pickle safety for {file_path}: {e}")
            # If we can't analyze it, assume it's not safe
            return False

