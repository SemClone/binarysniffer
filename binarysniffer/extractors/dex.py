"""
DEX file extractor for Android bytecode analysis
"""

import logging
import subprocess
from pathlib import Path
from typing import List, Set

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

from .base import BaseExtractor, ExtractedFeatures

logger = logging.getLogger(__name__)


class DexExtractor(BaseExtractor):
    """Extract features from Android DEX files"""
    
    def __init__(self, min_string_length: int = 4, max_strings: int = 50000):
        """Initialize DEX extractor"""
        super().__init__(min_string_length, max_strings)
        self.has_lief = HAS_LIEF
        
    def can_handle(self, file_path: Path) -> bool:
        """Check if file is a DEX file"""
        if file_path.suffix.lower() == '.dex':
            return True
            
        # Check magic bytes
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(8)
                # DEX magic: "dex\n035\0" or "dex\n037\0" etc
                if magic.startswith(b'dex\n'):
                    return True
        except Exception:
            pass
            
        return False
    
    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from DEX file"""
        logger.debug(f"Extracting features from DEX: {file_path}")
        
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type="dex"
        )
        
        strings = set()
        
        # Try LIEF first for structured extraction
        if self.has_lief:
            try:
                dex = lief.DEX.parse(str(file_path))
                if dex:
                    # Extract class names
                    for cls in dex.classes:
                        if cls.name:
                            # Convert Lcom/example/Class; to com.example.Class
                            class_name = cls.name.replace('/', '.').strip('L;')
                            strings.add(class_name)
                            features.imports.append(class_name)
                    
                    # Extract method names
                    for method in dex.methods:
                        if method.name:
                            strings.add(method.name)
                            features.functions.append(method.name)
                    
                    # Extract strings
                    for string in dex.strings:
                        if string and len(string) >= self.min_string_length:
                            strings.add(string)
                            
            except Exception as e:
                logger.debug(f"LIEF DEX parsing failed for {file_path}: {e}")
        
        # Also use strings command for comprehensive extraction
        try:
            result = subprocess.run(
                ['strings', '-n', str(self.min_string_length), str(file_path)],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line and len(line) >= self.min_string_length:
                        strings.add(line.strip())
                        
                        # Identify package names
                        if line.startswith('L') and line.endswith(';') and '/' in line:
                            # Convert Lcom/example/Class; format
                            class_name = line.replace('/', '.').strip('L;')
                            if '.' in class_name:
                                features.imports.append(class_name)
                        
                        # Common Android/Java patterns
                        if any(line.startswith(prefix) for prefix in 
                              ['com.', 'org.', 'android.', 'java.', 'javax.', 'kotlin.']):
                            features.imports.append(line)
                            
        except Exception as e:
            logger.debug(f"String extraction failed for {file_path}: {e}")
        
        # Process extracted strings
        features.strings = list(strings)[:self.max_strings]
        
        # Extract meaningful patterns
        for s in features.strings:
            # Library indicators
            if any(lib in s.lower() for lib in 
                  ['firebase', 'crashlytics', 'analytics', 'facebook', 'twitter',
                   'okhttp', 'retrofit', 'glide', 'picasso', 'gson', 'jackson',
                   'sqlite', 'realm', 'room', 'rxjava', 'rxandroid', 'dagger',
                   'butterknife', 'eventbus', 'volley', 'admob', 'unity3d']):
                features.constants.append(s)
        
        # Deduplicate
        features.functions = list(set(features.functions))[:10000]
        features.imports = list(set(features.imports))[:10000]
        features.constants = list(set(features.constants))[:5000]
        
        # Metadata
        features.metadata = {
            'size': file_path.stat().st_size,
            'has_lief': self.has_lief,
            'total_strings': len(strings)
        }
        
        return features