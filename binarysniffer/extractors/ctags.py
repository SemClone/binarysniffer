"""
CTags-based source code feature extractor (example implementation)
"""

import subprocess
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseExtractor, ExtractedFeatures


logger = logging.getLogger(__name__)


class CTagsExtractor(BaseExtractor):
    """Extract features from source code using CTags"""
    
    # Source code extensions that CTags supports
    SOURCE_EXTENSIONS = {
        # C/C++
        '.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.hxx',
        # Python
        '.py', '.pyw',
        # Java
        '.java',
        # JavaScript/TypeScript
        '.js', '.jsx', '.ts', '.tsx',
        # Go
        '.go',
        # Rust
        '.rs',
        # Ruby
        '.rb',
        # PHP
        '.php',
        # and many more...
    }
    
    def __init__(self, min_string_length: int = 5, max_strings: int = 10000):
        super().__init__(min_string_length, max_strings)
        self.ctags_available = self._check_ctags()
    
    def _check_ctags(self) -> bool:
        """Check if universal-ctags is available"""
        try:
            result = subprocess.run(
                ['ctags', '--version'],
                capture_output=True,
                text=True
            )
            return 'Universal Ctags' in result.stdout
        except Exception:
            logger.warning("CTags not found. Install universal-ctags for source code analysis.")
            return False
    
    def can_handle(self, file_path: Path) -> bool:
        """Check if this extractor can handle the file"""
        return (
            self.ctags_available and 
            file_path.suffix.lower() in self.SOURCE_EXTENSIONS
        )
    
    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features using CTags"""
        logger.debug(f"Extracting features from source: {file_path}")
        
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type="source"
        )
        
        if not self.ctags_available:
            logger.error("CTags not available")
            return features
        
        try:
            # Run ctags with JSON output
            result = subprocess.run(
                [
                    'ctags',
                    '--output-format=json',
                    '--fields=+n',  # Include line numbers
                    '--kinds-all=*',  # All symbol types
                    '--recurse=no',
                    str(file_path)
                ],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                logger.error(f"CTags failed: {result.stderr}")
                return features
            
            # Parse JSON output
            for line in result.stdout.splitlines():
                if line.strip():
                    try:
                        tag = json.loads(line)
                        self._process_tag(tag, features)
                    except json.JSONDecodeError:
                        continue
            
            # Also extract string literals and imports using regex
            self._extract_additional_features(file_path, features)
            
        except Exception as e:
            logger.error(f"Error running CTags: {e}")
        
        return features
    
    def _process_tag(self, tag: Dict[str, Any], features: ExtractedFeatures):
        """Process a single CTags entry"""
        name = tag.get('name', '')
        kind = tag.get('kind', '')
        
        if not name or len(name) < self.min_string_length:
            return
        
        # Map CTags kinds to our categories
        if kind in ['function', 'method', 'procedure']:
            features.functions.append(name)
        elif kind in ['constant', 'macro', 'enumerator']:
            features.constants.append(name)
        elif kind in ['class', 'struct', 'interface', 'typedef']:
            features.symbols.append(name)
        elif kind in ['import', 'include', 'package']:
            features.imports.append(tag.get('pattern', name))
        else:
            # Generic symbol
            features.symbols.append(name)
    
    def _extract_additional_features(self, file_path: Path, features: ExtractedFeatures):
        """Extract additional features not captured by CTags"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Extract string literals
            # Simple regex for quoted strings (can be improved)
            import re
            
            # Double-quoted strings
            strings = re.findall(r'"([^"]{5,})"', content)
            features.strings.extend(self._filter_strings(strings))
            
            # Single-quoted strings
            strings = re.findall(r"'([^']{5,})'", content)
            features.strings.extend(self._filter_strings(strings))
            
            # Language-specific imports
            if file_path.suffix == '.py':
                # Python imports
                imports = re.findall(r'(?:from|import)\s+([a-zA-Z0-9_.]+)', content)
                features.imports.extend(imports)
            elif file_path.suffix in ['.js', '.ts']:
                # JavaScript imports
                imports = re.findall(r'(?:import|require)\s*\(?[\'"]([^\'"]+ )[\'"]', content)
                features.imports.extend(imports)
            
        except Exception as e:
            logger.debug(f"Error extracting additional features: {e}")


# Example of how to integrate into ExtractorFactory:
"""
def __init__(self):
    self.extractors = [
        BinaryExtractor(),
        CTagsExtractor(),  # Add CTags support
        # Add more extractors here
    ]
"""