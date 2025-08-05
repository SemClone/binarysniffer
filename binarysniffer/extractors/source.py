"""
Simple source code feature extractor using regex
"""

import re
import logging
from pathlib import Path
from typing import List, Dict, Set

from .base import BaseExtractor, ExtractedFeatures


logger = logging.getLogger(__name__)


class SourceCodeExtractor(BaseExtractor):
    """Extract features from source code files using regex patterns"""
    
    # Source file extensions
    SOURCE_EXTENSIONS = {
        '.py', '.js', '.java', '.c', '.cpp', '.h', '.hpp',
        '.go', '.rs', '.rb', '.php', '.cs', '.swift', '.kt'
    }
    
    # Language-specific patterns (improved for better coverage)
    PATTERNS = {
        'function': [
            r'def\s+([a-zA-Z_]\w+)(?:\s*\(|$|\s)',  # Python/Ruby (improved)
            r'function\s+([a-zA-Z_]\w+)\s*\(',  # JavaScript
            r'func\s+([a-zA-Z_]\w+)\s*\(',  # Go/Swift
            r'fn\s+([a-zA-Z_]\w+)\s*\(',  # Rust
            r'fun\s+([a-zA-Z_]\w+)\s*\(',  # Kotlin
            r'(?:public|private|protected)?\s*\w+\s+([a-zA-Z_]\w+)\s*\([^)]*\)\s*[{;]',  # Java/C#/C++ (improved)
        ],
        'class': [
            r'class\s+([A-Z]\w+)',  # Most languages
            r'struct\s+([A-Z]\w+)',  # C/C++/Rust
            r'interface\s+([A-Z]\w+)',  # TypeScript/Java
            r'type\s+([A-Z]\w+)\s+struct',  # Go
            r'enum\s+([A-Z]\w+)',  # Rust/Swift/C#
        ],
        'import': [
            r'import\s+([a-zA-Z0-9_.]+)',  # Python/Java
            r'from\s+([a-zA-Z0-9_.]+)\s+import',  # Python
            r'require\s*\([\'"]([^\'\"]+)[\'"]',  # Node.js
            r'use\s+([a-zA-Z0-9_:]+)',  # Rust
            r'#include\s*[<"]([^>"]+)[>"]',  # C/C++
            r'import\s+"([^"]+)"',  # Go
            r'using\s+([a-zA-Z0-9_.]+)',  # C#
            r'import\s+([a-zA-Z0-9_.]+)\.\*',  # Kotlin wildcard imports
        ],
        'constant': [
            r'(?:const|final|readonly)\s+\w+\s+([A-Z_][A-Z0-9_]+)',  # Constants
            r'([A-Z_][A-Z0-9_]+)\s*=\s*["\'\d]',  # Assignment to uppercase
            r'#define\s+([A-Z_][A-Z0-9_]+)',  # C/C++ macros
            r'const\s+([A-Z_][A-Z0-9_]+)\s*:',  # Rust
            r'const\s+val\s+([A-Z_][A-Z0-9_]+)',  # Kotlin
        ]
    }
    
    def can_handle(self, file_path: Path) -> bool:
        """Check if file is source code"""
        return file_path.suffix.lower() in self.SOURCE_EXTENSIONS
    
    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from source code"""
        logger.debug(f"Extracting features from source: {file_path}")
        
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type="source"
        )
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Extract functions
            for pattern in self.PATTERNS['function']:
                matches = re.findall(pattern, content, re.MULTILINE)
                features.functions.extend(self._filter_strings(matches))
            
            # Extract classes/structs
            for pattern in self.PATTERNS['class']:
                matches = re.findall(pattern, content, re.MULTILINE)
                features.symbols.extend(self._filter_strings(matches))
            
            # Extract imports
            for pattern in self.PATTERNS['import']:
                matches = re.findall(pattern, content, re.MULTILINE)
                features.imports.extend(matches)
            
            # Extract constants
            for pattern in self.PATTERNS['constant']:
                matches = re.findall(pattern, content, re.MULTILINE)
                features.constants.extend(self._filter_strings(matches))
            
            # Extract string literals
            strings = re.findall(r'["\']([^"\']{10,})["\']', content)
            features.strings.extend(self._filter_strings(strings))
            
            # Remove duplicates
            features.functions = list(set(features.functions))[:1000]
            features.symbols = list(set(features.symbols))[:1000]
            features.constants = list(set(features.constants))[:500]
            features.imports = list(set(features.imports))[:200]
            features.strings = list(set(features.strings))[:self.max_strings]
            
            # Set metadata
            features.metadata = {
                'language': self._detect_language(file_path),
                'size': file_path.stat().st_size,
                'line_count': content.count('\n')
            }
            
        except Exception as e:
            logger.error(f"Error extracting from {file_path}: {e}")
        
        return features
    
    def _detect_language(self, file_path: Path) -> str:
        """Detect programming language from extension"""
        ext_to_lang = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.go': 'go',
            '.rs': 'rust',
            '.rb': 'ruby',
            '.php': 'php',
            '.cs': 'csharp',
            '.swift': 'swift',
            '.kt': 'kotlin'
        }
        return ext_to_lang.get(file_path.suffix.lower(), 'unknown')