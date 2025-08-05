"""
Base extractor class and data structures
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Set, Dict, Any
from pathlib import Path


@dataclass
class ExtractedFeatures:
    """Container for extracted features from a file"""
    
    file_path: str
    file_type: str
    strings: List[str] = field(default_factory=list)
    symbols: List[str] = field(default_factory=list)
    functions: List[str] = field(default_factory=list)
    constants: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def all_features(self) -> List[str]:
        """Get all extracted features"""
        features = []
        features.extend(self.strings)
        features.extend(self.symbols)
        features.extend(self.functions)
        features.extend(self.constants)
        features.extend(self.imports)
        return features
    
    @property
    def unique_features(self) -> Set[str]:
        """Get unique features"""
        return set(self.all_features)
    
    def filter_by_length(self, min_length: int = 5) -> "ExtractedFeatures":
        """Filter features by minimum length"""
        return ExtractedFeatures(
            file_path=self.file_path,
            file_type=self.file_type,
            strings=[s for s in self.strings if len(s) >= min_length],
            symbols=[s for s in self.symbols if len(s) >= min_length],
            functions=[s for s in self.functions if len(s) >= min_length],
            constants=[s for s in self.constants if len(s) >= min_length],
            imports=self.imports,  # Keep all imports
            metadata=self.metadata
        )


class BaseExtractor(ABC):
    """Base class for all feature extractors"""
    
    def __init__(self, min_string_length: int = 5, max_strings: int = 10000):
        """
        Initialize extractor.
        
        Args:
            min_string_length: Minimum length for extracted strings
            max_strings: Maximum number of strings to extract
        """
        self.min_string_length = min_string_length
        self.max_strings = max_strings
    
    @abstractmethod
    def can_handle(self, file_path: Path) -> bool:
        """Check if this extractor can handle the file"""
        pass
    
    @abstractmethod
    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from the file"""
        pass
    
    def _filter_strings(self, strings: List[str]) -> List[str]:
        """Filter and limit strings"""
        # Filter by length
        filtered = [s for s in strings if len(s) >= self.min_string_length]
        
        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for s in filtered:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        
        # Limit number of strings
        return unique[:self.max_strings]