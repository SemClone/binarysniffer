"""
Feature extraction modules
"""

from .base import BaseExtractor, ExtractedFeatures
from .factory import ExtractorFactory

__all__ = [
    "ExtractorFactory",
    "BaseExtractor",
    "ExtractedFeatures"
]
