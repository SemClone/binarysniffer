"""
Semantic Copycat BinarySniffer - High-performance OSS component detection

A CLI tool and Python library for detecting open source components in binaries
through semantic signature matching.
"""

__version__ = "1.8.6"
__author__ = "Oscar Valenzuela B."
__email__ = "oscar.valenzuela.b@gmail.com"
__license__ = "Apache-2.0"

from .core.analyzer import BinarySniffer
from .core.analyzer_enhanced import EnhancedBinarySniffer
from .core.config import Config
from .core.results import AnalysisResult, ComponentMatch

__all__ = [
    "BinarySniffer",
    "EnhancedBinarySniffer",
    "Config", 
    "AnalysisResult",
    "ComponentMatch",
]