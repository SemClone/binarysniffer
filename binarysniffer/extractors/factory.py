"""
Factory for selecting appropriate feature extractor
"""

import logging
from pathlib import Path
from typing import Optional

from .base import BaseExtractor, ExtractedFeatures
from .binary_improved import ImprovedBinaryExtractor
from .source import SourceCodeExtractor
from .archive import ArchiveExtractor
from .dex import DexExtractor
from .binary_lief import LiefBinaryExtractor


logger = logging.getLogger(__name__)


class ExtractorFactory:
    """Factory for creating appropriate extractors"""
    
    def __init__(self, enable_ctags=True):
        """Initialize factory with available extractors
        
        Args:
            enable_ctags: Whether to enable CTags extractor if available
        """
        self.extractors = [
            ArchiveExtractor(),     # Check archives first (contains other files)
            DexExtractor(),        # DEX files (Android bytecode)
        ]
        
        # Add LIEF-based binary extractor if available
        try:
            lief_extractor = LiefBinaryExtractor()
            if lief_extractor.has_lief:
                self.extractors.append(lief_extractor)
                logger.debug("LIEF binary extractor enabled")
        except Exception as e:
            logger.debug(f"LIEF binary extractor not available: {e}")
        
        # Try to add CTags extractor if enabled
        if enable_ctags:
            try:
                from .ctags import CTagsExtractor
                ctags_extractor = CTagsExtractor()
                if ctags_extractor.ctags_available:
                    self.extractors.append(ctags_extractor)
                    logger.debug("CTags extractor enabled")
            except ImportError:
                logger.debug("CTags extractor not available")
        
        # Add remaining extractors
        self.extractors.extend([
            SourceCodeExtractor(),  # Source code (fallback if CTags unavailable)
            ImprovedBinaryExtractor(),      # Finally binaries as fallback
        ])
    
    def get_extractor(self, file_path: Path) -> BaseExtractor:
        """
        Get appropriate extractor for file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Appropriate extractor instance
        """
        file_path = Path(file_path)
        
        # Try each extractor
        for extractor in self.extractors:
            if extractor.can_handle(file_path):
                logger.debug(f"Using {extractor.__class__.__name__} for {file_path}")
                return extractor
        
        # Default to binary extractor
        logger.debug(f"No specific extractor found, using ImprovedBinaryExtractor for {file_path}")
        return ImprovedBinaryExtractor()
    
    def extract(self, file_path: Path) -> ExtractedFeatures:
        """
        Extract features using appropriate extractor.
        
        Args:
            file_path: Path to file
            
        Returns:
            Extracted features
        """
        extractor = self.get_extractor(file_path)
        return extractor.extract(file_path)