"""
Factory for selecting appropriate feature extractor
"""

import logging
from pathlib import Path

from .archive import ArchiveExtractor
from .base import BaseExtractor, ExtractedFeatures
from .binary_improved import ImprovedBinaryExtractor
from .binary_lief import LiefBinaryExtractor
from .dex import DexExtractor
from .hermes import HermesExtractor
from .onnx_model import ONNXModelExtractor
from .pickle_model import PickleModelExtractor
from .pytorch_native import PyTorchNativeExtractor
from .safetensors import SafeTensorsExtractor
from .source import SourceCodeExtractor
from .static_library import StaticLibraryExtractor
from .tensorflow_native import TensorFlowNativeExtractor

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
            StaticLibraryExtractor(),  # Static libraries (.a files)
        ]

        # Add Androguard APK extractor if available
        try:
            from .androguard_apk import ANDROGUARD_AVAILABLE, AndroguardExtractor
            if ANDROGUARD_AVAILABLE:
                androguard_extractor = AndroguardExtractor()
                self.extractors.append(androguard_extractor)
                logger.debug("Androguard APK extractor enabled")
            else:
                logger.debug("Androguard not available, APK files will use basic extraction")
        except ImportError:
            logger.debug("Androguard module not found, APK files will use basic extraction")

        # Add other extractors
        # Note: More specific extractors should come before general ones
        self.extractors.extend([
            DexExtractor(),        # DEX files (Android bytecode)
            HermesExtractor(),     # Hermes bytecode (React Native)
            PyTorchNativeExtractor(), # PyTorch native formats (.pt, .pth) - before pickle
            TensorFlowNativeExtractor(), # TensorFlow native formats (.pb, .h5) - before ONNX
            SafeTensorsExtractor(), # SafeTensors format (secure tensor storage)
            ONNXModelExtractor(),  # ONNX models (protobuf-based)
            PickleModelExtractor(), # Pickle files (ML models) - most general, last
        ])

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
