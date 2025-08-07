"""
Core analyzer module - Main entry point for library usage
"""

import logging
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..storage.database import SignatureDatabase
from ..storage.updater import SignatureUpdater
from ..matchers.progressive import ProgressiveMatcher
from ..extractors.factory import ExtractorFactory
from .config import Config
from .results import AnalysisResult, ComponentMatch
from .base_analyzer import BaseAnalyzer


logger = logging.getLogger(__name__)


class BinarySniffer(BaseAnalyzer):
    """
    Main analyzer class for detecting OSS components in binaries.
    
    Can be used as a library or through the CLI interface.
    
    Example:
        >>> sniffer = BinarySniffer()
        >>> result = sniffer.analyze_file("/path/to/binary")
        >>> for match in result.matches:
        ...     print(f"{match.component}: {match.confidence:.2%}")
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the BinarySniffer analyzer.
        
        Args:
            config: Optional configuration object. If None, uses default config.
        """
        super().__init__(config)
        
        # Initialize components specific to BinarySniffer
        self.matcher = ProgressiveMatcher(self.config)
        self.extractor_factory = ExtractorFactory()
        self.updater = SignatureUpdater(self.config)
        
        # Check if database needs initialization
        if not self.db.is_initialized():
            logger.info("Initializing signature database...")
            self._initialize_database()
    
    def analyze_file(
        self, 
        file_path: Union[str, Path],
        confidence_threshold: Optional[float] = None,
        deep_analysis: bool = False
    ) -> AnalysisResult:
        """
        Analyze a single file for OSS components.
        
        Args:
            file_path: Path to the file to analyze
            confidence_threshold: Minimum confidence score (0.0-1.0)
            deep_analysis: Enable deep analysis mode
            
        Returns:
            AnalysisResult object containing matches and metadata
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        logger.info(f"Analyzing file: {file_path}")
        
        # Extract features from file
        extractor = self.extractor_factory.get_extractor(file_path)
        features = extractor.extract(file_path)
        
        # Perform matching
        threshold = confidence_threshold or self.config.min_confidence
        matches = self.matcher.match(
            features, 
            threshold=threshold,
            deep=deep_analysis
        )
        
        # Build result
        return AnalysisResult(
            file_path=str(file_path),
            file_size=file_path.stat().st_size,
            file_type=features.file_type,
            matches=matches,
            analysis_time=self.matcher.last_analysis_time,
            features_extracted=len(features.all_features),
            confidence_threshold=threshold
        )
    
    
    def analyze_batch(
        self,
        file_paths: List[Union[str, Path]],
        confidence_threshold: Optional[float] = None,
        parallel: bool = True
    ) -> Dict[str, AnalysisResult]:
        """
        Analyze a batch of files.
        
        Args:
            file_paths: List of file paths
            confidence_threshold: Minimum confidence score
            parallel: Use parallel processing
            
        Returns:
            Dictionary mapping file paths to results
        """
        results = {}
        
        if parallel and len(file_paths) > 1:
            with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
                future_to_file = {
                    executor.submit(
                        self.analyze_file,
                        file_path,
                        confidence_threshold
                    ): file_path
                    for file_path in file_paths
                }
                
                for future in as_completed(future_to_file):
                    file_path = str(future_to_file[future])
                    try:
                        result = future.result()
                        results[file_path] = result
                    except Exception as e:
                        logger.error(f"Error analyzing {file_path}: {e}")
                        results[file_path] = AnalysisResult.error(file_path, str(e))
        else:
            for file_path in file_paths:
                try:
                    results[str(file_path)] = self.analyze_file(
                        file_path,
                        confidence_threshold
                    )
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
                    results[str(file_path)] = AnalysisResult.error(
                        str(file_path), str(e)
                    )
        
        return results
    
    def check_updates(self) -> bool:
        """
        Check if signature updates are available.
        
        Returns:
            True if updates are available
        """
        return self.updater.check_updates()
    
    def update_signatures(self, force: bool = False) -> bool:
        """
        Update signature database.
        
        Args:
            force: Force full update instead of delta
            
        Returns:
            True if update was successful
        """
        try:
            if force:
                return self.updater.force_update()
            else:
                return self.updater.update()
        except Exception as e:
            logger.error(f"Failed to update signatures: {e}")
            return False
    
    def get_signature_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the signature database.
        
        Returns:
            Dictionary with signature statistics
        """
        return self.db.get_statistics()
    
    
    
