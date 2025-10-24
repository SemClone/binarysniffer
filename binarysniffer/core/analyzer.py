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
from ..matchers.license import LicenseMatcher
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
        self.license_matcher = LicenseMatcher()
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
        
        logger.info(f"Analyzing file: {file_path} (size: {file_path.stat().st_size:,} bytes)")

        # Extract features from file
        import time
        start_time = time.time()
        extractor = self.extractor_factory.get_extractor(file_path)
        logger.debug(f"Using extractor: {extractor.__class__.__name__} for {file_path}")
        features = extractor.extract(file_path)
        extract_time = time.time() - start_time
        if extract_time > 1.0:
            logger.warning(f"Feature extraction took {extract_time:.2f}s for {file_path}")
        
        # Perform matching
        threshold = confidence_threshold or self.config.min_confidence
        matches = self.matcher.match(
            features, 
            threshold=threshold,
            deep=deep_analysis
        )
        
        # Extract package metadata if available (from UPMEX integration)
        package_metadata = None
        if hasattr(features, 'metadata') and features.metadata and 'package_metadata' in features.metadata:
            package_metadata = features.metadata['package_metadata']

        # Build result
        return AnalysisResult(
            file_path=str(file_path),
            file_size=file_path.stat().st_size,
            file_type=features.file_type,
            matches=matches,
            analysis_time=self.matcher.last_analysis_time,
            features_extracted=len(features.all_features),
            confidence_threshold=threshold,
            package_metadata=package_metadata
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
    
    def analyze_licenses(
        self,
        file_path: Union[str, Path],
        include_dependencies: bool = True
    ) -> Dict[str, Any]:
        """
        Perform license-focused analysis on a file or directory.
        
        Args:
            file_path: Path to file or directory to analyze
            include_dependencies: Also detect licenses in dependencies
            
        Returns:
            Dictionary with license analysis results
        """
        file_path = Path(file_path)
        all_matches = []
        license_files = {}
        
        if file_path.is_file():
            # Analyze single file
            result = self.analyze_file(file_path)
            all_matches.extend(result.matches)
            
            # Check if it's a license file and analyze content
            if self.license_matcher.is_license_file(str(file_path)):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                license_matches = self.license_matcher.detect_licenses_in_content(
                    content, str(file_path)
                )
                all_matches.extend(license_matches)
                if license_matches:
                    license_files[str(file_path)] = license_matches
                    
        elif file_path.is_dir():
            # Find all relevant files
            relevant_files = []
            license_file_paths = []
            
            for p in file_path.rglob('*'):
                if p.is_file():
                    if self.license_matcher.is_license_file(str(p)):
                        license_file_paths.append(p)
                    elif p.suffix in self.license_matcher.CODE_FILE_EXTENSIONS:
                        relevant_files.append(p)
            
            # Analyze license files
            for lf in license_file_paths:
                try:
                    with open(lf, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1024 * 100)  # Read first 100KB
                    license_matches = self.license_matcher.detect_licenses_in_content(
                        content, str(lf)
                    )
                    if license_matches:
                        all_matches.extend(license_matches)
                        license_files[str(lf)] = license_matches
                except Exception as e:
                    logger.warning(f"Failed to analyze license file {lf}: {e}")
            
            # Analyze code files for embedded licenses
            if include_dependencies:
                batch_results = self.analyze_batch(relevant_files[:100])  # Limit to 100 files
                for result in batch_results.values():
                    all_matches.extend(result.matches)
        
        # Aggregate license information
        license_info = self.license_matcher.aggregate_licenses(all_matches)
        
        # Check license compatibility
        detected_licenses = set(license_info.keys())
        compatibility = self.license_matcher.check_license_compatibility(detected_licenses)
        
        return {
            'licenses_detected': list(detected_licenses),
            'license_details': license_info,
            'license_files': license_files,
            'compatibility': compatibility,
            'total_components': len(all_matches),
            'analysis_path': str(file_path)
        }
    
    
    
