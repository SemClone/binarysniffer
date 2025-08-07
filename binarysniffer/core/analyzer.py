"""
Core analyzer module - Main entry point for library usage
"""

import os
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


logger = logging.getLogger(__name__)


class BinarySniffer:
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
        self.config = config or Config()
        self._ensure_data_directory()
        
        # Initialize components
        self.db = SignatureDatabase(self.config.db_path)
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
    
    def analyze_directory(
        self,
        directory_path: Union[str, Path],
        recursive: bool = True,
        file_patterns: Optional[List[str]] = None,
        confidence_threshold: Optional[float] = None,
        parallel: bool = True
    ) -> Dict[str, AnalysisResult]:
        """
        Analyze all files in a directory.
        
        Args:
            directory_path: Path to directory
            recursive: Analyze subdirectories
            file_patterns: List of glob patterns (e.g., ["*.exe", "*.so"])
            confidence_threshold: Minimum confidence score
            parallel: Use parallel processing
            
        Returns:
            Dictionary mapping file paths to results
        """
        directory_path = Path(directory_path)
        if not directory_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory_path}")
        
        # Collect files
        files = self._collect_files(directory_path, recursive, file_patterns)
        logger.info(f"Found {len(files)} files to analyze")
        
        results = {}
        
        if parallel and len(files) > 1:
            # Parallel processing
            with ThreadPoolExecutor(max_workers=self.config.parallel_workers) as executor:
                future_to_file = {
                    executor.submit(
                        self.analyze_file, 
                        file, 
                        confidence_threshold
                    ): file 
                    for file in files
                }
                
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        results[str(file_path)] = result
                    except Exception as e:
                        logger.error(f"Error analyzing {file_path}: {e}")
                        results[str(file_path)] = AnalysisResult.create_error(
                            str(file_path), str(e)
                        )
        else:
            # Sequential processing
            for file_path in files:
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
    
    def _ensure_data_directory(self):
        """Ensure data directory exists"""
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (self.config.data_dir / "bloom_filters").mkdir(exist_ok=True)
        (self.config.data_dir / "index").mkdir(exist_ok=True)
        (self.config.data_dir / "cache").mkdir(exist_ok=True)
    
    def _initialize_database(self):
        """Initialize database with packaged signatures (auto-import)"""
        from ..signatures.manager import SignatureManager
        
        # Create signature manager
        manager = SignatureManager(self.config, self.db)
        
        # Auto-import packaged signatures if database needs sync
        try:
            synced = manager.ensure_database_synced()
            if synced:
                logger.info("Imported packaged signatures on first run")
            else:
                logger.debug("Database already synced with packaged signatures")
        except Exception as e:
            logger.error(f"Failed to auto-import signatures: {e}")
            logger.warning("Database may be empty. Run 'binarysniffer signatures import' manually.")
    
    def _collect_files(
        self,
        directory: Path,
        recursive: bool,
        patterns: Optional[List[str]]
    ) -> List[Path]:
        """Collect files from directory based on patterns"""
        files = []
        
        # Excluded directories - always exclude these
        excluded_dirs = {'.git', '__pycache__', 'node_modules', '.venv', 'venv'}
        
        # Also exclude the data directory if it's under the scan directory
        try:
            data_dir_abs = self.config.data_dir.resolve()
            directory_abs = directory.resolve()
            
            # Check if data_dir is inside the directory being scanned
            # Use string comparison for Python 3.8 compatibility
            if str(data_dir_abs).startswith(str(directory_abs)):
                # Add the relative part to excluded dirs
                try:
                    relative_data_dir = data_dir_abs.relative_to(directory_abs)
                    excluded_dirs.add(str(relative_data_dir.parts[0]))
                except ValueError:
                    pass
        except (AttributeError, OSError):
            # If path operations fail, just use default exclusions
            pass
        
        # Always exclude .binarysniffer directories regardless
        excluded_dirs.add('.binarysniffer')
        
        if patterns:
            # Use glob patterns
            for pattern in patterns:
                if recursive:
                    all_files = directory.rglob(pattern)
                else:
                    all_files = directory.glob(pattern)
                # Filter out files in excluded directories
                files.extend([
                    f for f in all_files 
                    if not any(excluded in f.parts for excluded in excluded_dirs)
                ])
        else:
            # All files
            if recursive:
                all_files = [f for f in directory.rglob("*") if f.is_file()]
            else:
                all_files = [f for f in directory.iterdir() if f.is_file()]
            
            # Filter out files in excluded directories
            files = [
                f for f in all_files 
                if not any(excluded in f.parts for excluded in excluded_dirs)
            ]
        
        # Filter out common non-binary files if no patterns specified
        if not patterns:
            excluded_extensions = {'.txt', '.md', '.rst', '.json', '.xml', '.yml', '.yaml'}
            files = [f for f in files if f.suffix.lower() not in excluded_extensions]
        
        # Debug logging
        logger.debug(f"Collected {len(files)} files after filtering")
        logger.debug(f"Excluded dirs: {excluded_dirs}")
        if files and '.binarysniffer' in str(files[0]):
            logger.warning(f"Warning: .binarysniffer files still in list: {[str(f) for f in files if '.binarysniffer' in str(f)]}")
        
        return sorted(set(files))  # Remove duplicates and sort