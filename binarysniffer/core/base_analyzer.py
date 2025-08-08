"""
Base analyzer class with shared functionality
"""

import logging
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..storage.database import SignatureDatabase
from .config import Config
from .results import AnalysisResult


logger = logging.getLogger(__name__)


class BaseAnalyzer:
    """
    Base analyzer class containing shared functionality between different analyzer implementations.
    
    This class provides common methods for database initialization, file collection,
    and directory analysis that are used by both BinarySniffer and EnhancedBinarySniffer.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the base analyzer.
        
        Args:
            config: Optional configuration object. If None, uses default config.
        """
        self.config = config or Config()
        self.db = SignatureDatabase(self.config.db_path)
        
        # Ensure data directory exists
        self._ensure_data_directory()
    
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
                    results[str(file_path)] = AnalysisResult.create_error(
                        str(file_path), str(e)
                    )
        
        return results
    
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
    
    def analyze_file(
        self, 
        file_path: Union[str, Path],
        confidence_threshold: Optional[float] = None,
        **kwargs
    ) -> AnalysisResult:
        """
        Analyze a single file for OSS components.
        
        This is an abstract method that must be implemented by subclasses.
        
        Args:
            file_path: Path to the file to analyze
            confidence_threshold: Minimum confidence score (0.0-1.0)
            **kwargs: Additional arguments specific to the implementation
            
        Returns:
            AnalysisResult object containing matches and metadata
        """
        raise NotImplementedError("Subclasses must implement analyze_file method")