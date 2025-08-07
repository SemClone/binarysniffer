"""
Base analyzer with shared functionality for all analyzer implementations
"""

import logging
from pathlib import Path
from typing import List, Optional, Set, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Config
from .results import AnalysisResult, BatchAnalysisResult
from ..signatures.manager import SignatureManager
from ..storage.database import SignatureDatabase

logger = logging.getLogger(__name__)


class BaseAnalyzer:
    """Base class with shared functionality for analyzers"""
    
    def __init__(self, config: Optional[Config] = None):
        """Initialize base analyzer
        
        Args:
            config: Optional configuration object
        """
        self.config = config or Config()
        self.sig_manager = SignatureManager(self.config.db_path.parent)
        self._db = None
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize and sync signature database"""
        # Ensure database exists
        if not self.config.db_path.exists():
            logger.info("Creating signature database...")
            self.sig_manager.force_rebuild()
        else:
            # Check if we need to sync with packaged signatures
            if self.sig_manager.needs_sync():
                logger.info("Syncing database with packaged signatures...")
                try:
                    self.sig_manager.import_packaged_signatures()
                    logger.info("Database synced successfully")
                except Exception as e:
                    logger.warning(f"Failed to sync signatures: {e}")
            else:
                logger.debug("Database already synced with packaged signatures")
    
    def _collect_files(
        self,
        directory: Path,
        recursive: bool = True,
        patterns: Optional[List[str]] = None,
        excluded_dirs: Optional[Set[str]] = None
    ) -> List[Path]:
        """Collect files from directory
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan recursively
            patterns: Optional file patterns to match
            excluded_dirs: Optional set of directory names to exclude
            
        Returns:
            List of file paths to analyze
        """
        if excluded_dirs is None:
            excluded_dirs = {
                '.git', '.svn', '.hg', '.bzr', '__pycache__',
                'node_modules', 'venv', '.env', 'env',
                '.venv', 'virtualenv', '.virtualenv'
            }
        
        files = []
        
        def should_exclude_dir(dir_path: Path) -> bool:
            """Check if directory should be excluded"""
            return dir_path.name in excluded_dirs or dir_path.name.startswith('.')
        
        if recursive:
            # Walk directory tree
            for path in directory.rglob('*'):
                # Skip if any parent directory should be excluded
                if any(should_exclude_dir(p) for p in path.parents):
                    continue
                    
                if path.is_file():
                    # Check pattern match if patterns provided
                    if patterns:
                        if any(path.match(pattern) for pattern in patterns):
                            files.append(path)
                    else:
                        files.append(path)
        else:
            # Non-recursive scan
            for path in directory.iterdir():
                if path.is_file():
                    if patterns:
                        if any(path.match(pattern) for pattern in patterns):
                            files.append(path)
                    else:
                        files.append(path)
        
        logger.debug(f"Collected {len(files)} files after filtering")
        return files
    
    def analyze_directory(
        self,
        directory: Union[str, Path],
        recursive: bool = True,
        patterns: Optional[List[str]] = None,
        parallel: bool = True,
        max_workers: Optional[int] = None,
        **kwargs
    ) -> BatchAnalysisResult:
        """Analyze all files in a directory
        
        Args:
            directory: Directory path to analyze
            recursive: Whether to scan recursively
            patterns: Optional file patterns to match
            parallel: Whether to analyze files in parallel
            max_workers: Maximum number of parallel workers
            **kwargs: Additional arguments for analyze_file
            
        Returns:
            Batch analysis results
        """
        directory = Path(directory)
        if not directory.exists():
            raise ValueError(f"Directory does not exist: {directory}")
        
        # Collect files
        files = self._collect_files(directory, recursive, patterns)
        
        if not files:
            logger.warning(f"No files found to analyze in {directory}")
            return BatchAnalysisResult()
        
        logger.info(f"Analyzing {len(files)} files...")
        
        # Analyze files
        batch_result = BatchAnalysisResult()
        
        if parallel and len(files) > 1:
            # Parallel analysis
            max_workers = max_workers or self.config.parallel_workers
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_file = {
                    executor.submit(self.analyze_file, file_path, **kwargs): file_path
                    for file_path in files
                }
                
                # Collect results
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        batch_result.add_result(str(file_path), result)
                    except Exception as e:
                        logger.error(f"Error analyzing {file_path}: {e}")
                        error_result = AnalysisResult(
                            file_path=str(file_path),
                            error=str(e)
                        )
                        batch_result.add_result(str(file_path), error_result)
        else:
            # Sequential analysis
            for file_path in files:
                try:
                    result = self.analyze_file(file_path, **kwargs)
                    batch_result.add_result(str(file_path), result)
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
                    error_result = AnalysisResult(
                        file_path=str(file_path),
                        error=str(e)
                    )
                    batch_result.add_result(str(file_path), error_result)
        
        return batch_result
    
    def analyze_file(self, file_path: Union[str, Path], **kwargs) -> AnalysisResult:
        """Analyze a single file - must be implemented by subclasses
        
        Args:
            file_path: Path to file to analyze
            **kwargs: Additional implementation-specific arguments
            
        Returns:
            Analysis results
        """
        raise NotImplementedError("Subclasses must implement analyze_file")