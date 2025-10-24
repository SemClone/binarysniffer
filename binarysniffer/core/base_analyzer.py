"""
Base analyzer class with shared functionality
"""

import logging
from pathlib import Path
from typing import List, Optional, Union, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import threading

from ..storage.database import SignatureDatabase
from .config import Config
from .results import AnalysisResult, BatchAnalysisResult


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
        self.include_large_files = False  # By default, skip large files (>50MB)
        self.skip_metadata_files = False  # By default, process metadata files

        # Ensure data directory exists
        self._ensure_data_directory()
    
    def _ensure_data_directory(self):
        """Ensure data directory exists"""
        self.config.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (self.config.data_dir / "bloom_filters").mkdir(exist_ok=True)
        (self.config.data_dir / "index").mkdir(exist_ok=True)
    
    def _analyze_file_with_features(self, file_path: Union[str, Path], confidence_threshold: Optional[float] = None) -> AnalysisResult:
        """Helper method to analyze file with instance-level feature settings"""
        # Check if we have the enhanced analyze_file method with additional parameters
        if hasattr(self, 'show_features') and hasattr(self, 'full_export'):
            # Call analyze_file with the instance attributes
            return self.analyze_file(
                file_path,
                confidence_threshold,
                show_features=self.show_features,
                full_export=self.full_export
            )
        else:
            # Fallback to basic analyze_file
            return self.analyze_file(file_path, confidence_threshold)
    
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
        parallel: bool = True,
        progress_callback: Optional[callable] = None,
        include_large: bool = False
    ) -> BatchAnalysisResult:
        """
        Analyze all files in a directory.

        Args:
            directory_path: Path to directory
            recursive: Analyze subdirectories
            file_patterns: List of glob patterns (e.g., ["*.exe", "*.so"])
            confidence_threshold: Minimum confidence score
            parallel: Use parallel processing
            progress_callback: Optional callback(current, total) for progress updates
            include_large: Include large files (>50MB) in analysis

        Returns:
            BatchAnalysisResult containing all file results
        """
        # Store include_large setting for this analysis
        self.include_large_files = include_large
        directory_path = Path(directory_path)
        if not directory_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory_path}")
        
        # Collect files
        files = self._collect_files(directory_path, recursive, file_patterns)
        logger.info(f"Found {len(files)} files to analyze")

        results = {}
        successful = 0
        failed = 0
        total_time = 0.0

        # Initialize progress
        if progress_callback:
            progress_callback(0, len(files))
        
        # Disable parallel processing for large file sets to avoid hanging
        # Files timing out in parallel cause thread accumulation
        if len(files) > 100:
            logger.info(f"Large directory ({len(files)} files) - using sequential processing for stability")
            parallel = False

        if parallel and len(files) > 1:
            # Parallel processing with improved timeout handling
            max_workers = min(self.config.parallel_workers, 2)  # Limit to 2 workers to avoid overwhelming
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_file = {}
                for file in files:
                    future = executor.submit(
                        self._analyze_file_with_timeout,
                        file,
                        confidence_threshold
                    )
                    future_to_file[future] = file

                # Process results as they complete
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        logger.debug(f"Processing file {len(results)+1}/{len(files)}: {file_path}")
                        # Call progress callback with file path BEFORE processing
                        if progress_callback:
                            try:
                                progress_callback(len(results), len(files), str(file_path))
                            except TypeError:
                                # Fallback for callbacks that don't accept file_path
                                progress_callback(len(results), len(files))

                        result = future.result()

                        if result:
                            results[str(file_path)] = result
                            total_time += result.analysis_time
                            if result.error:
                                failed += 1
                                logger.info(f"File skipped/error: {file_path} - {result.error}")
                            else:
                                successful += 1
                            if result.analysis_time > 1.0:
                                logger.warning(f"Slow file analysis ({result.analysis_time:.2f}s): {file_path}")
                    except Exception as e:
                        logger.error(f"Error analyzing {file_path}: {e}")
                        failed += 1
                        results[str(file_path)] = AnalysisResult.create_error(
                            str(file_path), str(e)
                        )

                    # Update progress after completion
                    if progress_callback:
                        try:
                            progress_callback(len(results), len(files), None)  # No file path after completion
                        except TypeError:
                            progress_callback(len(results), len(files))
        else:
            # Sequential processing with timeout
            for i, file_path in enumerate(files):
                try:
                    logger.debug(f"Processing file {i+1}/{len(files)}: {file_path}")
                    # Call progress callback with file path BEFORE processing
                    if progress_callback:
                        try:
                            progress_callback(i, len(files), str(file_path))
                        except TypeError:
                            # Fallback for callbacks that don't accept file_path
                            progress_callback(i, len(files))

                    # Use timeout wrapper for sequential processing too
                    result = self._analyze_file_with_timeout(
                        file_path,
                        confidence_threshold
                    )
                    results[str(file_path)] = result
                    total_time += result.analysis_time
                    if result.error:
                        failed += 1
                        logger.info(f"File skipped/error: {file_path} - {result.error}")
                    else:
                        successful += 1
                    if result.analysis_time > 1.0:
                        logger.warning(f"Slow file analysis ({result.analysis_time:.2f}s): {file_path}")
                except Exception as e:
                    logger.error(f"Error analyzing {file_path}: {e}")
                    failed += 1
                    results[str(file_path)] = AnalysisResult.create_error(
                        str(file_path), str(e)
                    )

                # Update progress after completion
                if progress_callback:
                    try:
                        progress_callback(i + 1, len(files), None)
                    except TypeError:
                        progress_callback(i + 1, len(files))
        
        # Create and return BatchAnalysisResult
        return BatchAnalysisResult(
            results=results,
            total_files=len(files),
            successful_files=successful,
            failed_files=failed,
            total_time=total_time
        )
    
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
            # Exclude text-based and metadata files that don't contain binary components
            excluded_extensions = {
                '.txt', '.md', '.rst', '.json', '.xml', '.yml', '.yaml',
                '.plist',  # Apple property list files (XML format)
                '.xcprivacy',  # Apple privacy manifest files (XML format)
                '.xcconfig',  # Xcode configuration files
                '.xib', '.storyboard', '.nib',  # Interface builder files
                '.html', '.htm', '.css', '.scss', '.less',  # Web files
                '.ini', '.cfg', '.conf', '.config',  # Config files
                '.log', '.gitignore', '.gitattributes',  # Log/git files
                '.properties', '.toml',  # Properties files
                '.svg', '.ico',  # Vector/icon files
                '.strings',  # Apple localization files
                '.js', '.min.js',  # JavaScript files (can be large and problematic)
                '.map',  # Source map files
            }
            files = [f for f in files if f.suffix.lower() not in excluded_extensions]
        
        # Debug logging
        logger.debug(f"Collected {len(files)} files after filtering")
        logger.debug(f"Excluded dirs: {excluded_dirs}")
        if files and '.binarysniffer' in str(files[0]):
            logger.warning(f"Warning: .binarysniffer files still in list: {[str(f) for f in files if '.binarysniffer' in str(f)]}")
        
        return sorted(set(files))  # Remove duplicates and sort

    def _analyze_file_with_timeout(self, file_path: Path, confidence_threshold: Optional[float], timeout: int = None) -> AnalysisResult:
        """
        Analyze a file with timeout protection.

        Args:
            file_path: Path to file
            confidence_threshold: Minimum confidence threshold
            timeout: Timeout in seconds

        Returns:
            AnalysisResult
        """
        import queue
        import time

        # Use timeout from configuration if not specified
        if timeout is None:
            timeout = getattr(self, 'file_timeout', 60)  # Default to 60 seconds

        # Log file being analyzed
        logger.info(f"Starting analysis: {file_path}")

        # Quick pre-checks to avoid known problematic files
        try:
            file_size = file_path.stat().st_size
            logger.debug(f"File size: {file_size / (1024*1024):.2f}MB - {file_path}")
            # Skip large files (>50MB) unless explicitly included
            max_size = 50 * 1024 * 1024  # 50MB
            if not getattr(self, 'include_large_files', False) and file_size > max_size:
                logger.info(f"Skipping large file ({file_size / 1024 / 1024:.1f}MB): {file_path.name} (use --include-large to analyze)")
                return AnalysisResult.create_error(
                    str(file_path),
                    f"File skipped ({file_size / 1024 / 1024:.1f}MB) - use --include-large to analyze"
                )
            # Even with include_large, skip extremely large files (>500MB)
            elif file_size > 500 * 1024 * 1024:
                logger.warning(f"Skipping extremely large file ({file_size / 1024 / 1024:.1f}MB): {file_path}")
                return AnalysisResult.create_error(
                    str(file_path),
                    f"File too large ({file_size / 1024 / 1024:.1f}MB) - maximum 500MB"
                )

            # Skip metadata files if flag is set or if plist files are large
            metadata_extensions = {'.plist', '.xib', '.storyboard', '.nib', '.strings', '.xcprivacy', '.xcconfig'}
            if getattr(self, 'skip_metadata_files', False) and file_path.suffix.lower() in metadata_extensions:
                logger.info(f"Skipping metadata file: {file_path.name}")
                return AnalysisResult.create_error(
                    str(file_path),
                    f"Metadata file skipped (--skip-metadata enabled)"
                )
            # Skip XML-based metadata files over 100KB even without the flag (they're just metadata and can cause hangs)
            elif file_path.suffix.lower() in {'.plist', '.xcprivacy', '.xcconfig'} and file_size > 100 * 1024:
                logger.info(f"Skipping large XML metadata file ({file_size / 1024:.1f}KB): {file_path.name}")
                return AnalysisResult.create_error(
                    str(file_path),
                    f"Large XML metadata file skipped"
                )

            # Skip known problematic extensions that cause hangs
            problematic_extensions = {
                '.strings', '.js', '.min.js', '.css', '.min.css',
                '.plist',  # Property list files can be large and slow to parse
                '.xcprivacy',  # Privacy manifest files (XML)
                '.xcconfig',  # Xcode config files
                '.xib', '.storyboard',  # Interface builder files
                '.nib',  # NeXT Interface Builder files
                '.car',  # Asset catalog files
                '.lzfse', '.lz4', '.zst',  # Compressed files
                '.map',  # Source map files (can be huge)
            }
            if file_path.suffix.lower() in problematic_extensions:
                # Very short timeout for known problematic files
                timeout = 3
                logger.info(f"Reduced timeout to {timeout}s for potentially slow {file_path.suffix} file: {file_path.name}")
        except Exception as e:
            logger.debug(f"Pre-check failed for {file_path}: {e}")

        result_queue = queue.Queue()
        error_queue = queue.Queue()

        def analyze_wrapper():
            try:
                logger.debug(f"Thread started for: {file_path}")
                result = self._analyze_file_with_features(file_path, confidence_threshold)
                result_queue.put(result)
                logger.debug(f"Thread completed for: {file_path}")
            except Exception as e:
                logger.debug(f"Thread error for {file_path}: {e}")
                error_queue.put(e)

        # Start analysis in a separate thread
        thread = threading.Thread(target=analyze_wrapper)
        thread.daemon = True  # Daemon thread will be killed if main thread exits
        thread.start()

        # Wait for the thread to complete or timeout
        thread.join(timeout=timeout)

        if thread.is_alive():
            # Thread is still running, timeout occurred
            logger.error(f"Timeout analyzing {file_path} (>{timeout}s)")
            # Note: We can't kill the thread, but we can return an error result
            return AnalysisResult.create_error(
                str(file_path),
                f"Analysis timeout (>{timeout}s) - file may be too large or complex"
            )

        # Check for errors
        if not error_queue.empty():
            error = error_queue.get()
            logger.error(f"Error analyzing {file_path}: {error}")
            return AnalysisResult.create_error(str(file_path), str(error))

        # Get result
        if not result_queue.empty():
            return result_queue.get()
        else:
            # Shouldn't happen but handle it
            return AnalysisResult.create_error(
                str(file_path),
                "Analysis completed but no result returned"
            )

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