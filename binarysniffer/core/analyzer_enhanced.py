"""
Enhanced Binary Sniffer analyzer with improved detection
"""

import logging
from pathlib import Path
from typing import Union, Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Config
from .results import AnalysisResult, ComponentMatch
from .base_analyzer import BaseAnalyzer
from ..extractors.factory import ExtractorFactory
# Progressive matcher removed - using only direct matching for deterministic results
from ..matchers.direct import DirectMatcher
from ..matchers.license import LicenseMatcher
# Enhanced OSLiLi integration imported in __init__ method
from ..storage.database import SignatureDatabase
from ..signatures.manager import SignatureManager
from ..hashing.tlsh_hasher import TLSHHasher, TLSHSignatureStore


logger = logging.getLogger(__name__)


class EnhancedBinarySniffer(BaseAnalyzer):
    """
    Enhanced main analyzer class with improved detection capabilities.
    Uses both progressive and direct matching for better results.
    """
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the analyzer.
        
        Args:
            config: Configuration object (uses default if not provided)
        """
        super().__init__(config)
        
        # Initialize components specific to EnhancedBinarySniffer
        self.extractor_factory = ExtractorFactory()
        self.signature_manager = SignatureManager(self.config, self.db)
        
        # Check if database needs initialization BEFORE creating matchers
        if not self.db.is_initialized():
            logger.info("Initializing signature database...")
            self._initialize_database()
        
        # Create direct matcher only (bloom filters disabled for deterministic results)
        self.direct_matcher = DirectMatcher(self.config)
        
        # Initialize enhanced OSLiLi for license detection (required dependency)
        from ..integrations.enhanced_oslili import EnhancedOsliliIntegration
        self.oslili = EnhancedOsliliIntegration()
        # OSLiLi is now a required dependency, no fallback needed
        self.license_matcher = None
        
        # Initialize TLSH components
        self.tlsh_hasher = TLSHHasher()
        self.tlsh_store = TLSHSignatureStore()
        
        # Instance attributes for feature collection
        self.show_features = False
        self.full_export = False
    
    def analyze_file(
        self, 
        file_path: Union[str, Path],
        confidence_threshold: Optional[float] = None,
        deep_analysis: bool = False,
        show_features: bool = False,
        use_tlsh: bool = True,
        tlsh_threshold: int = 70,
        include_hashes: bool = False,
        include_fuzzy_hashes: bool = False,
        full_export: bool = False
    ) -> AnalysisResult:
        """
        Analyze a single file for OSS components using enhanced detection.
        
        Args:
            file_path: Path to the file to analyze
            confidence_threshold: Minimum confidence score (0.0-1.0)
            deep_analysis: Enable deep analysis mode
            show_features: Show extracted features in result
            use_tlsh: Enable TLSH fuzzy matching
            tlsh_threshold: TLSH distance threshold for matches (lower = more similar)
            include_hashes: Include MD5, SHA1, SHA256 hashes in result
            include_fuzzy_hashes: Include TLSH and ssdeep fuzzy hashes in result
            
        Returns:
            AnalysisResult object containing matches and metadata
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        logger.debug(f"Analyzing file: {file_path}")
        
        # Extract features from file
        extractor = self.extractor_factory.get_extractor(file_path)
        features = extractor.extract(file_path)
        
        # Use lower threshold for direct matching since we're not using bloom filters
        threshold = confidence_threshold or 0.5
        
        # Use direct matcher only for deterministic results
        # (bloom filters disabled per user request)
        direct_matches = self.direct_matcher.match(
            features,
            threshold=threshold,
            deep=deep_analysis
        )
        
        # No merging needed - just use direct matches
        merged_matches = direct_matches
        
        # Apply TLSH fuzzy matching if enabled
        if use_tlsh and self.tlsh_hasher.enabled:
            tlsh_matches = self._apply_tlsh_matching(
                file_path, features, tlsh_threshold
            )
            # Merge TLSH matches with direct matches
            merged_matches = self._merge_tlsh_matches(merged_matches, tlsh_matches)
        
        # Apply technology filtering to reduce false positives
        file_type = features.file_type
        filtered_matches = self._filter_by_technology(merged_matches, file_type)
        
        # Build result
        total_time = self.direct_matcher.last_analysis_time
        
        # Prepare extracted features summary if requested
        extracted_features_summary = None
        if show_features:
            from .results import ExtractedFeaturesSummary
            
            # Categorize features by type
            features_by_type = {}
            if features.strings:
                # No limit if full_export is enabled
                features_by_type["strings"] = features.strings if full_export else features.strings[:100]
            if features.symbols:
                features_by_type["symbols"] = features.symbols if full_export else features.symbols[:100]
            if hasattr(features, 'functions') and features.functions:
                features_by_type["functions"] = features.functions if full_export else features.functions[:50]
            if hasattr(features, 'classes') and features.classes:
                features_by_type["classes"] = features.classes if full_export else features.classes[:50]
            
            extractor_info = {
                "count": len(features.strings) + len(features.symbols),
                "features_by_type": features_by_type
            }
            
            # Include metadata if available (e.g., for archives)
            if hasattr(features, 'metadata') and features.metadata:
                extractor_info["metadata"] = features.metadata
            
            extracted_features_summary = ExtractedFeaturesSummary(
                total_count=len(features.strings) + len(features.symbols),
                by_extractor={
                    extractor.__class__.__name__: extractor_info
                }
            )
        
        # Calculate file hashes if requested
        file_hashes = None
        if include_hashes or include_fuzzy_hashes:
            from binarysniffer.utils.file_metadata import calculate_file_hashes
            try:
                file_hashes = calculate_file_hashes(file_path, include_fuzzy=include_fuzzy_hashes)
            except Exception as e:
                logger.debug(f"Failed to calculate hashes: {e}")
        
        # Add licenses detected by OSLiLi from archive metadata
        if hasattr(features, 'metadata') and features.metadata and 'licenses' in features.metadata:
            for license_info in features.metadata['licenses']:
                license_match = ComponentMatch(
                    component=f"License: {license_info['name']}",
                    ecosystem='license',
                    confidence=license_info['confidence'],
                    license=license_info['spdx_id'],
                    match_type='oslili_detection',
                    evidence={
                        'detection_method': license_info['detection_method'],
                        'category': license_info['category'],
                        'source_file': license_info['source_file']
                    }
                )
                filtered_matches.append(license_match)
                logger.debug(f"Added OSLiLi-detected license: {license_info['spdx_id']} ({license_info['confidence']:.2%} confidence)")

        # Add direct OSLiLi license detection for source code files and individual files
        if file_path.is_file():
            # Check if it's a source code file or readable text file
            source_extensions = {'.py', '.js', '.java', '.c', '.cpp', '.h', '.hpp', '.go', '.rs', '.rb', '.php', '.cs', '.swift', '.kt', '.txt', '.md', '.license', '.copyright'}
            if file_path.suffix.lower() in source_extensions or file_path.name.lower() in {'license', 'copyright', 'notice', 'copying', 'licence'}:
                try:
                    license_results = self.oslili.detect_licenses_in_path(str(file_path))
                    for license_result in license_results:
                        license_match = ComponentMatch(
                            component=f"License: {license_result.name}",
                            ecosystem='license',
                            confidence=license_result.confidence,
                            license=license_result.spdx_id,
                            match_type='oslili_detection',
                            evidence={
                                'detection_method': license_result.detection_method,
                                'category': license_result.category,
                                'source_file': license_result.source_file or str(file_path),
                                'match_type': license_result.match_type
                            }
                        )
                        filtered_matches.append(license_match)
                        logger.debug(f"OSLiLi detected license in source file: {license_result.spdx_id} ({license_result.confidence:.2%} confidence, {license_result.detection_method})")
                except Exception as e:
                    logger.debug(f"OSLiLi license detection failed for {file_path}: {e}")
        
        # Extract package metadata if available (from UPMEX integration)
        package_metadata = None
        if hasattr(features, 'metadata') and features.metadata and 'package_metadata' in features.metadata:
            package_metadata = features.metadata['package_metadata']

        return AnalysisResult(
            file_path=str(file_path),
            file_size=file_path.stat().st_size,
            file_type=features.file_type,
            matches=filtered_matches,
            analysis_time=total_time,
            features_extracted=len(features.strings) + len(features.symbols),
            confidence_threshold=threshold,
            extracted_features=extracted_features_summary,
            file_hashes=file_hashes,
            package_metadata=package_metadata
        )
    
    def _merge_matches(
        self,
        progressive_matches: List[ComponentMatch],
        direct_matches: List[ComponentMatch]
    ) -> List[ComponentMatch]:
        """Merge matches from different matchers, keeping highest confidence"""
        component_map = {}
        
        # Process all matches
        for match in progressive_matches + direct_matches:
            key = match.component
            
            if key not in component_map:
                component_map[key] = match
            else:
                # Keep match with higher confidence
                if match.confidence > component_map[key].confidence:
                    component_map[key] = match
                elif match.confidence == component_map[key].confidence:
                    # Merge evidence
                    existing_evidence = component_map[key].evidence or {}
                    new_evidence = match.evidence or {}
                    
                    # Combine evidence
                    if 'signature_count' in existing_evidence and 'signature_count' in new_evidence:
                        existing_evidence['signature_count'] += new_evidence['signature_count']
                    
                    existing_evidence.update(new_evidence)
                    component_map[key].evidence = existing_evidence
        
        # Sort by confidence
        matches = list(component_map.values())
        matches.sort(key=lambda m: m.confidence, reverse=True)
        
        return matches
    
    def _filter_by_technology(self, matches: List[ComponentMatch], file_type: str) -> List[ComponentMatch]:
        """
        Filter matches based on technology compatibility.
        Remove false positives like Android/iOS components in native binaries.
        """
        # Define incompatible technology combinations
        incompatible_platforms = {
            'binary': {  # Native ELF/PE/Mach-O binaries
                'android', 'ios', 'react-native', 'flutter',
                'java', 'kotlin', 'javascript', 'typescript'
            },
            'zip': {  # ZIP files (often containing binaries)
                'android', 'ios', 'react-native', 'flutter',
                'java', 'kotlin', 'javascript', 'typescript'
            },
            'apk': {  # Android APK
                'ios', 'swift', 'objective-c', 'cocoa'
            },
            'ipa': {  # iOS IPA
                'android', 'java', 'kotlin'
            }
        }
        
        # Get incompatible platforms for this file type
        incompatible = incompatible_platforms.get(file_type, set())
        
        if not incompatible:
            return matches  # No filtering needed
        
        filtered_matches = []
        for match in matches:
            # Check if component has platform/technology metadata
            component_name_lower = match.component.lower()
            
            # Skip obvious technology mismatches
            skip = False
            for tech in incompatible:
                if tech in component_name_lower:
                    logger.debug(f"Filtering out {match.component} - incompatible technology '{tech}' for {file_type}")
                    skip = True
                    break
            
            # Additional checks for specific components
            if not skip and file_type in ('binary', 'zip'):
                # Filter out mobile-specific components from native binaries
                mobile_keywords = ['firebase', 'crashlytics', 'android sdk', 'google ads', 
                                 'facebook sdk', 'react native', 'flutter', 'xamarin']
                for keyword in mobile_keywords:
                    if keyword in component_name_lower:
                        logger.debug(f"Filtering out {match.component} - mobile component in {file_type}")
                        skip = True
                        break
            
            if not skip:
                filtered_matches.append(match)
        
        if len(filtered_matches) < len(matches):
            logger.debug(f"Filtered {len(matches) - len(filtered_matches)} incompatible components")
        
        return filtered_matches
    
    def _apply_tlsh_matching(
        self,
        file_path: Path,
        features,
        threshold: int = 70
    ) -> List[ComponentMatch]:
        """
        Apply TLSH fuzzy matching to find similar components.
        
        Args:
            file_path: Path to the file being analyzed
            features: Extracted features from the file
            threshold: TLSH distance threshold
            
        Returns:
            List of component matches based on TLSH similarity
        """
        matches = []
        
        # Generate TLSH hash for the file
        file_hash = self.tlsh_hasher.hash_file(file_path)
        if not file_hash:
            # Try hashing from features if file hash fails
            all_features = list(features.strings) + list(features.symbols)
            if all_features:
                file_hash = self.tlsh_hasher.hash_features(all_features[:1000])  # Limit features
        
        if not file_hash:
            logger.debug("Could not generate TLSH hash for file")
            return matches
        
        logger.debug(f"Generated TLSH hash: {file_hash[:16]}...")
        
        # Find matches in TLSH signature store
        tlsh_matches = self.tlsh_store.find_matches(file_hash, threshold)
        
        # Convert TLSH matches to ComponentMatch objects
        for match_info in tlsh_matches:
            # Confidence based on similarity score
            confidence = match_info['similarity_score']
            
            # Create component match (version included in component name)
            component_name = match_info['component']
            version = match_info.get('version', 'unknown')
            if version and version != 'unknown':
                component_name = f"{component_name}@{version}"
            
            match = ComponentMatch(
                component=component_name,
                ecosystem='native',  # Default to native for TLSH matches
                confidence=confidence,
                license=match_info.get('metadata', {}).get('license', 'unknown'),
                match_type='tlsh_fuzzy',
                evidence={
                    'tlsh_distance': match_info['distance'],
                    'similarity_level': match_info['similarity_level'],
                    'similarity_score': confidence,
                    'file_path': str(file_path)  # Add file path for tracking
                }
            )
            matches.append(match)
            
            logger.info(f"TLSH match: {match.component} (distance: {match_info['distance']}, "
                       f"similarity: {match_info['similarity_level']})")
        
        return matches
    
    def rebuild_signatures(self, include_github: bool = True) -> Dict[str, int]:
        """
        Rebuild signature database from scratch.
        
        Args:
            include_github: Whether to download signatures from GitHub first
            
        Returns:
            Dictionary with statistics about the rebuild
        """
        return self.signature_manager.rebuild_database(include_github)
    
    def update_signatures(self, source: str = "github") -> Dict[str, int]:
        """
        Update signatures from a source.
        
        Args:
            source: Source to update from ('github' or path to signatures directory)
            
        Returns:
            Dictionary with statistics about the update
        """
        if source == "github":
            return self.signature_manager.update_from_github()
        else:
            # Import from directory
            from pathlib import Path
            return self.signature_manager.import_from_directory(Path(source))
    
    def get_signature_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the signature database.
        
        Returns:
            Dictionary with database statistics
        """
        return self.signature_manager.get_status()
    
    def extract_package_inventory(
        self, 
        package_path: Union[str, Path],
        analyze_contents: bool = False,
        include_hashes: bool = False,
        include_fuzzy_hashes: bool = False,
        detect_components: bool = False
    ) -> Dict[str, Any]:
        """
        Extract file inventory from a package/archive with comprehensive analysis.
        
        Args:
            package_path: Path to the package file
            analyze_contents: Extract and analyze file contents (slower but comprehensive)
            include_hashes: Include MD5, SHA1, SHA256 hashes
            include_fuzzy_hashes: Include TLSH and ssdeep fuzzy hashes
            detect_components: Run component detection on files
            
        Returns:
            Dictionary containing comprehensive package inventory with:
            - files: List of files with metadata, hashes, components detected
            - summary: Statistics including total files, sizes, components found
        """
        from binarysniffer.utils.inventory import extract_package_inventory
        return extract_package_inventory(
            Path(package_path), 
            analyzer=self,
            analyze_contents=analyze_contents,
            include_hashes=include_hashes,
            include_fuzzy_hashes=include_fuzzy_hashes,
            detect_components=detect_components
        )
    
    def _merge_tlsh_matches(
        self,
        direct_matches: List[ComponentMatch],
        tlsh_matches: List[ComponentMatch]
    ) -> List[ComponentMatch]:
        """
        Merge TLSH fuzzy matches with direct matches.
        
        Args:
            direct_matches: Matches from direct pattern matching
            tlsh_matches: Matches from TLSH fuzzy matching
            
        Returns:
            Merged list of matches, keeping highest confidence for duplicates
        """
        # Create a map of component -> best match
        component_map = {}
        
        # Add direct matches first (usually higher confidence)
        for match in direct_matches:
            key = f"{match.component}_{match.version}"
            component_map[key] = match
        
        # Add TLSH matches if not already present or if higher confidence
        for match in tlsh_matches:
            key = f"{match.component}_{match.version}"
            if key not in component_map:
                component_map[key] = match
                logger.debug(f"Added TLSH-only match: {match.component}")
            elif match.confidence > component_map[key].confidence:
                # TLSH match has higher confidence, update
                old_confidence = component_map[key].confidence
                component_map[key] = match
                logger.debug(f"TLSH match for {match.component} has higher confidence "
                           f"({match.confidence:.2f} vs {old_confidence:.2f})")
        
        # Return sorted list
        merged = list(component_map.values())
        merged.sort(key=lambda x: x.confidence, reverse=True)
        
        return merged
    
    
    
    
    def get_signature_stats(self) -> Dict[str, any]:
        """Get signature database statistics"""
        return self.db.get_statistics()
    
    def check_updates(self) -> bool:
        """Check if signature updates are available"""
        # Update functionality not implemented in enhanced analyzer
        return False
    
    def update_signatures(self, force: bool = False) -> bool:
        """Update signature database"""
        # Update functionality not implemented in enhanced analyzer
        return False
    
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
        
        # Use OSLiLi for license detection (required dependency)
        # OSLiLi will handle all license detection including file identification
        license_results = self.oslili.detect_licenses_in_path(str(file_path))

        for license_result in license_results:
            match = ComponentMatch(
                component=f"License: {license_result.name}",
                ecosystem='license',
                confidence=license_result.confidence,
                license=license_result.spdx_id,
                match_type='oslili_detection',
                evidence={
                    'detection_method': license_result.detection_method,
                    'category': license_result.category,
                    'source_file': license_result.source_file
                }
            )
            all_matches.append(match)

            # Track license files
            if license_result.source_file:
                if license_result.source_file not in license_files:
                    license_files[license_result.source_file] = []
                license_files[license_result.source_file].append(match)
            # Fallback to pattern matching if OSLiLi is not available
            if file_path.is_file():
                # Analyze single file
                result = self.analyze_file(file_path)
                all_matches.extend(result.matches)
                
                # Always analyze file content for licenses (not just license files)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1024 * 100)  # Read first 100KB
                    license_matches = self.license_matcher.detect_licenses_in_content(
                        content, str(file_path)
                    )
                    if license_matches:
                        all_matches.extend(license_matches)
                        if self.license_matcher.is_license_file(str(file_path)):
                            license_files[str(file_path)] = license_matches
                except Exception as e:
                    logger.debug(f"Could not read file {file_path} for license detection: {e}")
                        
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
                
                # Also analyze source code files for embedded licenses
                for sf in relevant_files[:50]:  # Limit to 50 files for performance
                    try:
                        with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read(1024 * 10)  # Read first 10KB of source files
                        license_matches = self.license_matcher.detect_licenses_in_content(
                            content, str(sf)
                        )
                        if license_matches:
                            all_matches.extend(license_matches)
                    except Exception as e:
                        logger.debug(f"Could not analyze source file {sf}: {e}")
            
            # Analyze code files for embedded licenses
            if include_dependencies:
                batch_results = self.analyze_directory(
                    file_path,
                    recursive=True,
                    file_patterns=None,
                    confidence_threshold=0.5,
                    parallel=True
                )
                for result in batch_results.results.values():
                    if not result.error:
                        all_matches.extend(result.matches)
        
        # Aggregate license information
        if self.oslili.is_available:
            # Aggregate licenses from matches
            license_info = {}
            for match in all_matches:
                if match.license:
                    if match.license not in license_info:
                        license_info[match.license] = {
                            'count': 0,
                            'confidence': 0.0,
                            'components': set(),
                            'files': set()
                        }
                    license_info[match.license]['count'] += 1
                    license_info[match.license]['confidence'] = max(
                        license_info[match.license]['confidence'],
                        match.confidence
                    )
                    if match.ecosystem != 'license':
                        license_info[match.license]['components'].add(match.component)
                    if 'source_file' in match.evidence:
                        license_info[match.license]['files'].add(match.evidence['source_file'])
            
            # Convert sets to lists for JSON serialization
            for license_id in license_info:
                license_info[license_id]['components'] = list(license_info[license_id]['components'])
                license_info[license_id]['files'] = list(license_info[license_id]['files'])
            
            # Check compatibility using OSLiLi
            detected_licenses = set(license_info.keys())
            compatibility = self.oslili.get_license_compatibility_info(detected_licenses)
        elif self.license_matcher:
            # Use license_matcher for aggregation and compatibility
            license_info = self.license_matcher.aggregate_licenses(all_matches)
            detected_licenses = set(license_info.keys())
            compatibility = self.license_matcher.check_license_compatibility(detected_licenses)
        else:
            # No license detection available
            license_info = {}
            detected_licenses = set()
            compatibility = {'compatible': True, 'warnings': ['License detection not available']}
        
        return {
            'licenses_detected': list(detected_licenses),
            'license_details': license_info,
            'license_files': license_files,
            'compatibility': compatibility,
            'total_components': len(all_matches),
            'analysis_path': str(file_path)
        }