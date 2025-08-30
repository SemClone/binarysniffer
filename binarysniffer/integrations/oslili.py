"""
Integration with semantic-copycat-oslili for license detection
"""

import logging
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from ..core.results import ComponentMatch

logger = logging.getLogger(__name__)


@dataclass
class LicenseDetectionResult:
    """Result from oslili license detection"""
    spdx_id: str
    name: str
    confidence: float
    detection_method: str
    source_file: Optional[str] = None
    category: Optional[str] = None
    match_type: Optional[str] = None
    text: Optional[str] = None


class OsliliIntegration:
    """
    Integration with semantic-copycat-oslili for license detection.
    Replaces the built-in license pattern matching with oslili's more accurate detection.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize oslili integration"""
        self.config = config or {}
        self._detector = None
        self._init_detector()
    
    def _init_detector(self):
        """Initialize the oslili detector"""
        try:
            from semantic_copycat_oslili import LicenseCopyrightDetector, Config
            
            # Create oslili config from our config
            oslili_config = Config(
                similarity_threshold=self.config.get('similarity_threshold', 0.97),
                max_recursion_depth=self.config.get('max_recursion_depth', 5),
                max_extraction_depth=self.config.get('max_extraction_depth', 3),
                thread_count=self.config.get('thread_count', 2),
                verbose=self.config.get('verbose', False),
                debug=self.config.get('debug', False),
                cache_dir=self.config.get('cache_dir', None)
            )
            
            self._detector = LicenseCopyrightDetector(oslili_config)
            logger.debug("Initialized oslili detector successfully")
            
        except ImportError:
            logger.warning("semantic-copycat-oslili not available. License detection will be limited.")
            self._detector = None
        except Exception as e:
            logger.error(f"Failed to initialize oslili detector: {e}")
            self._detector = None
    
    def detect_licenses_in_path(self, path: str) -> List[LicenseDetectionResult]:
        """
        Detect licenses in a file or directory using oslili
        
        Args:
            path: Path to analyze
            
        Returns:
            List of detected licenses
        """
        if not self._detector:
            logger.warning("Oslili detector not available")
            return []
        
        try:
            result = self._detector.process_local_path(path)
            
            license_results = []
            for license_info in result.licenses:
                license_results.append(LicenseDetectionResult(
                    spdx_id=license_info.spdx_id,
                    name=license_info.name,
                    confidence=license_info.confidence,
                    detection_method=license_info.detection_method,
                    source_file=license_info.source_file,
                    category=license_info.category,
                    match_type=license_info.match_type,
                    text=license_info.text
                ))
            
            logger.debug(f"Detected {len(license_results)} licenses using oslili")
            return license_results
            
        except Exception as e:
            logger.error(f"Error detecting licenses with oslili: {e}")
            return []
    
    def detect_licenses_in_content(self, content: str, file_path: Optional[str] = None) -> List[LicenseDetectionResult]:
        """
        Detect licenses in text content using oslili
        
        Args:
            content: Text content to analyze
            file_path: Optional file path for context
            
        Returns:
            List of detected licenses
        """
        if not self._detector:
            return []
        
        # Create a temporary file with the content
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_file:
                tmp_file.write(content)
                tmp_path = tmp_file.name
            
            try:
                results = self.detect_licenses_in_path(tmp_path)
                # Update source file to original path if provided
                if file_path:
                    for result in results:
                        result.source_file = file_path
                return results
            finally:
                # Clean up temporary file
                Path(tmp_path).unlink(missing_ok=True)
                
        except Exception as e:
            logger.error(f"Error creating temporary file for license detection: {e}")
            return []
    
    def detect_licenses_in_extracted_files(self, extracted_dir: str, original_file: str) -> List[ComponentMatch]:
        """
        Detect licenses in extracted archive files and convert to ComponentMatch format
        
        Args:
            extracted_dir: Directory containing extracted files
            original_file: Original archive file path
            
        Returns:
            List of license matches in ComponentMatch format
        """
        if not self._detector:
            return []
        
        try:
            license_results = self.detect_licenses_in_path(extracted_dir)
            matches = []
            
            # Group licenses by SPDX ID for deduplication
            license_groups = {}
            for license_result in license_results:
                spdx_id = license_result.spdx_id
                if spdx_id not in license_groups:
                    license_groups[spdx_id] = []
                license_groups[spdx_id].append(license_result)
            
            # Convert to ComponentMatch format
            for spdx_id, group_results in license_groups.items():
                # Use the highest confidence result as primary
                best_result = max(group_results, key=lambda x: x.confidence)
                
                # Collect all source files
                source_files = [r.source_file for r in group_results if r.source_file]
                
                # Create evidence
                evidence = {
                    'detection_method': 'oslili',
                    'confidence': best_result.confidence,
                    'category': best_result.category,
                    'match_type': best_result.match_type,
                    'source_files': list(set(source_files)),
                    'original_archive': original_file,
                    'detection_methods': list(set(r.detection_method for r in group_results))
                }
                
                match = ComponentMatch(
                    component=f"License: {best_result.name}",
                    ecosystem='license',
                    confidence=best_result.confidence,
                    license=spdx_id,
                    match_type='license_detection',
                    evidence=evidence
                )
                matches.append(match)
            
            logger.debug(f"Converted {len(license_results)} oslili results to {len(matches)} component matches")
            return matches
            
        except Exception as e:
            logger.error(f"Error detecting licenses in extracted files: {e}")
            return []
    
    def analyze_license_files(self, file_paths: List[str]) -> Dict[str, List[ComponentMatch]]:
        """
        Analyze specific files for license content
        
        Args:
            file_paths: List of file paths to analyze
            
        Returns:
            Dictionary mapping file paths to detected licenses
        """
        results = {}
        
        for file_path in file_paths:
            if self.is_license_file(file_path):
                try:
                    license_results = self.detect_licenses_in_path(file_path)
                    matches = []
                    
                    for license_result in license_results:
                        evidence = {
                            'detection_method': 'oslili',
                            'confidence': license_result.confidence,
                            'category': license_result.category,
                            'match_type': license_result.match_type,
                            'source_file': file_path
                        }
                        
                        match = ComponentMatch(
                            component=f"License: {license_result.name}",
                            ecosystem='license',
                            confidence=license_result.confidence,
                            license=license_result.spdx_id,
                            match_type='license_file',
                            evidence=evidence
                        )
                        matches.append(match)
                    
                    if matches:
                        results[file_path] = matches
                        
                except Exception as e:
                    logger.warning(f"Failed to analyze license file {file_path}: {e}")
        
        return results
    
    def is_license_file(self, file_path: str) -> bool:
        """
        Check if a file path appears to be a license file
        
        Args:
            file_path: Path to check
            
        Returns:
            True if the file appears to be a license file
        """
        file_name = Path(file_path).name.upper()
        license_indicators = [
            'LICENSE', 'LICENCE', 'COPYING', 'COPYRIGHT', 
            'NOTICE', 'UNLICENSE', 'LEGAL'
        ]
        
        return any(indicator in file_name for indicator in license_indicators)
    
    def get_license_compatibility_info(self, spdx_ids: Set[str]) -> Dict[str, Any]:
        """
        Get basic compatibility information for detected licenses.
        This is simplified compared to the original implementation since
        oslili provides SPDX identifiers which are standardized.
        
        Args:
            spdx_ids: Set of SPDX license identifiers
            
        Returns:
            Basic compatibility information
        """
        # Simplified license categorization using SPDX IDs
        COPYLEFT_LICENSES = {
            'GPL-2.0', 'GPL-2.0+', 'GPL-2.0-only', 'GPL-2.0-or-later',
            'GPL-3.0', 'GPL-3.0+', 'GPL-3.0-only', 'GPL-3.0-or-later',
            'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later'
        }
        
        WEAK_COPYLEFT = {
            'LGPL-2.1', 'LGPL-2.1+', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
            'LGPL-3.0', 'LGPL-3.0+', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
            'MPL-2.0', 'EPL-2.0'
        }
        
        PERMISSIVE = {
            'MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 
            'ISC', 'BSD-3-Clause-Clear'
        }
        
        compatibility = {
            'compatible': True,
            'warnings': [],
            'license_types': {
                'copyleft': [],
                'weak_copyleft': [],
                'permissive': [],
                'unknown': []
            },
            'spdx_ids': list(spdx_ids)
        }
        
        for spdx_id in spdx_ids:
            if spdx_id in COPYLEFT_LICENSES:
                compatibility['license_types']['copyleft'].append(spdx_id)
            elif spdx_id in WEAK_COPYLEFT:
                compatibility['license_types']['weak_copyleft'].append(spdx_id)
            elif spdx_id in PERMISSIVE:
                compatibility['license_types']['permissive'].append(spdx_id)
            else:
                compatibility['license_types']['unknown'].append(spdx_id)
        
        # Basic compatibility checks
        copyleft_count = len(compatibility['license_types']['copyleft'])
        if copyleft_count > 1:
            compatibility['warnings'].append(
                f"Multiple copyleft licenses detected - review compatibility: {compatibility['license_types']['copyleft']}"
            )
        
        if compatibility['license_types']['copyleft'] and compatibility['license_types']['permissive']:
            compatibility['warnings'].append(
                "Mixing copyleft and permissive licenses - copyleft terms may apply"
            )
        
        if compatibility['license_types']['unknown']:
            compatibility['warnings'].append(
                f"Unknown/unrecognized licenses: {compatibility['license_types']['unknown']}"
            )
        
        return compatibility
    
    @property
    def is_available(self) -> bool:
        """Check if oslili integration is available"""
        return self._detector is not None