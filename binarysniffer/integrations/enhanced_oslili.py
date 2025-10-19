"""
Enhanced OSLiLi integration consolidating general and package-specific license detection.

This module replaces the separate OSLiLi integrations in oslili.py and upmex_adapter.py
with a unified, reusable interface that supports both general license detection and
package-specific metadata enhancement.
"""

import logging
import tempfile
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Union
from dataclasses import dataclass

from ..core.results import ComponentMatch

logger = logging.getLogger(__name__)


@dataclass
class LicenseDetectionResult:
    """Result from OSLiLi license detection"""
    spdx_id: str
    name: str
    confidence: float
    detection_method: str
    source_file: Optional[str] = None
    category: Optional[str] = None
    match_type: Optional[str] = None
    text: Optional[str] = None


class EnhancedOsliliIntegration:
    """
    Unified OSLiLi integration for both general license detection and package enhancement.

    This class consolidates the functionality from:
    - binarysniffer.integrations.oslili.OsliliIntegration
    - UPMEXAdapter._enhance_with_license_detection

    Providing a single, consistent interface for all OSLiLi operations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize enhanced OSLiLi integration"""
        self.config = config or {}
        self._detector = None
        self._is_available = False
        self._init_detector()

    def _init_detector(self):
        """Initialize the OSLiLi detector - this is a required dependency"""
        try:
            from semantic_copycat_oslili.core.generator import LicenseCopyrightDetector
            from semantic_copycat_oslili.core.models import Config

            # Create OSLiLi config from our config
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
            self._is_available = True
            logger.debug("Initialized enhanced OSLiLi detector successfully")

        except ImportError as e:
            # OSLiLi is a required dependency - this should not happen
            logger.error(f"Required dependency semantic-copycat-oslili not available: {e}")
            raise ImportError(
                "semantic-copycat-oslili is a required dependency. "
                "Please install with: pip install semantic-copycat-oslili>=1.3.2"
            ) from e
        except Exception as e:
            logger.error(f"Failed to initialize OSLiLi detector: {e}")
            raise RuntimeError(f"Failed to initialize required OSLiLi detector: {e}") from e

    @property
    def is_available(self) -> bool:
        """Check if OSLiLi is available and functional"""
        return self._is_available and self._detector is not None

    def detect_licenses_in_path(self, path: str) -> List[LicenseDetectionResult]:
        """
        Detect licenses in a file or directory using OSLiLi

        Args:
            path: Path to analyze

        Returns:
            List of detected licenses
        """
        if not self.is_available:
            logger.warning("OSLiLi detector not available")
            return []

        try:
            result = self._detector.process_local_path(path, extract_archives=False)

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

            logger.debug(f"Detected {len(license_results)} licenses using OSLiLi")
            return license_results

        except Exception as e:
            logger.error(f"OSLiLi license detection failed: {e}")
            return []

    def detect_licenses_in_content(self, content: str, file_path: Optional[str] = None) -> List[ComponentMatch]:
        """
        Detect licenses in text content and return as ComponentMatch objects

        Args:
            content: Text content to analyze
            file_path: Optional file path for context

        Returns:
            List of ComponentMatch objects for detected licenses
        """
        if not self.is_available:
            return []

        # Write content to temporary file and analyze
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp_file:
            tmp_file.write(content)
            tmp_path = tmp_file.name

        try:
            license_results = self.detect_licenses_in_path(tmp_path)
            matches = []

            for license_result in license_results:
                # Convert to ComponentMatch format
                match = ComponentMatch(
                    component=f"License: {license_result.name}",
                    ecosystem="license",
                    confidence=license_result.confidence,
                    license=license_result.spdx_id,
                    match_type="oslili_detection",
                    evidence={
                        "detection_method": license_result.detection_method,
                        "category": license_result.category,
                        "source_file": file_path or tmp_path
                    }
                )
                matches.append(match)
                logger.debug(f"Added OSLiLi-detected license: {license_result.spdx_id} ({license_result.confidence:.2%} confidence)")

            return matches

        except Exception as e:
            logger.error(f"OSLiLi content analysis failed: {e}")
            return []
        finally:
            # Clean up temporary file
            try:
                Path(tmp_path).unlink()
            except:
                pass

    def enhance_package_with_license_detection(self, package_path: Path, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enhance package metadata with proper SPDX license detection using OSLiLi.

        This method consolidates the package-specific license detection logic
        from UPMEXAdapter._enhance_with_license_detection.

        Args:
            package_path: Path to the package file
            result: Package metadata result to enhance

        Returns:
            Enhanced result with SPDX license information
        """
        if not self.is_available:
            logger.debug("OSLiLi not available for package license enhancement")
            return self._parse_license_references_fallback(result)

        try:
            logger.debug("Using OSLiLi for SPDX license detection on package")

            # Create a temporary extraction to analyze the package contents
            import zipfile

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Extract package if it's an archive
                if package_path.suffix.lower() in ['.jar', '.war', '.ear', '.zip', '.whl']:
                    try:
                        with zipfile.ZipFile(package_path, 'r') as archive:
                            # Extract only license-related files
                            license_files = [f for f in archive.namelist() if any(
                                word in f.lower() for word in ['license', 'licence', 'notice', 'copyright', 'copying']
                            )]

                            if license_files:
                                for lf in license_files[:5]:  # Limit to first 5 license files
                                    try:
                                        archive.extract(lf, temp_path)
                                    except Exception:
                                        continue

                                # Run OSLiLi on extracted license files
                                detection_result = self._detector.process_local_path(str(temp_path), extract_archives=False)

                                if detection_result.licenses:
                                    # Structure the license information
                                    result['metadata']['spdx_licenses'] = []
                                    result['metadata']['license_details'] = []

                                    for license_info in detection_result.licenses:
                                        spdx_id = license_info.spdx_id
                                        confidence = license_info.confidence

                                        if spdx_id and spdx_id != 'Unknown':
                                            result['metadata']['spdx_licenses'].append(spdx_id)
                                            result['metadata']['license_details'].append({
                                                'spdx_id': spdx_id,
                                                'confidence': confidence,
                                                'detection_method': license_info.detection_method,
                                                'source_file': license_info.source_file or str(package_path),
                                                'category': license_info.category or 'package_license',
                                                'match_type': license_info.match_type
                                            })

                                    # Remove duplicates
                                    result['metadata']['spdx_licenses'] = list(set(result['metadata']['spdx_licenses']))

                                    if result['metadata']['spdx_licenses']:
                                        logger.info(f"Detected SPDX licenses: {result['metadata']['spdx_licenses']}")
                                        result['source'] = 'enhanced_analysis_with_oslili'
                                    else:
                                        logger.debug("No SPDX licenses detected by OSLiLi")

                                # Add copyright information if available
                                if detection_result.copyrights:
                                    result['metadata']['copyright_info'] = []
                                    for copyright_info in detection_result.copyrights:
                                        result['metadata']['copyright_info'].append({
                                            'holder': copyright_info.holder,
                                            'years': copyright_info.years,
                                            'statement': copyright_info.statement,
                                            'source_file': copyright_info.source_file,
                                            'confidence': copyright_info.confidence
                                        })

                    except Exception as e:
                        logger.debug(f"Archive extraction for license detection failed: {e}")

        except Exception as e:
            logger.debug(f"OSLiLi license detection enhancement failed: {e}")

        # Parse license references for SPDX mapping if no licenses were detected by OSLiLi
        if 'spdx_licenses' not in result.get('metadata', {}) or not result['metadata']['spdx_licenses']:
            result = self._parse_license_references_fallback(result)

        # Always keep basic license info as fallback
        if 'extracted_license_info' in result.get('metadata', {}):
            result['metadata']['license_notes'] = result['metadata']['extracted_license_info']

        return result

    def _parse_license_references_fallback(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse license references from metadata to identify SPDX licenses.
        Fallback method when OSLiLi is not available or doesn't detect licenses.
        """
        # Common license name to SPDX mapping
        license_mappings = {
            'apache license 2.0': 'Apache-2.0',
            'apache license, version 2.0': 'Apache-2.0',
            'apache-2.0': 'Apache-2.0',
            'apache 2': 'Apache-2.0',
            'apache v2': 'Apache-2.0',
            'mozilla public license, v. 2.0': 'MPL-2.0',
            'mozilla public license 2.0': 'MPL-2.0',
            'mpl-2.0': 'MPL-2.0',
            'mpl 2.0': 'MPL-2.0',
            'mit license': 'MIT',
            'mit': 'MIT',
            'bsd license': 'BSD-3-Clause',
            'bsd-3-clause': 'BSD-3-Clause',
            'bsd 3-clause': 'BSD-3-Clause',
            'gpl-2.0': 'GPL-2.0',
            'gpl-3.0': 'GPL-3.0',
            'lgpl-2.1': 'LGPL-2.1',
            'lgpl-3.0': 'LGPL-3.0',
            'eclipse public license': 'EPL-1.0',
            'epl-1.0': 'EPL-1.0',
            'creative commons': 'CC-BY-4.0'  # Default CC license
        }

        metadata = result.get('metadata', {})
        license_candidates = []

        # Collect all text that might contain license references
        text_sources = []

        # From extracted license info
        if 'extracted_license_info' in metadata:
            text_sources.extend(metadata['extracted_license_info'])

        # From notice text
        if 'notice_text' in metadata:
            text_sources.append(metadata['notice_text'])

        # From manifest bundle license
        if 'manifest_bundle_license' in metadata:
            text_sources.append(metadata['manifest_bundle_license'])

        # Parse each text source for license references
        for text in text_sources:
            if not text:
                continue

            text_lower = text.lower()
            for license_name, spdx_id in license_mappings.items():
                if license_name in text_lower:
                    license_candidates.append({
                        'spdx_id': spdx_id,
                        'confidence': 0.8,  # High confidence for direct name matches
                        'detection_method': 'reference_parsing',
                        'source_text': text.strip(),
                        'matched_term': license_name
                    })

        # Add unique SPDX licenses to metadata
        if license_candidates:
            if 'spdx_licenses' not in metadata:
                metadata['spdx_licenses'] = []
            if 'license_details' not in metadata:
                metadata['license_details'] = []

            seen_spdx = set(metadata['spdx_licenses'])
            for candidate in license_candidates:
                spdx_id = candidate['spdx_id']
                if spdx_id not in seen_spdx:
                    metadata['spdx_licenses'].append(spdx_id)
                    metadata['license_details'].append({
                        'spdx_id': spdx_id,
                        'confidence': candidate['confidence'],
                        'detection_method': candidate['detection_method'],
                        'source_file': 'package_metadata',
                        'category': 'referenced_license',
                        'match_details': {
                            'matched_term': candidate['matched_term'],
                            'source_text': candidate['source_text']
                        }
                    })
                    seen_spdx.add(spdx_id)

            if metadata['spdx_licenses']:
                logger.info(f"Mapped license references to SPDX: {metadata['spdx_licenses']}")
                # Update source to indicate enhanced analysis
                if result.get('source') == 'basic_analysis':
                    result['source'] = 'enhanced_analysis_with_reference_parsing'

        return result

    def get_copyright_info(self, path: str) -> List[Dict[str, Any]]:
        """
        Extract copyright information from a path using OSLiLi

        Args:
            path: Path to analyze

        Returns:
            List of copyright information dictionaries
        """
        if not self.is_available:
            return []

        try:
            result = self._detector.process_local_path(path, extract_archives=False)
            copyright_info = []

            for copyright_data in result.copyrights:
                copyright_info.append({
                    'holder': copyright_data.holder,
                    'years': copyright_data.years,
                    'statement': copyright_data.statement,
                    'source_file': copyright_data.source_file,
                    'confidence': copyright_data.confidence
                })

            logger.debug(f"Extracted {len(copyright_info)} copyright entries using OSLiLi")
            return copyright_info

        except Exception as e:
            logger.error(f"OSLiLi copyright extraction failed: {e}")
            return []

    def get_license_compatibility_info(self, spdx_ids: Set[str]) -> Dict[str, Any]:
        """
        Get basic compatibility information for detected licenses.
        This provides simplified compatibility analysis using SPDX identifiers.

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
            'MPL-2.0', 'EPL-1.0', 'EPL-2.0'
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