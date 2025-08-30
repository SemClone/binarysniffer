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