"""License-specific pattern matcher for BinarySniffer."""

import re
import logging
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

from ..core.results import ComponentMatch

logger = logging.getLogger(__name__)


class LicenseMatcher:
    """Specialized matcher for license detection using pattern matching."""
    
    LICENSE_FILE_PATTERNS = [
        r'LICENSE(?:\.(?:txt|md|rst))?$',
        r'LICENCE(?:\.(?:txt|md|rst))?$',
        r'COPYING(?:\.(?:txt|md|rst))?$',
        r'COPYRIGHT(?:\.(?:txt|md|rst))?$',
        r'NOTICE(?:\.(?:txt|md|rst))?$',
        r'.*LICENSE.*',  # Match any file with LICENSE in the name
        r'.*LICENCE.*',  # Match any file with LICENCE in the name
        r'.*COPYING.*',  # Match any file with COPYING in the name
        r'license\..*',
        r'UNLICENSE(?:\.(?:txt|md|rst))?$',
    ]
    
    CODE_FILE_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.hpp',
        '.cs', '.go', '.rs', '.rb', '.php', '.swift', '.kt', '.scala',
        '.m', '.mm', '.sh', '.bash', '.zsh', '.pl', '.r', '.lua'
    }
    
    def __init__(self):
        """Initialize the license matcher."""
        self.license_signatures = self._load_license_signatures()
        self.compiled_file_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.LICENSE_FILE_PATTERNS
        ]
        
    def _load_license_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Load license-specific signatures from the licenses directory."""
        import json
        license_sigs = {}
        licenses_dir = Path('signatures/licenses')
        
        if licenses_dir.exists():
            for sig_file in licenses_dir.glob('*.json'):
                try:
                    with open(sig_file, 'r') as f:
                        sig_data = json.load(f)
                    if sig_data and 'component' in sig_data:
                        license_name = sig_data['component'].get('license', '')
                        if license_name:
                            license_sigs[license_name] = sig_data
                            logger.debug(f"Loaded license signature: {license_name}")
                except Exception as e:
                    logger.warning(f"Failed to load license signature {sig_file}: {e}")
        
        logger.debug(f"Loaded {len(license_sigs)} license signatures")
        return license_sigs
    
    def is_license_file(self, file_path: str) -> bool:
        """Check if a file path matches common license file patterns.
        
        Args:
            file_path: Path to check
            
        Returns:
            True if the file appears to be a license file
        """
        file_name = Path(file_path).name
        return any(pattern.match(file_name) for pattern in self.compiled_file_patterns)
    
    def detect_licenses_in_content(self, content: str, file_path: Optional[str] = None) -> List[ComponentMatch]:
        """Detect licenses in text content using pattern matching.
        
        Args:
            content: Text content to analyze
            file_path: Optional file path for context
            
        Returns:
            List of detected license matches
        """
        matches = []
        content_lower = content.lower()
        
        for license_id, sig_data in self.license_signatures.items():
            component_info = sig_data.get('component', {})
            signatures = sig_data.get('signatures', [])
            
            total_confidence = 0.0
            matched_patterns = []
            
            for sig in signatures:
                pattern = sig.get('pattern', '')
                sig_type = sig.get('type', 'string_pattern')
                confidence = sig.get('confidence', 0.5)
                context = sig.get('context', '')
                
                found = False
                if sig_type == 'regex_pattern':
                    try:
                        if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                            found = True
                    except re.error as e:
                        logger.warning(f"Invalid regex pattern '{pattern}': {e}")
                elif sig_type == 'string_pattern':
                    if pattern.lower() in content_lower:
                        found = True
                
                if found:
                    matched_patterns.append({
                        'pattern': pattern,
                        'context': context,
                        'confidence': confidence
                    })
                    total_confidence = max(total_confidence, confidence)
                    
                    if context == 'spdx_identifier':
                        total_confidence = 1.0
            
            if matched_patterns:
                if file_path and self.is_license_file(file_path):
                    total_confidence = min(1.0, total_confidence * 1.2)
                
                match = ComponentMatch(
                    component=component_info.get('name', f'License: {license_id}'),
                    ecosystem='license',
                    confidence=total_confidence,
                    license=license_id,
                    match_type='license_pattern',
                    evidence={
                        'matched_patterns': len(matched_patterns),
                        'pattern_details': matched_patterns[:3],
                        'detection_method': 'pattern_matching',
                        'file_path': file_path or 'unknown'
                    }
                )
                matches.append(match)
                logger.debug(f"Detected license {license_id} with confidence {total_confidence}")
        
        return matches
    
    def detect_licenses_in_files(self, file_paths: List[str], 
                                 read_content_func=None) -> Dict[str, List[ComponentMatch]]:
        """Detect licenses across multiple files.
        
        Args:
            file_paths: List of file paths to analyze
            read_content_func: Optional function to read file content
            
        Returns:
            Dictionary mapping file paths to detected licenses
        """
        results = {}
        
        for file_path in file_paths:
            try:
                if read_content_func:
                    content = read_content_func(file_path)
                else:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(1024 * 100)
                
                if self.is_license_file(file_path):
                    logger.info(f"Analyzing license file: {file_path}")
                
                matches = self.detect_licenses_in_content(content, file_path)
                if matches:
                    results[file_path] = matches
                    
            except Exception as e:
                logger.warning(f"Failed to analyze file {file_path}: {e}")
        
        return results
    
    def aggregate_licenses(self, all_matches: List[ComponentMatch]) -> Dict[str, Dict[str, Any]]:
        """Aggregate license information from multiple matches.
        
        Args:
            all_matches: List of all component matches
            
        Returns:
            Dictionary with aggregated license information
        """
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
                    license_info[match.license]['components'].add(match.name)
                
                if 'file_path' in match.evidence:
                    license_info[match.license]['files'].add(match.evidence['file_path'])
        
        for license_id in license_info:
            license_info[license_id]['components'] = list(license_info[license_id]['components'])
            license_info[license_id]['files'] = list(license_info[license_id]['files'])
        
        return license_info
    
    def check_license_compatibility(self, licenses: Set[str]) -> Dict[str, Any]:
        """Check compatibility between detected licenses.
        
        Args:
            licenses: Set of license identifiers
            
        Returns:
            Dictionary with compatibility information
        """
        COPYLEFT_LICENSES = {'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'GPL-2.0+', 'GPL-3.0+'}
        WEAK_COPYLEFT = {'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-2.0'}
        PERMISSIVE = {'MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'ISC'}
        
        compatibility = {
            'compatible': True,
            'warnings': [],
            'license_types': {
                'copyleft': [],
                'weak_copyleft': [],
                'permissive': [],
                'unknown': []
            }
        }
        
        for license_id in licenses:
            if license_id in COPYLEFT_LICENSES:
                compatibility['license_types']['copyleft'].append(license_id)
            elif license_id in WEAK_COPYLEFT:
                compatibility['license_types']['weak_copyleft'].append(license_id)
            elif license_id in PERMISSIVE:
                compatibility['license_types']['permissive'].append(license_id)
            else:
                compatibility['license_types']['unknown'].append(license_id)
        
        if len(compatibility['license_types']['copyleft']) > 1:
            gpl_versions = [l for l in compatibility['license_types']['copyleft'] if 'GPL' in l]
            if 'GPL-2.0' in gpl_versions and 'GPL-3.0' in gpl_versions:
                compatibility['compatible'] = False
                compatibility['warnings'].append(
                    "GPL-2.0 and GPL-3.0 are incompatible with each other"
                )
        
        if compatibility['license_types']['copyleft'] and compatibility['license_types']['permissive']:
            compatibility['warnings'].append(
                "Mixing copyleft and permissive licenses - copyleft terms may apply to combined work"
            )
        
        if compatibility['license_types']['unknown']:
            compatibility['warnings'].append(
                f"Unknown licenses detected: {', '.join(compatibility['license_types']['unknown'])}"
            )
        
        return compatibility