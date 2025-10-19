"""UPMEX integration adapter for package metadata extraction."""

import logging
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)


class UPMEXAdapter:
    """Adapter for semantic-copycat-upmex metadata extraction"""

    # Package types that UPMEX can handle
    SUPPORTED_PACKAGE_TYPES = {
        'pypi': ['.whl', '.egg'],
        'maven': ['.jar', '.war', '.ear'],
        'npm': ['.tgz', '.tar.gz'],
        'nuget': ['.nupkg'],
        'composer': ['.phar'],
        'cargo': ['.crate'],
        'gem': ['.gem'],
        'conda': ['.conda', '.tar.bz2'],
    }

    def __init__(self, enable_online: bool = False, use_cache: bool = True):
        """Initialize UPMEX adapter.

        Args:
            enable_online: Enable online enrichment from package APIs
            use_cache: Use local cache for repeated requests
        """
        self.enable_online = enable_online
        self.use_cache = use_cache
        self._check_upmex_available()

    def _check_upmex_available(self) -> bool:
        """Check if UPMEX is available."""
        try:
            # For now, always use basic analysis since UPMEX CLI isn't available
            # TODO: Re-enable when UPMEX is properly available
            self._use_api = True  # Use our basic analysis method
            logger.debug("Using basic package analysis")
            return True
        except Exception as e:
            logger.warning(f"Package analysis not available: {e}")
            return False

    def is_supported_package(self, file_path: Path) -> Optional[str]:
        """Check if file is a supported package type.

        Args:
            file_path: Path to package file

        Returns:
            Package type if supported, None otherwise
        """
        if not file_path.exists():
            return None

        suffix = file_path.suffix.lower()
        name = file_path.name.lower()

        # Check exact suffix matches
        for pkg_type, extensions in self.SUPPORTED_PACKAGE_TYPES.items():
            if suffix in extensions:
                return pkg_type

        # Check compound extensions
        if name.endswith('.tar.gz'):
            # Could be npm or generic tar.gz
            return 'npm'
        elif name.endswith('.tar.bz2'):
            return 'conda'

        return None

    def extract_metadata(self, package_path: Path,
                        package_type: Optional[str] = None) -> Dict[str, Any]:
        """Extract metadata from a package file.

        Args:
            package_path: Path to package file
            package_type: Package type hint (auto-detected if None)

        Returns:
            Dictionary containing package metadata with SPDX license IDs
        """
        if not package_path.exists():
            return {"error": f"Package file not found: {package_path}", "metadata": {}}

        # Auto-detect package type if not provided
        if package_type is None:
            package_type = self.is_supported_package(package_path)

        if package_type is None:
            return {"error": "Unsupported package type", "metadata": {}}

        try:
            if self._use_api:
                result = self._extract_with_api(package_path, package_type)
                # Enhance with proper license detection
                result = self._enhance_with_license_detection(package_path, result)
                return result
            else:
                return self._extract_with_subprocess(package_path, package_type)
        except Exception as e:
            logger.warning(f"UPMEX extraction failed for {package_path}: {e}")
            return {"error": str(e), "metadata": {}}

    def _extract_with_api(self, package_path: Path, package_type: str) -> Dict[str, Any]:
        """Extract metadata using basic package analysis."""
        # For now, provide basic package identification and structure analysis
        # This will be enhanced when UPMEX is properly available

        metadata = {
            "name": package_path.stem,
            "file_size": package_path.stat().st_size,
            "file_path": str(package_path),
            "detected_type": package_type
        }

        # Add package-specific analysis
        if package_type == 'maven' and package_path.suffix == '.jar':
            metadata.update(self._analyze_jar_basic(package_path))
        elif package_type == 'pypi' and package_path.suffix == '.whl':
            metadata.update(self._analyze_wheel_basic(package_path))

        return {
            "package_type": package_type,
            "metadata": metadata,
            "source": "basic_analysis"
        }

    def _analyze_jar_basic(self, jar_path: Path) -> Dict[str, Any]:
        """Basic JAR analysis for Maven packages."""
        import zipfile

        metadata = {}
        try:
            with zipfile.ZipFile(jar_path, 'r') as jar:
                files = jar.namelist()

                # Look for Maven metadata
                pom_files = [f for f in files if f.endswith('pom.xml') or f.endswith('pom.properties')]
                if pom_files:
                    metadata['has_maven_metadata'] = True
                    metadata['maven_files'] = pom_files

                    # Try to extract info from pom.properties
                    pom_props = [f for f in pom_files if f.endswith('pom.properties')]
                    if pom_props:
                        try:
                            props_content = jar.read(pom_props[0]).decode('utf-8', errors='ignore')
                            for line in props_content.split('\n'):
                                if '=' in line and not line.strip().startswith('#'):
                                    key, value = line.split('=', 1)
                                    key = key.strip()
                                    value = value.strip()
                                    if key in ['groupId', 'artifactId', 'version']:
                                        metadata[f'maven_{key}'] = value
                        except Exception as e:
                            logger.debug(f"Failed to read pom.properties: {e}")

                # Look for MANIFEST.MF
                manifest_files = [f for f in files if f.endswith('MANIFEST.MF')]
                if manifest_files:
                    try:
                        manifest_content = jar.read(manifest_files[0]).decode('utf-8', errors='ignore')
                        # Extract comprehensive info from manifest
                        for line in manifest_content.split('\n'):
                            if ':' in line:
                                key, value = line.split(':', 1)
                                key = key.strip()
                                value = value.strip()
                                if key in [
                                    'Implementation-Title', 'Implementation-Version', 'Implementation-Vendor',
                                    'Implementation-URL', 'Specification-Title', 'Specification-Version',
                                    'Specification-Vendor', 'Bundle-Name', 'Bundle-Version', 'Bundle-Vendor',
                                    'Bundle-License', 'Bundle-Homepage', 'Bundle-Description'
                                ]:
                                    metadata[f'manifest_{key.lower().replace("-", "_")}'] = value
                    except Exception as e:
                        logger.debug(f"Failed to read manifest: {e}")

                # Look for LICENSE files
                license_files = [f for f in files if any(
                    word in f.lower() for word in ['license', 'licence', 'copying']
                ) and f.lower().endswith(('.txt', '.md', ''))]

                if license_files:
                    metadata['license_files'] = license_files
                    # Try to read the first license file
                    try:
                        license_content = jar.read(license_files[0]).decode('utf-8', errors='ignore')
                        if len(license_content) < 2000:  # Only for reasonably sized files
                            metadata['license_text'] = license_content.strip()
                    except Exception as e:
                        logger.debug(f"Failed to read license file: {e}")

                # Look for NOTICE files
                notice_files = [f for f in files if 'notice' in f.lower()]
                if notice_files:
                    metadata['notice_files'] = notice_files
                    # Try to read notice for license info
                    try:
                        notice_content = jar.read(notice_files[0]).decode('utf-8', errors='ignore')
                        if len(notice_content) < 1000:
                            metadata['notice_text'] = notice_content.strip()

                            # Extract license info from notice
                            if 'license' in notice_content.lower():
                                lines = notice_content.split('\n')
                                license_info = []
                                for line in lines:
                                    if any(word in line.lower() for word in ['license', 'licence', 'copyright']):
                                        license_info.append(line.strip())
                                if license_info:
                                    metadata['extracted_license_info'] = license_info
                    except Exception as e:
                        logger.debug(f"Failed to read notice file: {e}")

                # Look for COPYRIGHT files
                copyright_files = [f for f in files if 'copyright' in f.lower()]
                if copyright_files:
                    metadata['copyright_files'] = copyright_files

                # Count classes and resources
                class_files = [f for f in files if f.endswith('.class')]
                metadata['class_count'] = len(class_files)
                metadata['total_entries'] = len(files)

        except Exception as e:
            logger.debug(f"JAR analysis failed: {e}")

        return metadata

    def _analyze_wheel_basic(self, wheel_path: Path) -> Dict[str, Any]:
        """Basic wheel analysis for PyPI packages."""
        import zipfile

        metadata = {}
        try:
            with zipfile.ZipFile(wheel_path, 'r') as wheel:
                # Look for METADATA file
                metadata_files = [f for f in wheel.namelist() if f.endswith('METADATA')]
                if metadata_files:
                    try:
                        metadata_content = wheel.read(metadata_files[0]).decode('utf-8', errors='ignore')
                        # Extract basic info
                        for line in metadata_content.split('\n'):
                            if ':' in line:
                                key, value = line.split(':', 1)
                                key = key.strip()
                                value = value.strip()
                                if key in ['Name', 'Version', 'Author', 'License']:
                                    metadata[f'wheel_{key.lower()}'] = value
                    except Exception as e:
                        logger.debug(f"Failed to read wheel metadata: {e}")

                metadata['total_entries'] = len(wheel.namelist())

        except Exception as e:
            logger.debug(f"Wheel analysis failed: {e}")

        return metadata

    def _extract_with_subprocess(self, package_path: Path, package_type: str) -> Dict[str, Any]:
        """Extract metadata using UPMEX CLI subprocess."""
        import subprocess

        cmd = [
            "python", "-m", "upmex.cli", "extract",
            str(package_path),
            "--format", "json"
        ]

        if self.enable_online:
            cmd.append("--online")

        if not self.use_cache:
            cmd.append("--no-cache")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return {"error": f"UPMEX CLI failed: {result.stderr}", "metadata": {}}

            try:
                metadata = json.loads(result.stdout)
                return {
                    "package_type": package_type,
                    "metadata": metadata,
                    "source": "upmex_cli"
                }
            except json.JSONDecodeError as e:
                return {"error": f"Invalid JSON from UPMEX: {e}", "metadata": {}}

        except subprocess.TimeoutExpired:
            return {"error": "UPMEX extraction timed out", "metadata": {}}
        except FileNotFoundError:
            return {"error": "UPMEX CLI not found", "metadata": {}}
        except Exception as e:
            return {"error": f"Subprocess failed: {e}", "metadata": {}}

    def extract_multiple(self, file_paths: List[Path]) -> Dict[Path, Dict[str, Any]]:
        """Extract metadata from multiple package files.

        Args:
            file_paths: List of package file paths

        Returns:
            Dictionary mapping file paths to metadata
        """
        results = {}

        for file_path in file_paths:
            package_type = self.is_supported_package(file_path)
            if package_type:
                results[file_path] = self.extract_metadata(file_path, package_type)
            else:
                logger.debug(f"Skipping unsupported package: {file_path}")

        return results

    def _enhance_with_license_detection(self, package_path: Path, result: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance package metadata with proper SPDX license detection using OSLiLi."""
        try:
            # Import OSLiLi components
            from semantic_copycat_oslili.core.generator import LicenseCopyrightDetector
            from semantic_copycat_oslili.core.models import Config

            logger.debug("Using OSLiLi for SPDX license detection on package")

            # Initialize OSLiLi detector with default config
            config = Config()
            detector = LicenseCopyrightDetector(config)

            # Create a temporary extraction to analyze the package contents
            import tempfile
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
                                detection_result = detector.process_local_path(str(temp_path), extract_archives=False)

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

        except ImportError:
            logger.debug("OSLiLi not available for license detection")
        except Exception as e:
            logger.debug(f"License detection enhancement failed: {e}")

        # Parse license references for SPDX mapping if no licenses were detected by OSLiLi
        if 'spdx_licenses' not in result.get('metadata', {}) or not result['metadata']['spdx_licenses']:
            self._parse_license_references(result)

        # Always keep basic license info as fallback
        if 'extracted_license_info' in result.get('metadata', {}):
            result['metadata']['license_notes'] = result['metadata']['extracted_license_info']

        return result

    def _parse_license_references(self, result: Dict[str, Any]) -> None:
        """Parse license references from metadata to identify SPDX licenses."""
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

    def get_supported_extensions(self) -> List[str]:
        """Get list of all supported file extensions."""
        extensions = []
        for exts in self.SUPPORTED_PACKAGE_TYPES.values():
            extensions.extend(exts)
        return sorted(set(extensions))