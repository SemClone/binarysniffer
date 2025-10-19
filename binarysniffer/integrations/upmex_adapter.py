"""UPMEX integration adapter for package metadata extraction."""

import logging
import json
import zipfile
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
        """Enhance package metadata with proper SPDX license detection using consolidated OSLiLi integration."""
        from .enhanced_oslili import EnhancedOsliliIntegration

        # Use consolidated OSLiLi integration
        oslili = EnhancedOsliliIntegration()
        return oslili.enhance_package_with_license_detection(package_path, result)

    def get_supported_extensions(self) -> List[str]:
        """Get list of all supported file extensions."""
        extensions = []
        for exts in self.SUPPORTED_PACKAGE_TYPES.values():
            extensions.extend(exts)
        return sorted(set(extensions))