"""
Archive file extractor for ZIP, JAR, APK, IPA, TAR, etc.
"""

import logging
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import List, Optional

from .base import BaseExtractor, ExtractedFeatures
from ..integrations.enhanced_oslili import EnhancedOsliliIntegration
from ..integrations import UPMEXAdapter

logger = logging.getLogger(__name__)


class ArchiveExtractor(BaseExtractor):
    """Extract features from archive files"""

    def __init__(self):
        """Initialize archive extractor"""
        super().__init__()
        self._seven_zip_path = self._find_seven_zip()
        if self._seven_zip_path:
            logger.debug(f"7-Zip found at: {self._seven_zip_path}")
        
        # Initialize OSLiLi for license detection
        self.oslili = EnhancedOsliliIntegration()
        if self.oslili.is_available:
            logger.debug("OSLiLi integration available for license detection")

        # Initialize UPMEX for package metadata extraction
        self.upmex = UPMEXAdapter()
        logger.debug("UPMEX integration initialized for package metadata")

    # Archive extensions
    ARCHIVE_EXTENSIONS = {
        # ZIP-based
        '.zip', '.jar', '.war', '.ear', '.apk', '.ipa', '.xpi',
        '.egg', '.whl', '.nupkg', '.vsix', '.crx',
        # TAR-based
        '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz',
        '.tar.zst', '.tzst',  # Zstandard compressed tar
        # Windows installers (require 7-Zip)
        '.msi',
        # macOS installers (require 7-Zip)
        '.pkg', '.dmg',
        # Package formats
        '.deb', '.rpm',  # Linux packages
        # Additional archive formats
        '.7z', '.rar',  # Common archives
        '.cpio', '.squashfs',  # Firmware/embedded formats
        # Other compression formats
        '.gz', '.bz2', '.xz', '.zst', '.vpkg'  # Added .zst and .vpkg for Zstandard
    }

    # Special archive types that need specific handling
    SPECIAL_ARCHIVES = {
        '.apk': 'android',
        '.ipa': 'ios',
        '.jar': 'java',
        '.war': 'java_web',
        '.egg': 'python',
        '.whl': 'python_wheel',
        '.nupkg': 'nuget',
        '.crx': 'chrome_extension'
    }

    def can_handle(self, file_path: Path) -> bool:
        """Check if file is an archive or NSIS installer"""
        suffix = file_path.suffix.lower()

        # Check standard archive extensions
        if suffix in self.ARCHIVE_EXTENSIONS:
            # Some formats have special requirements
            if suffix in ['.msi', '.pkg', '.dmg']:
                # MSI, PKG, and DMG files require 7-Zip
                return self._seven_zip_path is not None
            if suffix == '.rpm':
                # RPM requires rpm2cpio or 7-Zip
                import subprocess
                try:
                    result = subprocess.run(['which', 'rpm2cpio'], capture_output=True)
                    if result.returncode == 0:
                        return True
                except:
                    pass
                return self._seven_zip_path is not None
            if suffix == '.deb':
                # DEB can be handled with ar command or python-debian
                import subprocess
                try:
                    result = subprocess.run(['which', 'ar'], capture_output=True)
                    if result.returncode == 0:
                        return True
                except:
                    pass
                try:
                    import debian
                    return True
                except ImportError:
                    pass
                return self._seven_zip_path is not None
            # Other formats can be handled with Python libraries
            return True

        # Check for NSIS installers (Windows .exe files)
        if suffix == '.exe' and self._seven_zip_path:
            # Try to detect if it's an NSIS installer
            return self._is_nsis_installer(file_path)

        return False

    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from archive"""
        logger.debug(f"Extracting features from archive: {file_path}")

        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type=self._get_archive_type(file_path)
        )
        features.metadata = {}

        # UPMEX Integration: Extract package metadata if supported
        package_type = self.upmex.is_supported_package(file_path)
        if package_type:
            logger.debug(f"Detected supported package type: {package_type}")
            upmex_result = self.upmex.extract_metadata(file_path, package_type)
            if "error" not in upmex_result:
                features.metadata['package_metadata'] = upmex_result
                logger.info(f"Extracted {package_type} package metadata: {upmex_result.get('metadata', {}).get('name', 'Unknown')}")
            else:
                logger.debug(f"UPMEX extraction failed: {upmex_result['error']}")

        # Extract archive to temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            try:
                # Extract archive
                extracted_files = self._extract_archive(file_path, temp_path)

                if not extracted_files:
                    logger.warning(f"No files extracted from {file_path}")
                    return features

                # Special handling for known archive types
                archive_type = self.SPECIAL_ARCHIVES.get(file_path.suffix.lower())
                if archive_type:
                    self._handle_special_archive(
                        archive_type, temp_path, features
                    )

                # Process extracted files
                # Import here to avoid circular dependency
                from .factory import ExtractorFactory
                factory = ExtractorFactory()

                # Remove self from extractors to avoid infinite recursion
                factory.extractors = [e for e in factory.extractors
                                    if not isinstance(e, ArchiveExtractor)]

                # For single file archives, use all features; for multi-file, apply limits
                is_single_file = len(extracted_files) == 1

                # Track which files we process for verbose output
                processed_files = []

                # INTELLIGENT PRIORITIZATION: Detect archive type based on content
                # Priority 1: Native libraries and executables (highest value for detection)
                # Priority 2: Bytecode and intermediate files
                # Priority 3: Source code files
                # Priority 4: Configuration and data files

                priority_extensions = {
                    1: ['.so', '.dll', '.dylib', '.a', '.lib', '.exe', '.elf', '.ko', '.o'],  # Native binaries
                    2: ['.dex', '.class', '.jar', '.pyc', '.pyo', '.beam', '.wasm'],  # Bytecode
                    3: ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.m', '.mm', '.swift'],  # Source code
                    4: ['.js', '.py', '.java', '.kt', '.ts', '.go', '.rs', '.rb'],  # High-level source
                    5: ['.json', '.xml', '.yaml', '.yml', '.conf', '.ini', '.properties']  # Config files
                }

                # Check if archive contains native libraries or mobile app content
                has_native_libs = any(f.suffix.lower() in priority_extensions[1] for f in extracted_files[:100])
                has_mobile_content = any(f.suffix.lower() in ['.dex', '.swift', '.m', '.mm'] for f in extracted_files[:100])
                has_embedded_content = any('lib/' in str(f) or 'bin/' in str(f) or 'usr/' in str(f) for f in extracted_files[:100])

                # Determine if this is a binary-rich archive (embedded, mobile, or contains many native libs)
                is_binary_rich = has_native_libs or has_mobile_content or has_embedded_content or \
                                 features.file_type == 'android' or features.file_type == 'ios'

                if is_binary_rich:
                    # Smart prioritization for binary-rich archives
                    prioritized_files = {1: [], 2: [], 3: [], 4: [], 5: [], 6: []}

                    for f in extracted_files:
                        suffix = f.suffix.lower()
                        placed = False
                        for priority, extensions in priority_extensions.items():
                            if suffix in extensions:
                                prioritized_files[priority].append(f)
                                placed = True
                                break
                        if not placed:
                            prioritized_files[6].append(f)  # Other files

                    # Combine prioritized files, sorted within each priority level
                    extracted_files = []
                    remaining_slots = 10000  # Maximum files to process

                    for priority in sorted(prioritized_files.keys()):
                        files = sorted(prioritized_files[priority])
                        if priority <= 2:  # Native and bytecode - take all up to limit
                            extracted_files.extend(files[:remaining_slots])
                            remaining_slots -= len(files[:remaining_slots])
                        else:  # Other files - take subset
                            subset_size = min(100, remaining_slots // 2)  # Take fewer of lower priority
                            extracted_files.extend(files[:subset_size])
                            remaining_slots -= len(files[:subset_size])

                        if remaining_slots <= 0:
                            break

                    file_limit = len(extracted_files)
                else:
                    # Standard processing for non-binary archives
                    file_limit = 10000 if not is_single_file else 1

                # Keep track of nested archives to process recursively
                nested_archives = []

                for extracted_file in extracted_files[:file_limit]:  # Limit files for large archives
                    # No need to check is_file() again since we already filtered
                    try:
                        # Check if this is a nested archive
                        if self.can_handle(extracted_file):
                            # Queue it for recursive extraction
                            nested_archives.append(extracted_file)
                            logger.debug(f"Found nested archive: {extracted_file}")
                            continue

                        # Extract features from each file
                        file_features = factory.extract(extracted_file)

                        # Track relative path within archive
                        relative_path = str(extracted_file.relative_to(temp_path))
                        processed_files.append(relative_path)

                        # Merge features - use all features for single file archives
                        if is_single_file:
                            features.strings.extend(file_features.strings)
                            features.functions.extend(file_features.functions)
                            features.constants.extend(file_features.constants)
                            features.imports.extend(file_features.imports)
                            features.symbols.extend(file_features.symbols)
                        else:
                            # Apply limits only for multi-file archives - ULTRA MASSIVE
                            features.strings.extend(file_features.strings[:50000])  # Was 5000
                            features.functions.extend(file_features.functions[:10000])  # Was 1000
                            features.constants.extend(file_features.constants[:10000])  # Was 1000
                            features.imports.extend(file_features.imports[:5000])  # Was 500
                            features.symbols.extend(file_features.symbols[:10000])  # Was 1000

                    except Exception as e:
                        logger.debug(f"Error processing {extracted_file}: {e}")

                # Process nested archives recursively (with depth limit)
                max_recursion_depth = 5
                current_depth = 0

                while nested_archives and current_depth < max_recursion_depth:
                    current_depth += 1
                    next_level_archives = []

                    for nested_archive in nested_archives:
                        logger.info(f"Extracting nested archive (depth {current_depth}): {nested_archive.name}")
                        try:
                            # Create a subdirectory for nested archive extraction
                            nested_temp = temp_path / f"nested_{current_depth}_{nested_archive.stem}"
                            nested_temp.mkdir(exist_ok=True)

                            # Extract nested archive
                            nested_files = self._extract_archive(nested_archive, nested_temp)

                            for nested_file in nested_files[:1000]:  # Limit nested files
                                if not nested_file.is_file():
                                    continue

                                # Check if this is another nested archive
                                if self.can_handle(nested_file):
                                    next_level_archives.append(nested_file)
                                    continue

                                try:
                                    # Extract features from nested file
                                    nested_features = factory.extract(nested_file)

                                    # Track nested path
                                    nested_relative = f"[nested:{current_depth}]{nested_archive.name}/{nested_file.name}"
                                    processed_files.append(nested_relative)

                                    # Merge features with limits for nested content
                                    features.strings.extend(nested_features.strings[:10000])
                                    features.functions.extend(nested_features.functions[:2000])
                                    features.constants.extend(nested_features.constants[:2000])
                                    features.imports.extend(nested_features.imports[:1000])
                                    features.symbols.extend(nested_features.symbols[:2000])

                                except Exception as e:
                                    logger.debug(f"Error processing nested file {nested_file}: {e}")

                        except Exception as e:
                            logger.warning(f"Failed to extract nested archive {nested_archive}: {e}")

                    # Move to next level of nesting
                    nested_archives = next_level_archives

                # Deduplicate and limit (be generous for single-file archives)
                if is_single_file:
                    # For single file archives, use the same limits as the original extractor
                    # Use dict.fromkeys() for order-preserving deduplication
                    features.strings = list(dict.fromkeys(features.strings))[:self.max_strings]
                    features.functions = list(dict.fromkeys(features.functions))
                    features.constants = list(dict.fromkeys(features.constants))
                    features.imports = list(dict.fromkeys(features.imports))
                    features.symbols = list(dict.fromkeys(features.symbols))
                else:
                    # For multi-file archives, apply limits based on detected content type
                    if is_binary_rich:
                        # Binary-rich archives (mobile apps, embedded systems, firmware, etc.) - very generous limits
                        features.strings = list(dict.fromkeys(features.strings))[:100000]  # 100k strings
                        features.functions = list(dict.fromkeys(features.functions))[:20000]
                        features.constants = list(dict.fromkeys(features.constants))[:10000]
                        features.imports = list(dict.fromkeys(features.imports))[:5000]
                        features.symbols = list(dict.fromkeys(features.symbols))[:20000]
                    else:
                        # Standard archives (source code, documents, etc.) - moderate limits
                        features.strings = list(dict.fromkeys(features.strings))[:self.max_strings]
                        features.functions = list(dict.fromkeys(features.functions))[:5000]
                        features.constants = list(dict.fromkeys(features.constants))[:2000]
                        features.imports = list(dict.fromkeys(features.imports))[:1000]
                        features.symbols = list(dict.fromkeys(features.symbols))[:5000]

                # Add base metadata
                if not hasattr(features, 'metadata') or features.metadata is None:
                    features.metadata = {}

                features.metadata.update({
                    'archive_type': archive_type or 'generic',
                    'file_count': len(extracted_files),
                    'processed_files': processed_files,
                    'processed_count': len(processed_files),
                    'size': file_path.stat().st_size
                })
                
                # Use OSLiLi to detect licenses in extracted files
                if self.oslili.is_available:
                    try:
                        logger.debug(f"Running OSLiLi license detection on extracted files from {file_path}")
                        license_results = self.oslili.detect_licenses_in_path(str(temp_path))
                        
                        if license_results:
                            # Store license information in metadata
                            features.metadata['licenses'] = []
                            features.metadata['license_spdx_ids'] = []
                            
                            for license_result in license_results:
                                license_info = {
                                    'spdx_id': license_result.spdx_id,
                                    'name': license_result.name,
                                    'confidence': license_result.confidence,
                                    'detection_method': license_result.detection_method,
                                    'source_file': license_result.source_file,
                                    'category': license_result.category
                                }
                                features.metadata['licenses'].append(license_info)
                                
                                # Add SPDX ID to list if not already there
                                if license_result.spdx_id not in features.metadata['license_spdx_ids']:
                                    features.metadata['license_spdx_ids'].append(license_result.spdx_id)
                            
                            logger.info(f"Detected {len(license_results)} licenses in {file_path}: {features.metadata['license_spdx_ids']}")
                    except Exception as e:
                        logger.warning(f"OSLiLi license detection failed for {file_path}: {e}")

            except Exception as e:
                logger.error(f"Error extracting archive {file_path}: {e}")

        return features

    def _extract_archive(self, archive_path: Path, extract_to: Path) -> List[Path]:
        """Extract archive and return list of extracted files"""
        extracted_files = []
        suffix = archive_path.suffix.lower()

        try:
            # Check for Zstandard compressed files first (.zst, .tar.zst, .vpkg)
            if suffix in ['.zst', '.vpkg'] or str(archive_path).lower().endswith('.tar.zst'):
                extracted_files = self._extract_zstd_archive(archive_path, extract_to)

            # 7z archives
            elif suffix == '.7z':
                extracted_files = self._extract_7z_archive(archive_path, extract_to)

            # RAR archives
            elif suffix == '.rar':
                extracted_files = self._extract_rar_archive(archive_path, extract_to)

            # DEB packages
            elif suffix == '.deb':
                extracted_files = self._extract_deb_archive(archive_path, extract_to)

            # RPM packages
            elif suffix == '.rpm':
                extracted_files = self._extract_rpm_archive(archive_path, extract_to)

            elif zipfile.is_zipfile(archive_path):
                # Handle ZIP-based archives
                with zipfile.ZipFile(archive_path, 'r') as zip_file:
                    zip_file.extractall(extract_to)
                    extracted_files = sorted([f for f in extract_to.rglob('*') if f.is_file()])

            elif tarfile.is_tarfile(archive_path):
                # Handle TAR archives (including .tar.gz, .tar.bz2, .tar.xz)
                with tarfile.open(archive_path, 'r:*') as tar_file:
                    tar_file.extractall(extract_to)
                    extracted_files = sorted([f for f in extract_to.rglob('*') if f.is_file()])

            elif self._seven_zip_path and suffix in ['.exe', '.msi', '.pkg', '.dmg']:
                # Try to extract NSIS installer, MSI, PKG, or DMG with 7-Zip
                extracted_files = self._extract_with_seven_zip(archive_path, extract_to)
                if not extracted_files:
                    logger.warning(f"7-Zip extraction failed for: {archive_path}")
            else:
                logger.warning(f"Unsupported archive format: {archive_path}")

        except Exception as e:
            logger.error(f"Failed to extract {archive_path}: {e}")

        return extracted_files

    def _get_archive_type(self, file_path: Path) -> str:
        """Determine archive type"""
        suffix = file_path.suffix.lower()

        # Check for installer types
        if suffix == '.msi':
            return 'msi_installer'
        if suffix == '.pkg':
            return 'pkg_installer'
        if suffix == '.dmg':
            return 'dmg_image'

        # Check for NSIS installer
        if suffix == '.exe' and self._is_nsis_installer(file_path):
            return 'nsis_installer'

        # Check for compound extensions like .tar.gz
        full_suffix = ''.join(file_path.suffixes).lower()

        if suffix in self.SPECIAL_ARCHIVES:
            return self.SPECIAL_ARCHIVES[suffix]
        if suffix in ['.zip', '.jar', '.apk', '.ipa']:
            return 'zip'
        if '.tar' in full_suffix:
            return 'tar'
        return 'archive'

    def _handle_special_archive(
        self,
        archive_type: str,
        extract_path: Path,
        features: ExtractedFeatures
    ):
        """Handle special archive types"""

        if archive_type == 'android':
            # APK specific handling
            self._handle_apk(extract_path, features)

        elif archive_type == 'ios':
            # IPA specific handling
            self._handle_ipa(extract_path, features)

        elif archive_type in ['java', 'java_web']:
            # JAR/WAR specific handling
            self._handle_java_archive(extract_path, features)

        elif archive_type in ['python', 'python_wheel']:
            # Python package handling
            self._handle_python_archive(extract_path, features)

    def _handle_apk(self, extract_path: Path, features: ExtractedFeatures):
        """Handle Android APK files"""
        # Look for AndroidManifest.xml
        manifest = extract_path / "AndroidManifest.xml"
        if manifest.exists():
            features.metadata['has_android_manifest'] = True

        # Look for classes.dex
        dex_files = sorted(list(extract_path.glob("classes*.dex")))
        if dex_files:
            features.metadata['dex_files'] = len(dex_files)
            # Extract strings from DEX files using simple strings command
            for dex_file in dex_files[:3]:  # Process first 3 DEX files
                try:
                    import subprocess
                    result = subprocess.run(
                        ['strings', str(dex_file)],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        dex_strings = result.stdout.split('\n')
                        # Add meaningful strings from DEX
                        for s in dex_strings[:5000]:  # Limit per DEX file
                            if len(s) >= 5 and not s.startswith('/'):
                                features.strings.append(s)
                except Exception:
                    pass  # Strings command might not be available

        # Look for lib directory with native libraries
        lib_dir = extract_path / "lib"
        if lib_dir.exists():
            native_libs = []
            for arch_dir in lib_dir.iterdir():
                if arch_dir.is_dir():
                    for lib in arch_dir.glob("*.so"):
                        native_libs.append(lib.name)
                        # CRITICAL FIX: Don't just add the name, let the main loop process the .so file!
                        # The main extraction loop will handle these files properly
            features.metadata['native_libs'] = native_libs[:20]

        # Package name from directory structure
        java_files = list(extract_path.rglob("*.class"))
        packages = set()
        for java_file in java_files[:100]:
            parts = java_file.relative_to(extract_path).parts
            if len(parts) > 1:
                package = '.'.join(parts[:-1])
                packages.add(package)

        if packages:
            features.metadata['java_packages'] = list(packages)[:10]

    def _handle_ipa(self, extract_path: Path, features: ExtractedFeatures):
        """Handle iOS IPA files"""
        # Look for Info.plist
        info_plists = sorted(list(extract_path.rglob("Info.plist")))
        if info_plists:
            features.metadata['has_info_plist'] = True

        # Look for executable in .app directory
        app_dirs = sorted(list(extract_path.glob("Payload/*.app")))
        if app_dirs:
            app_dir = app_dirs[0]
            # Find main executable
            for file in app_dir.iterdir():
                if file.is_file() and file.stat().st_mode & 0o111:  # Executable
                    features.metadata['main_executable'] = file.name
                    break

        # Look for frameworks
        frameworks = []
        framework_dirs = sorted(list(extract_path.rglob("*.framework")))
        for fw in framework_dirs[:20]:
            frameworks.append(fw.name)
            features.imports.append(fw.name)

        if frameworks:
            features.metadata['frameworks'] = frameworks

    def _handle_java_archive(self, extract_path: Path, features: ExtractedFeatures):
        """Handle JAR/WAR files"""
        # Look for META-INF/MANIFEST.MF
        manifest = extract_path / "META-INF" / "MANIFEST.MF"
        if manifest.exists():
            try:
                content = manifest.read_text(errors='ignore')
                # Extract Main-Class
                for line in content.splitlines():
                    if line.startswith("Main-Class:"):
                        main_class = line.split(":", 1)[1].strip()
                        features.metadata['main_class'] = main_class
                        features.symbols.append(main_class)
            except Exception:
                pass

        # Look for web.xml (for WAR files)
        web_xml = extract_path / "WEB-INF" / "web.xml"
        if web_xml.exists():
            features.metadata['is_webapp'] = True

        # Extract package structure
        class_files = sorted(list(extract_path.rglob("*.class")))
        packages = set()
        for class_file in class_files[:100]:
            parts = class_file.relative_to(extract_path).parts
            if len(parts) > 1:
                package = '.'.join(parts[:-1])
                packages.add(package)

        if packages:
            features.metadata['packages'] = list(packages)[:20]

    def _handle_python_archive(self, extract_path: Path, features: ExtractedFeatures):
        """Handle Python egg/wheel files"""
        # Look for metadata
        metadata_files = list(extract_path.rglob("METADATA")) + \
                        list(extract_path.rglob("PKG-INFO"))

        if metadata_files:
            try:
                content = metadata_files[0].read_text(errors='ignore')
                for line in content.splitlines():
                    if line.startswith("Name:"):
                        features.metadata['package_name'] = line.split(":", 1)[1].strip()
                    elif line.startswith("Version:"):
                        features.metadata['version'] = line.split(":", 1)[1].strip()
            except Exception:
                pass

        # Look for top-level packages
        py_files = list(extract_path.glob("*.py"))
        init_files = list(extract_path.glob("*/__init__.py"))

        packages = set()
        for init_file in init_files[:20]:
            package = init_file.parent.name
            packages.add(package)
            features.symbols.append(package)

        if packages:
            features.metadata['python_packages'] = list(packages)

    def _find_seven_zip(self) -> Optional[str]:
        """Find 7-Zip executable if available"""

        # Common 7-Zip command names
        for cmd in ['7z', '7za', '7zr']:
            path = shutil.which(cmd)
            if path:
                return path

        return None

    def _is_nsis_installer(self, file_path: Path) -> bool:
        """Check if file is an NSIS installer using 7-Zip"""
        if not self._seven_zip_path:
            return False

        try:
            # Use 7z to check if it's an NSIS installer
            result = subprocess.run(
                [self._seven_zip_path, 'l', str(file_path)],
                capture_output=True,
                text=True,
                timeout=5
            )

            # Check for NSIS indicators in output
            if result.returncode == 0:
                output = result.stdout.lower()
                # NSIS installers often have these characteristics
                if 'nsis' in output or 'nullsoft' in output:
                    return True
                # Also check if it's a PE file that 7z can extract
                if 'type = pe' in output or 'type = nsis' in output:
                    # Try to list contents - if successful, it's likely extractable
                    return '$pluginsdir' in output.lower() or '.exe' in output

        except Exception as e:
            logger.debug(f"Error checking NSIS installer: {e}")

        return False

    def _extract_zstd_archive(self, archive_path: Path, extract_to: Path) -> List[Path]:
        """Extract Zstandard compressed archive"""
        import io
        import subprocess

        import zstandard as zstd

        try:
            # First try with Python zstandard library
            compressed_data = archive_path.read_bytes()
            decompressor = zstd.ZstdDecompressor()

            try:
                decompressed_data = decompressor.decompress(compressed_data)
            except zstd.ZstdError as e:
                # If Python library fails, try system zstd command as fallback
                logger.debug(f"Python zstandard failed ({e}), trying system zstd command")

                # Check if zstd command is available
                try:
                    result = subprocess.run(['which', 'zstd'], capture_output=True, text=True)
                    if result.returncode != 0:
                        logger.error("System zstd command not found")
                        return []

                    # Use system zstd to decompress
                    temp_output = extract_to / 'decompressed.tmp'
                    result = subprocess.run(
                        ['zstd', '-d', str(archive_path), '-o', str(temp_output), '-f'],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if result.returncode != 0:
                        logger.error(f"System zstd decompression failed: {result.stderr}")
                        return []

                    # Read decompressed data
                    decompressed_data = temp_output.read_bytes()
                    temp_output.unlink()  # Clean up temp file

                except Exception as e:
                    logger.error(f"Failed to use system zstd: {e}")
                    return []

            # Check if it's a tar.zst or vpkg (which are often tar archives)
            if str(archive_path).lower().endswith(('.tar.zst', '.vpkg')):
                # Extract tar from decompressed data
                tar_buffer = io.BytesIO(decompressed_data)
                with tarfile.open(fileobj=tar_buffer, mode='r') as tar_file:
                    tar_file.extractall(extract_to)
                    extracted_files = sorted([f for f in extract_to.rglob('*') if f.is_file()])
                    logger.info(f"Extracted {len(extracted_files)} files from {archive_path.name}")
                    return extracted_files
            else:
                # Plain .zst file - save decompressed content
                output_name = archive_path.stem  # Remove .zst extension
                output_path = extract_to / output_name
                output_path.write_bytes(decompressed_data)
                logger.info(f"Decompressed {archive_path.name} to {output_name}")
                return [output_path]

        except Exception as e:
            logger.error(f"Failed to extract Zstandard archive {archive_path}: {e}")
            return []

    def _extract_with_seven_zip(self, archive_path: Path, extract_to: Path) -> List[Path]:
        """Extract archive using 7-Zip"""
        if not self._seven_zip_path:
            return []

        try:
            # Extract with 7-Zip
            result = subprocess.run(
                [self._seven_zip_path, 'x', str(archive_path), f'-o{extract_to}', '-y'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Get list of extracted files
                extracted_files = sorted([f for f in extract_to.rglob('*') if f.is_file()])
                logger.info(f"7-Zip extracted {len(extracted_files)} files from {archive_path.name}")
                return extracted_files
            logger.warning(f"7-Zip extraction failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error(f"7-Zip extraction timed out for {archive_path}")
        except Exception as e:
            logger.error(f"7-Zip extraction error: {e}")

        return []

    def _extract_7z_archive(self, archive_path: Path, extract_to: Path) -> List[Path]:
        """Extract 7z archive using py7zr"""
        try:
            import py7zr
            with py7zr.SevenZipFile(archive_path, mode='r') as z:
                z.extractall(path=extract_to)
            extracted_files = sorted([f for f in extract_to.rglob('*') if f.is_file()])
            logger.info(f"Extracted {len(extracted_files)} files from 7z archive")
            return extracted_files
        except ImportError:
            logger.warning("py7zr not installed, trying 7-Zip command")
            if self._seven_zip_path:
                return self._extract_with_seven_zip(archive_path, extract_to)
        except Exception as e:
            logger.error(f"Failed to extract 7z archive: {e}")
        return []

    def _extract_rar_archive(self, archive_path: Path, extract_to: Path) -> List[Path]:
        """Extract RAR archive using rarfile"""
        try:
            import rarfile
            with rarfile.RarFile(archive_path) as rf:
                rf.extractall(extract_to)
            extracted_files = sorted([f for f in extract_to.rglob('*') if f.is_file()])
            logger.info(f"Extracted {len(extracted_files)} files from RAR archive")
            return extracted_files
        except ImportError:
            logger.warning("rarfile not installed, trying 7-Zip command")
            if self._seven_zip_path:
                return self._extract_with_seven_zip(archive_path, extract_to)
        except Exception as e:
            logger.error(f"Failed to extract RAR archive: {e}")
        return []

    def _extract_deb_archive(self, archive_path: Path, extract_to: Path) -> List[Path]:
        """Extract DEB package"""
        try:
            # DEB files are ar archives containing tar.gz files
            # First try with python-debian if available
            try:
                from debian import debfile
                deb = debfile.DebFile(str(archive_path))
                # Extract data.tar.* which contains the actual files
                # DebFile.data is a DebData object with a .tgz() method that returns a TarFile
                data_tar = deb.data.tgz()
                if data_tar:
                    data_tar.extractall(extract_to)
                # Also extract control information
                control_tar = deb.control.tgz()
                if control_tar:
                    control_dir = extract_to / 'DEBIAN'
                    control_dir.mkdir(exist_ok=True)
                    control_tar.extractall(control_dir)
            except (ImportError, AttributeError):
                # Fallback: DEB is an ar archive, extract with ar command
                import subprocess
                # Extract with ar
                subprocess.run(['ar', 'x', str(archive_path)], cwd=extract_to, check=True)
                # Extract data.tar.*
                for data_file in extract_to.glob('data.tar*'):
                    with tarfile.open(data_file, 'r:*') as tar:
                        tar.extractall(extract_to)
                    data_file.unlink()  # Clean up tar file
                # Extract control.tar.*
                for control_file in extract_to.glob('control.tar*'):
                    control_dir = extract_to / 'DEBIAN'
                    control_dir.mkdir(exist_ok=True)
                    with tarfile.open(control_file, 'r:*') as tar:
                        tar.extractall(control_dir)
                    control_file.unlink()  # Clean up tar file

            extracted_files = sorted([f for f in extract_to.rglob('*') if f.is_file()])
            logger.info(f"Extracted {len(extracted_files)} files from DEB package")
            return extracted_files
        except Exception as e:
            logger.error(f"Failed to extract DEB package: {e}")
        return []

    def _extract_rpm_archive(self, archive_path: Path, extract_to: Path) -> List[Path]:
        """Extract RPM package"""
        try:
            # RPM extraction using rpm2cpio and cpio
            import subprocess

            # Convert RPM to CPIO and extract
            rpm2cpio = subprocess.Popen(['rpm2cpio', str(archive_path)], stdout=subprocess.PIPE)
            cpio = subprocess.Popen(['cpio', '-idmv'], stdin=rpm2cpio.stdout, cwd=extract_to,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            rpm2cpio.stdout.close()
            output, error = cpio.communicate()

            if cpio.returncode != 0:
                logger.error(f"RPM extraction failed: {error.decode()}")
                # Try with 7-Zip as fallback
                if self._seven_zip_path:
                    return self._extract_with_seven_zip(archive_path, extract_to)
                return []

            extracted_files = sorted([f for f in extract_to.rglob('*') if f.is_file()])
            logger.info(f"Extracted {len(extracted_files)} files from RPM package")
            return extracted_files
        except FileNotFoundError:
            logger.warning("rpm2cpio not found, trying 7-Zip")
            if self._seven_zip_path:
                return self._extract_with_seven_zip(archive_path, extract_to)
        except Exception as e:
            logger.error(f"Failed to extract RPM package: {e}")
        return []
