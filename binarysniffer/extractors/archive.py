"""
Archive file extractor for ZIP, JAR, APK, IPA, TAR, etc.
"""

import zipfile
import tarfile
import tempfile
import shutil
import logging
from pathlib import Path
from typing import List, Set, Optional

from .base import BaseExtractor, ExtractedFeatures


logger = logging.getLogger(__name__)


class ArchiveExtractor(BaseExtractor):
    """Extract features from archive files"""
    
    # Archive extensions
    ARCHIVE_EXTENSIONS = {
        # ZIP-based
        '.zip', '.jar', '.war', '.ear', '.apk', '.ipa', '.xpi',
        '.egg', '.whl', '.nupkg', '.vsix', '.crx',
        # TAR-based
        '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz',
        # Other
        '.gz', '.bz2', '.xz'
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
        """Check if file is an archive"""
        return file_path.suffix.lower() in self.ARCHIVE_EXTENSIONS
    
    def extract(self, file_path: Path) -> ExtractedFeatures:
        """Extract features from archive"""
        logger.debug(f"Extracting features from archive: {file_path}")
        
        features = ExtractedFeatures(
            file_path=str(file_path),
            file_type=self._get_archive_type(file_path)
        )
        features.metadata = {}
        
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
                
                # CRITICAL: For APKs, prioritize native libraries and DEX files
                if features.file_type == 'android':
                    # Sort files to prioritize .so and .dex files
                    prioritized_files = []
                    other_files = []
                    for f in extracted_files:
                        if f.suffix in ['.so', '.dex']:
                            prioritized_files.append(f)
                        else:
                            other_files.append(f)
                    # Process native libraries and DEX files first, then others
                    extracted_files = prioritized_files + other_files[:100]  # Limit other files
                    file_limit = len(extracted_files)
                else:
                    file_limit = 10000 if not is_single_file else 1
                
                for extracted_file in extracted_files[:file_limit]:  # Limit files for large archives
                    if extracted_file.is_file():
                        try:
                            # Extract features from each file
                            file_features = factory.extract(extracted_file)
                            
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
                
                # Deduplicate and limit (be generous for single-file archives)
                if is_single_file:
                    # For single file archives, use the same limits as the original extractor
                    features.strings = list(set(features.strings))[:self.max_strings]
                    features.functions = list(set(features.functions))
                    features.constants = list(set(features.constants))
                    features.imports = list(set(features.imports))
                    features.symbols = list(set(features.symbols))
                else:
                    # For multi-file archives, apply limits based on type
                    if features.file_type == 'android':
                        # For APKs, be very generous with limits
                        features.strings = list(set(features.strings))[:100000]  # 100k strings for APKs
                        features.functions = list(set(features.functions))[:20000]
                        features.constants = list(set(features.constants))[:10000]
                        features.imports = list(set(features.imports))[:5000]
                        features.symbols = list(set(features.symbols))[:20000]
                    else:
                        # Standard limits for other archives
                        features.strings = list(set(features.strings))[:self.max_strings]
                        features.functions = list(set(features.functions))[:5000]
                        features.constants = list(set(features.constants))[:2000]
                        features.imports = list(set(features.imports))[:1000]
                        features.symbols = list(set(features.symbols))[:5000]
                
                # Add base metadata
                if not hasattr(features, 'metadata') or features.metadata is None:
                    features.metadata = {}
                    
                features.metadata.update({
                    'archive_type': archive_type or 'generic',
                    'file_count': len(extracted_files),
                    'size': file_path.stat().st_size
                })
                
            except Exception as e:
                logger.error(f"Error extracting archive {file_path}: {e}")
        
        return features
    
    def _extract_archive(self, archive_path: Path, extract_to: Path) -> List[Path]:
        """Extract archive and return list of extracted files"""
        extracted_files = []
        
        try:
            if zipfile.is_zipfile(archive_path):
                # Handle ZIP-based archives
                with zipfile.ZipFile(archive_path, 'r') as zip_file:
                    zip_file.extractall(extract_to)
                    extracted_files = list(extract_to.rglob('*'))
                    
            elif tarfile.is_tarfile(archive_path):
                # Handle TAR archives
                with tarfile.open(archive_path, 'r:*') as tar_file:
                    tar_file.extractall(extract_to)
                    extracted_files = list(extract_to.rglob('*'))
                    
            else:
                logger.warning(f"Unsupported archive format: {archive_path}")
                
        except Exception as e:
            logger.error(f"Failed to extract {archive_path}: {e}")
        
        return extracted_files
    
    def _get_archive_type(self, file_path: Path) -> str:
        """Determine archive type"""
        suffix = file_path.suffix.lower()
        # Check for compound extensions like .tar.gz
        full_suffix = ''.join(file_path.suffixes).lower()
        
        if suffix in self.SPECIAL_ARCHIVES:
            return self.SPECIAL_ARCHIVES[suffix]
        elif suffix in ['.zip', '.jar', '.apk', '.ipa']:
            return 'zip'
        elif '.tar' in full_suffix:
            return 'tar'
        else:
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
        dex_files = list(extract_path.glob("classes*.dex"))
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
        info_plists = list(extract_path.rglob("Info.plist"))
        if info_plists:
            features.metadata['has_info_plist'] = True
        
        # Look for executable in .app directory
        app_dirs = list(extract_path.glob("Payload/*.app"))
        if app_dirs:
            app_dir = app_dirs[0]
            # Find main executable
            for file in app_dir.iterdir():
                if file.is_file() and file.stat().st_mode & 0o111:  # Executable
                    features.metadata['main_executable'] = file.name
                    break
        
        # Look for frameworks
        frameworks = []
        framework_dirs = list(extract_path.rglob("*.framework"))
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
        class_files = list(extract_path.rglob("*.class"))
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