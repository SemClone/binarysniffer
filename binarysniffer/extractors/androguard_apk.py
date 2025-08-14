"""
Androguard-based extractor for comprehensive Android APK analysis.
"""

import hashlib
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from .base import BaseExtractor, ExtractedFeatures

if TYPE_CHECKING:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat

try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False

logger = logging.getLogger(__name__)


class AndroguardExtractor(BaseExtractor):
    """
    Enhanced Android APK extractor using Androguard for deep analysis.
    
    This extractor provides:
    - Java/Kotlin class and method extraction
    - Native library analysis
    - Permission and certificate extraction
    - SDK and framework detection
    - Android manifest parsing
    """

    def __init__(self):
        """Initialize the Androguard extractor."""
        super().__init__()

    def can_handle(self, file_path: Path) -> bool:
        """Check if this extractor can handle the file."""
        if not ANDROGUARD_AVAILABLE:
            return False

        # Check file extension
        if file_path.suffix.lower() not in ['.apk', '.xapk']:
            return False

        # Verify it's actually an APK (ZIP-based)
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic[:2] == b'PK'  # ZIP magic number
        except Exception:
            return False

    def extract(self, file_path: Path) -> ExtractedFeatures:
        """
        Extract features from APK using Androguard.
        
        Args:
            file_path: Path to the APK file
            
        Returns:
            ExtractedFeatures containing all extracted data
        """
        if not ANDROGUARD_AVAILABLE:
            logger.error("Androguard not available")
            return ExtractedFeatures()

        features = ExtractedFeatures()
        features.file_path = file_path
        features.file_type = "android_apk"

        try:
            # Load APK
            apk = APK(str(file_path))

            # Extract basic metadata
            self._extract_metadata(apk, features)

            # Extract Java/Kotlin components
            self._extract_java_components(apk, features)

            # Extract native libraries
            self._extract_native_libraries(apk, features)

            # Extract permissions and security info
            self._extract_security_info(apk, features)

            # Extract strings (enhanced)
            self._extract_strings_enhanced(apk, features)

            # Identify common SDKs
            self._identify_sdks(apk, features)

            logger.info(f"Extracted {len(features.all_features)} features from {file_path}")

        except Exception as e:
            logger.error(f"Error extracting from APK {file_path}: {e}")

        return features

    def _extract_metadata(self, apk: 'APK', features: ExtractedFeatures):
        """Extract APK metadata."""
        metadata = {}

        try:
            # Basic APK info
            metadata['package_name'] = apk.get_package()
            metadata['app_name'] = apk.get_app_name()
            metadata['version_code'] = apk.get_androidversion_code()
            metadata['version_name'] = apk.get_androidversion_name()

            # SDK versions
            metadata['min_sdk'] = apk.get_min_sdk_version()
            metadata['target_sdk'] = apk.get_target_sdk_version()
            metadata['max_sdk'] = apk.get_max_sdk_version()

            # Certificate info
            certs = apk.get_certificates()
            if certs:
                cert = certs[0]  # Primary certificate
                metadata['cert_subject'] = cert.subject.rfc4514_string()
                metadata['cert_issuer'] = cert.issuer.rfc4514_string()
                metadata['cert_serial'] = str(cert.serial_number)

                # Certificate fingerprint (simplified - just use str representation)
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization
                    cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
                    metadata['cert_sha256'] = hashlib.sha256(cert_der).hexdigest()
                except ImportError:
                    # If cryptography not available, skip fingerprint
                    pass

            # Main activity
            metadata['main_activity'] = apk.get_main_activity()

            features.metadata.update(metadata)

            # Add package name as feature for detection
            if metadata.get('package_name'):
                features.add_feature(metadata['package_name'])

        except Exception as e:
            logger.debug(f"Error extracting metadata: {e}")

    def _extract_java_components(self, apk: 'APK', features: ExtractedFeatures):
        """Extract Java/Kotlin class and method names."""
        try:
            # Get all DEX files
            for dex_name in apk.get_dex_names():
                dex_data = apk.get_file(dex_name)
                if not dex_data:
                    continue

                # Parse DEX
                dex = DalvikVMFormat(dex_data)

                # Extract class names
                for class_def in dex.get_classes():
                    class_name = class_def.get_name()
                    if class_name:
                        # Clean and add class name
                        clean_name = class_name.replace('L', '').replace(';', '').replace('/', '.')
                        features.add_feature(clean_name)

                        # Track package for SDK detection
                        if '.' in clean_name:
                            package = '.'.join(clean_name.split('.')[:3])
                            features.add_feature(package)

                # Extract method names (limit to public/protected)
                for method in dex.get_methods():
                    method_name = method.get_name()
                    if method_name and not method_name.startswith('<'):
                        features.add_feature(method_name)

                # Stop if we have enough features
                if len(features.all_features) > 50000:
                    break

        except Exception as e:
            logger.debug(f"Error extracting Java components: {e}")

    def _extract_native_libraries(self, apk: 'APK', features: ExtractedFeatures):
        """Extract and analyze native libraries."""
        native_libs = []

        try:
            # Get all files in lib/ directory
            for file_path in apk.get_files():
                if file_path.startswith('lib/') and file_path.endswith('.so'):
                    native_libs.append(file_path)

                    # Extract library name as feature
                    lib_name = Path(file_path).name
                    features.add_feature(lib_name)

                    # Common library prefixes for detection
                    if lib_name.startswith('lib'):
                        base_name = lib_name[3:].replace('.so', '')
                        features.add_feature(base_name)

            # Store native library list in metadata
            features.metadata['native_libraries'] = native_libs

            # Extract architecture info
            architectures = set()
            for lib_path in native_libs:
                parts = lib_path.split('/')
                if len(parts) >= 2:
                    arch = parts[1]  # lib/arm64-v8a/libxxx.so
                    architectures.add(arch)

            features.metadata['architectures'] = list(architectures)

        except Exception as e:
            logger.debug(f"Error extracting native libraries: {e}")

    def _extract_security_info(self, apk: 'APK', features: ExtractedFeatures):
        """Extract permissions and security-related information."""
        try:
            # Permissions
            permissions = apk.get_permissions()
            features.metadata['permissions'] = permissions

            # Add permission prefixes as features for detection
            for perm in permissions:
                if '.' in perm:
                    # Extract permission category
                    parts = perm.split('.')
                    if len(parts) > 2:
                        category = '.'.join(parts[:3])
                        features.add_feature(category)

            # Activities
            activities = apk.get_activities()
            features.metadata['activity_count'] = len(activities)

            # Services
            services = apk.get_services()
            features.metadata['service_count'] = len(services)

            # Receivers
            receivers = apk.get_receivers()
            features.metadata['receiver_count'] = len(receivers)

            # Providers
            providers = apk.get_providers()
            features.metadata['provider_count'] = len(providers)

        except Exception as e:
            logger.debug(f"Error extracting security info: {e}")

    def _extract_strings_enhanced(self, apk: 'APK', features: ExtractedFeatures):
        """Extract strings with better filtering."""
        try:
            # Get all strings from resources
            strings = set()

            # From string resources
            string_resources = apk.get_android_resources()
            if string_resources:
                for package in string_resources.packages.values():
                    for locale in package.locales:
                        for string_type in package.locales[locale]['string']:
                            for entry in package.locales[locale]['string'][string_type]:
                                if entry and len(entry) > 4:
                                    strings.add(entry)

            # Add filtered strings as features
            for string in strings:
                if self._is_significant_string(string):
                    features.add_feature(string)

                # Stop if too many
                if len(features.all_features) > 100000:
                    break

        except Exception as e:
            logger.debug(f"Error extracting strings: {e}")

    def _identify_sdks(self, apk: 'APK', features: ExtractedFeatures):
        """Identify common SDKs and frameworks."""
        sdks_detected = []

        # SDK patterns to check
        sdk_patterns = {
            'com.google.firebase': 'Firebase',
            'com.google.android.gms': 'Google Play Services',
            'com.facebook': 'Facebook SDK',
            'com.crashlytics': 'Crashlytics',
            'com.flurry': 'Flurry Analytics',
            'com.appsflyer': 'AppsFlyer',
            'com.amplitude': 'Amplitude',
            'com.mixpanel': 'Mixpanel',
            'com.onesignal': 'OneSignal',
            'com.urbanairship': 'Urban Airship',
            'com.braze': 'Braze',
            'com.mopub': 'MoPub',
            'com.unity3d': 'Unity',
            'com.amazon.device.ads': 'Amazon Ads',
            'com.ironsource': 'IronSource',
            'com.vungle': 'Vungle',
            'com.applovin': 'AppLovin',
            'com.squareup.okhttp': 'OkHttp',
            'com.squareup.retrofit': 'Retrofit',
            'com.squareup.picasso': 'Picasso',
            'com.bumptech.glide': 'Glide',
            'io.reactivex': 'RxJava',
            'androidx': 'AndroidX',
            'kotlin': 'Kotlin',
            'org.tensorflow': 'TensorFlow',
            'com.google.mlkit': 'ML Kit',
        }

        # Check features for SDK patterns
        for feature in features.all_features:
            for pattern, sdk_name in sdk_patterns.items():
                if pattern in feature and sdk_name not in sdks_detected:
                    sdks_detected.append(sdk_name)
                    features.add_feature(f"SDK:{sdk_name}")

        features.metadata['detected_sdks'] = sdks_detected

    def _is_significant_string(self, string: str) -> bool:
        """Check if a string is significant for detection."""
        # Skip very short strings
        if len(string) < 5:
            return False

        # Skip numeric strings
        if string.replace('.', '').replace('-', '').isdigit():
            return False

        # Skip single words that are too common
        common_words = {'true', 'false', 'null', 'none', 'error', 'warning',
                       'info', 'debug', 'success', 'failed', 'unknown'}
        if string.lower() in common_words:
            return False

        # Keep URLs, package names, file paths
        if any(pattern in string for pattern in ['://', 'com.', 'org.', '/', '\\']):
            return True

        # Keep if it looks like a class or method name
        if '.' in string or '::' in string or string[0].isupper():
            return True

        return len(string) > 10  # Keep longer strings
