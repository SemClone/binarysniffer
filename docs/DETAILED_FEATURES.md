# BinarySniffer - Detailed Features

This document contains comprehensive information about all BinarySniffer features and capabilities.

## Core Analysis Features

### Fuzzy Matching
- Detect modified, recompiled, or patched OSS components using TLSH
- Deterministic results across multiple runs
- Fast local analysis with SQLite-based signature storage
- MinHash LSH for similarity detection
- Trigram indexing for substring matching
- Smart compression with ZSTD (~90% size reduction)
- Low memory footprint (<100MB memory usage)

## SBOM Export Support

- **CycloneDX Format**: Industry-standard SBOM export for security and compliance toolchains
- **File Path Tracking**: Evidence includes file paths for component location tracking
- **Feature Extraction**: Optional feature dump for signature recreation
- **Confidence Scores**: All detections include confidence levels in SBOM
- **Multi-file Support**: Aggregate SBOM for entire projects

## Package Inventory Extraction

- **Comprehensive File Enumeration**: Extract complete file listings from archives
- **Rich Metadata**: MIME types, compression ratios, file sizes, timestamps
- **Hash Calculation**: MD5, SHA1, SHA256 for integrity verification
- **Fuzzy Hashing**: TLSH and ssdeep for similarity analysis
- **Component Detection**: Run OSS detection on individual files within packages
- **Multiple Export Formats**: JSON, CSV, tree visualization, summary reports

## Binary Analysis Capabilities

### Advanced Format Support
- ELF, PE, Mach-O analysis with symbol and import extraction via LIEF
- Static library support (.a archives)
- Android DEX bytecode analysis
- Improved detection with 25+ components in APK files
- 152K+ features extracted from binaries
- Substring matching for partial pattern detection
- Real-time progress bars for long operations

## Archive Format Support

### Mobile Applications
- Android APK with manifest parsing and native library analysis
- iOS IPA with plist parsing and framework detection
- Automatic DEX bytecode extraction

### Java Archives
- JAR/WAR files with MANIFEST.MF parsing
- Package structure detection
- Class file analysis

### Python Packages
- Wheels (.whl) with metadata extraction
- Eggs (.egg) with setup information
- Requirements parsing

### Linux Packages
- DEB (Debian/Ubuntu) packages
- RPM (Red Hat/Fedora) packages
- Package metadata extraction

### Extended Formats
- 7z archives
- RAR archives
- Zstandard (.zst, .tar.zst)
- CPIO archives
- Nested archives (up to 5 levels deep)

## Source Code Analysis

### CTags Integration
- Advanced analysis when universal-ctags is available
- Multi-language support: C/C++, Python, Java, JavaScript, Go, Rust, PHP, Swift, Kotlin
- Semantic symbol extraction
- Function, class, struct, constant detection
- Dependency analysis
- Graceful fallback to regex extraction

## ML Model Security Analysis

### Comprehensive Security Module
- Deep analysis of ML models for security threats
- MITRE ATT&CK framework integration
- Multi-level risk assessment: SAFE, LOW, MEDIUM, HIGH, CRITICAL
- Supply chain security verification

### Supported Formats
- **Pickle Files**: Safe analysis without code execution
- **ONNX Models**: Comprehensive format validation
- **SafeTensors**: Secure tensor storage validation
- **PyTorch Native**: .pt, .pth format support
- **TensorFlow Native**: .pb, .h5 format support

### Detection Capabilities
- 100% detection rate on real-world ML exploits
- Framework detection: PyTorch (96%), TensorFlow, sklearn (94%), XGBoost (77%)
- Obfuscation detection via entropy analysis
- Model integrity validation
- Architecture recognition (ResNet, BERT, YOLO, LLaMA, ViT)
- Tampering and injection detection
- Data exfiltration pattern detection
- Oversized tensor flagging

### Security Output Formats
- SARIF for CI/CD integration
- Security-enhanced CycloneDX SBOM
- Markdown reports
- JSON risk assessments

## Signature Database Details

### Coverage
- 188 OSS components
- 1,400+ total signatures
- Improved accuracy with reduced false positives

### Component Categories

#### Multimedia Support
- H.264/H.265 codecs
- AAC, Dolby, AV1
- GStreamer, GLib
- FFmpeg components

#### System Libraries
- libcap, Expat XML
- LZ4, XZ Utils
- WebP, cURL
- Cairo, Opus

#### Mobile SDKs
- Facebook Android SDK
- Google Firebase
- Google Ads
- React Native

#### Java Libraries
- Jackson, Apache Commons
- Google Guava, Netty
- Spring Framework
- Lombok, Dagger

#### Development Tools
- RxJava, OkHttp
- Retrofit
- Bouncy Castle crypto

### Metadata
- Automatic license identification
- Security severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Publisher and version information
- Ecosystem classification

## Performance Metrics

- **Analysis Speed**: ~1 second per binary file
- **Archive Processing**: 100-500ms for APK/IPA files
- **Signature Storage**: ~3.5MB database with 5,136 signatures
- **Memory Usage**: <100MB during analysis, <200MB for large archives
- **Deterministic Results**: Consistent detection across runs

## Installation Options

### Performance Extras
```bash
pip install binarysniffer[fast]
```

### Fuzzy Matching Support
```bash
pip install binarysniffer[fuzzy]
```

### Extended Archive Support
```bash
pip install binarysniffer[archives]
```

### Android APK Analysis
```bash
pip install binarysniffer[android]
```

## External Tool Integration

### 7-Zip (Recommended)
Enables extraction and analysis of:
- Windows installers (.exe, .msi)
- macOS packages (.pkg, .dmg)
- NSIS, InnoSetup formats
- Self-extracting archives
- Additional archive formats (RAR, CAB, ISO)

### Universal CTags (Optional)
Provides:
- Better function/class/method detection
- Multi-language semantic analysis
- More accurate symbol extraction
- Improved signature matching

## Advanced Configuration

```json
{
  "signature_sources": [
    "https://signatures.binarysniffer.io/core.xmdb"
  ],
  "cache_size_mb": 100,
  "parallel_workers": 4,
  "min_confidence": 0.5,
  "auto_update": true,
  "update_check_interval_days": 7
}
```

## Version History Highlights

- **v1.10.0**: ML Model Security Analysis with MITRE ATT&CK
- **v1.9.x**: Enhanced ML framework detection
- **v1.8.x**: TLSH fuzzy matching, CycloneDX SBOM
- **v1.7.0**: MSI/PKG/DMG installer support
- **v1.6.x**: LIEF integration, DEX support
- **v1.5.x**: Signature quality improvements
- **v1.4.x**: Default enhanced mode
- **v1.3.0**: License display fixes
- **v1.2.0**: Enhanced detection mode
- **v1.1.0**: Archive support, CTags integration