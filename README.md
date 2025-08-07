# Semantic Copycat BinarySniffer

A high-performance CLI tool and Python library for detecting open source components in binaries through semantic signature matching. Specialized for analyzing mobile apps (APK/IPA), Java archives, and source code to identify OSS components and their licenses.

## Features

### Core Analysis
- **TLSH Fuzzy Matching**: Detect modified, recompiled, or patched OSS components (NEW in v1.8.0)
- **Deterministic Results**: Consistent analysis results across multiple runs (NEW in v1.6.3)
- **Fast Local Analysis**: SQLite-based signature storage with optimized direct matching
- **Efficient Matching**: MinHash LSH for similarity detection, trigram indexing for substring matching
- **Dual Interface**: Use as CLI tool or Python library
- **Smart Compression**: ZSTD-compressed signatures with ~90% size reduction
- **Low Memory Footprint**: Streaming analysis with <100MB memory usage

### SBOM Export Support (NEW in v1.8.6)
- **CycloneDX Format**: Industry-standard SBOM export for security and compliance toolchains
- **File Path Tracking**: Evidence includes file paths for component location tracking
- **Feature Extraction**: Optional feature dump for signature recreation
- **Confidence Scores**: All detections include confidence levels in SBOM
- **Multi-file Support**: Aggregate SBOM for entire projects

### Package Inventory Extraction (NEW in v1.8.6)
- **Comprehensive File Enumeration**: Extract complete file listings from archives
- **Rich Metadata**: MIME types, compression ratios, file sizes, timestamps
- **Hash Calculation**: MD5, SHA1, SHA256 for integrity verification
- **Fuzzy Hashing**: TLSH and ssdeep for similarity analysis
- **Component Detection**: Run OSS detection on individual files within packages
- **Multiple Export Formats**: JSON, CSV, tree visualization, summary reports

### Enhanced Binary Analysis (v1.6.0)
- **LIEF Integration**: Advanced ELF/PE/Mach-O analysis with symbol and import extraction
- **Android DEX Support**: Specialized extractor for DEX bytecode files
- **Improved APK Detection**: 25+ components detected vs 1 previously (152K features extracted)
- **Substring Matching**: Detects components even with partial pattern matches
- **Progress Indication**: Real-time progress bars for long analysis operations
- **New Component Signatures**: OkHttp, OpenSSL, SQLite, ICU, FreeType, WebKit

### Archive Support
- **Android APK Analysis**: Extract and analyze AndroidManifest.xml, DEX files, native libraries
- **iOS IPA Analysis**: Parse Info.plist, detect frameworks, analyze executables
- **Java Archive Support**: Process JAR/WAR files with MANIFEST.MF parsing and package detection
- **Python Package Support**: Analyze wheels (.whl) and eggs (.egg) with metadata extraction
- **Nested Archive Processing**: Handle archives containing other archives
- **Comprehensive Format Support**: ZIP, TAR, 7z, and compound formats

### Enhanced Source Analysis
- **CTags Integration**: Advanced source code analysis when universal-ctags is available
- **Multi-language Support**: C/C++, Python, Java, JavaScript, Go, Rust, PHP, Swift, Kotlin
- **Semantic Symbol Extraction**: Functions, classes, structs, constants, and dependencies
- **Graceful Fallback**: Regex-based extraction when CTags is unavailable

### Signature Database
- **90+ OSS Components**: Pre-loaded signatures from Facebook SDK, Jackson, FFmpeg, and more
- **Real-world Detection**: Thousands of component signatures from BSA database migration
- **License Detection**: Automatic license identification for detected components
- **Metadata Rich**: Publisher, version, and ecosystem information for each component

## Installation

### From PyPI
```bash
pip install semantic-copycat-binarysniffer
```

### From Source
```bash
git clone https://github.com/oscarvalenzuelab/semantic-copycat-binarysniffer
cd semantic-copycat-binarysniffer
pip install -e .
```

### With Performance Extras
```bash
pip install semantic-copycat-binarysniffer[fast]
```

### With Fuzzy Matching Support
```bash
# Includes TLSH for detecting modified/recompiled components
pip install semantic-copycat-binarysniffer[fuzzy]
```

## Optional Tools for Enhanced Format Support

BinarySniffer can leverage external tools when available to provide enhanced analysis capabilities. These tools are **optional** - the core functionality works without them, but installing them unlocks additional features:

### 7-Zip (Recommended)
**Enables**: Extraction and analysis of Windows installers, macOS packages, and additional compressed formats

```bash
# macOS
brew install p7zip

# Ubuntu/Debian
sudo apt-get install p7zip-full

# Windows
# Download from https://www.7-zip.org/
```

**Benefits**:
- Analyze Windows installers (.exe, .msi) by extracting embedded components
- Analyze macOS installers (.pkg, .dmg) to detect bundled frameworks
- Support for NSIS, InnoSetup, and other installer formats
- Extract and analyze self-extracting archives
- Support for additional archive formats (RAR, CAB, ISO, etc.)

### Universal CTags (Optional)
**Enables**: Enhanced source code analysis with semantic understanding

```bash
# macOS
brew install universal-ctags

# Ubuntu/Debian
sudo apt-get install universal-ctags

# Windows
# Download from https://github.com/universal-ctags/ctags-win32/releases
```

**Benefits**:
- Better function/class/method detection in source code
- Multi-language semantic analysis
- More accurate symbol extraction
- Improved signature matching for source code components

### Example: Analyzing Installers

Without 7-Zip:
```bash
$ binarysniffer analyze installer.exe
# Analyzes as compressed binary - limited detection
```

With 7-Zip installed:
```bash
# Windows installers
$ binarysniffer analyze installer.exe
$ binarysniffer analyze setup.msi
# Automatically extracts and analyzes contents
# Detects: Qt5, OpenSSL, SQLite, ICU, libpng, etc.

# macOS installers
$ binarysniffer analyze app.pkg
$ binarysniffer analyze app.dmg
# Automatically extracts and analyzes contents
# Detects: Qt5, WebKit, OpenCV, React Native, etc.
```

## Quick Start

### CLI Usage

```bash
# Basic analysis
binarysniffer analyze /path/to/binary
binarysniffer analyze app.apk                    # Android APK
binarysniffer analyze app.ipa                    # iOS IPA
binarysniffer analyze library.jar                # Java JAR

# Analyze directories recursively
binarysniffer analyze /path/to/project -r

# Output with auto-format detection
binarysniffer analyze app.apk -o report.json     # Auto-detects JSON format
binarysniffer analyze app.apk -o report.csv      # Auto-detects CSV format
binarysniffer analyze app.apk -o app.sbom        # Auto-detects SBOM format

# Performance modes
binarysniffer analyze large.bin --fast           # Quick scan (no fuzzy matching)
binarysniffer analyze app.apk --deep             # Thorough analysis

# Custom confidence threshold
binarysniffer analyze file.exe -t 0.3            # More sensitive (30% confidence)
binarysniffer analyze file.exe -t 0.8            # More conservative (80% confidence)

# Include file hashes in output
binarysniffer analyze file.exe --with-hashes -o report.json
binarysniffer analyze file.exe --basic-hashes    # Only MD5, SHA1, SHA256

# Filter by file patterns
binarysniffer analyze project/ -r -p "*.so" -p "*.dll"

# Export as CycloneDX SBOM
binarysniffer analyze app.apk -f sbom -o app-sbom.json
binarysniffer analyze app.apk --format cyclonedx -o sbom.json

# Save features for signature creation
binarysniffer analyze binary.exe --save-features features.json --show-features

# Filter results
binarysniffer analyze lib.so --min-matches 5     # Show components with 5+ matches
binarysniffer analyze app.apk --show-evidence    # Show detailed match evidence
```

### Python Library Usage

```python
from binarysniffer import EnhancedBinarySniffer

# Initialize analyzer (enhanced mode is default)
sniffer = EnhancedBinarySniffer()

# Analyze a single file
result = sniffer.analyze_file("/path/to/binary")
for match in result.matches:
    print(f"{match.component} - {match.confidence:.2%}")
    print(f"License: {match.license}")

# Analyze mobile applications
apk_result = sniffer.analyze_file("app.apk")
ipa_result = sniffer.analyze_file("app.ipa")
jar_result = sniffer.analyze_file("library.jar")

# Analyze with custom threshold (default is 0.5)
result = sniffer.analyze_file("file.exe", confidence_threshold=0.3)  # More sensitive
result = sniffer.analyze_file("file.exe", confidence_threshold=0.8)  # More conservative

# Analyze with file hashes
result = sniffer.analyze_file("file.exe", include_hashes=True, include_fuzzy_hashes=True)

# Directory analysis
results = sniffer.analyze_directory("/path/to/project", recursive=True)
for file_path, result in results.items():
    if result.matches:
        print(f"{file_path}: {len(result.matches)} components detected")

# TLSH fuzzy matching for modified components
result = sniffer.analyze_file(
    "modified_binary.exe",
    use_tlsh=True,              # Enable TLSH fuzzy matching (default)
    tlsh_threshold=50           # Lower threshold = more similar required
)
for match in result.matches:
    if match.match_type == 'tlsh_fuzzy':
        print(f"Fuzzy match: {match.component} (similarity: {match.confidence:.0%})")
```

### SBOM Export (NEW in v1.8.6)

Generate Software Bill of Materials in CycloneDX format for integration with security and compliance tools:

```bash
# Export single file analysis as SBOM
binarysniffer analyze app.apk --format cyclonedx -o app-sbom.json

# Export directory analysis as aggregated SBOM
binarysniffer analyze project/ -r --format cdx -o project-sbom.json

# Include extracted features for signature recreation
binarysniffer analyze binary.exe --format cyclonedx --show-features -o sbom-with-features.json
```

The SBOM includes:
- Component names, versions, and licenses
- Confidence scores for each detection
- File paths showing where components were found
- Evidence details including matched patterns
- Optional extracted features for signature recreation

### Package Inventory Extraction (NEW in v1.8.6)

Extract comprehensive file inventories from packages with metadata, hashes, and component detection:

```bash
# Basic inventory summary
binarysniffer inventory app.apk

# Export full inventory with auto-format detection
binarysniffer inventory app.apk -o inventory.json
binarysniffer inventory app.jar -o files.csv

# Include file hashes (MD5, SHA1, SHA256, TLSH, ssdeep)
binarysniffer inventory app.jar --analyze --with-hashes -o files.csv

# Full analysis with component detection
binarysniffer inventory app.ipa \
  --analyze \
  --with-hashes \
  --with-components \
  -o full_inventory.json

# Export as directory tree visualization
binarysniffer inventory archive.zip --format tree -o structure.txt
```

#### Python API for Inventory Extraction

```python
from binarysniffer import EnhancedBinarySniffer

sniffer = EnhancedBinarySniffer()

# Basic inventory extraction
inventory = sniffer.extract_package_inventory("app.apk")
print(f"Total files: {inventory['summary']['total_files']}")
print(f"Package size: {inventory['package_size']:,} bytes")

# Full analysis with all features
inventory = sniffer.extract_package_inventory(
    "app.apk",
    analyze_contents=True,        # Extract and analyze file contents
    include_hashes=True,          # Calculate MD5, SHA1, SHA256
    include_fuzzy_hashes=True,    # Calculate TLSH and ssdeep
    detect_components=True        # Run OSS component detection
)

# Access comprehensive file metadata
for file_entry in inventory['files']:
    if not file_entry['is_directory']:
        print(f"File: {file_entry['path']}")
        print(f"  MIME: {file_entry['mime_type']}")
        print(f"  Size: {file_entry['size']:,} bytes")
        print(f"  Compression ratio: {file_entry['compression_ratio']:.1%}")
        
        if 'hashes' in file_entry:
            print(f"  SHA256: {file_entry['hashes']['sha256']}")
        
        if 'components' in file_entry:
            for comp in file_entry['components']:
                print(f"  Component: {comp['name']} ({comp['confidence']:.0%})")
```

#### Inventory Export Formats

- **JSON**: Complete structured data with all metadata
- **CSV**: Tabular format for data analysis (includes hashes, MIME types, components)
- **Tree**: Visual directory structure representation
- **Summary**: Quick overview with file type statistics

### Creating Signatures

Create custom signatures for your components:

```bash
# From binary files (recommended)
binarysniffer signatures create /usr/bin/ffmpeg --name FFmpeg --version 4.4.1

# From source code
binarysniffer signatures create /path/to/source --name MyLibrary --license MIT

# With full metadata
binarysniffer signatures create binary.so \
  --name "My Component" \
  --version 2.0.0 \
  --license Apache-2.0 \
  --publisher "My Company" \
  --output signatures/my-component.json
```

## Architecture

The tool uses a multi-tiered approach for efficient matching:

1. **Pattern Matching**: Direct string/symbol matching against signature database
2. **MinHash LSH**: Fast similarity search for near-duplicate detection (milliseconds)
3. **TLSH Fuzzy Matching**: Locality-sensitive hashing to detect modified/recompiled components
4. **Detailed Verification**: Precise signature verification with confidence scoring

### TLSH Fuzzy Matching (v1.8.0+)

TLSH (Trend Micro Locality Sensitive Hash) enables detection of:
- **Modified Components**: Components with patches or custom modifications
- **Recompiled Binaries**: Same source code compiled with different options
- **Version Variants**: Different versions of the same library
- **Obfuscated Code**: Components with mild obfuscation or optimization

The TLSH algorithm generates a compact hash that remains similar even when files are modified, making it ideal for detecting OSS components that have been customized or rebuilt.

## Performance

- **Analysis Speed**: ~1 second per binary file (5x faster in v1.6.3)
- **Archive Processing**: ~100-500ms for APK/IPA files (depends on contents)
- **Signature Storage**: ~3.5MB database with 5,136 signatures from 131 components
- **Memory Usage**: <100MB during analysis, <200MB for large archives
- **Deterministic Results**: Consistent detection across runs (NEW in v1.6.3)

## Configuration

Configuration file location: `~/.binarysniffer/config.json`

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

## Signature Database

The tool includes a pre-built signature database with **131 OSS components** including:
- **Mobile SDKs**: Facebook Android SDK, Google Firebase, Google Ads
- **Java Libraries**: Jackson, Apache Commons, Google Guava, Netty  
- **Media Libraries**: FFmpeg, x264, x265, Vorbis, Opus
- **Crypto Libraries**: Bounty Castle, mbedTLS variants
- **Development Tools**: Lombok, Dagger, RxJava, OkHttp

### Signature Management

Maintaining an up-to-date signature database is critical for accurate detection. BinarySniffer provides comprehensive signature management commands:

#### Viewing Signature Status

```bash
# Check current signature database status
binarysniffer signatures status
# Shows: total signatures, components, last update, database location

# View detailed statistics
binarysniffer signatures stats
# Shows: signatures per component, database size, index status
```

#### Updating Signatures

```bash
# Update signatures from GitHub repository (recommended)
binarysniffer signatures update
# Pulls latest community-contributed signatures

# Alternative update command (backward compatible)
binarysniffer update

# Force update even if current
binarysniffer signatures update --force
```

#### Rebuilding Database

```bash
# Rebuild database from packaged signatures
binarysniffer signatures rebuild
# Useful when database is corrupted or needs fresh start

# Import specific signature files
binarysniffer signatures import signatures/*.json

# Import from custom directory
binarysniffer signatures import /path/to/signatures --recursive
```

#### Creating Custom Signatures

```bash
# Create signature from binary
binarysniffer signatures create /usr/bin/curl \
  --name "curl" \
  --version 7.81.0 \
  --license "MIT" \
  --output signatures/curl.json

# Create from source code directory
binarysniffer signatures create /path/to/source \
  --name "MyLibrary" \
  --version 1.0.0 \
  --license "Apache-2.0" \
  --min-length 8  # Minimum pattern length

# Create with metadata
binarysniffer signatures create binary.so \
  --name "Custom Component" \
  --publisher "My Company" \
  --description "Custom implementation" \
  --url "https://github.com/mycompany/component"
```

#### Signature Validation

```bash
# Validate signature quality before adding
binarysniffer signatures validate signatures/new-component.json
# Checks for: generic patterns, minimum length, uniqueness

# Test signature against known files
binarysniffer signatures test signatures/component.json /path/to/test/files
```

#### Database Management

```bash
# Export signatures to JSON (for backup or sharing)
binarysniffer signatures export --output my-signatures/
# Creates one JSON file per component

# Clear database (use with caution)
binarysniffer signatures clear --confirm
# Removes all signatures from database

# Optimize database
binarysniffer signatures optimize
# Rebuilds indexes and vacuums database for better performance
```

#### Automated Updates

Configure automatic signature updates in `~/.binarysniffer/config.json`:

```json
{
  "auto_update": true,
  "update_check_interval_days": 7,
  "signature_sources": [
    "https://github.com/oscarvalenzuelab/binarysniffer-signatures"
  ]
}
```

#### Best Practices

1. **Regular Updates**: Run `binarysniffer signatures update` weekly for latest detections
2. **Custom Signatures**: Create signatures for proprietary components you want to track
3. **Validation**: Always validate new signatures to avoid false positives
4. **Backup**: Export signatures before major updates using `signatures export`
5. **Performance**: Run `signatures optimize` monthly for best performance

For detailed signature creation and management documentation, see [docs/SIGNATURE_MANAGEMENT.md](docs/SIGNATURE_MANAGEMENT.md).

## License

Apache License 2.0 - See LICENSE file for details.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.