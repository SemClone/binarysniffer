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

### Enhanced Binary Analysis (NEW in v1.6.0)
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
# Analyze a single file (enhanced detection is always enabled)
binarysniffer analyze /path/to/binary

# Analyze mobile applications
binarysniffer analyze app.apk                    # Android APK
binarysniffer analyze app.ipa                    # iOS IPA
binarysniffer analyze library.jar                # Java JAR

# Analyze directories recursively
binarysniffer analyze /path/to/project --recursive

# Custom threshold (default is 0.5 for optimal detection)
binarysniffer analyze file.exe --threshold 0.3   # More sensitive
binarysniffer analyze file.exe --threshold 0.8   # More conservative

# Export results as JSON
binarysniffer analyze project/ --format json -o results.json

# Deep analysis with pattern filtering
binarysniffer analyze project/ --recursive --deep -p "*.so" -p "*.dll"

# Non-deterministic mode (if needed for performance testing)
binarysniffer --non-deterministic analyze file.bin

# TLSH fuzzy matching for detecting modified components
binarysniffer analyze modified_ffmpeg.bin --use-tlsh        # Enable fuzzy matching (default)
binarysniffer analyze file.bin --tlsh-threshold 30          # More sensitive fuzzy matching
binarysniffer analyze file.bin --no-tlsh                    # Disable fuzzy matching
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

# Analyze with custom threshold (default is 0.3)
result = sniffer.analyze_file("file.exe", confidence_threshold=0.1)  # More sensitive
result = sniffer.analyze_file("file.exe", confidence_threshold=0.8)  # More conservative

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

For detailed information on creating, updating, and managing signatures, see [docs/SIGNATURE_MANAGEMENT.md](docs/SIGNATURE_MANAGEMENT.md).

```bash
# View current database stats
python -c "
from binarysniffer.storage.database import SignatureDatabase
db = SignatureDatabase('data/signatures.db')
print(db.get_stats())
"
```

## Development

### Setting up development environment
```bash
git clone https://github.com/oscarvalenzuelab/semantic-copycat-binarysniffer
cd semantic-copycat-binarysniffer
pip install -e .[dev]

# Optional: Install CTags for enhanced source analysis
# macOS: brew install universal-ctags
# Ubuntu: apt install universal-ctags

# Optional: Install LIEF for enhanced binary analysis
pip install lief
```

### Running tests
```bash
# Run all tests
pytest tests/

# Run specific test suites  
pytest tests/test_archive_extractor.py -v    # Archive processing
pytest tests/test_integration.py -v         # End-to-end scenarios

# Run with coverage
pytest tests/ --cov=binarysniffer
```

### Building and Testing Package
```bash
# Build package
python -m build

# Test installation
pip install dist/*.whl

# Test CLI
binarysniffer --help
```

## License

Apache License 2.0 - See LICENSE file for details.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.