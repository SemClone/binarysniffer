# Semantic Copycat BinarySniffer

A high-performance CLI tool and Python library for detecting open source components in binaries through semantic signature matching. Specialized for analyzing mobile apps (APK/IPA), Java archives, and source code to identify OSS components and their licenses.

## Features

### Core Analysis
- **Fast Local Analysis**: SQLite-based signature storage with tiered bloom filters
- **Efficient Matching**: MinHash LSH for similarity detection, trigram indexing for substring matching
- **Dual Interface**: Use as CLI tool or Python library
- **Smart Compression**: ZSTD-compressed signatures with ~90% size reduction
- **Low Memory Footprint**: Streaming analysis with <100MB memory usage

### Archive Support (NEW in v1.1.0)
- **Android APK Analysis**: Extract and analyze AndroidManifest.xml, DEX files, native libraries
- **iOS IPA Analysis**: Parse Info.plist, detect frameworks, analyze executables
- **Java Archive Support**: Process JAR/WAR files with MANIFEST.MF parsing and package detection
- **Python Package Support**: Analyze wheels (.whl) and eggs (.egg) with metadata extraction
- **Nested Archive Processing**: Handle archives containing other archives
- **Comprehensive Format Support**: ZIP, TAR, 7z, and compound formats

### Enhanced Source Analysis (NEW in v1.1.0)
- **CTags Integration**: Advanced source code analysis when universal-ctags is available
- **Multi-language Support**: C/C++, Python, Java, JavaScript, Go, Rust, PHP, Swift, Kotlin
- **Semantic Symbol Extraction**: Functions, classes, structs, constants, and dependencies
- **Graceful Fallback**: Regex-based extraction when CTags is unavailable

### Signature Database (NEW in v1.1.0)
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

## Quick Start

### CLI Usage

```bash
# Analyze a single file
binarysniffer analyze /path/to/binary

# Analyze mobile applications (NEW in v1.1.0)
binarysniffer analyze app.apk                    # Android APK
binarysniffer analyze app.ipa                    # iOS IPA
binarysniffer analyze library.jar                # Java JAR

# Analyze directories recursively
binarysniffer analyze /path/to/project --recursive

# Show detailed matches with confidence scores
binarysniffer analyze file.exe --detailed --threshold 0.7

# Export results as JSON
binarysniffer analyze project/ --format json -o results.json

# CTags-enhanced source analysis (if universal-ctags installed)
binarysniffer analyze source_project/ --detailed
```

### Python Library Usage

```python
from binarysniffer import BinarySniffer

# Initialize analyzer
sniffer = BinarySniffer()

# Analyze a single file
result = sniffer.analyze_file("/path/to/binary")
for match in result.matches:
    print(f"{match.component} - {match.confidence:.2%}")
    print(f"License: {match.license}")

# Analyze mobile applications (NEW in v1.1.0)
apk_result = sniffer.analyze_file("app.apk")
ipa_result = sniffer.analyze_file("app.ipa")
jar_result = sniffer.analyze_file("library.jar")

# Analyze with custom threshold
result = sniffer.analyze_file("file.exe", confidence_threshold=0.8)

# Directory analysis
results = sniffer.analyze_directory("/path/to/project", recursive=True)
for file_path, result in results.items():
    if result.matches:
        print(f"{file_path}: {len(result.matches)} components detected")
```

## Architecture

The tool uses a multi-tiered approach for efficient matching:

1. **Tier 1 - Bloom Filters**: Quick elimination of non-matches (microseconds)
2. **Tier 2 - MinHash LSH**: Fast similarity search (milliseconds)
3. **Tier 3 - Detailed Matching**: Precise signature verification (seconds)

## Performance

- **Analysis Speed**: ~10-50ms per file (after index loading)
- **Archive Processing**: ~100-500ms for APK/IPA files (depends on contents)
- **Signature Storage**: ~1-5MB for 1K signatures, ~50-100MB for 1M signatures
- **Memory Usage**: <100MB during analysis, <200MB for large archives
- **Database Size**: Current database: ~2MB with 90+ components and 1000+ signatures

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

The tool includes a pre-built signature database with **90+ OSS components** including:
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