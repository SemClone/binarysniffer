# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.5] - 2025-08-05

### Fixed
- **Release pipeline** - Fixed automated release and deployment pipeline issues

## [1.4.0] - 2025-08-05

### Fixed
- **Complete repository reset** - Fresh git history with single clean commit
- **Professional contributor attribution** - All commits properly attributed to Oscar Valenzuela B
- **Clean release process** - New major version with proper identity management

### Features
- **License extraction from database** - DirectMatcher properly queries license column
- **Evidence formatting** - Clear display of pattern counts in evidence column
- **License information display** - All detected components show their proper licenses
- **Enhanced detection mode** - Improved component detection accuracy (42x improvement on APK analysis)
- **Comprehensive signature database** - 8,852+ signatures from 129+ components

### Updated
- **Project metadata** - Updated author information and repository URLs
- **Documentation links** - Fixed project URLs to point to correct GitHub repository

## [1.3.0] - 2025-08-04

### Fixed
- **License extraction from database** - DirectMatcher now properly queries license column
- **Component name display** - No more "@unknown" suffix for components without versions
- **Evidence formatting** - Clear display of pattern counts in evidence column

### Enhanced
- **License information display** - All detected components now show their proper licenses
- **Database queries** - Optimized to fetch all component metadata including licenses
- **Output clarity** - Better formatted evidence showing number of matched patterns

### Technical Fixes
- Fixed DirectMatcher SQL query to include license column
- Updated component mapping to extract license from correct database column
- Improved component name formatting to exclude redundant version info

## [1.2.0] - 2025-08-04

### Added

#### Enhanced Detection Mode
- **New `--enhanced` CLI flag** for improved component detection accuracy
- **ImprovedBinaryExtractor** with more permissive string extraction (min_length=4, max_strings=50000)
- **DirectMatcher** implementation bypassing bloom filters for exhaustive string matching
- **EnhancedBinarySniffer** analyzer combining progressive and direct matching strategies
- **Symbol extraction patterns** for common library prefixes and function names
- **Comprehensive User Guide** at `docs/USER_GUIDE.md` with examples and troubleshooting

#### Enhanced Signatures
- **Expanded libpng signatures** from 10 to 20 patterns for better detection
- **New libjpeg-enhanced.json** with 25 comprehensive patterns
- **Enhanced signature metadata** with confidence thresholds and contexts

### Enhanced
- **APK analysis accuracy** improved from 1 to 42 components detected (42x improvement)
- **String extraction** with reduced filtering for better signature preservation
- **Confidence scoring** with adjusted thresholds (0.3 default for enhanced mode)
- **Component detection** for libraries like libpng, libxml2, FFMPEG, Firebase Crashlytics, SKIA
- **Evidence reporting** with signature counts and match methods in output

### Fixed
- **Binary extractor filtering** removing potential signatures
- **Bloom filter false negatives** preventing component detection
- **Import issues** between analyzer modules
- **Component lookup** in DirectMatcher using proper database queries

### Technical Improvements
- **Dual matching strategy** for better accuracy vs performance tradeoff
- **Configurable extraction parameters** for different analysis needs
- **Merged match results** keeping highest confidence scores
- **Better error handling** in enhanced analyzer

### Documentation
- **Comprehensive User Guide** covering installation, usage, examples, and troubleshooting
- **Enhanced detection mode** explanation and performance impact
- **Output format documentation** for table, JSON, and CSV formats
- **Performance optimization tips** for large-scale analysis

### Known Issues
- **Code duplication** between binary.py and binary_improved.py (~90% similar)
- **Analyzer duplication** between analyzer.py and analyzer_enhanced.py
- **Unused imports** in several modules (shutil, os, Set)
- **Inconsistent error handling** between analyzers

## [1.1.0] - 2025-08-04

### Added

#### Archive Support
- **Complete archive file support** for ZIP, JAR, APK, IPA, TAR, and other formats
- **Android APK analysis** with AndroidManifest.xml parsing, DEX file detection, and native library extraction
- **iOS IPA analysis** with Info.plist parsing, framework detection, and executable identification
- **Java archive support** with MANIFEST.MF parsing and package structure analysis
- **Python package support** for wheels (.whl) and eggs (.egg) with metadata extraction
- **Nested archive processing** for archives containing other archives
- **Archive-specific metadata extraction** including package names, versions, and dependencies

#### CTags Integration
- **Universal CTags support** for enhanced source code analysis when available
- **Graceful fallback** to regex-based extraction when CTags is not installed
- **Multi-language support** including C/C++, Python, Java, JavaScript, Go, Rust, and more
- **Semantic symbol extraction** including functions, classes, structs, and constants
- **Optional integration** via ExtractorFactory configuration

#### Signature Migration
- **BSA signature database migration** supporting 90+ open source components
- **Real-world signature database** with thousands of component signatures
- **Automated migration scripts** for converting legacy signature formats
- **Component metadata preservation** including licenses, publishers, and versions
- **Efficient signature indexing** with trigram support for fast substring matching

#### Enhanced Testing
- **Comprehensive test suite** for archive extraction (10/10 tests passing)
- **Integration tests** for end-to-end APK/IPA/JAR analysis
- **CTags integration testing** with fallback verification
- **Migration verification** ensuring signature database functionality

### Enhanced
- **ExtractorFactory improvements** with configurable extractor selection
- **Source code extraction** with improved regex patterns and error handling
- **Error handling** throughout archive processing with graceful degradation
- **Performance optimizations** for large archive processing with file limits
- **Logging improvements** with detailed debug information for troubleshooting

### Fixed
- **Circular import issues** in archive extractor factory integration
- **Regex pattern corrections** for JavaScript require statements
- **Metadata handling** ensuring proper initialization across all extractors
- **TAR file type detection** with proper compound extension handling

### Technical Improvements
- **Plugin architecture** for extractors with easy extensibility
- **Memory management** for large archive processing with limits and cleanup
- **Type safety** improvements with proper dataclass usage
- **Test coverage** expansion with comprehensive edge case handling

### Documentation
- **Archive format support** documentation
- **CTags installation and usage** guidelines
- **Migration script usage** examples
- **API documentation** for new extractor interfaces

## [1.0.0] - 2025-08-03

### Added
- Initial release with core functionality
- Three-tier progressive matching system
- SQLite-based signature storage with ZSTD compression
- MinHash LSH indexing for fast similarity detection
- Bloom filter pre-filtering for performance
- CLI and Python library interfaces
- Basic file type support (binaries, source code)
- Trigram indexing for substring matching
- Component detection and confidence scoring

### Features
- Fast local analysis with <100MB memory usage
- Multi-format binary analysis
- Source code feature extraction
- License and component identification
- Batch processing capabilities
- JSON output format
- Configurable confidence thresholds

[1.3.0]: https://github.com/oscarvalenzuelab/semantic-copycat-binarysniffer/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/oscarvalenzuelab/semantic-copycat-binarysniffer/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/oscarvalenzuelab/semantic-copycat-binarysniffer/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/oscarvalenzuelab/semantic-copycat-binarysniffer/releases/tag/v1.0.0