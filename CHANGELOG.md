# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.4] - 2025-08-06

### Fixed
- **Eliminated .NET Core false positives** - Removed 59 overly generic patterns (90.8% reduction)
- **Reduced wolfSSL false detections** - Removed 32 generic crypto patterns that appear in many libraries
- **No more type name collisions** - Removed generic patterns like int32, float64, libc that match everywhere

### Added
- **Ultra-aggressive signature cleaning** - New script `scripts/ultra_aggressive_clean.py` for deep pattern cleaning
- **Better pattern validation** - Filters out basic types, generic prefixes, and common C library functions

### Improved
- **.NET Core signatures** - Reduced from 65 to 6 highly specific patterns
- **wolfSSL signatures** - Kept only wolfSSL-specific patterns (159 remaining from 191)
- **Detection accuracy** - FFmpeg and other binaries no longer show incorrect .NET or wolfSSL detections

### Technical
- **Pattern filtering** - Removes int/float types, generic prefixes (prefix1-7), macOS standard symbols
- **Signature quality** - Only truly component-specific patterns remain in signatures
- **Testing verified** - No false positives in FFmpeg, libcap, and other test binaries

## [1.8.3] - 2025-08-06

### Added
- **Git hooks for problematic word detection** - Prevent commits with AI references and other problematic content
- **Comprehensive pattern checking** - Detect AI/assistant references, hardcoded secrets, TODOs, inappropriate language
- **Pre-commit and commit-msg hooks** - Check both staged files and commit messages before allowing commits
- **Customizable word patterns** - Easy to add/remove patterns in `.githooks/check-problematic-words.sh`

### Security
- **Automated secret detection** - Hooks now check for hardcoded passwords, API keys, and tokens
- **Confidential content blocking** - Prevent accidental commit of internal/confidential markers

### Technical
- **Git hooks directory** - `.githooks/` directory with reusable hook scripts
- **Automatic hook configuration** - Repository configured to use `.githooks/` via `core.hooksPath`
- **Documentation** - Added `.githooks/README.md` with installation and usage instructions

## [1.8.2] - 2025-08-06

### Added
- **ALSA signature** - Comprehensive Advanced Linux Sound Architecture detection with 48 specific patterns
- **Aggressive signature cleaning** - New script to remove overly generic patterns causing false positives
- **Verbose evidence tracking** - Enhanced `-ve` flag now shows which files within archives triggered matches

### Fixed
- **Major false positive reduction** - Removed 16,090 generic patterns from signatures that caused incorrect detections
- **Archive content tracking** - Verbose mode now properly displays which files in archives contain matches
- **Signature quality** - Eliminated problematic patterns like "copy", "exit", "path", "bool" that match everywhere

### Improved
- **Detection accuracy** - Dramatically reduced false positives (e.g., .NET Core no longer incorrectly detected in FFmpeg)
- **PCoIP SDK** - Removed 4,312 generic patterns
- **wolfSSL** - Removed 3,143 generic patterns  
- **.NET Core** - Removed 2,064 generic patterns
- **FFmpeg** - Removed 3,503 generic patterns from BSA signature
- **Qt5** - Cleaned to only 13 high-quality patterns

### Technical
- **New tool** - `scripts/aggressive_clean_signatures.py` for comprehensive pattern filtering
- **Pattern validation** - Filters patterns <4 chars, common C functions, generic programming terms
- **Safe prefix preservation** - Keeps library-specific prefixes like `snd_`, `av_`, `ff_`, `png_`

## [1.8.1] - 2025-08-06

### Fixed
- **Database initialization on clean install** - Fixed critical issue preventing tool from working on new systems
- **Directory creation** - Database parent directory is now created automatically before initialization
- **Signature import method** - Fixed enhanced analyzer calling non-existent `auto_import()` method

### Improved
- **Installation reliability** - Tool now works correctly on first install without manual intervention
- **Error handling** - Better error messages when database cannot be created
- **Documentation** - Added comprehensive TLSH fuzzy matching examples to README

## [1.8.0] - 2025-08-06

### Added
- **TLSH Fuzzy Matching** - Detect similar/modified OSS components using locality-sensitive hashing
- **Enhanced FFmpeg signature** - 2,000 high-quality patterns covering versions 4.4 to 6.0 with TLSH hash
- **CLI options for fuzzy matching** - New `--use-tlsh` and `--tlsh-threshold` parameters for similarity detection
- **TLSH signature store** - Manage and query TLSH hashes for fuzzy component matching
- **Optional TLSH addition script** - Tool to add TLSH hashes to existing signatures (`scripts/add_tlsh_to_signatures.py`)

### Improved
- **Detection accuracy** - Find modified, recompiled, or patched OSS components that pattern matching might miss
- **Signature generation** - Automatically generates TLSH hashes for new signatures
- **Version detection** - Better identification of different versions of the same library
- **Component matching** - Merged fuzzy and pattern matching for comprehensive detection

### Technical
- **New dependency** - Added `python-tlsh` as optional dependency (`pip install binarysniffer[fuzzy]`)
- **New module** - `binarysniffer.hashing.tlsh_hasher` for TLSH operations
- **Documentation** - Comprehensive TLSH guide in `docs/TLSH_FUZZY_MATCHING.md`

## [1.7.0] - 2025-08-06

### Added
- **MSI installer support** - Extract and analyze Windows Installer packages (.msi files) with 7-Zip
- **PKG installer support** - Extract and analyze macOS installer packages (.pkg files) with 7-Zip  
- **DMG support** - Extract and analyze macOS disk images (.dmg files) with 7-Zip
- **New signatures** - Added Qt5 Framework, OpenCV, Foxit PDF SDK, wolfSSL, PCoIP SDK, and .NET Core Runtime
- **Logging improvements** - Clean logging output and debug features from GitHub issues #6 and #3
- **Version display** - Show version in main help output for better user experience

### Improved
- **Installer analysis** - Significantly improved detection rates for Windows and macOS installers
- **Archive extraction** - Enhanced extraction capabilities for various installer formats
- **Documentation** - Updated README with comprehensive optional tools section

### Fixed
- **Signature cleanup** - Removed unnecessary vendor-specific signatures

## [1.6.6] - 2025-08-06

### Improved
- **Pipeline and tests** - Improved pipeline and rebuilt tests

## [1.6.5] - 2025-08-06

### Added
- **New component signatures** - Added multiple new signatures for improved detection coverage
- **Script improvements** - Enhanced signature import and management scripts

### Improved  
- **Signature cleanup** - Refined and optimized existing signatures for better accuracy
- **LIEF and DEX parsers** - Enhanced binary analysis with LIEF library and Android DEX support
- **Detection accuracy** - Continued improvements to component detection algorithms

### Fixed
- **Script cleanup** - Fixed and optimized signature processing scripts

## [1.6.4] - 2025-08-06

### Changed
- **Signature metadata optimization** - Removed proprietary references from signature source descriptions
- **Cleaner attribution** - Updated signature metadata to use generic "APK analysis" instead of specific app references

### Improved
- **Professional metadata** - All signature files now have cleaner, more professional source attributions
- **Signature consistency** - Standardized metadata format across all signature files

## [1.6.3] - 2025-08-06

### Added
- **Deterministic mode by default** - Tool now runs with PYTHONHASHSEED=0 automatically for consistent results
- **Non-deterministic flag** - Added `--non-deterministic` flag to disable deterministic mode when needed
- **Duplicate log prevention** - Added DuplicateFilter to prevent the same log messages from appearing twice

### Changed
- **Default confidence threshold** - Changed from 0.8 to 0.5 to detect more components like Opus codec
- **Removed bloom filter tier** - Disabled probabilistic bloom filters for fully deterministic results
- **Optimized direct matching** - Improved performance from 5.3s to 1.0s (5x faster) using pre-computed indices

### Fixed
- **SQL query ordering** - Added ORDER BY clauses to ensure consistent database query results
- **Non-deterministic iterations** - Fixed all dictionary and set iterations to use sorted order
- **Configuration loading** - Prevented multiple Config instances from setting up duplicate loggers

### Performance
- **5x faster analysis** - Direct matcher optimization reduces analysis time from 5.3s to 1.0s
- **Memory efficient** - Removed bloom filter memory overhead while maintaining fast lookups
- **Deterministic results** - Consistent component detection across multiple runs

## [1.6.2] - 2025-08-05

### Investigated
- **Root cause of non-determinism** - Identified that Python's hash randomization (PYTHONHASHSEED) causes inconsistent results across CLI invocations
- **Bloom filter probabilistic behavior** - Bloom filters inherently have false positives that vary with different hash seeds

### Fixed
- **Sorted dictionary iterations** - Made component_scores iteration deterministic in DirectMatcher
- **Sorted set conversions** - Fixed non-deterministic list creation from sets in multiple places
- **Deterministic final sorting** - Added component name as secondary sort key for consistent ordering
- **Deterministic feature ordering** - Sort unique features before processing in ProgressiveMatcher

### Added
- **Deterministic bloom filter implementation** - Created new implementation using SHA-256 instead of Python's hash()

### Known Issues
- Component detection still shows some inconsistency due to bloom filter's probabilistic nature
- Running with `PYTHONHASHSEED=0` provides consistent results
- Consider making bloom filter tier optional or removing it for fully deterministic behavior

## [1.6.1] - 2025-08-05

### Fixed
- **Progress bar removed** - Removed tqdm progress bar from DirectMatcher that was causing display issues
- **Matcher initialization order** - Fixed issue where DirectMatcher was initialized before database was populated
- **Deterministic file ordering** - Archive extraction now uses sorted file lists for consistent results
- **Order-preserving deduplication** - Replaced set() with dict.fromkeys() to maintain consistent string order

### Known Issues
- Component detection still shows some inconsistency across runs (under investigation)
- Duplicate log messages appear in CLI output

## [1.6.0] - 2025-08-05

### Added
- **LIEF-based extractors** - Enhanced binary analysis using LIEF library for ELF/PE/Mach-O formats
- **DEX file extractor** - Specialized extractor for Android DEX bytecode analysis
- **New component signatures** - Added signatures for OkHttp, OpenSSL, SQLite, ICU, FreeType, and WebKit
- **Progress indication** - Added tqdm progress bars for long analysis operations
- **Substring matching** - Direct matcher now supports partial string matching for better detection

### Improved
- **APK analysis** - Dramatically improved component detection in Android APKs (from 1 to 25+ components)
- **Feature extraction** - Increased from 6,741 to 152,640 features for complex archives like APKs
- **Bloom filter capacity** - Increased limit from 1,000 to 100,000 features for better coverage
- **Component name display** - Fixed "@unknown" suffix when version is not available
- **Matching performance** - Optimized substring matching with early termination and pre-filtering

### Fixed
- **Archive processing** - DEX files and native libraries within APKs are now properly analyzed
- **Feature counting** - Analyzer now correctly reports total features extracted
- **Substring matching logic** - Fixed reversed logic (pattern in string, not string in pattern)
- **Progressive matcher** - Component names no longer show "@unknown" for unknown versions

## [1.5.1] - 2025-08-05

### Fixed
- **Major signature cleanup** - Removed 479 generic patterns causing false positives
- **Apache HTTP Core false positives** - Removed generic HTTP patterns that matched FFmpeg
- **Signature quality improvement** - Filtered patterns shorter than 6 characters
- **Cross-component contamination** - Removed patterns appearing in 5+ components

### Improved
- **Signature validation** - More strict criteria for keeping patterns
- **Library-specific prefixes** - Preserved valid prefixes like `av_`, `x264_`, `png_`
- **Reduced false positive rate** - 5.4% reduction in total signatures

### Statistics
- Total signatures before: 8,916
- Total signatures after: 8,437
- Apache HTTP Core: 31/65 patterns removed (47.7%)
- FFmpeg: Only 15/6,660 patterns removed (0.2%)
- SKIA: 77/268 patterns removed (28.7%)

## [1.5.0] - 2025-08-05

### Added
- **Integrated signature creation** - New `binarysniffer signatures create` command
- **Binary symbol extraction** - Extract symbols using readelf, nm, and strings
- **Smart signature generation** - Automatically identifies library prefixes and functions
- **Source code analysis** - Create signatures from source code repositories
- **Auto-detection** - Automatically detects binary vs source code input

### Improved
- **CLI integration** - Signature creation is now part of the main tool
- **Symbol-based signatures** - Uses actual binary symbols instead of arbitrary strings
- **Better validation** - Accepts library prefixes like `av_`, `x264_`, `png_`

### Usage
```bash
# Create signatures from binary
binarysniffer signatures create /path/to/ffmpeg --name FFmpeg --version 4.4.1

# Create from source code
binarysniffer signatures create /path/to/source --name MyLib --license MIT

# With full metadata
binarysniffer signatures create binary --name Component \\
  --version 1.0 --license GPL-3.0 --publisher "Company" \\
  --description "Component description" --output custom.json
```

## [1.4.9] - 2025-08-05

### Added
- **Signature quality validation** - New SignatureValidator class filters out generic patterns
- **Automatic filtering** - DirectMatcher now rejects overly generic signatures like "react", "log", "test"
- **Quality metrics** - 1,153 problematic patterns identified and filtered from signature database

### Improved
- **Drastically reduced false positives** - No more React Native detection in C++ projects
- **Better precision** - Filters short patterns (<6 chars) and common programming terms
- **Smarter matching** - Accepts specific patterns with special characters, mixed case, or namespaces

### Fixed
- **Generic signature problem** - Signatures like "React", "apache", "get", "set" no longer cause false matches
- **Cross-technology false positives** - C++ projects no longer show JavaScript/mobile components

## [1.4.8] - 2025-08-05

### Improved
- **Higher default threshold** - Increased from 0.5 to 0.7 for better precision
- **ZIP file filtering** - Added technology filtering for ZIP files containing binaries
- **Mobile component filtering** - React Native, Firebase, and other mobile components now filtered from ZIP files

### Fixed
- **False positives in ZIP files** - ZIP files with native binaries no longer show mobile-specific components

## [1.4.7] - 2025-08-05

### Improved
- **Reduced false positives** - Increased default threshold from 0.3 to 0.5 for better accuracy
- **Technology filtering** - Automatically filters incompatible components (e.g., no Android/iOS components in native binaries)
- **Archive extraction** - Fixed single-file archive extraction to use all features instead of limiting to 100 strings
- **Context validation** - Binary type now influences component detection to prevent impossible matches

### Fixed
- **ZIP file analysis** - Single-file archives like ffmpeg-4.4.1-linux-64.zip now properly analyzed with full feature extraction
- **False positive filtering** - Removed mobile-specific components (Firebase, React Native, etc.) from native binary results

## [1.4.6] - 2025-08-05

### Improved
- **Enhanced mode is now default** - All analysis now uses dual matching strategy (ProgressiveMatcher + DirectMatcher) for superior detection accuracy
- **Lower default threshold** - Reduced from 0.5 to 0.3 for better component detection without requiring manual threshold adjustment
- **Simplified CLI interface** - Removed `--enhanced` flag as enhanced detection is always active
- **Multi-language regex patterns** - Enhanced SourceCodeExtractor with comprehensive language support
- **Pattern coverage** - Achieved 100% test coverage across all 9 supported programming languages
- **Language-specific parsing** - Added support for Ruby methods without parentheses, C/C++ macros, Rust const syntax, Go imports and structs, C# using statements, C++ method declarations, and Kotlin functions
- **Detection accuracy** - Improved success rate from 85.4% to 100% for source code symbol extraction

### Added
- **Enhanced function patterns** - 6 regex patterns covering Python, JavaScript, Go, Rust, Kotlin, Java/C#/C++
- **Comprehensive class patterns** - 5 patterns for class, struct, interface, Go types, and enums
- **Extended import patterns** - 8 patterns supporting Python, JS, Rust, C/C++, Go, C#, Kotlin imports
- **Robust constant patterns** - 5 patterns for general constants, assignments, C macros, Rust, and Kotlin

### Breaking Changes
- **Enhanced mode always enabled** - The `--enhanced` flag has been removed as enhanced detection is now the default behavior

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