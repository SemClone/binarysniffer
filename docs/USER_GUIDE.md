# BinarySniffer User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Command Reference](#command-reference)
5. [Usage Examples](#usage-examples)
6. [Output Formats](#output-formats)
7. [Detection Modes](#detection-modes)
8. [Performance Tips](#performance-tips)
9. [Troubleshooting](#troubleshooting)

## Introduction

BinarySniffer is a high-performance CLI tool for detecting open source components in binary files through semantic signature matching. It can analyze executables, shared libraries, APK files, and other binary formats to identify embedded open source software components.

### Key Features
- Fast binary analysis with dual matching system (Progressive + Direct)
- Support for multiple file types (ELF, PE, Mach-O, APK, JAR, etc.)
- Enhanced detection enabled by default for superior accuracy
- Multiple output formats (table, JSON, CSV)
- Parallel processing for large directories
- Comprehensive signature database with 100+ components

## Installation

### From PyPI (when available)
```bash
pip install semantic-copycat-binarysniffer
```

### From Source
```bash
git clone https://github.com/yourusername/semantic-copycat-binarysniffer.git
cd semantic-copycat-binarysniffer
pip install -e .
```

### Verify Installation
```bash
binarysniffer --version
```

## Quick Start

### Analyze a Single File
```bash
# Basic analysis
binarysniffer analyze myapp.exe

# Enhanced detection (recommended for better results)
binarysniffer analyze myapp.exe --enhanced
```

### Analyze a Directory
```bash
# Analyze all files in a directory
binarysniffer analyze /path/to/project -r

# Analyze only specific file types
binarysniffer analyze /path/to/project -r -p "*.so" -p "*.dll"
```

### Save Results
```bash
# Save as JSON
binarysniffer analyze myapp.apk --enhanced -f json -o results.json

# Save as CSV
binarysniffer analyze myapp.apk --enhanced -f csv -o results.csv
```

## Command Reference

### Main Commands

#### `analyze` - Analyze files for OSS components
```bash
binarysniffer analyze [OPTIONS] PATH
```

**Options:**
- `-r, --recursive` - Analyze directories recursively
- `-t, --threshold FLOAT` - Confidence threshold (0.0-1.0, default: 0.5)
- `-p, --patterns TEXT` - File patterns to match (e.g., *.exe, *.so)
- `-o, --output PATH` - Save results to file
- `-f, --format [table|json|csv|cyclonedx|sbom]` - Output format (default: table)
- `--deep` - Enable deep analysis mode (slower, more thorough)
- `--fast` - Fast mode (skip TLSH fuzzy matching for speed)
- `--parallel/--no-parallel` - Enable/disable parallel processing
- `--with-hashes` - Include all hashes (MD5, SHA1, SHA256, TLSH, ssdeep)
- `--basic-hashes` - Include only basic hashes (MD5, SHA1, SHA256)
- `--min-matches INTEGER` - Minimum pattern matches to show component
- `--license-focus` - Focus on license detection and compliance
- `--license-only` - Only detect licenses, skip component detection
- `-v, --debug` - Enable debug output (shows each file being processed)
- `--show-evidence` - Show detailed match evidence
- `--show-features` - Display extracted features (for debugging)
- `--save-features PATH` - Save features to JSON (for signature creation)
- `-l, --include-large` - Include large files (>50MB) in analysis
- `--skip-metadata` - Skip metadata files (plist, config, etc.) - speeds up analysis
- `--timeout INTEGER` - Timeout in seconds for analyzing each file (default: 60)

#### `update` - Update signature database
```bash
binarysniffer update [OPTIONS]
```

**Options:**
- `--force` - Force full update instead of delta

#### `stats` - Show signature database statistics
```bash
binarysniffer stats
```

#### `config` - Show current configuration
```bash
binarysniffer config
```

### Signature Management Commands

#### `signatures status` - Show signature database status
```bash
binarysniffer signatures status
```

#### `signatures import` - Import packaged signatures
```bash
binarysniffer signatures import [--force]
```

#### `signatures rebuild` - Rebuild signature database
```bash
binarysniffer signatures rebuild [--github/--no-github]
```

#### `inventory` - Extract package file inventory (v1.8.6+)
```bash
# Basic inventory extraction
binarysniffer inventory package.apk

# With full analysis and component detection
binarysniffer inventory package.jar \
  --analyze \
  --include-hashes \
  --include-fuzzy-hashes \
  --detect-components \
  --format csv \
  --output inventory.csv

Options:
  --analyze               Extract and analyze file contents
  --include-hashes       Include MD5, SHA1, SHA256 hashes
  --include-fuzzy-hashes Include TLSH and ssdeep fuzzy hashes
  --detect-components    Run OSS component detection on files
  --format              Output format: json, csv, tree, summary
  --output              Save results to file
```

## Usage Examples

### Example 1: Analyzing an Android APK
```bash
# Fast analysis of an APK
binarysniffer analyze my_android_app.apk --fast

# Output:
# ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━┓
# ┃ Component                        ┃ Confidence ┃ License ┃ Type   ┃ Evidence  ┃
# ┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━┩
# │ x265@unknown                     │ 92.0%      │ -       │ string │  (direct) │
# │ x264@unknown                     │ 92.0%      │ -       │ string │  (direct) │
# │ React Native@unknown             │ 92.0%      │ -       │ string │  (direct) │
# │ FFMPEG@unknown                   │ 88.0%      │ -       │ string │  (direct) │
# ...
```

### Example 2: Batch Analysis with Filtering
```bash
# Analyze only .so files in lib directory
binarysniffer analyze app/lib -r -p "*.so" --fast -f json -o libs_analysis.json

# Analyze with custom threshold
binarysniffer analyze app/lib -r --threshold 0.3 --fast

# Skip metadata files for faster analysis
binarysniffer analyze app/lib -r --skip-metadata --fast
```

### Example 3: Performance Modes
```bash
# Fast mode - skip TLSH fuzzy matching for speed
binarysniffer analyze large_binary --fast

# Deep analysis mode for thorough scanning (slower)
binarysniffer analyze suspicious_binary --deep

# Custom timeout for slow files
binarysniffer analyze problematic_file --timeout 120
```

### Example 4: Parallel Processing and Large Files
```bash
# Analyze large directory with parallel processing
binarysniffer analyze /opt/android-sdk -r --parallel --fast

# Include large files (>50MB) in analysis
binarysniffer analyze /opt/android-sdk -r --include-large --fast

# Debug mode to see which files are being processed
binarysniffer analyze /opt/android-sdk -r -v --fast
```

### Example 5: ML Model Security Analysis (v1.9.7+)
```bash
# Analyze pickle files for malicious code
binarysniffer analyze model.pkl --show-features

# Analyze ONNX models for security risks
binarysniffer analyze model.onnx

# Analyze SafeTensors format for tampering
binarysniffer analyze model.safetensors

# Batch analysis of ML models
binarysniffer analyze models/ -r -p "*.pkl" -p "*.onnx" -p "*.pt" -p "*.safetensors"

# Output shows risk assessment:
# ┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
# ┃ Component         ┃ Confidence ┃ Classification  ┃ Type   ┃ Evidence         ┃
# ┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
# │ PyTorch-Native    │ 94.0%      │ BSD-3-Clause    │ string │ 2 patterns       │
# │ XGBoost           │ 77.3%      │ Apache-2.0      │ string │ 7 patterns       │
# │ Pickle-Malicious  │ 98.5%      │ CRITICAL        │ string │ 4 patterns       │
# │ Malformed-Pickle  │ 100.0%     │ WARNING         │ string │ 2 patterns       │
# └───────────────────┴────────────┴─────────────────┴────────┴──────────────────┘
```

### Example 6: Hash Calculation and Evidence
```bash
# Include file hashes in the output
binarysniffer analyze binary.exe --with-hashes

# Basic hashes only (MD5, SHA1, SHA256)
binarysniffer analyze binary.exe --basic-hashes

# Show detailed evidence of matches
binarysniffer analyze binary.so --show-evidence

# Output with hashes:
# File Hashes:
#   MD5:    009b6a807f883fc3e50ed7b5fcdd9db4
#   SHA1:   bf4b401d898b7ac454aa82bc97a50c121ccbe2ea
#   SHA256: a2f5fda6ba24ad67ec7eaa48a0bf61bba94a49b34c744eb02a9700feff79451e
#   TLSH:   T142C5AD12E77E1429DE997078A3873AF7E120BD540132D8D33BA6DA118BA94C53B25F37
```

### Example 7: Package Inventory Extraction (v1.8.6+)
```bash
# Basic inventory summary
binarysniffer inventory app.apk

# Export inventory with file hashes
binarysniffer inventory app.jar --analyze --include-hashes --format csv -o inventory.csv

# Full analysis with component detection
binarysniffer inventory app.ipa \
  --analyze \
  --include-hashes \
  --detect-components \
  --format json \
  -o full_inventory.json

# The inventory includes:
# - Complete file listing with relative paths
# - MIME types for all files
# - MD5, SHA1, SHA256 hashes (when --include-hashes)
# - TLSH and ssdeep fuzzy hashes (when --include-fuzzy-hashes)
# - Detected OSS components per file (when --detect-components)
# - Compression ratios and metadata
```

## Output Formats

### Table Format (Default)
- Human-readable table with components, confidence scores, classification, and evidence
- **Classification column** shows either software licenses (e.g., Apache-2.0, MIT) or security severity levels (CRITICAL, HIGH, MEDIUM, LOW, WARNING)
- Color-coded output for easy reading
- Summary statistics at the end

### JSON Format
```json
{
  "results": {
    "file_path": {
      "file_path": "downloads/my_android_app.apk",
      "file_size": 172796734,
      "file_type": "android",
      "matches": [
        {
          "component": "FFMPEG@unknown",
          "confidence": 0.88,
          "license": null,
          "match_type": "string",
          "evidence": {
            "signature_count": 1781,
            "match_method": "direct"
          }
        }
      ],
      "analysis_time": 0.562,
      "features_extracted": 1971
    }
  },
  "summary": {
    "total_files": 1,
    "successful_files": 1,
    "all_components": ["FFMPEG@unknown", "libpng@unknown", ...]
  }
}
```

### CSV Format
```csv
File,Component,Confidence,License,Type,Ecosystem
my_android_app.apk,FFMPEG@unknown,0.880,-,string,unknown
my_android_app.apk,libpng@unknown,0.740,-,string,unknown
```

## Detection Modes

BinarySniffer uses enhanced detection by default with dual matching strategy:

### Benefits
- **Better Detection Rate**: Finds more components with higher accuracy
- **Direct Matching**: Bypasses bloom filters for exhaustive string matching
- **Lower Thresholds**: Uses confidence threshold of 0.3 by default
- **More Signatures**: Loads all available signatures for matching

### When to Use
- Analyzing APK or JAR files with embedded libraries
- When standard mode misses expected components
- For security audits requiring comprehensive detection
- When accuracy is more important than speed

### Performance Impact
- Enhanced mode is slower (10-20 seconds for large files)
- Uses more memory to load all signatures
- Recommended for thorough analysis rather than quick scans

## Performance Tips

### 1. Use File Patterns
```bash
# Only analyze binary files, skip source code
binarysniffer analyze project/ -r -p "*.so" -p "*.dll" -p "*.exe"
```

### 2. Adjust Confidence Threshold
```bash
# Lower threshold for more matches (may include false positives)
binarysniffer analyze file.bin --threshold 0.2

# Higher threshold for fewer, more confident matches
binarysniffer analyze file.bin --threshold 0.8
```

### 3. Parallel Processing
```bash
# Use all CPU cores (default)
binarysniffer analyze large_dir/ -r --parallel

# Disable for debugging
binarysniffer analyze large_dir/ -r --no-parallel
```

### 4. Output to File
```bash
# Redirect large outputs to file for better performance
binarysniffer analyze project/ -r -f json -o results.json
```

## Troubleshooting

### Common Issues

#### 1. "No components detected"
**Solution**: Try with lower threshold
```bash
binarysniffer analyze file --threshold 0.2
```

#### 2. False Positives (v1.5.1+)
As of version 1.5.1, the signature database has been cleaned to reduce false positives:
- Removed 479 generic patterns that caused cross-component matches
- Fixed Apache HTTP Core appearing in unrelated binaries (e.g., FFmpeg)
- Improved signature quality by filtering patterns shorter than 6 characters

If you still experience false positives:
- Increase the confidence threshold: `--threshold 0.7`
- Report specific false positives for further signature refinement

#### 3. "Analysis taking too long" or "Tool gets stuck"
**Solutions**: Multiple options to speed up or fix hanging analysis
```bash
# Use fast mode to skip TLSH fuzzy matching
binarysniffer analyze dir/ -r --fast

# Skip metadata files (plist, xcprivacy, etc.) that can cause hangs
binarysniffer analyze app.app -r --skip-metadata

# Set custom timeout for problematic files (default: 60s)
binarysniffer analyze dir/ -r --timeout 10

# Debug mode to see which file is causing issues
binarysniffer analyze dir/ -r -v

# Use file patterns to limit scope
binarysniffer analyze dir/ -r -p "*.so" --no-parallel
```

#### 4. "Memory usage too high"
**Solution**: Process files in smaller batches
```bash
# Analyze subdirectories separately
find . -type d -maxdepth 1 -exec binarysniffer analyze {} \;
```

#### 5. "Permission denied" errors
**Solution**: Run with appropriate permissions or skip protected files
```bash
# Skip files that can't be read
binarysniffer analyze /system --recursive 2>/dev/null
```

### Debug Mode
Enable verbose logging for troubleshooting:
```bash
# Increase verbosity
binarysniffer -v analyze file.bin  # INFO level
binarysniffer -vv analyze file.bin # DEBUG level
```

### Getting Help
```bash
# Show help for any command
binarysniffer --help
binarysniffer analyze --help
binarysniffer signatures --help
```

## Advanced Usage

### Custom Configuration
Create a configuration file at `~/.binarysniffer/config.json`:
```json
{
  "default_threshold": 0.5,
  "parallel_workers": 4,
  "auto_update": true,
  "enhanced_by_default": true
}
```

### Signature Generation
Generate signatures from known binaries:
```bash
# Coming in future versions
binarysniffer generate-signatures /path/to/reference/binary
```

### API Integration
```python
from binarysniffer import BinarySniffer

# Programmatic usage
sniffer = BinarySniffer()
result = sniffer.analyze_file("myapp.exe", threshold=0.5, deep=True)

for match in result.matches:
    print(f"{match.component}: {match.confidence:.1%}")
```

## Best Practices

1. **Use `--fast` for quick scans, `--deep` for thorough analysis**
2. **Start with default threshold (0.5), adjust based on results**
3. **Use `--with-hashes` for security audits and verification**
4. **Use `-v/--debug` to troubleshoot hanging scans**
5. **Use `--skip-metadata` to speed up analysis of app bundles**
6. **Set custom `--timeout` for problematic files**
7. **Use JSON output for automated processing**
8. **Regularly update signature database**
9. **Combine with other tools for comprehensive analysis**

## Support

- GitHub Issues: [Report bugs and request features]
- Documentation: [Full API documentation]
- Signatures: [Contribute new signatures]

---

*Last updated: August 2025*
