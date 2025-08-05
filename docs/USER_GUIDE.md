# BinarySniffer User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Command Reference](#command-reference)
5. [Usage Examples](#usage-examples)
6. [Output Formats](#output-formats)
7. [Enhanced Detection Mode](#enhanced-detection-mode)
8. [Performance Tips](#performance-tips)
9. [Troubleshooting](#troubleshooting)

## Introduction

BinarySniffer is a high-performance CLI tool for detecting open source components in binary files through semantic signature matching. It can analyze executables, shared libraries, APK files, and other binary formats to identify embedded open source software components.

### Key Features
- Fast binary analysis with multi-tier matching system
- Support for multiple file types (ELF, PE, Mach-O, APK, JAR, etc.)
- Enhanced detection mode for improved accuracy
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
- `--deep` - Enable deep analysis mode
- `-f, --format [table|json|csv]` - Output format (default: table)
- `-o, --output PATH` - Save results to file
- `-p, --patterns TEXT` - File patterns to match (e.g., *.exe, *.so)
- `--parallel/--no-parallel` - Enable/disable parallel processing
- `--enhanced` - Use enhanced detection (recommended)

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

## Usage Examples

### Example 1: Analyzing an Android APK
```bash
# Enhanced analysis of a Kindle APK
binarysniffer analyze kindle.apk --enhanced

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
binarysniffer analyze app/lib -r -p "*.so" --enhanced -f json -o libs_analysis.json

# Analyze with custom threshold
binarysniffer analyze app/lib -r --threshold 0.3 --enhanced
```

### Example 3: Deep Analysis Mode
```bash
# Enable deep analysis for thorough scanning
binarysniffer analyze suspicious_binary --deep --enhanced
```

### Example 4: Parallel Processing
```bash
# Analyze large directory with parallel processing
binarysniffer analyze /opt/android-sdk -r --parallel --enhanced
```

## Output Formats

### Table Format (Default)
- Human-readable table with components, confidence scores, licenses, and evidence
- Color-coded output for easy reading
- Summary statistics at the end

### JSON Format
```json
{
  "results": {
    "file_path": {
      "file_path": "downloads/kindle.apk",
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
kindle.apk,FFMPEG@unknown,0.880,-,string,unknown
kindle.apk,libpng@unknown,0.740,-,string,unknown
```

## Enhanced Detection Mode

The `--enhanced` flag enables improved detection capabilities:

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
**Solution**: Try enhanced mode with lower threshold
```bash
binarysniffer analyze file --enhanced --threshold 0.2
```

#### 2. "Analysis taking too long"
**Solution**: Use file patterns to limit scope
```bash
binarysniffer analyze dir/ -r -p "*.so" --no-parallel
```

#### 3. "Memory usage too high"
**Solution**: Process files in smaller batches
```bash
# Analyze subdirectories separately
find . -type d -maxdepth 1 -exec binarysniffer analyze {} \;
```

#### 4. "Permission denied" errors
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

1. **Always use `--enhanced` for security audits**
2. **Start with default threshold, adjust based on results**
3. **Use JSON output for automated processing**
4. **Regularly update signature database**
5. **Combine with other tools for comprehensive analysis**

## Support

- GitHub Issues: [Report bugs and request features]
- Documentation: [Full API documentation]
- Signatures: [Contribute new signatures]

---

*Last updated: August 2025*