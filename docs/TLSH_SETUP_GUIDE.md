# TLSH Signature Database Setup Guide

## Overview

TLSH (Trend Micro Locality Sensitive Hash) provides fuzzy matching capabilities to detect similar binaries even when they've been modified, recompiled, or partially embedded. This guide shows you how to create and manage a TLSH signature database.

## Quick Setup

### 1. Install TLSH Support

```bash
# py-tlsh should already be installed, but if not:
pip install python-tlsh
```

### 2. Create TLSH Signature Database

The TLSH signature database is stored as JSON at `~/.binarysniffer/tlsh_signatures.json`.

You can create it using the provided example script:

```bash
# Create example database with system binaries
python create_tlsh_example.py

# Generate hash for a specific file
python create_tlsh_example.py /path/to/binary
```

### 3. Test TLSH Fuzzy Matching

```bash
# Analyze WITHOUT --fast flag to enable TLSH
binarysniffer analyze /usr/bin/curl --show-evidence

# Should show results like:
# │ curl@system     │ 100.0%     │ unknown        │ tlsh_fuzzy │ -               │
```

## TLSH Database Format

The TLSH signature database is a JSON file with this structure:

```json
{
  "component_version": {
    "component": "ComponentName",
    "version": "1.0.0",
    "hash": "T1A2C5D62F7318E9A3B4C5D6E7F89012345678901234567890123456789ABCDEF",
    "metadata": {
      "license": "MIT",
      "source_path": "/path/to/original/binary",
      "file_size": 123456,
      "description": "Component description",
      "ecosystem": "native",
      "created_at": "2024-01-15T10:30:00Z"
    }
  }
}
```

### Field Descriptions

- **component**: Component name (e.g., "OpenSSL", "FFmpeg", "curl")
- **version**: Version string (e.g., "1.1.1", "4.4.0", "system")
- **hash**: TLSH hash string (64-character hex starting with "T")
- **metadata**: Optional metadata including:
  - `license`: SPDX license identifier
  - `source_path`: Original file path
  - `file_size`: File size in bytes
  - `description`: Human-readable description
  - `ecosystem`: Package ecosystem (native, npm, pypi, etc.)
  - `created_at`: ISO timestamp

## Creating TLSH Signatures

### Manual Creation

```python
from binarysniffer.hashing.tlsh_hasher import TLSHHasher, TLSHSignatureStore

# Initialize
hasher = TLSHHasher()
store = TLSHSignatureStore()

# Generate hash for a binary
tlsh_hash = hasher.hash_file("/path/to/binary")

if tlsh_hash:
    # Add to database
    store.add_signature(
        component="MyComponent",
        version="2.1.0",
        tlsh_hash=tlsh_hash,
        metadata={
            "license": "Apache-2.0",
            "source_path": "/path/to/binary",
            "description": "My custom component"
        }
    )
```

### Batch Creation Script

```python
#!/usr/bin/env python3
"""Batch create TLSH signatures for multiple binaries"""

import os
from pathlib import Path
from binarysniffer.hashing.tlsh_hasher import TLSHHasher, TLSHSignatureStore

def scan_directory(directory, component_name, version):
    """Scan directory for binaries and create TLSH signatures"""
    hasher = TLSHHasher()
    store = TLSHSignatureStore()

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = Path(root) / file

            # Only process binary files
            if file_path.is_file() and file_path.stat().st_size > 256:
                tlsh_hash = hasher.hash_file(file_path)

                if tlsh_hash:
                    signature_id = f"{component_name}_{version}_{file}"
                    store.add_signature(
                        component=component_name,
                        version=version,
                        tlsh_hash=tlsh_hash,
                        metadata={
                            "source_path": str(file_path),
                            "file_size": file_path.stat().st_size,
                            "binary_name": file
                        }
                    )
                    print(f"✅ Added: {signature_id}")

# Usage
scan_directory("/usr/local/lib", "MyLibrary", "1.0.0")
```

## Using TLSH Fuzzy Matching

### Basic Usage

```bash
# Enable TLSH (default when not using --fast)
binarysniffer analyze binary_file

# Disable TLSH (fast mode)
binarysniffer analyze binary_file --fast

# Adjust similarity threshold (0-300, lower = more similar)
binarysniffer analyze binary_file --tlsh-threshold 50
```

### Threshold Guidelines

| Distance | Similarity Level | Use Case |
|----------|-----------------|----------|
| 0-30     | Very Similar    | Same component, minor changes |
| 31-70    | Similar         | Same component, moderate changes |
| 71-100   | Related         | Same family/library |
| 100+     | Loosely Related | Different but possibly related |

### Example Results

```bash
# Exact match (distance: 0)
│ curl@system     │ 100.0%     │ unknown        │ tlsh_fuzzy │ exact match     │

# Very similar (distance: 25)
│ FFmpeg@4.4.0    │ 92.0%      │ LGPL-2.1       │ tlsh_fuzzy │ distance: 25    │

# Similar (distance: 55)
│ OpenSSL@1.1.1   │ 78.0%      │ Apache-2.0     │ tlsh_fuzzy │ distance: 55    │
```

## Best Practices

1. **Start with known good binaries** - Use clean, official builds for signature creation
2. **Use appropriate thresholds** - Start with default (70) and adjust based on results
3. **Include version information** - Help distinguish between different versions
4. **Add meaningful metadata** - Include license, source, and description information
5. **Test your signatures** - Verify they work with known test cases
6. **Regular updates** - Refresh signatures when new versions are released

## Troubleshooting

### TLSH Not Working

```bash
# Check if py-tlsh is installed
pip show python-tlsh

# Check if TLSH database exists
ls -la ~/.binarysniffer/tlsh_signatures.json

# Check if TLSH is enabled (don't use --fast)
binarysniffer analyze binary_file --show-evidence

# Look for "tlsh_fuzzy" in the Type column
```

### No TLSH Matches Found

1. **File too small**: TLSH requires files >256 bytes
2. **No signatures**: Database might be empty or not created
3. **Threshold too strict**: Try increasing `--tlsh-threshold` to 100-150
4. **Fast mode enabled**: Remove `--fast` flag to enable TLSH

### False Positives

1. **Lower threshold**: Use stricter threshold (30-50)
2. **Generic binaries**: Some system utilities may match incorrectly
3. **Check evidence**: Look at TLSH distance in detailed output

## Integration with CI/CD

```bash
# Create signatures as part of build process
python generate_signatures.py --component MyApp --version ${BUILD_VERSION} --input dist/

# Test against known vulnerabilities
binarysniffer analyze build_artifacts/ --tlsh-threshold 40 --format json -o security_scan.json
```

## Performance Notes

- **Hash generation**: ~1-5ms per file
- **Comparison**: <1ms per signature
- **Memory usage**: ~100 bytes per signature
- **Storage**: JSON file grows ~200 bytes per signature

## Security Considerations

- TLSH signatures can help detect:
  - Modified/backdoored binaries
  - Vulnerable library versions
  - Unauthorized code changes
  - Supply chain contamination

- Limitations:
  - Won't detect completely different malware
  - Requires existing signature database
  - Quality depends on original signatures