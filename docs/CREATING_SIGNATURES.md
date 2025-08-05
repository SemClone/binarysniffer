# Creating Signatures for BinarySniffer

This guide explains how to create high-quality signatures for detecting open-source components.

## Overview

BinarySniffer uses pattern-based signatures to identify components. Good signatures are:
- **Specific**: Unique to the component (not generic like "test" or "init")
- **Stable**: Present across different versions
- **Symbol-based**: Extracted from actual function/variable names in binaries

## Methods for Creating Signatures

### 1. From Binary Files (Recommended)

The most accurate method is to extract symbols directly from compiled binaries:

```bash
# Extract signatures from a binary
python scripts/create_signatures.py \
  --binary /path/to/ffmpeg \
  --name "FFmpeg" \
  --version "4.4.1" \
  --license "LGPL-2.1" \
  --publisher "FFmpeg Team" \
  --output signatures/ffmpeg.json
```

This method:
- Uses `readelf`/`nm` to extract actual symbols
- Identifies library-specific prefixes (e.g., `av_`, `avcodec_`)
- Filters out generic symbols automatically
- Groups related symbols by component

### 2. From Source Code

For interpreted languages or when binaries aren't available:

```bash
# Extract signatures from source code
python scripts/create_signatures.py \
  --source /path/to/project/src \
  --name "React" \
  --version "18.0.0" \
  --license "MIT" \
  --publisher "Facebook" \
  --output signatures/react.json
```

This method:
- Parses source files for functions, classes, and constants
- Uses CTags when available for better extraction
- Works with multiple programming languages

### 3. Manual Creation

For fine-tuning or special cases, you can create signatures manually:

```json
{
  "component": {
    "name": "OpenSSL",
    "version": "3.0.0",
    "license": "Apache-2.0",
    "publisher": "OpenSSL Project"
  },
  "signatures": [
    {
      "pattern": "SSL_",
      "type": "prefix_pattern",
      "confidence": 0.85
    },
    {
      "pattern": "EVP_EncryptInit_ex",
      "type": "function_pattern", 
      "confidence": 0.95
    },
    {
      "pattern": "OpenSSL 3.0.0",
      "type": "version_string",
      "confidence": 0.98
    }
  ]
}
```

## Best Practices

### 1. Use Library Prefixes

Good signatures often start with library-specific prefixes:
- ✅ `av_` (FFmpeg)
- ✅ `SSL_` (OpenSSL)
- ✅ `png_` (libpng)
- ❌ `get_` (too generic)
- ❌ `init_` (too generic)

### 2. Include Multiple Signature Types

A good signature file contains:
- **Prefixes**: `av_`, `x264_` (confidence: 0.85)
- **Specific functions**: `av_register_all`, `SSL_CTX_new` (confidence: 0.90)
- **Version strings**: `FFmpeg version 4.4.1` (confidence: 0.95)
- **Constants**: `PNG_LIBPNG_VER_STRING` (confidence: 0.95)

### 3. Test Your Signatures

Always test signatures against known files:

```bash
# Test the signature file
binarysniffer analyze /path/to/test/binary --debug

# Check for false positives
binarysniffer analyze /path/to/unrelated/binary --debug
```

### 4. Avoid Generic Patterns

These patterns are too generic and will cause false positives:
- ❌ Single words: `test`, `log`, `data`, `init`
- ❌ Common prefixes without underscore: `get`, `set`, `add`
- ❌ Short patterns: `fmt`, `db`, `io` (unless with underscore)
- ❌ Language keywords: `class`, `function`, `var`

### 5. Set Appropriate Confidence Levels

- **0.95-1.0**: Version strings, unique identifiers
- **0.85-0.95**: Specific function names
- **0.75-0.85**: Library prefixes
- **0.70-0.75**: Common patterns (use sparingly)

## Examples

### Creating FFmpeg Signatures

```bash
# 1. Extract ffmpeg binary from archive
unzip ffmpeg-4.4.1-linux-64.zip

# 2. Create signatures
python scripts/create_signatures.py \
  --binary ffmpeg \
  --name "FFmpeg" \
  --version "4.4.1" \
  --license "LGPL-2.1/GPL-2.0" \
  --publisher "FFmpeg Team" \
  --description "Multimedia framework for audio/video processing" \
  --output signatures/ffmpeg-4.4.1.json

# 3. Review generated signatures
cat signatures/ffmpeg-4.4.1.json | jq '.signatures[:10]'
```

Expected output:
```json
[
  {
    "pattern": "av_",
    "type": "prefix_pattern",
    "confidence": 0.85
  },
  {
    "pattern": "av_register_all",
    "type": "function_pattern",
    "confidence": 0.9
  },
  {
    "pattern": "avcodec_",
    "type": "prefix_pattern",
    "confidence": 0.85
  }
]
```

### Creating Python Package Signatures

```bash
# From source code
python scripts/create_signatures.py \
  --source /path/to/django \
  --name "Django" \
  --version "4.0" \
  --license "BSD-3-Clause" \
  --publisher "Django Software Foundation" \
  --output signatures/django.json
```

## Signature File Format

```json
{
  "component": {
    "name": "Component Name",
    "version": "1.0.0",
    "category": "imported",
    "platforms": ["all"],
    "languages": ["native"],
    "description": "Component description",
    "license": "License-ID",
    "publisher": "Publisher Name"
  },
  "signature_metadata": {
    "version": "1.0.0",
    "created": "2025-01-01T00:00:00Z",
    "signature_count": 20,
    "confidence_threshold": 0.7,
    "source": "binary_analysis",
    "extraction_method": "symbol_extraction"
  },
  "signatures": [
    {
      "id": "component_0",
      "type": "prefix_pattern",
      "pattern": "prefix_",
      "confidence": 0.85,
      "context": "binary_symbol",
      "platforms": ["all"]
    }
  ]
}
```

## Troubleshooting

### Too Few Signatures Generated

- Ensure the binary is not stripped (`file binary` should show "not stripped")
- Try analyzing multiple related binaries
- Include source code if available
- Lower the confidence threshold

### Too Many False Positives

- Remove generic patterns
- Increase confidence thresholds
- Use more specific function names instead of prefixes
- Test against unrelated binaries

### Platform-Specific Issues

- On macOS: Install GNU tools (`brew install binutils`)
- On Windows: Use WSL or Docker
- Ensure tools are in PATH: `readelf`, `nm`, `strings`

## Contributing Signatures

1. Create high-quality signatures following this guide
2. Test thoroughly to avoid false positives
3. Submit a pull request with:
   - The signature JSON file in `signatures/`
   - Test results showing detection accuracy
   - License information for the component

## Advanced: Bulk Signature Generation

For multiple components:

```bash
#!/bin/bash
# bulk_create_signatures.sh

for binary in binaries/*.so; do
  name=$(basename "$binary" .so)
  python scripts/create_signatures.py \
    --binary "$binary" \
    --name "$name" \
    --output "signatures/$name.json"
done
```

## Summary

Good signatures are the key to accurate component detection. Always:
1. Extract from real binaries when possible
2. Use specific patterns, not generic words
3. Include multiple signature types
4. Test to avoid false positives
5. Document the component's license