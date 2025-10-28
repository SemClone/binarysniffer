# Signature Creation Guide

## Overview

Signatures are patterns extracted from binaries or source code that uniquely identify OSS components. BinarySniffer provides tools to create, validate, and contribute signatures.

## Creating Signatures

### From Binary Files

Binary files provide the most reliable signatures as they contain compiled patterns unique to each component.

```bash
# Basic signature creation
binarysniffer signatures create /usr/bin/ffmpeg --name FFmpeg --version 4.4.1

# With complete metadata
binarysniffer signatures create /usr/local/lib/libcurl.so \
  --name "cURL" \
  --version "7.81.0" \
  --license "MIT" \
  --publisher "Daniel Stenberg" \
  --description "Command line tool and library for transferring data with URLs" \
  --output signatures/curl.json
```

### From Source Code

Source code analysis extracts function names, class definitions, and unique identifiers.

```bash
# Analyze source directory
binarysniffer signatures create /path/to/source \
  --name "MyLibrary" \
  --version "1.0.0" \
  --license "Apache-2.0" \
  --min-signatures 20  # Require at least 20 unique patterns
```

### From Multiple Files

Create comprehensive signatures from multiple related files:

```bash
# Create signature from multiple binaries
binarysniffer signatures create \
  /usr/lib/libssl.so \
  /usr/lib/libcrypto.so \
  --name "OpenSSL" \
  --version "1.1.1" \
  --license "Apache-2.0"
```

## Signature Quality

### Minimum Requirements

Good signatures should have:
- At least 10 unique patterns (configurable with `--min-signatures`)
- Patterns longer than 6 characters
- Library-specific prefixes when possible
- No generic programming terms

### Collision Detection

BinarySniffer automatically checks for pattern collisions with existing signatures:

```bash
# Check for collisions
binarysniffer signatures create /usr/bin/myapp \
  --name "MyApp" \
  --check-collisions

# Interactive review
binarysniffer signatures create /usr/bin/myapp \
  --name "MyApp" \
  --interactive  # Review each collision

# Auto-remove high-severity collisions
binarysniffer signatures create /usr/bin/myapp \
  --name "MyApp" \
  --check-collisions \
  --collision-threshold high  # Remove patterns in 3+ components
```

### Collision Severity Levels

- **Critical**: Pattern in 5+ components (likely generic)
- **High**: Pattern in 3-4 components  
- **Medium**: Pattern in 2 unrelated components
- **Low**: Pattern in 2 related components (e.g., ffmpeg/libav)

## Signature Format

Signatures are stored as JSON files with the following structure:

```json
{
  "name": "Component Name",
  "version": "1.0.0",
  "license": "MIT",
  "publisher": "Publisher Name",
  "description": "Component description",
  "url": "https://github.com/...",
  "ecosystem": "native",
  "signatures": [
    {
      "pattern": "unique_function_name",
      "type": "function",
      "confidence": 0.9
    },
    {
      "pattern": "LIBRARY_VERSION_STRING",
      "type": "string",
      "confidence": 0.95
    }
  ],
  "metadata": {
    "created_at": "2024-01-01T00:00:00Z",
    "source_files": ["binary.so"],
    "total_patterns": 25,
    "unique_patterns": 20
  }
}
```

## Validation

### Validate Before Adding

Always validate signatures before adding to the database:

```bash
# Validate signature file
binarysniffer signatures validate signatures/new-component.json

# Test against known files
binarysniffer signatures test signatures/component.json /path/to/test/files
```

### Common Validation Checks

1. **Pattern Length**: Patterns must be ≥6 characters
2. **Generic Terms**: Filters ~100 common programming terms
3. **Uniqueness**: No duplicate patterns within signature
4. **Format**: Valid JSON structure
5. **Required Fields**: name, version, signatures array

## Testing Signatures

### Local Testing

Test signatures before committing:

```bash
# Import signature locally
binarysniffer signatures import signatures/my-component.json

# Test detection
binarysniffer analyze /path/to/test/binary

# Check for false positives
binarysniffer analyze /path/to/unrelated/files
```

### Coverage Testing

Ensure signatures detect multiple versions:

```bash
# Test against different versions
for version in v1.0 v1.1 v2.0; do
  binarysniffer analyze /path/to/component/$version
done
```

## Contributing Signatures

### Submission Process

1. **Fork the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/binarysniffer
   cd binarysniffer
   ```

2. **Create signature**:
   ```bash
   binarysniffer signatures create /path/to/component \
     --name "Component" \
     --version "1.0.0" \
     --license "MIT" \
     --check-collisions \
     --output signatures/component.json
   ```

3. **Validate signature**:
   ```bash
   binarysniffer signatures validate signatures/component.json
   ```

4. **Test locally**:
   ```bash
   binarysniffer signatures import signatures/component.json
   binarysniffer analyze /path/to/test/files
   ```

5. **Submit PR**:
   ```bash
   git add signatures/component.json
   git commit -m "Add signatures for Component v1.0.0"
   git push origin main
   # Create Pull Request on GitHub
   ```

### Contribution Guidelines

- One component per JSON file
- Use lowercase, hyphenated filenames (e.g., `apache-commons.json`)
- Include version in signature metadata
- Provide accurate license information
- Test for false positives
- Document any special considerations

## Advanced Topics

### Pattern Extraction Options

```bash
# Control pattern extraction
binarysniffer signatures create binary.exe \
  --name "Component" \
  --min-length 8        # Minimum pattern length (default: 6)
  --max-patterns 1000   # Maximum patterns to extract
  --include-numbers     # Include patterns with numbers
  --case-sensitive      # Preserve case in patterns
```

### Multi-Architecture Support

Create signatures covering multiple architectures:

```bash
# x86_64 signature
binarysniffer signatures create /usr/lib/x86_64/libfoo.so \
  --name "libfoo" \
  --arch "x86_64" \
  --output signatures/libfoo-x86_64.json

# ARM64 signature
binarysniffer signatures create /usr/lib/aarch64/libfoo.so \
  --name "libfoo" \
  --arch "arm64" \
  --output signatures/libfoo-arm64.json

# Merge architectures
binarysniffer signatures merge \
  signatures/libfoo-x86_64.json \
  signatures/libfoo-arm64.json \
  --output signatures/libfoo.json
```

### Signature Optimization

Optimize signatures for better performance:

```bash
# Remove redundant patterns
binarysniffer signatures optimize signatures/component.json \
  --remove-substrings   # Remove patterns that are substrings of others
  --remove-similar      # Remove highly similar patterns
  --min-confidence 0.7  # Remove low-confidence patterns
```

## Best Practices

### DO's
- ✅ Create signatures from official releases
- ✅ Include version information
- ✅ Test against multiple samples
- ✅ Check for collisions
- ✅ Validate before submission
- ✅ Use descriptive component names

### DON'Ts
- ❌ Don't include passwords or keys
- ❌ Don't use overly generic patterns
- ❌ Don't skip validation
- ❌ Don't include debug symbols only
- ❌ Don't mix multiple components
- ❌ Don't use patterns < 6 characters

## Troubleshooting

### Few Patterns Extracted

If extraction yields few patterns:
- Check if binary is stripped
- Try source code instead
- Use `--min-length 4` for shorter patterns
- Analyze multiple related files

### High Collision Rate

If many collisions detected:
- Review patterns manually with `--interactive`
- Increase minimum pattern length
- Focus on library-specific prefixes
- Consider version-specific strings

### False Positives

If signature causes false positives:
- Increase pattern count requirement
- Remove generic patterns
- Add more specific patterns
- Test against diverse file set

## Examples

### Creating FFmpeg Signature

```bash
# Extract from multiple FFmpeg binaries
binarysniffer signatures create \
  /usr/bin/ffmpeg \
  /usr/bin/ffprobe \
  /usr/lib/libavcodec.so \
  /usr/lib/libavformat.so \
  --name "FFmpeg" \
  --version "4.4.1" \
  --license "LGPL-2.1" \
  --publisher "FFmpeg Team" \
  --description "Complete multimedia framework" \
  --check-collisions \
  --collision-threshold medium \
  --min-signatures 50 \
  --output signatures/ffmpeg.json

# Validate
binarysniffer signatures validate signatures/ffmpeg.json

# Test
binarysniffer analyze /usr/bin/ffmpeg
```

### Creating Python Package Signature

```bash
# From installed package
binarysniffer signatures create \
  /usr/lib/python3.9/site-packages/numpy \
  --name "NumPy" \
  --version "1.21.0" \
  --license "BSD-3-Clause" \
  --ecosystem "python" \
  --min-length 10 \
  --output signatures/numpy.json
```

### Creating Mobile SDK Signature

```bash
# Extract from AAR/Framework
binarysniffer signatures create \
  facebook-sdk.aar \
  --name "Facebook Android SDK" \
  --version "12.0.0" \
  --license "Facebook Platform License" \
  --ecosystem "android" \
  --check-collisions \
  --output signatures/facebook-android-sdk.json
```