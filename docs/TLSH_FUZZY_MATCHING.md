# TLSH Fuzzy Matching Support

## Overview

BinarySniffer now supports **TLSH (Trend Micro Locality Sensitive Hash)** fuzzy matching to detect similar OSS components even when they have been modified, recompiled, or partially embedded.

## What is TLSH?

TLSH is a fuzzy matching algorithm that:
- Generates a hash that captures the "essence" of binary/text data
- Allows similarity comparison between different files
- Detects near-matches even with modifications
- Works well for binaries, source code, and extracted features

## Benefits

1. **Find Modified Components** - Detect OSS even after patches or customization
2. **Version Detection** - Identify different versions of the same library
3. **Partial Matches** - Find components embedded within larger binaries
4. **Recompilation Tolerance** - Match despite different compiler optimizations

## Installation

TLSH support requires the `python-tlsh` library:

```bash
# Install with fuzzy matching support
pip install semantic-copycat-binarysniffer[fuzzy]

# Or install TLSH separately
pip install python-tlsh
```

## Usage

### CLI Options

```bash
# Basic analysis with TLSH (enabled by default)
binarysniffer analyze /path/to/binary

# Disable TLSH matching
binarysniffer analyze /path/to/binary --no-tlsh

# Adjust TLSH similarity threshold (0-300, lower = more similar)
binarysniffer analyze /path/to/binary --tlsh-threshold 50

# Very strict matching (nearly identical)
binarysniffer analyze /path/to/binary --tlsh-threshold 20

# Relaxed matching (find related components)
binarysniffer analyze /path/to/binary --tlsh-threshold 100
```

### TLSH Distance Thresholds

| Distance | Similarity Level | Use Case |
|----------|-----------------|----------|
| 0 | Identical | Exact same binary |
| 1-30 | Very Similar | Same component, minor changes |
| 31-70 | Similar | Same component, moderate changes |
| 71-100 | Related | Possibly same family/library |
| 100+ | Different | Unrelated components |

### Python API

```python
from binarysniffer.core.analyzer_enhanced import EnhancedBinarySniffer

# Create analyzer
analyzer = EnhancedBinarySniffer()

# Analyze with custom TLSH settings
result = analyzer.analyze_file(
    "binary.exe",
    use_tlsh=True,           # Enable TLSH matching
    tlsh_threshold=50        # Similarity threshold
)

# Check for TLSH matches
for match in result.matches:
    if match.match_type == 'tlsh_fuzzy':
        print(f"Fuzzy match: {match.component}")
        print(f"  Similarity: {match.evidence['similarity_score']:.2%}")
        print(f"  Distance: {match.evidence['tlsh_distance']}")
```

## How It Works

### 1. Signature Generation

When creating signatures, BinarySniffer now generates TLSH hashes:

```bash
binarysniffer signatures create /path/to/library --name MyLib
```

This:
- Extracts features (symbols, strings, functions)
- Generates a TLSH hash from these features
- Stores hash with the signature

### 2. Analysis Phase

During analysis:
1. Generate TLSH hash for target file
2. Compare against stored TLSH signatures
3. Calculate similarity scores
4. Report fuzzy matches above threshold

### 3. Match Merging

TLSH matches are merged with pattern matches:
- Direct pattern matches (high confidence)
- TLSH fuzzy matches (similarity-based confidence)
- Combined results sorted by confidence

## Advanced Usage

### Working with TLSH Hashes Directly

```python
from binarysniffer.hashing.tlsh_hasher import TLSHHasher

# Create hasher
hasher = TLSHHasher()

# Hash a file
hash1 = hasher.hash_file("binary1.exe")

# Hash extracted features
features = ["function1", "function2", "symbol1"]
hash2 = hasher.hash_features(features)

# Compare hashes
distance = hasher.compare(hash1, hash2)
similarity = hasher.similarity_score(hash1, hash2)
level = hasher.get_similarity_level(hash1, hash2)

print(f"Distance: {distance}")
print(f"Similarity: {similarity:.2%}")
print(f"Level: {level}")  # identical/very_similar/similar/related/different
```

### Managing TLSH Signature Store

```python
from binarysniffer.hashing.tlsh_hasher import TLSHSignatureStore

# Create store
store = TLSHSignatureStore()

# Add signature
store.add_signature(
    component="OpenSSL",
    version="3.0.0",
    tlsh_hash="T1234567890ABCDEF...",
    metadata={"license": "Apache-2.0"}
)

# Find matches
target_hash = "T1234567890ABCDEF..."
matches = store.find_matches(target_hash, threshold=70)

for match in matches:
    print(f"{match['component']} v{match['version']}")
    print(f"  Similarity: {match['similarity_score']:.2%}")
```

## Examples

### Example 1: Detect Modified FFmpeg

```bash
# Original FFmpeg binary
binarysniffer signatures create /usr/bin/ffmpeg --name FFmpeg

# Analyze custom-compiled FFmpeg
binarysniffer analyze ./my-ffmpeg --tlsh-threshold 50
# Output: FFmpeg detected with 85% similarity (TLSH distance: 42)
```

### Example 2: Find Similar Libraries

```bash
# Analyze with relaxed threshold to find related components
binarysniffer analyze app.exe --tlsh-threshold 100

# May detect:
# - OpenSSL 1.1.1 (distance: 65)
# - LibreSSL 3.0 (distance: 89)  # Related but different
```

### Example 3: Version Detection

```bash
# Different versions of same library will have small TLSH distances
binarysniffer analyze libcurl.so
# Output:
# - curl 7.88.0 (pattern match, 95% confidence)
# - curl 7.87.0 (TLSH match, distance: 28, 88% similarity)
```

## Performance Considerations

- **TLSH Generation**: Fast (~milliseconds per file)
- **Comparison**: Very fast (microseconds)
- **Memory**: Minimal (72-byte hash per signature)
- **Storage**: Signatures include TLSH hash (adds ~100 bytes)

## Limitations

1. **Minimum Size**: Files need 256+ bytes for TLSH
2. **Feature-Based**: Quality depends on feature extraction
3. **False Positives**: Very generic code may match incorrectly
4. **Threshold Tuning**: May need adjustment per use case

## Best Practices

1. **Start with Default Threshold** (70) and adjust based on results
2. **Use Lower Thresholds** (30-50) for version detection
3. **Use Higher Thresholds** (80-100) for family detection
4. **Combine with Pattern Matching** for best accuracy
5. **Generate Signatures from Clean Binaries** for best hashes

## Troubleshooting

### TLSH Not Working

```bash
# Check if TLSH is installed
python -c "import tlsh; print('TLSH available')"

# Install if missing
pip install python-tlsh
```

### No TLSH Matches Found

- File too small (< 256 bytes)
- Threshold too strict (try increasing)
- No TLSH signatures in database
- Too different from known components

### Too Many False Positives

- Threshold too relaxed (try decreasing)
- Generic code patterns
- Use pattern matching confidence as primary filter

## Technical Details

### TLSH Algorithm

TLSH uses:
- Sliding window hash
- Quartile boundaries
- Body and tail hashes
- 72-byte final hash

### Integration Points

1. **Signature Generation** - `SignatureGenerator` creates TLSH hashes
2. **Storage** - `TLSHSignatureStore` manages hash database
3. **Matching** - `EnhancedBinarySniffer` applies fuzzy matching
4. **CLI** - `--use-tlsh` and `--tlsh-threshold` options

## Future Enhancements

- [ ] Automatic threshold tuning
- [ ] TLSH clustering for component families
- [ ] Weighted combination with pattern matching
- [ ] TLSH-based version detection
- [ ] Bulk TLSH signature generation

## References

- [TLSH GitHub](https://github.com/trendmicro/tlsh)
- [TLSH Paper](https://github.com/trendmicro/tlsh/blob/master/TLSH_CTC_final.pdf)
- [python-tlsh Documentation](https://pypi.org/project/python-tlsh/)