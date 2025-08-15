# API Reference

## Core Classes

### EnhancedBinarySniffer

The main analyzer class for detecting OSS components in files.

```python
from binarysniffer import EnhancedBinarySniffer

sniffer = EnhancedBinarySniffer(
    db_path=None,           # Custom database path (default: ~/.binarysniffer/signatures.db)
    cache_size_mb=100,      # Cache size in MB
    parallel_workers=4      # Number of parallel workers
)
```

#### Methods

##### analyze_file()
Analyze a single file for OSS components.

```python
result = sniffer.analyze_file(
    file_path,                      # Path to file to analyze
    confidence_threshold=0.5,       # Minimum confidence (0.0-1.0)
    use_tlsh=True,                 # Enable TLSH fuzzy matching
    tlsh_threshold=50,              # TLSH similarity threshold (lower = more similar)
    include_hashes=False,           # Include file hashes in result
    include_fuzzy_hashes=False      # Include TLSH/ssdeep hashes
)

# Returns: AnalysisResult object
```

##### analyze_directory()
Analyze all files in a directory.

```python
results = sniffer.analyze_directory(
    directory_path,                 # Directory to analyze
    recursive=True,                 # Recurse into subdirectories
    patterns=None,                  # List of glob patterns (e.g., ["*.so", "*.dll"])
    confidence_threshold=0.5,       # Minimum confidence
    parallel=True                   # Use parallel processing
)

# Returns: Dict[str, AnalysisResult] - filepath to result mapping
```

##### extract_package_inventory()
Extract comprehensive inventory from archive files.

```python
inventory = sniffer.extract_package_inventory(
    package_path,                   # Path to package/archive
    analyze_contents=False,         # Extract and analyze file contents
    include_hashes=False,           # Calculate MD5, SHA1, SHA256
    include_fuzzy_hashes=False,     # Calculate TLSH and ssdeep
    detect_components=False         # Run OSS detection on files
)

# Returns: Dict with inventory data
```

##### analyze_licenses()
Detect and analyze software licenses.

```python
license_result = sniffer.analyze_licenses(
    path,                          # File or directory path
    check_compatibility=True,       # Check license compatibility
    show_files=False               # Include file paths in result
)

# Returns: Dict with license detection results
```

### AnalysisResult

Result object from file analysis.

```python
class AnalysisResult:
    file_path: str                 # Analyzed file path
    file_type: str                 # Detected file type
    matches: List[ComponentMatch]  # Detected components
    metadata: Dict                 # Additional metadata
    features_extracted: int        # Number of features extracted
    analysis_time: float          # Analysis duration in seconds
    file_hashes: Dict             # File hashes (if requested)
```

### ComponentMatch

Represents a detected OSS component.

```python
class ComponentMatch:
    component: str                 # Component name
    confidence: float             # Confidence score (0.0-1.0)
    license: str                  # License or severity level
    version: Optional[str]        # Version if detected
    match_type: str              # 'direct', 'minhash', or 'tlsh_fuzzy'
    evidence: Dict               # Match evidence details
    matched_patterns: int        # Number of patterns matched
```

## Utility Functions

### create_signature()
Create signatures from binaries or source code.

```python
from binarysniffer.signatures import create_signature

signature = create_signature(
    file_path,                    # Path to binary or source
    name="Component Name",        # Component name
    version="1.0.0",             # Version
    license="MIT",               # License
    publisher=None,              # Publisher name
    description=None,            # Description
    min_signatures=10,           # Minimum patterns required
    check_collisions=True        # Check for pattern collisions
)

# Returns: Dict with signature data
```

### validate_signature()
Validate signature quality.

```python
from binarysniffer.signatures import validate_signature

is_valid, issues = validate_signature(
    signature_data,              # Signature dict or JSON path
    check_generics=True,        # Check for generic patterns
    min_pattern_length=6        # Minimum pattern length
)

# Returns: Tuple[bool, List[str]] - validity and issues list
```

## Configuration

### Config File Location
`~/.binarysniffer/config.json`

### Configuration Options
```python
{
    "signature_sources": [       # Signature update sources
        "https://github.com/..."
    ],
    "cache_size_mb": 100,       # Memory cache size
    "parallel_workers": 4,       # Parallel processing threads
    "min_confidence": 0.5,      # Default confidence threshold
    "auto_update": true,        # Auto-update signatures
    "update_check_interval_days": 7,
    "max_archive_files": 100,   # Max files to process in archives
    "max_file_size_mb": 100     # Max file size to analyze
}
```

## Examples

### Basic Component Detection
```python
from binarysniffer import EnhancedBinarySniffer

sniffer = EnhancedBinarySniffer()

# Analyze APK file
result = sniffer.analyze_file("app.apk")
print(f"Found {len(result.matches)} components")

for match in result.matches:
    print(f"  {match.component}: {match.confidence:.1%}")
```

### Batch Analysis with Filtering
```python
# Analyze only .so and .dll files
results = sniffer.analyze_directory(
    "/path/to/project",
    recursive=True,
    patterns=["*.so", "*.dll"],
    confidence_threshold=0.7
)

# Process results
for file_path, result in results.items():
    if result.matches:
        print(f"\n{file_path}:")
        for match in result.matches:
            print(f"  - {match.component} ({match.license})")
```

### SBOM Generation
```python
from binarysniffer import EnhancedBinarySniffer
from binarysniffer.sbom import generate_cyclonedx

sniffer = EnhancedBinarySniffer()
result = sniffer.analyze_file("application.jar")

# Generate CycloneDX SBOM
sbom = generate_cyclonedx(
    results={"application.jar": result},
    include_evidence=True,
    include_hashes=True
)

# Save to file
import json
with open("sbom.json", "w") as f:
    json.dump(sbom, f, indent=2)
```

### ML Model Security Analysis
```python
# Analyze ML model for security threats
result = sniffer.analyze_file("model.pkl")

for match in result.matches:
    if match.license in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        print(f"Security threat detected: {match.component}")
        print(f"Severity: {match.license}")
        print(f"Evidence: {match.evidence}")
```

### Custom Signature Creation
```python
from binarysniffer.signatures import create_signature, import_signature

# Create signature from binary
signature = create_signature(
    "/usr/local/bin/mycli",
    name="MyCLI Tool",
    version="2.0.0",
    license="Apache-2.0",
    publisher="My Company",
    min_signatures=20
)

# Save signature
import json
with open("mycli.json", "w") as f:
    json.dump(signature, f, indent=2)

# Import into database
import_signature("mycli.json")
```

### License Compatibility Check
```python
# Check license compatibility in project
license_result = sniffer.analyze_licenses(
    "/path/to/project",
    check_compatibility=True
)

if not license_result['compatibility']['compatible']:
    print("License compatibility issues found:")
    for warning in license_result['compatibility']['warnings']:
        print(f"  - {warning}")
```

## Error Handling

```python
from binarysniffer import EnhancedBinarySniffer
from binarysniffer.exceptions import (
    AnalysisError,
    SignatureError,
    DatabaseError
)

sniffer = EnhancedBinarySniffer()

try:
    result = sniffer.analyze_file("file.bin")
except AnalysisError as e:
    print(f"Analysis failed: {e}")
except SignatureError as e:
    print(f"Signature error: {e}")
except DatabaseError as e:
    print(f"Database error: {e}")
```

## Thread Safety

The `EnhancedBinarySniffer` class is thread-safe for read operations. For concurrent writes (signature updates), use appropriate locking mechanisms.

```python
import threading
from binarysniffer import EnhancedBinarySniffer

# Single instance can be shared across threads
sniffer = EnhancedBinarySniffer()

def analyze_file(path):
    result = sniffer.analyze_file(path)
    # Process result...

# Create threads
threads = []
for file_path in file_paths:
    t = threading.Thread(target=analyze_file, args=(file_path,))
    threads.append(t)
    t.start()

# Wait for completion
for t in threads:
    t.join()
```

## Performance Tips

1. **Use Fast Mode** for large files when fuzzy matching isn't needed:
   ```python
   result = sniffer.analyze_file("large.bin", use_tlsh=False)
   ```

2. **Batch Processing** for multiple files:
   ```python
   # More efficient than individual calls
   results = sniffer.analyze_directory("/path", parallel=True)
   ```

3. **Adjust Cache Size** for memory-constrained environments:
   ```python
   sniffer = EnhancedBinarySniffer(cache_size_mb=50)
   ```

4. **Filter File Types** to avoid unnecessary processing:
   ```python
   results = sniffer.analyze_directory(
       "/path",
       patterns=["*.exe", "*.dll", "*.so"]
   )
   ```