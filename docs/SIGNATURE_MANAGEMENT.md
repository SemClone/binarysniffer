# Signature Management

This document describes how to create, update, and manage signature databases for the Semantic Copycat BinarySniffer.

## Overview

The BinarySniffer uses a SQLite-based signature database that contains:
- **Components**: OSS libraries/frameworks with metadata (name, version, publisher, license)
- **Signatures**: String patterns, function names, and identifiers extracted from each component
- **Indexes**: Optimized trigram and hash indexes for fast matching

## Database Location and Version Management

### Database Storage Location
The signature database is **NOT included in the Python package** to avoid version conflicts. Instead, it's created locally:

- **Default Location**: `data/signatures.db` (relative to current working directory)
- **User Data Directory**: `~/.binarysniffer/signatures.db` (when using standard config)
- **CLI Override**: `--data-dir /custom/path` to specify custom location
- **Library Override**: `BinarySniffer(db_path="custom/path.db")`

### Package Installation Behavior
When you install or upgrade the package:
- ✅ **No Database Conflicts**: The `.db` files are NOT included in wheel/tarball
- ✅ **Clean Upgrades**: Your existing signature database is preserved
- ✅ **No Overwrites**: Package upgrades never replace your signature data
- ✅ **User Control**: You manage signature updates separately from code updates

### Database Lifecycle
1. **First Run**: Database is created empty, needs signature migration or download
2. **Upgrades**: Code updates don't affect signature database
3. **Signature Updates**: Managed separately via CLI commands or manual migration

## Current Signature Database

The project includes a pre-built signature database with **90+ OSS components** migrated from the BSA (Binary Signature Analysis) project, including:

### Major Components
- **Mobile SDKs**: Facebook Android SDK, Google Firebase, Google Ads
- **Java Libraries**: Jackson, Apache Commons, Google Guava, Netty
- **Media Libraries**: FFmpeg, x264, x265, Vorbis, Opus
- **Crypto Libraries**: Bouncy Castle, mbedTLS, OpenSSL variants
- **Development Tools**: Lombok, Dagger, RxJava, OkHttp

### Component Categories
- **Android/Mobile**: 15+ SDKs and frameworks
- **Java/JVM**: 25+ libraries and frameworks  
- **Native/C++**: 20+ media, crypto, and system libraries
- **Go Libraries**: 10+ standard and third-party packages
- **JavaScript/Node**: 5+ popular packages

## Creating Signatures

### From BSA Format (JSON)

The project includes a migration script for BSA-format signature files:

```bash
# Migrate specific signatures (for testing)
python scripts/simple_migrate.py path/to/signatures/ --limit 10

# Migrate all signatures
python scripts/simple_migrate.py path/to/signatures/

# Migrate to custom database location
python scripts/simple_migrate.py path/to/signatures/ --db-path custom/signatures.db
```

### BSA JSON Format

The project includes a signature template at `signatures/template.json`:

```json
{
  "publisher": "Example Publisher",
  "updated": "2025-08-04",
  "package": "Example Library",
  "version": "1.0.0",
  "license": "MIT",
  "ecosystem": "native",
  "description": "Template for creating signature files",
  "symbols": [
    "ExampleLibraryInit",
    "ExampleLibraryProcess", 
    "ExampleLibraryCleanup",
    "ExampleFunction",
    "EXAMPLE_CONSTANT",
    "ExampleClass",
    "example_namespace"
  ],
  "metadata": {
    "signature_type": "manual",
    "confidence_default": 0.7,
    "language": "C++",
    "categories": ["utility", "framework"],
    "notes": "Template showing expected JSON format"
  }
}
```

**Required Fields:**
- `publisher`: Organization or individual who maintains the component
- `package`: Component name (e.g., "Apache HTTP Core")
- `symbols`: Array of identifiers found in the component
- `license`: SPDX license identifier or license name

**Optional Fields:**
- `version`: Specific version of the component
- `ecosystem`: Package ecosystem (native, npm, maven, pypi, etc.)
- `updated`: Last update date (YYYY-MM-DD format)
- `description`: Human-readable description
- `metadata`: Additional structured data for processing

### Manual Signature Creation

For custom signature creation, use the database API:

```python
from binarysniffer.storage.database import SignatureDatabase

# Initialize database
db = SignatureDatabase("custom_signatures.db")

# Add a component
component_data = {
    'name': 'MyLibrary',
    'version': '2.1.0',
    'publisher': 'My Company',
    'license': 'MIT',
    'ecosystem': 'native',
    'description': 'Custom library signatures'
}
component_id = db.add_component(component_data)

# Add signatures
signatures = ['MyLibraryInit', 'MyLibraryProcess', 'MyLibraryCleanup']
for sig in signatures:
    db.add_signature(
        component_id=component_id,
        signature=sig,
        sig_type=1,  # String signature
        confidence=0.8
    )

# Build indexes for performance
db.build_indexes()
```

## Updating Signatures

### From Upstream Sources

The tool provides CLI commands for signature updates:

```bash
# Check for and apply signature updates
binarysniffer update

# Force full update (replace current database)
binarysniffer update --force

# Check current signature database status
binarysniffer stats

# Show configuration (including data directory)
binarysniffer config
```

**Note**: In the current implementation (v1.1.0), the upstream update mechanism is a stub. For production use, you would:
1. Set up a signature server with versioned signature files
2. Configure `signature_sources` in the config file
3. Use the migration scripts to populate your database

### Programmatic Updates

```python
from binarysniffer import BinarySniffer

analyzer = BinarySniffer()

# Check for updates
if analyzer.signature_db.needs_update():
    print("Updates available")
    
# Update signatures
analyzer.update_signatures(source_url="https://example.com/signatures.db")

# Or merge from another database
analyzer.merge_signatures("additional_signatures.db")
```

### Delta Updates

For efficient updates, the system supports delta updates:

```python
# Create delta from two databases
db.create_delta("old_signatures.db", "new_signatures.db", "delta.db")

# Apply delta to existing database
db.apply_delta("delta.db")
```

## Signature Quality

### Confidence Scoring

Signatures are assigned confidence scores based on:
- **0.9-1.0**: Highly specific identifiers (unique function names, copyright strings)
- **0.7-0.8**: Moderately specific (common function names with context)
- **0.5-0.6**: Generic patterns (common variable names, standard patterns)
- **<0.5**: Low confidence (too generic for reliable detection)

### Best Practices

1. **Unique Identifiers**: Prefer copyright strings, unique function names, version strings
2. **Avoid Generic Terms**: Skip common words like "init", "process", "data"
3. **Context Matters**: Include namespace/package context when possible
4. **Version Specificity**: Include version-specific identifiers when available
5. **License Compliance**: Ensure signature extraction complies with component licenses

## Database Management

### Database Schema

```sql
-- Components table
CREATE TABLE components (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT,
    publisher TEXT,
    license TEXT,
    ecosystem TEXT,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Signatures table  
CREATE TABLE signatures (
    id INTEGER PRIMARY KEY,
    component_id INTEGER REFERENCES components(id),
    signature_hash TEXT NOT NULL,
    signature_compressed BLOB,
    sig_type INTEGER DEFAULT 1,
    confidence REAL DEFAULT 0.5,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Trigrams for substring matching
CREATE TABLE trigrams (
    signature_id INTEGER REFERENCES signatures(id),
    trigram TEXT
);
```

### Database Maintenance

```bash
# Check database statistics
python -c "
from binarysniffer.storage.database import SignatureDatabase
db = SignatureDatabase('data/signatures.db')
print(db.get_stats())
"

# Rebuild indexes
python -c "
from binarysniffer.storage.database import SignatureDatabase
db = SignatureDatabase('data/signatures.db')
db.build_indexes()
print('Indexes rebuilt')
"

# Vacuum database (reclaim space)
python -c "
from binarysniffer.storage.database import SignatureDatabase
db = SignatureDatabase('data/signatures.db')
db.vacuum()
print('Database vacuumed')
"
```

### Backup and Recovery

```bash
# Backup database
cp data/signatures.db data/signatures_backup_$(date +%Y%m%d).db

# Export to JSON (for migration)
python scripts/export_signatures.py data/signatures.db exported_signatures.json

# Import from JSON
python scripts/import_signatures.py exported_signatures.json new_signatures.db
```

## Performance Optimization

### Index Management

The database uses several indexes for performance:
- **Hash indexes**: For exact signature matching
- **Trigram indexes**: For substring/fuzzy matching  
- **Component indexes**: For metadata queries
- **Bloom filters**: In-memory pre-filtering

### Memory Usage

- **Database file**: ~1-5MB per 1000 signatures
- **Runtime memory**: ~50-100MB for bloom filters and caches
- **Trigram indexes**: Additional 2-3x storage overhead

### Query Optimization

- Use confidence thresholds to limit result sets
- Leverage bloom filters for negative matches
- Batch queries when analyzing multiple files
- Use prepared statements for repeated queries

## Troubleshooting

### Common Issues

1. **Database locked**: Close other connections or restart the application
2. **Memory usage**: Reduce bloom filter size or increase system memory
3. **Slow queries**: Rebuild indexes or vacuum database
4. **Missing signatures**: Check database path and migration logs

### Debug Information

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

from binarysniffer import BinarySniffer
analyzer = BinarySniffer(debug=True)
result = analyzer.analyze_file("test_file.jar")
```

### Performance Profiling

```bash
# Profile signature matching
python -m cProfile -s cumulative -m binarysniffer large_file.apk

# Memory profiling
python -m memory_profiler analysis_script.py
```

## Future Enhancements

### Planned Features
- **Automatic signature generation** from OSS repositories
- **Cloud-based signature updates** with authentication
- **Signature quality scoring** with machine learning
- **Community signature contributions** with verification
- **Version-specific signature management** for better accuracy

### Integration Opportunities
- **CI/CD pipeline integration** for continuous compliance
- **SPDX/SBOM generation** from detected components
- **Vulnerability database integration** for security scanning
- **License compatibility checking** for compliance automation