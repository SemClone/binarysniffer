# BinarySniffer - Binary Component Detection and Security Analysis

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PyPI version](https://img.shields.io/pypi/v/binarysniffer.svg)](https://pypi.org/project/binarysniffer/)

A high-performance CLI tool and Python library for detecting open source components and security threats in binaries through semantic signature matching. Specialized for analyzing mobile apps (APK/IPA), Java archives, ML models, and source code to identify OSS components, their licenses, and potential security risks.

## Features

- **Binary Component Detection**: Identify 188+ OSS components in compiled binaries using semantic signatures
- **ML Model Security Analysis**: Comprehensive security scanning with MITRE ATT&CK mapping
- **Multi-Format Support**: APK/IPA, JAR/WAR, ELF/PE/Mach-O, ML models (pickle, ONNX, SafeTensors)
- **SEMCL.ONE Integration**: Works seamlessly with osslili, purl2notices, and other ecosystem tools

## Installation

```bash
pip install binarysniffer
```

For development:
```bash
git clone https://github.com/SemClone/binarysniffer.git
cd binarysniffer
pip install -e .
```

With performance extras:
```bash
pip install binarysniffer[fast]
```

## Quick Start

```bash
# Analyze a binary file
binarysniffer analyze /path/to/binary

# ML model security scan
binarysniffer ml-scan model.pkl --deep

# Generate SBOM
binarysniffer analyze app.apk --format cyclonedx -o sbom.json
```

## Usage

### CLI Usage

```bash
# Basic analysis
binarysniffer analyze app.apk

# ML model security analysis
binarysniffer ml-scan model.pkl --risk-threshold 0.5

# Directory scanning with recursion
binarysniffer analyze /path/to/project -r

# Generate CycloneDX SBOM
binarysniffer analyze app.jar --format sbom -o app-sbom.json

# Extract package inventory
binarysniffer inventory app.apk --with-hashes -o inventory.json
```

### Python API

```python
from binarysniffer import EnhancedBinarySniffer

# Initialize analyzer
sniffer = EnhancedBinarySniffer()

# Analyze a file
result = sniffer.analyze_file("app.apk")
for match in result.matches:
    print(f"{match.component} - {match.confidence:.2%}")
    print(f"License: {match.license}")

# ML security analysis
from binarysniffer.ml_security import MLSecurityAnalyzer

analyzer = MLSecurityAnalyzer()
risks = analyzer.analyze_model("model.pkl")
```

## Core Capabilities

### Binary Analysis
- Advanced format support (ELF, PE, Mach-O) via LIEF
- Android DEX bytecode analysis
- Static library (.a) support
- Symbol and import extraction

### Archive Support
- Mobile apps (APK, IPA)
- Java archives (JAR, WAR)
- Python packages (wheel, egg)
- Linux packages (DEB, RPM)
- Extended formats (7z, RAR, Zstandard)

### ML Model Security (v1.10.0+)
- Safe pickle file analysis
- ONNX and SafeTensors validation
- PyTorch/TensorFlow native formats
- 100% detection rate on known exploits
- SARIF output for CI/CD integration

### Signature Database
- 188 OSS components covered
- 1,400+ high-quality signatures
- Automatic license detection
- Security severity classification

## Integration with SEMCL.ONE

BinarySniffer is a core component of the SEMCL.ONE ecosystem:

- Complements **osslili** for source code license detection
- Works with **purl2notices** for comprehensive attribution
- Integrates with **ospac** for policy evaluation
- Supports **upmex** for package metadata extraction

## Configuration

```yaml
# ~/.binarysniffer/config.json
{
  "signature_sources": [
    "https://signatures.binarysniffer.io/core.xmdb"
  ],
  "min_confidence": 0.5,
  "parallel_workers": 4,
  "auto_update": true
}
```

## Documentation

- [User Guide](docs/USER_GUIDE.md) - Comprehensive usage examples
- [API Reference](docs/API_REFERENCE.md) - Python API documentation
- [ML Security](docs/ML_SECURITY.md) - ML model security analysis
- [Signature Management](docs/SIGNATURE_MANAGEMENT.md) - Creating and managing signatures
- [Architecture](docs/ARCHITECTURE.md) - System design and internals

## Advanced Topics

- [TLSH Fuzzy Matching](docs/TLSH_FUZZY_MATCHING.md) - Detecting modified components
- [Creating Signatures](docs/CREATING_SIGNATURES.md) - Contributing new signatures
- [Installation Guide](docs/INSTALLATION.md) - Platform-specific setup
- [Package Verification](docs/PACKAGE_VERIFICATION.md) - Archive analysis

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on:
- Code of conduct
- Development setup
- Submitting pull requests
- Signature contributions

## Support

For support and questions:
- [GitHub Issues](https://github.com/SemClone/binarysniffer/issues) - Bug reports and feature requests
- [Documentation](https://github.com/SemClone/binarysniffer) - Complete project documentation
- [SEMCL.ONE Community](https://semcl.one) - Ecosystem support and discussions

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details.

## Authors

See [AUTHORS.md](AUTHORS.md) for a list of contributors.

---

*Part of the [SEMCL.ONE](https://semcl.one) ecosystem for comprehensive OSS compliance and code analysis.*