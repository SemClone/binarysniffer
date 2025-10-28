# Installation Guide

## Basic Installation

### From PyPI
```bash
pip install binarysniffer
```

### From Source
```bash
git clone https://github.com/SemClone/binarysniffer
cd binarysniffer
pip install -e .
```

## Installation Options

### Performance Extras
```bash
pip install binarysniffer[fast]
```

### Fuzzy Matching Support
Includes TLSH for detecting modified/recompiled components:
```bash
pip install binarysniffer[fuzzy]
```

### Extended Archive Support
Includes support for 7z, RAR, DEB, RPM formats:
```bash
pip install binarysniffer[archives]
```

### Android APK Analysis
Includes Androguard for advanced APK analysis:
```bash
pip install binarysniffer[android]
```

## Optional Tools for Enhanced Format Support

BinarySniffer can leverage external tools when available to provide enhanced analysis capabilities. These tools are **optional** - the core functionality works without them, but installing them unlocks additional features.

### Quick Reference: Archive Format Requirements

| Format | Python Package | System Tool (Alternative) | Fallback |
|--------|---------------|---------------------------|----------|
| 7z | py7zr (included) | 7-Zip | - |
| RAR | rarfile (included) | unrar | 7-Zip |
| DEB | python-debian (included) | ar | 7-Zip |
| RPM | - | rpm2cpio | 7-Zip |
| ZIP/JAR | Built-in | - | - |
| TAR/GZ | Built-in | - | - |

### 7-Zip (Recommended)
**Enables**: Extraction and analysis of Windows installers, macOS packages, and additional compressed formats

```bash
# macOS
brew install p7zip

# Ubuntu/Debian
sudo apt-get install p7zip-full

# Windows
# Download from https://www.7-zip.org/
```

**Benefits**:
- Analyze Windows installers (.exe, .msi) by extracting embedded components
- Analyze macOS installers (.pkg, .dmg) to detect bundled frameworks
- Support for NSIS, InnoSetup, and other installer formats
- Extract and analyze self-extracting archives
- Support for additional archive formats (RAR, CAB, ISO, etc.)

### Tools for Extended Archive Support (Optional)

When using the `[archives]` installation option, these tools enhance format support:

#### DEB Package Analysis
```bash
# For DEB packages (Debian/Ubuntu)
# Option 1: Install python-debian (included with [archives])
pip install binarysniffer[archives]

# Option 2: Use system ar command (usually pre-installed)
# Ubuntu/Debian
which ar  # Check if available

# macOS
# ar is included with Xcode Command Line Tools
xcode-select --install  # If not already installed
```

#### RPM Package Analysis
```bash
# For RPM packages (Red Hat/Fedora/CentOS)
# Option 1: Install rpm2cpio
# Ubuntu/Debian
sudo apt-get install rpm2cpio

# macOS
brew install rpm2cpio

# Fedora/RHEL/CentOS
# rpm2cpio is usually pre-installed

# Option 2: Falls back to 7-Zip if available
```

#### Additional Archive Formats
The `[archives]` option includes Python libraries for:
- **7z files**: py7zr (pure Python, no external tools needed)
- **RAR files**: rarfile (requires unrar tool)
  ```bash
  # Install unrar for RAR support
  # Ubuntu/Debian
  sudo apt-get install unrar
  
  # macOS
  brew install unrar
  
  # Note: Falls back to 7-Zip if unrar not available
  ```

### Universal CTags (Optional)
**Enables**: Enhanced source code analysis with semantic understanding

```bash
# macOS
brew install universal-ctags

# Ubuntu/Debian
sudo apt-get install universal-ctags

# Windows
# Download from https://github.com/universal-ctags/ctags-win32/releases
```

**Benefits**:
- Better function/class/method detection in source code
- Multi-language semantic analysis
- More accurate symbol extraction
- Improved signature matching for source code components

### Example: Analyzing Installers

Without 7-Zip:
```bash
$ binarysniffer analyze installer.exe
# Analyzes as compressed binary - limited detection
```

With 7-Zip installed:
```bash
# Windows installers
$ binarysniffer analyze installer.exe
$ binarysniffer analyze setup.msi
# Automatically extracts and analyzes contents
# Detects: Qt5, OpenSSL, SQLite, ICU, libpng, etc.

# macOS installers
$ binarysniffer analyze app.pkg
$ binarysniffer analyze app.dmg
# Automatically extracts and analyzes contents
# Detects: Qt5, WebKit, OpenCV, React Native, etc.
```

## Troubleshooting

### Missing Dependencies
If you encounter import errors, ensure all dependencies are installed:
```bash
pip install --upgrade semantic-copycat-binarysniffer
```

### CTags Not Found
If CTags is not found, the tool will fallback to regex extraction. Install universal-ctags for enhanced source code analysis.

### Archive Extraction Issues
For archive-related errors, install the appropriate system tools or use the `[archives]` extra:
```bash
pip install binarysniffer[archives]
```

### Memory Issues
For large archives, the tool limits file processing to prevent OOM. You can adjust limits in `~/.binarysniffer/config.json`.

## Platform-Specific Notes

### macOS
- Use Homebrew for system tools: `brew install p7zip universal-ctags unrar`
- Xcode Command Line Tools required for some features

### Linux
- Most distributions have required tools in standard repositories
- Use package manager (apt, yum, dnf) for system tools

### Windows
- Download installers from official websites
- Add tools to PATH for command-line access
- Consider using WSL for better compatibility