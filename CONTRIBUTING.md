# Contributing to Semantic Copycat BinarySniffer

Thank you for your interest in contributing to BinarySniffer! This guide will help you contribute new component signatures to help the community detect OSS components in binaries.

## 🎯 How to Contribute Signatures

We welcome signature contributions from the community! Here's how you can help:

### Option 1: Using BinarySniffer Tool (Recommended)

The easiest way to contribute is by using BinarySniffer itself to extract signatures from binaries containing your target component.

#### Step 1: Extract Signatures from a Binary

```bash
# Install BinarySniffer
pip install binarysniffer

# Analyze a binary containing your target component
binarysniffer analyze path/to/binary.so --detailed --format json -o analysis.json

# Look for string patterns unique to your component
grep -i "your_component_name" analysis.json
```

#### Step 2: Manual Signature Creation

Create a signature file using our template:

```bash
# Copy the template
cp signatures/EXAMPLE_template.json signatures/my-new-component.json

# Edit with your component's information
```

#### Step 3: Test Your Signature

```bash
# Test your signature locally
binarysniffer signatures import --force
binarysniffer analyze test_binary_with_component.so
```

### Option 2: Manual Signature Extraction

If you have access to the component's source code or documentation:

#### Step 1: Identify Unique Strings

Look for unique identifiers in the component:
- Function names (e.g., `av_codec_init`, `MyLibraryFunction`)
- Class names (e.g., `FacebookSDK`, `JacksonParser`)
- Resource identifiers (e.g., `com_facebook_button`, `libavcodec`)
- Version strings (e.g., `MyLib version 2.1.0`)
- Error messages (e.g., `MyLib: Failed to initialize`)
- Configuration keys (e.g., `my_lib_config`, `MYLIB_DEBUG`)

#### Step 2: Verify Uniqueness

Ensure your strings are unique to avoid false positives:
- Search GitHub/Google to see if strings appear in other projects
- Avoid generic terms like "error", "init", "config"
- Prefer longer, specific strings over short ones

## 📝 Signature File Format

Create a JSON file following this structure:

```json
{
  "component": {
    "name": "Your Component Name",
    "version": "1.2.3",
    "category": "choose-from-categories-below",
    "platforms": ["android", "ios", "linux", "windows", "macos", "web", "all"],
    "languages": ["java", "kotlin", "swift", "c", "c++", "python", "javascript", "go"],
    "description": "Brief description of what this component does",
    "license": "MIT/Apache-2.0/GPL-3.0/etc",
    "publisher": "Component Publisher/Author",
    "homepage": "https://github.com/author/component"
  },
  "signature_metadata": {
    "version": "1.0.0",
    "created": "2025-08-04T00:00:00Z",
    "signature_count": 5,
    "confidence_threshold": 0.8,
    "contributor": "Your Name <email@example.com>",
    "extraction_method": "manual/automated/hybrid"
  },
  "signatures": [
    {
      "id": "unique_signature_id",
      "type": "string_pattern",
      "pattern": "YourLibraryInit",
      "confidence": 0.9,
      "context": "initialization",
      "platforms": ["all"],
      "description": "Library initialization function"
    }
  ]
}
```

### Categories

Choose the most appropriate category:
- `mobile-sdk`: Mobile development SDKs (Facebook SDK, Firebase, etc.)
- `enterprise-library`: Enterprise Java/business libraries (Apache, Google, etc.)
- `media-processing`: Audio/video codecs and processing (FFmpeg, x264, etc.)
- `networking`: HTTP clients, networking libraries (OkHttp, Retrofit, etc.)
- `data-processing`: JSON, XML parsers and data libraries (Jackson, GSON, etc.)
- `crypto`: Cryptographic libraries (BouncyCastle, OpenSSL, etc.)
- `ui-framework`: UI and graphics libraries (React Native, Skia, etc.)
- `testing`: Testing frameworks and tools
- `logging`: Logging libraries (Log4j, SLF4J, etc.)
- `imported`: Legacy or uncategorized imports

### Confidence Levels

Set appropriate confidence levels:
- `0.95-1.0`: Extremely unique strings (version strings, unique function names)
- `0.85-0.94`: Highly specific (component-specific class names, API calls)
- `0.75-0.84`: Moderately specific (prefixed identifiers, resource names)
- `0.65-0.74`: Less specific but still meaningful (common function names with context)

### Context Types

Categorize your signatures by context:
- `initialization`: Library/SDK initialization
- `api_calls`: Function calls and method invocations
- `user_interface`: UI elements, buttons, dialogs
- `networking`: HTTP requests, URL handling
- `data_processing`: Parsing, serialization, data handling
- `error_handling`: Error messages, exception handling
- `configuration`: Config keys, settings, parameters
- `resource_identifier`: Android resources, asset names
- `library_function`: Core library functions
- `logging`: Log messages, debug output

## 🔄 Submission Process

### Step 1: Fork the Repository

```bash
git clone https://github.com/YOUR_USERNAME/binarysniffer.git
cd binarysniffer
```

### Step 2: Create Your Signature

1. Create a new file in `signatures/` directory
2. Name it descriptively: `component-name.json` (use kebab-case)
3. Follow the JSON format above
4. Include 5-20 high-quality signatures

### Step 3: Test Your Signature

```bash
# Install in development mode
pip install -e .

# Test your signature
binarysniffer signatures import --force
binarysniffer signatures status

# Test against known binaries containing your component
binarysniffer analyze test_binary.so
```

### Step 4: Submit Pull Request

```bash
git add signatures/your-component.json
git commit -m "Add signatures for Your Component Name

- Added X signatures for Your Component
- Covers initialization, API calls, and error handling
- Tested against version X.Y.Z binaries"

git push origin main
```

Create a pull request with:
- **Title**: `Add signatures for [Component Name]`
- **Description**: Brief description of the component and signature sources
- **Testing**: Mention how you tested the signatures

## ✅ Quality Guidelines

### DO:
- ✅ Test signatures against real binaries
- ✅ Use descriptive signature IDs
- ✅ Include variety of contexts (init, API, errors)
- ✅ Set appropriate confidence levels
- ✅ Add meaningful descriptions
- ✅ Verify component information (license, publisher)

### DON'T:
- ❌ Use overly generic strings ("init", "error", "config")
- ❌ Copy signatures from unrelated components
- ❌ Include too many low-confidence signatures
- ❌ Use extremely long patterns (>100 characters)
- ❌ Include personal/private information
- ❌ Submit without testing

## 🛠 Advanced: Using the Signature Generator

For automated signature extraction from binaries:

```bash
# Extract all strings from a binary
strings binary_file.so > strings.txt

# Filter for component-specific patterns
grep -i "component_name" strings.txt

# Use BinarySniffer's generator (if available)
binarysniffer generate-signatures binary_file.so --component "Component Name"
```

## 📊 Signature Database Statistics

Current signature database includes:
- **120+ components** from major software vendors
- **8,700+ signatures** covering popular OSS libraries
- **Categories**: Mobile SDKs, Enterprise Java, Media Processing, Networking, etc.
- **Platforms**: Android, iOS, Linux, Windows, macOS, Web

## 🎉 Recognition

Contributors will be:
- Listed in release notes
- Credited in signature metadata
- Mentioned in project documentation
- Invited to join the project maintainers (for significant contributions)

## 📞 Support

Need help contributing?
- 📧 Create an issue with the `contribution-help` label
- 💬 Ask questions in pull request comments
- 📖 Check existing signatures for examples
- 🔍 Search the documentation

## 🚀 Future Enhancements

We're working on:
- **Automated signature extraction** from popular package managers *(Note: This feature assumes availability of source code alongside binaries, which is not always the case. As such, automated signature creation from package managers is considered out of scope for the CLI tool and will be implemented in a separate scanning orchestrator)*
- **Binary analysis tools** for signature discovery
- **Community signature validation** system
- **Integration with vulnerability databases**

Thank you for helping make BinarySniffer better for everyone! 🙏