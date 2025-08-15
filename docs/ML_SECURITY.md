# ML Model Security Analysis

## Overview

BinarySniffer provides comprehensive security analysis for ML models, detecting malicious code, backdoors, and supply chain attacks in ML artifacts.

## Supported Formats

### Python Pickle Files (.pkl, .pickle)
- Safe parsing without code execution
- Detection of malicious code injection
- Protocol support: 0-5
- 100% detection rate on real-world exploits

### ONNX Models (.onnx)
- Comprehensive format validation
- Architecture recognition
- Metadata extraction
- Tampering detection

### SafeTensors (.safetensors)
- Secure tensor format validation
- Metadata security checks
- Size anomaly detection

### Native Frameworks
- **PyTorch**: .pt, .pth files
- **TensorFlow**: .pb, .h5, .tf files
- **XGBoost**: .xgb, .model files
- **scikit-learn**: .joblib, .pkl files

## Security Features

### Malicious Code Detection

Detects common attack patterns:
- Remote code execution (RCE)
- Command injection
- Data exfiltration
- Backdoor installation
- Supply chain attacks

```bash
# Analyze suspicious model
binarysniffer analyze suspicious_model.pkl --show-features

# Output includes security classification
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Component        ┃ Confidence ┃ Classification ┃ Evidence         ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ Pickle-Malicious │ 98.5%      │ CRITICAL       │ RCE risk detected│
└──────────────────┴────────────┴────────────────┴──────────────────┘
```

### Risk Assessment Levels

- **CRITICAL**: Active exploit or malicious code
- **HIGH**: Dangerous operations or backdoors
- **MEDIUM**: Suspicious patterns or anomalies
- **LOW**: Minor security concerns
- **SAFE**: No threats detected

### Framework Detection

Identifies the ML framework and architecture:
- PyTorch models (ResNet, BERT, ViT, etc.)
- TensorFlow models (YOLO, EfficientNet, etc.)
- Transformer architectures (GPT, LLaMA, T5)
- Classical ML (XGBoost, Random Forest)

## Usage Examples

### Command Line

```bash
# Basic security scan
binarysniffer analyze model.pkl

# Detailed analysis with features
binarysniffer analyze model.onnx --show-features

# Batch analysis of ML models
binarysniffer analyze ml_models/ -r -p "*.pkl" -p "*.onnx" -p "*.pt"

# Export security report
binarysniffer analyze models/ -r -f json -o ml_security_report.json
```

### Python API

```python
from binarysniffer import EnhancedBinarySniffer

sniffer = EnhancedBinarySniffer()

# Analyze ML model
result = sniffer.analyze_file("model.pkl")

# Check for security threats
for match in result.matches:
    if match.license in ["CRITICAL", "HIGH"]:
        print(f"⚠️ Security threat: {match.component}")
        print(f"   Severity: {match.license}")
        print(f"   Details: {match.evidence}")
    else:
        print(f"✓ Safe component: {match.component}")

# Extract model metadata
if result.metadata.get("model_type"):
    print(f"Model type: {result.metadata['model_type']}")
    print(f"Framework: {result.metadata['framework']}")
```

## Detection Capabilities

### Pickle Security

Detects pickle-specific threats:
- `__reduce__` exploitation
- `exec` and `eval` usage
- `os.system` calls
- `subprocess` invocations
- Network operations (`urllib`, `requests`)
- File system manipulation

### ONNX Validation

Validates ONNX models for:
- Format compliance
- Graph structure integrity
- Operator compatibility
- Metadata injection
- Size anomalies

### SafeTensors Security

Ensures SafeTensors integrity:
- Header validation
- Tensor size verification
- Metadata safety checks
- Format compliance

## Real-World Attack Detection

BinarySniffer detects these real attack patterns:

### 1. Pickle RCE Exploits
```python
# Malicious pickle that executes commands
import pickle
class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('malicious_command',))
```

### 2. Model Backdoors
```python
# Hidden layers or triggers in neural networks
# Detected through architecture analysis
```

### 3. Data Exfiltration
```python
# Models that leak data during inference
# Detected through network operation patterns
```

### 4. Supply Chain Attacks
```python
# Compromised dependencies or injected code
# Detected through component analysis
```

## Security Best Practices

### For Model Consumers

1. **Always scan models** before loading:
   ```bash
   binarysniffer analyze untrusted_model.pkl
   ```

2. **Use SafeTensors** when possible:
   ```python
   # Safer than pickle
   from safetensors import safe_open
   ```

3. **Verify model sources**:
   - Check signatures and hashes
   - Use trusted repositories
   - Validate publisher identity

4. **Sandbox model loading**:
   - Use containers or VMs
   - Limit network access
   - Monitor file system changes

### For Model Producers

1. **Avoid pickle** for distribution:
   ```python
   # Use SafeTensors instead
   from safetensors.torch import save_file
   save_file(tensors, "model.safetensors")
   ```

2. **Sign your models**:
   ```bash
   # Create cryptographic signatures
   gpg --sign model.safetensors
   ```

3. **Provide hashes**:
   ```bash
   # Generate and publish hashes
   sha256sum model.onnx > model.onnx.sha256
   ```

4. **Document architecture**:
   - List all dependencies
   - Describe model structure
   - Include training details

## Integration with CI/CD

### GitHub Actions

Here's a comprehensive example workflow for automated ML model security scanning:

```yaml
name: ML Model Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:  # Allow manual triggering

jobs:
  ml-security-scan:
    runs-on: ubuntu-latest
    
    permissions:
      # Required for uploading SARIF results
      security-events: write
      # Required for checking out code
      contents: read
    
    steps:
    - name: Checkout repository
      uses: actions/checkout@v3
      
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
        
    - name: Install BinarySniffer
      run: |
        pip install semantic-copycat-binarysniffer
        # Or install from source:
        # pip install -e .
        
    - name: Run ML Security Scan
      run: |
        # Scan all ML models in the repository
        binarysniffer ml-scan . \
          --recursive \
          --format sarif \
          --output ml-security-results.sarif \
          --risk-threshold LOW
      continue-on-error: true  # Don't fail the build, just report
      
    - name: Upload SARIF results to GitHub
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: ml-security-results.sarif
        category: ml-security
      if: always()  # Upload even if scan found issues
      
    - name: Generate Markdown Report
      run: |
        # Also generate human-readable report
        binarysniffer ml-scan . \
          --recursive \
          --format markdown \
          --output ml-security-report.md \
          --security-only
      if: always()
      
    - name: Upload Markdown Report as Artifact
      uses: actions/upload-artifact@v3
      with:
        name: ml-security-report
        path: ml-security-report.md
      if: always()
      
    - name: Comment PR with Summary (Pull Request only)
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v6
      with:
        script: |
          const fs = require('fs');
          
          // Read the markdown report
          let report = '## 🔒 ML Security Scan Results\n\n';
          
          try {
            const markdown = fs.readFileSync('ml-security-report.md', 'utf8');
            // Extract summary section
            const lines = markdown.split('\n');
            const summaryStart = lines.findIndex(line => line.includes('Summary'));
            if (summaryStart !== -1) {
              report += lines.slice(summaryStart, summaryStart + 10).join('\n');
            }
            report += '\n\n[View full security report](https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }})';
          } catch (e) {
            report += 'No security issues detected in ML models.';
          }
          
          // Post comment on PR
          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: report
          });
      
    - name: Fail if Critical Issues Found
      run: |
        # Parse SARIF and fail if critical issues exist
        if grep -q '"level": "error"' ml-security-results.sarif; then
          echo "❌ Critical security issues found in ML models!"
          echo "Please review the security report in the Actions tab."
          exit 1
        else
          echo "✅ No critical security issues found."
        fi
```

#### Simpler Version

For a basic security check without SARIF integration:

```yaml
name: ML Security Check

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install BinarySniffer
        run: pip install semantic-copycat-binarysniffer
      
      - name: Scan ML Models
        run: |
          binarysniffer analyze models/ -r -f json -o report.json
          
      - name: Check for threats
        run: |
          python -c "
          import json
          with open('report.json') as f:
              report = json.load(f)
          threats = [m for r in report['results'].values() 
                    for m in r['matches'] 
                    if m['license'] in ['CRITICAL', 'HIGH']]
          if threats:
              print('Security threats detected!')
              for t in threats:
                  print(f'  - {t['component']}: {t['license']}')
              exit(1)
          "
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: ml-security
        name: ML Model Security Scan
        entry: binarysniffer analyze
        language: system
        files: \.(pkl|pickle|onnx|pt|pth|safetensors)$
```

## Advanced Analysis

### Feature Extraction

Extract and analyze model features:

```bash
# Save extracted features
binarysniffer analyze model.pkl --save-features model_features.json

# Analyze features for patterns
cat model_features.json | jq '.features | map(select(. | contains("exec")))'
```

### Custom Signatures

Create signatures for known malicious models:

```bash
# Create signature from malicious model
binarysniffer signatures create malicious.pkl \
  --name "Known-Malware-Model" \
  --license "CRITICAL" \
  --description "Known malicious ML model" \
  --output signatures/ml-malware.json
```

### Batch Validation

Validate model repositories:

```python
from binarysniffer import EnhancedBinarySniffer
import os

sniffer = EnhancedBinarySniffer()

def validate_model_repo(repo_path):
    """Validate all models in repository."""
    results = []
    
    for root, dirs, files in os.walk(repo_path):
        for file in files:
            if file.endswith(('.pkl', '.onnx', '.pt', '.safetensors')):
                path = os.path.join(root, file)
                result = sniffer.analyze_file(path)
                
                threats = [m for m in result.matches 
                          if m.license in ['CRITICAL', 'HIGH']]
                
                if threats:
                    results.append({
                        'file': path,
                        'threats': threats,
                        'severity': max(t.license for t in threats)
                    })
    
    return results

# Scan repository
threats = validate_model_repo('/path/to/models')
if threats:
    print(f"Found {len(threats)} suspicious models")
```

## Troubleshooting

### False Positives

Some legitimate models may trigger warnings:
- Models with custom operations
- Compressed or encrypted models
- Models with embedded preprocessing

Adjust threshold if needed:
```bash
binarysniffer analyze model.pkl -t 0.8  # Higher threshold
```

### Malformed Models

For corrupted or invalid models:
```bash
# Still attempts analysis
binarysniffer analyze corrupted.onnx --show-features
# Output: "Malformed ONNX model: invalid protobuf"
```

### Large Models

For very large models (>1GB):
```bash
# Use fast mode to skip fuzzy matching
binarysniffer analyze large_model.pt --fast
```

## References

- [ONNX Security Guide](https://onnx.ai/security)
- [PyTorch Security](https://pytorch.org/docs/stable/security.html)
- [SafeTensors Documentation](https://huggingface.co/docs/safetensors)
- [ML Supply Chain Security](https://mlsecops.com)