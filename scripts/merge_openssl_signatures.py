#!/usr/bin/env python3
"""
Merge two OpenSSL signature files into one comprehensive file
"""

import json
from pathlib import Path

def merge_openssl_signatures():
    """Merge openssl.json and openssl-enhanced.json"""
    
    signatures_dir = Path(__file__).parent.parent / 'signatures'
    original_file = signatures_dir / 'openssl.json'
    enhanced_file = signatures_dir / 'openssl-enhanced.json'
    
    print(f"Loading original OpenSSL signatures from {original_file}")
    with open(original_file, 'r') as f:
        original_data = json.load(f)
    
    print(f"Loading enhanced OpenSSL signatures from {enhanced_file}")
    with open(enhanced_file, 'r') as f:
        enhanced_data = json.load(f)
    
    # Start with enhanced data as base (it has better structure)
    merged_data = enhanced_data.copy()
    
    # Update component info to include best of both
    merged_data['component']['version'] = '1.0.0-3.0.x'
    merged_data['component']['publisher'] = 'OpenSSL Project'
    
    # Update signature metadata
    merged_data['signature_metadata']['version'] = '3.0.0'
    merged_data['signature_metadata']['notes'] = 'Merged comprehensive OpenSSL signatures from binary extraction and pattern analysis'
    merged_data['signature_metadata']['source'] = 'binary_extraction_and_pattern_analysis'
    
    # The enhanced signatures are already much better than the original 4 generic patterns
    # We'll use only the enhanced signatures as they're more specific
    # The original patterns like "CRYPTO_", "SSL_ERROR_", "SHA256_", "X509_" are too generic
    
    # Count signatures
    merged_data['signature_metadata']['signature_count'] = len(merged_data['signatures'])
    
    print(f"\nMerge Summary:")
    print(f"  Original file: {len(original_data.get('signatures', []))} patterns (very generic)")
    print(f"  Enhanced file: {len(enhanced_data.get('signatures', []))} patterns (specific)")
    print(f"  Merged file: {len(merged_data['signatures'])} patterns (using enhanced only)")
    
    # Write merged file (overwrite original)
    with open(original_file, 'w') as f:
        json.dump(merged_data, f, indent=2)
    
    print(f"\nMerged signatures written to {original_file}")
    
    # Remove the enhanced file since we've merged it
    if enhanced_file.exists():
        enhanced_file.unlink()
        print(f"Removed {enhanced_file} (now merged into openssl.json)")
    
    # Show some example patterns
    print("\nExample patterns in merged file:")
    for sig in merged_data['signatures'][:10]:
        print(f"  - {sig['pattern']} (confidence: {sig['confidence']})")

if __name__ == "__main__":
    merge_openssl_signatures()