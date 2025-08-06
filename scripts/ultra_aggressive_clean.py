#!/usr/bin/env python3
"""
Ultra-aggressive signature cleaning for .NET Core and wolfSSL
Removes patterns that are too generic to be reliable indicators
"""

import json
import sys
from pathlib import Path

# Patterns that are WAY too generic
ULTRA_GENERIC_PATTERNS = {
    # Basic types that appear EVERYWHERE
    'int8', 'int16', 'int32', 'int64', 'int128',
    'Int8', 'Int16', 'Int32', 'Int64', 'Int128',
    'uint8', 'uint16', 'uint32', 'uint64', 'uint128',
    'UInt8', 'UInt16', 'UInt32', 'UInt64', 'UInt128',
    'float', 'float32', 'float64', 'float128',
    'Float', 'Float32', 'Float64', 'Float128',
    'double', 'Double', 'bool', 'Bool', 'boolean', 'Boolean',
    
    # Generic prefixes
    'prefix1', 'prefix2', 'prefix3', 'prefix4', 'prefix5', 'prefix6', 'prefix7', 'prefix8',
    
    # Common C library functions
    'libc', 'libm', 'log', 'log2', 'log10', 'Log2', 'Log10',
    '_log', '_log2', '_log10', '_atan2', '_dup2',
    '_stat', '_fstat', '_lstat', '_statfs',
    'stat', 'fstat', 'lstat', 'statfs',
    
    # Generic patterns
    'dG0C', 'eX7D', 'I80I',  # Random looking short strings
    
    # Common math operations
    '___udivti3', '___divti3', '___modti3', '___umodti3',
    '_mp_div_2', '_mp_mul_2',
    
    # Generic tier/optimization names  
    'OptimizedTier1', 'OptimizedTier2', 'OptimizedTier3',
    
    # Generic parameter names
    'GenericParamV1_', 'GenericParam_',
    
    # Common stub names
    'InvokeStub_', 'CallStub_', 'HelperStub_',
    
    # macOS generic symbols
    '_mach_task_self_', '_vm_region_64', '_memset_pattern16',
    '_mrand48', '_srand48', '_rand48',
    
    # Generic INODE64 variants (standard macOS symbols)
    '_stat$INODE64', '_fstat$INODE64', '_lstat$INODE64', 
    '_statfs$INODE64', '_glob$INODE64',
    
    # Generic exception patterns
    'EXCEPTION_RAISE_64', 'EXCEPTION_RAISE_REPLY_64',
    'EXCEPTION_RAISE_STATE_64', 'EXCEPTION_RAISE_STATE_REPLY_64',
    'EXCEPTION_RAISE_STATE_IDENTITY_64', 'EXCEPTION_RAISE_STATE_IDENTITY_REPLY_64',
    
    # Generic tick counts
    'get_TickCount64', 'get_TickCount', 'TickCount', 'TickCount64',
    
    # Generic personality (C++ standard)
    '___gxx_personality_v0', '__gxx_personality_v0',
    
    # Too generic prefixes (when standalone)
    'COMPlus_', 'DOTNET_',  # These alone are too generic
    
    # Generic SHA/EVP patterns that are in many crypto libs
    '_wolfSSL_EVP_sha1', '_wolfSSL_EVP_sha224', '_wolfSSL_EVP_sha256',
    '_wolfSSL_EVP_sha384', '_wolfSSL_EVP_sha512',
    '_wolfSSL_EVP_sha3_224', '_wolfSSL_EVP_sha3_256', 
    '_wolfSSL_EVP_sha3_384', '_wolfSSL_EVP_sha3_512',
    '_wolfSSL_EVP_mdc2', '_wolfSSL_EVP_ripemd160',
    
    # Generic init patterns
    '_wc_InitSha224', '_wc_InitSha256', '_wc_InitSha384', '_wc_InitSha512',
    '_wc_InitSha3_224', '_wc_InitSha3_256', '_wc_InitSha3_384', '_wc_InitSha3_512',
}

def is_ultra_generic(pattern: str) -> bool:
    """Check if pattern is ultra-generic"""
    # Exact match
    if pattern in ULTRA_GENERIC_PATTERNS:
        return True
    
    # Very short patterns (less than 5 chars)
    if len(pattern) < 5:
        return True
    
    # Patterns that are just numbers
    if pattern.replace('_', '').replace('-', '').isdigit():
        return True
    
    # Random-looking short alphanumeric
    if len(pattern) <= 4 and pattern.replace('_', '').isalnum():
        return True
    
    return False

def clean_signature_file(file_path: Path):
    """Clean a signature file"""
    print(f"Processing {file_path.name}...")
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    original_count = len(data.get('signatures', []))
    cleaned_signatures = []
    removed_patterns = []
    
    for sig in data.get('signatures', []):
        pattern = sig.get('pattern', '')
        
        if is_ultra_generic(pattern):
            removed_patterns.append(pattern)
            print(f"  Removing: {pattern}")
        else:
            cleaned_signatures.append(sig)
    
    # Update the data
    data['signatures'] = cleaned_signatures
    
    # Update metadata
    if 'signature_metadata' in data:
        data['signature_metadata']['signature_count'] = len(cleaned_signatures)
        data['signature_metadata']['updated'] = '2025-01-06T00:00:00Z'
        data['signature_metadata']['cleaned'] = True
        data['signature_metadata']['cleaning_version'] = '3.0-ultra'
        if 'notes' not in data['signature_metadata']:
            data['signature_metadata']['notes'] = ''
        data['signature_metadata']['notes'] += ' Ultra-aggressive cleaning applied.'
    
    # Write back
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=2)
    
    removed_count = len(removed_patterns)
    print(f"✓ Removed {removed_count}/{original_count} patterns ({removed_count/original_count*100:.1f}%)")
    print(f"  Remaining: {len(cleaned_signatures)} patterns")
    
    return removed_count

def main():
    signatures_dir = Path(__file__).parent.parent / 'signatures'
    
    print("Ultra-aggressive cleaning for .NET Core and wolfSSL signatures")
    print("-" * 60)
    
    # Clean specific files
    files_to_clean = [
        signatures_dir / 'dotnet-core.json',
        signatures_dir / 'wolfssl.json'
    ]
    
    total_removed = 0
    for file_path in files_to_clean:
        if file_path.exists():
            removed = clean_signature_file(file_path)
            total_removed += removed
        else:
            print(f"File not found: {file_path}")
    
    print("-" * 60)
    print(f"Total patterns removed: {total_removed}")

if __name__ == '__main__':
    main()