#!/usr/bin/env python3
"""
Optimize signatures to reduce false positives between similar libraries.

This script removes overly generic patterns that cause false positives,
particularly between cryptographic libraries like OpenSSL, wolfSSL, and FFmpeg.
"""

import json
import logging
from pathlib import Path
from typing import Set, List, Dict

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Generic patterns that cause false positives
GENERIC_PATTERNS = {
    # Single words that are too common
    'base', 'block', 'fixed', 'flush', 'assign', 'export', 'import',
    'init', 'free', 'new', 'delete', 'create', 'destroy', 'open', 'close',
    'read', 'write', 'get', 'set', 'push', 'pop', 'add', 'remove',
    'start', 'stop', 'begin', 'end', 'first', 'last', 'next', 'prev',
    'copy', 'move', 'clear', 'reset', 'update', 'check', 'verify',
    'encode', 'decode', 'encrypt', 'decrypt', 'hash', 'sign', 'verify',
    'parse', 'format', 'convert', 'transform', 'process', 'handle',
    'config', 'option', 'param', 'value', 'data', 'buffer', 'size', 'length',
    'error', 'warning', 'info', 'debug', 'trace', 'log', 'print', 'output',
    'input', 'file', 'stream', 'memory', 'alloc', 'malloc', 'calloc', 'realloc',
    
    # Common crypto terms that appear in many libraries
    'aes', 'des', 'rsa', 'dsa', 'ecdsa', 'sha', 'md5', 'hmac',
    'aes128', 'aes192', 'aes256', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
    'pbkdf2', 'cipher', 'digest', 'signature', 'key', 'iv', 'nonce',
    'padding', 'mode', 'cbc', 'ecb', 'gcm', 'ccm', 'ctr', 'ofb', 'cfb',
    
    # Generic programming terms
    'public', 'private', 'static', 'const', 'void', 'int', 'char', 'float',
    'double', 'bool', 'true', 'false', 'null', 'nil', 'none', 'undefined',
    'class', 'struct', 'enum', 'typedef', 'namespace', 'using', 'template',
    'virtual', 'override', 'final', 'abstract', 'interface', 'extends',
    
    # Common prefixes/suffixes without context
    'lib', 'api', 'impl', 'internal', 'external', 'common', 'util', 'helper',
    'manager', 'handler', 'controller', 'service', 'factory', 'builder',
    'wrapper', 'adapter', 'proxy', 'delegate', 'observer', 'listener',
    
    # Too short or numeric
    'v1', 'v2', 'v3', '1', '2', '3', '10', '100', '1000',
    'i', 'j', 'k', 'n', 'm', 'x', 'y', 'z', 'a', 'b', 'c',
}

# Patterns that need library-specific context
CONTEXT_REQUIRED = {
    'ffmpeg': ['av_', 'avcodec_', 'avformat_', 'avutil_', 'swscale_', 'swresample_', 'ffmpeg'],
    'openssl': ['SSL_', 'TLS_', 'EVP_', 'X509_', 'BIO_', 'ERR_', 'CRYPTO_', 'OPENSSL_', 'PEM_', 'ASN1_', 'BN_', 'EC_', 'RSA_', 'DSA_', 'DH_'],
    'wolfssl': ['wc_', 'wolf', 'WOLFSSL_', 'CyaSSL_', 'CYASSL_'],
    'gstreamer': ['gst_', 'GST_', 'GStreamer'],
    'qt': ['Qt', 'QObject', 'QWidget', 'QString', 'QApplication', 'SIGNAL', 'SLOT'],
}

def is_generic_pattern(pattern: str) -> bool:
    """Check if a pattern is too generic"""
    pattern_lower = pattern.lower()
    
    # Check if pattern is in generic list
    if pattern_lower in GENERIC_PATTERNS:
        return True
    
    # Check if pattern is too short (less than 5 chars)
    if len(pattern) < 5:
        return True
    
    # Check if pattern is just numbers
    if pattern.isdigit():
        return True
    
    # Check if pattern is a common file extension
    if pattern.startswith('.') and len(pattern) < 6:
        return True
    
    return False

def get_library_specific_pattern(pattern: str, library: str) -> bool:
    """Check if pattern should be kept for specific library"""
    library_lower = library.lower()
    
    # Get context patterns for this library
    for lib_name, contexts in CONTEXT_REQUIRED.items():
        if lib_name in library_lower:
            # Check if pattern has library-specific context
            for context in contexts:
                if context.lower() in pattern.lower():
                    return True
    
    return False

def optimize_signature_file(file_path: Path) -> Dict:
    """Optimize a single signature file"""
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    if 'signatures' not in data:
        return {'removed': 0, 'kept': 0}
    
    component_name = data['component']['name']
    original_count = len(data['signatures'])
    
    # Filter signatures
    optimized_signatures = []
    removed_patterns = []
    
    for sig in data['signatures']:
        pattern = sig.get('pattern', '')
        
        # Check if pattern is too generic
        if is_generic_pattern(pattern):
            # Check if it has library-specific context
            if not get_library_specific_pattern(pattern, component_name):
                removed_patterns.append(pattern)
                continue
        
        # Keep the signature
        optimized_signatures.append(sig)
    
    # Update the data
    data['signatures'] = optimized_signatures
    data['signature_metadata']['signature_count'] = len(optimized_signatures)
    
    # Save if changes were made
    if len(removed_patterns) > 0:
        # Create backup
        backup_path = file_path.with_suffix('.json.backup')
        with open(backup_path, 'w') as f:
            with open(file_path, 'r') as orig:
                f.write(orig.read())
        
        # Save optimized version
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Optimized {file_path.name}: Removed {len(removed_patterns)}/{original_count} patterns")
        logger.debug(f"  Removed: {', '.join(removed_patterns[:10])}")
    
    return {
        'file': file_path.name,
        'component': component_name,
        'removed': len(removed_patterns),
        'kept': len(optimized_signatures),
        'removed_patterns': removed_patterns
    }

def create_openssl_specific_signatures() -> Dict:
    """Create OpenSSL-specific signatures that won't match other crypto libraries"""
    return {
        "component": {
            "name": "OpenSSL",
            "version": "1.1.1-3.x",
            "category": "imported",
            "platforms": ["all"],
            "languages": ["c", "c++"],
            "description": "OpenSSL cryptographic library - optimized signatures",
            "license": "Apache-2.0",
            "publisher": "OpenSSL Software Foundation"
        },
        "signature_metadata": {
            "version": "2.0.0",
            "created": "2025-08-08T00:00:00.000000Z",
            "updated": "2025-08-08T00:00:00.000000Z",
            "signature_count": 30,
            "confidence_threshold": 0.7,
            "source": "optimized_signatures",
            "extraction_method": "library_specific_patterns"
        },
        "signatures": [
            # OpenSSL-specific version strings
            {"id": "openssl_opt_0", "type": "string_pattern", "pattern": "OpenSSL_version", "confidence": 0.95, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_1", "type": "string_pattern", "pattern": "OPENSSL_VERSION_TEXT", "confidence": 0.95, "context": "constant", "platforms": ["all"]},
            {"id": "openssl_opt_2", "type": "string_pattern", "pattern": "SSLeay_version", "confidence": 0.90, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific initialization
            {"id": "openssl_opt_3", "type": "string_pattern", "pattern": "OPENSSL_init_crypto", "confidence": 0.90, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_4", "type": "string_pattern", "pattern": "OPENSSL_init_ssl", "confidence": 0.90, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_5", "type": "string_pattern", "pattern": "SSL_library_init", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific EVP functions
            {"id": "openssl_opt_6", "type": "string_pattern", "pattern": "EVP_CIPHER_CTX_new", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_7", "type": "string_pattern", "pattern": "EVP_MD_CTX_new", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_8", "type": "string_pattern", "pattern": "EVP_PKEY_CTX_new", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific SSL/TLS functions
            {"id": "openssl_opt_9", "type": "string_pattern", "pattern": "SSL_CTX_new", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_10", "type": "string_pattern", "pattern": "SSL_CTX_set_verify", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_11", "type": "string_pattern", "pattern": "TLS_method", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific error handling
            {"id": "openssl_opt_12", "type": "string_pattern", "pattern": "ERR_load_crypto_strings", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_13", "type": "string_pattern", "pattern": "ERR_get_error", "confidence": 0.80, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific X509 handling
            {"id": "openssl_opt_14", "type": "string_pattern", "pattern": "X509_STORE_CTX_new", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_15", "type": "string_pattern", "pattern": "X509_verify_cert", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific BIO functions
            {"id": "openssl_opt_16", "type": "string_pattern", "pattern": "BIO_new_file", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_17", "type": "string_pattern", "pattern": "BIO_s_mem", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific BIGNUM functions
            {"id": "openssl_opt_18", "type": "string_pattern", "pattern": "BN_CTX_new", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_19", "type": "string_pattern", "pattern": "BN_bin2bn", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific engine
            {"id": "openssl_opt_20", "type": "string_pattern", "pattern": "ENGINE_load_builtin_engines", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_21", "type": "string_pattern", "pattern": "ENGINE_register_all_complete", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific random
            {"id": "openssl_opt_22", "type": "string_pattern", "pattern": "RAND_load_file", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_23", "type": "string_pattern", "pattern": "RAND_seed", "confidence": 0.80, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific PEM functions
            {"id": "openssl_opt_24", "type": "string_pattern", "pattern": "PEM_read_bio_PrivateKey", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_25", "type": "string_pattern", "pattern": "PEM_write_bio_PUBKEY", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL-specific ASN1
            {"id": "openssl_opt_26", "type": "string_pattern", "pattern": "ASN1_STRING_to_UTF8", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            {"id": "openssl_opt_27", "type": "string_pattern", "pattern": "ASN1_TIME_adj", "confidence": 0.85, "context": "function", "platforms": ["all"]},
            
            # OpenSSL file patterns
            {"id": "openssl_opt_28", "type": "string_pattern", "pattern": "libcrypto.so", "confidence": 0.90, "context": "library_name", "platforms": ["linux"]},
            {"id": "openssl_opt_29", "type": "string_pattern", "pattern": "libssl.so", "confidence": 0.90, "context": "library_name", "platforms": ["linux"]}
        ]
    }

def main():
    """Main function to optimize signatures"""
    logger.info("Starting signature optimization...")
    
    # Find signature files
    signatures_dir = Path(__file__).parent.parent / 'signatures'
    signature_files = list(signatures_dir.glob('*.json'))
    
    # Files to optimize (known to have issues)
    problem_files = ['ffmpeg.json', 'wolfssl.json']
    
    results = []
    for file_name in problem_files:
        file_path = signatures_dir / file_name
        if file_path.exists():
            result = optimize_signature_file(file_path)
            results.append(result)
    
    # Create optimized OpenSSL signatures
    openssl_optimized = create_openssl_specific_signatures()
    openssl_path = signatures_dir / 'openssl-optimized.json'
    with open(openssl_path, 'w') as f:
        json.dump(openssl_optimized, f, indent=2)
    logger.info(f"Created optimized OpenSSL signatures: {openssl_path.name}")
    
    # Summary
    total_removed = sum(r['removed'] for r in results)
    total_kept = sum(r['kept'] for r in results)
    
    logger.info(f"\nOptimization complete:")
    logger.info(f"  Total patterns removed: {total_removed}")
    logger.info(f"  Total patterns kept: {total_kept}")
    logger.info(f"  Files optimized: {len(results)}")
    logger.info(f"  Created: openssl-optimized.json with 30 specific patterns")

if __name__ == '__main__':
    main()