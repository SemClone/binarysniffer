#!/usr/bin/env python3
"""
Analyze overlap between wolfSSL and OpenSSL signatures
"""

import json
from pathlib import Path

def load_patterns(file_path):
    """Load patterns from a signature file"""
    with open(file_path, 'r') as f:
        data = json.load(f)
    return {sig['pattern'].lower() for sig in data.get('signatures', [])}

def main():
    signatures_dir = Path(__file__).parent.parent / 'signatures'
    
    # Load patterns
    wolfssl_patterns = load_patterns(signatures_dir / 'wolfssl.json')
    openssl_patterns = load_patterns(signatures_dir / 'openssl.json')
    
    print("=== Signature Analysis ===")
    print(f"wolfSSL patterns: {len(wolfssl_patterns)}")
    print(f"OpenSSL patterns: {len(openssl_patterns)}")
    print()
    
    # Check OpenSSL patterns
    print("Current OpenSSL patterns:")
    for pattern in sorted(openssl_patterns):
        print(f"  - {pattern}")
    print()
    
    # Check for wolfSSL patterns that contain OpenSSL-like terms
    print("wolfSSL patterns that might match OpenSSL functions:")
    openssl_like = []
    for pattern in sorted(wolfssl_patterns):
        if any(term in pattern.lower() for term in ['ssl', 'evp', 'x509', 'crypto', 'sha', 'aes', 'rsa', 'ecdsa']):
            if not pattern.startswith('_wolf'):
                openssl_like.append(pattern)
    
    for pattern in openssl_like[:20]:  # First 20
        print(f"  - {pattern}")
    
    print(f"\nTotal OpenSSL-like patterns in wolfSSL: {len(openssl_like)}")
    
    # wolfSSL-specific patterns
    print("\nClearly wolfSSL-specific patterns:")
    wolfssl_specific = []
    for pattern in sorted(wolfssl_patterns):
        if 'wolf' in pattern.lower() or '_wc_' in pattern.lower():
            wolfssl_specific.append(pattern)
    
    for pattern in wolfssl_specific[:20]:  # First 20
        print(f"  - {pattern}")
    
    print(f"\nTotal wolfSSL-specific patterns: {len(wolfssl_specific)}")
    
    # Suggest better OpenSSL patterns
    print("\n=== Suggested OpenSSL-specific patterns ===")
    openssl_specific = [
        "OpenSSL ", "openssl.cnf",
        "SSL_CTX_new", "SSL_CTX_free", "SSL_CTX_set_verify",
        "SSL_new", "SSL_free", "SSL_connect", "SSL_accept",
        "SSL_read", "SSL_write", "SSL_get_error",
        "EVP_CIPHER_CTX_new", "EVP_CIPHER_CTX_free",
        "EVP_EncryptInit", "EVP_DecryptInit",
        "EVP_DigestInit", "EVP_DigestUpdate", "EVP_DigestFinal",
        "EVP_PKEY_new", "EVP_PKEY_free",
        "X509_new", "X509_free", "X509_verify_cert",
        "X509_STORE_new", "X509_STORE_free",
        "BIO_new", "BIO_free", "BIO_read", "BIO_write",
        "BN_new", "BN_free", "BN_add", "BN_sub",
        "RSA_new", "RSA_free", "RSA_generate_key",
        "EC_KEY_new", "EC_KEY_free", "EC_KEY_generate_key",
        "ECDSA_sign", "ECDSA_verify",
        "HMAC_Init", "HMAC_Update", "HMAC_Final",
        "RAND_bytes", "RAND_seed",
        "ERR_get_error", "ERR_error_string",
        "PEM_read_bio", "PEM_write_bio",
        "PKCS7_sign", "PKCS7_verify",
        "ASN1_INTEGER_new", "ASN1_INTEGER_free",
        "ENGINE_init", "ENGINE_finish",
        "CRYPTO_malloc", "CRYPTO_free",
        "OPENSSL_init_crypto", "OPENSSL_init_ssl",
        "libcrypto.so", "libssl.so",
        "OpenSSL/1.", "OpenSSL/3."  # Version strings
    ]
    
    for pattern in openssl_specific:
        print(f"  - {pattern}")

if __name__ == "__main__":
    main()