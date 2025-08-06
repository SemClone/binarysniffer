#!/usr/bin/env python3
"""
Identify which SSL library is actually being used based on specific patterns
"""

import sys
from pathlib import Path

def analyze_file(file_path):
    """Analyze a binary to determine SSL library"""
    
    # Read binary content
    with open(file_path, 'rb') as f:
        content = f.read()
    
    # Convert to string, ignoring decode errors
    text = content.decode('utf-8', errors='ignore').lower()
    
    # OpenSSL-specific indicators
    openssl_indicators = {
        'strong': [
            'openssl/',  # Version string
            'libcrypto.so',
            'libssl.so',
            'openssl.cnf',
            'ssl_ctx_new',
            'ssl_ctx_free',
            'evp_cipher_ctx_new',
            'bio_new_file',
            'pem_read_bio',
            'err_get_error',
            'openssl_init_crypto',
            'openssl_init_ssl',
            'openssl generated',
            'openssl project',
        ],
        'medium': [
            'evp_encryptinit',
            'evp_decryptinit', 
            'x509_store_new',
            'bn_ctx_new',
            'rsa_generate_key',
            'ecdsa_sign',
            'engine_init',
            'crypto_malloc',
        ]
    }
    
    # wolfSSL-specific indicators
    wolfssl_indicators = {
        'strong': [
            'wolfssl',
            'wolfcrypt',
            '_wc_',
            'wolfssl_ctx',
            'wolfssl_new',
            'wolfssl_accept',
            'wolfssl_connect',
            'wc_initsha',
            'wc_aes',
            'wc_rsa',
            'wc_ecc',
            'wolfssl embedded ssl',
            'wolfssl.com',
        ],
        'medium': [
            '_wolfssl_',
            'wc_pbkdf',
            'wc_hmac',
            'wolfssl_evp',
            'wolfssl_bio',
            'wolfssl_x509',
        ]
    }
    
    # LibreSSL-specific indicators
    libressl_indicators = {
        'strong': [
            'libressl',
            'libressl/',
            'libtls.so',
            'tls_init',
            'tls_config_new',
        ]
    }
    
    # BoringSSL-specific indicators  
    boringssl_indicators = {
        'strong': [
            'boringssl',
            'google/boringssl',
            'boringssl_',
        ]
    }
    
    # mbedTLS-specific indicators
    mbedtls_indicators = {
        'strong': [
            'mbedtls',
            'mbedtls_',
            'polarssl',  # Old name
            'mbedtls_ssl_init',
            'mbedtls_x509',
        ]
    }
    
    # Count matches
    scores = {}
    
    # Check OpenSSL
    openssl_score = 0
    openssl_matches = []
    for pattern in openssl_indicators['strong']:
        if pattern in text:
            openssl_score += 10
            openssl_matches.append(f"STRONG: {pattern}")
    for pattern in openssl_indicators['medium']:
        if pattern in text:
            openssl_score += 5
            openssl_matches.append(f"MEDIUM: {pattern}")
    scores['OpenSSL'] = (openssl_score, openssl_matches)
    
    # Check wolfSSL
    wolfssl_score = 0
    wolfssl_matches = []
    for pattern in wolfssl_indicators['strong']:
        if pattern in text:
            wolfssl_score += 10
            wolfssl_matches.append(f"STRONG: {pattern}")
    for pattern in wolfssl_indicators['medium']:
        if pattern in text:
            wolfssl_score += 5
            wolfssl_matches.append(f"MEDIUM: {pattern}")
    scores['wolfSSL'] = (wolfssl_score, wolfssl_matches)
    
    # Check others
    for lib, indicators in [('LibreSSL', libressl_indicators),
                            ('BoringSSL', boringssl_indicators),
                            ('mbedTLS', mbedtls_indicators)]:
        score = 0
        matches = []
        for pattern in indicators.get('strong', []):
            if pattern in text:
                score += 10
                matches.append(f"STRONG: {pattern}")
        scores[lib] = (score, matches)
    
    # Print analysis
    print(f"\n=== SSL Library Analysis for {file_path.name} ===\n")
    
    # Sort by score
    sorted_scores = sorted(scores.items(), key=lambda x: x[1][0], reverse=True)
    
    for lib, (score, matches) in sorted_scores:
        if score > 0:
            print(f"{lib}: Score = {score}")
            for match in matches[:5]:  # Show first 5 matches
                print(f"  - {match}")
            if len(matches) > 5:
                print(f"  ... and {len(matches)-5} more matches")
            print()
    
    # Determine most likely
    if sorted_scores[0][1][0] > 0:
        winner = sorted_scores[0][0]
        winner_score = sorted_scores[0][1][0]
        print(f"Most likely: {winner} (confidence: {winner_score})")
        
        # Check for wolfSSL compatibility layer
        if winner == 'wolfSSL' and any('openssl' in m.lower() for m in sorted_scores[0][1][1]):
            print("\nNote: This appears to be wolfSSL with OpenSSL compatibility layer enabled")
    else:
        print("Could not determine SSL library")
    
    # Look for version strings
    print("\n=== Version Strings Found ===")
    import re
    
    # OpenSSL version pattern
    openssl_ver = re.findall(r'openssl[/ ]+(\d+\.\d+\.\d+\w*)', text)
    if openssl_ver:
        print(f"OpenSSL version: {openssl_ver[0]}")
    
    # wolfSSL version pattern
    wolfssl_ver = re.findall(r'wolfssl[/ ]+(\d+\.\d+\.\d+)', text)
    if wolfssl_ver:
        print(f"wolfSSL version: {wolfssl_ver[0]}")
    
    # Generic SSL/TLS version strings
    ssl_strings = re.findall(r'((?:lib)?(?:ssl|crypto|tls)[.-]?\d+\.\d+)', text)
    if ssl_strings:
        print(f"Other SSL strings: {', '.join(set(ssl_strings[:5]))}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 identify_ssl_library.py <binary_file>")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    analyze_file(file_path)