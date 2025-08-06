#!/usr/bin/env python3
"""
Remove generic crypto algorithm patterns from wolfSSL signatures
These patterns appear in ALL SSL/crypto libraries, not just wolfSSL
"""

import json
from pathlib import Path

# Generic crypto patterns that appear in ALL SSL libraries
GENERIC_CRYPTO_PATTERNS = {
    # Cipher algorithms (appear in every crypto library)
    'aes128', 'aes192', 'aes256', 'aes-128', 'aes-192', 'aes-256',
    'des', '3des', 'des3', 'triple-des',
    'rc4', 'rc4-128', 'rc4-256',
    'chacha20', 'chacha', 'poly1305',
    'camellia128', 'camellia192', 'camellia256',
    'blowfish', 'twofish', 'serpent',
    'cast5', 'cast128', 'idea', 'seed',
    
    # Hash algorithms (standard everywhere)
    'md5', 'md4', 'md2',
    'sha', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512',
    'sha3', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
    'sha512_224', 'sha512_256',
    'shake128', 'shake256',
    'blake2b', 'blake2s', 'blake2b256', 'blake2b512', 'blake2s256',
    'ripemd', 'ripemd160', 'whirlpool',
    
    # Key exchange algorithms
    'rsa', 'dsa', 'ecdsa', 'ecdh', 'ecdhe', 'dhe', 'dh',
    'x25519', 'x448', 'ed25519', 'ed448',
    
    # TLS/SSL versions (standard protocol names)
    'ssl', 'ssl2', 'ssl3', 'sslv2', 'sslv3', 'ssl23',
    'tls', 'tls1', 'tls10', 'tls11', 'tls12', 'tls13',
    'tlsv1', 'tlsv1.0', 'tlsv1.1', 'tlsv1.2', 'tlsv1.3',
    'dtls', 'dtls1', 'dtls10', 'dtls12',
    
    # Elliptic curves (standard curve names)
    'secp112r1', 'secp112r2', 'secp128r1', 'secp128r2',
    'secp160k1', 'secp160r1', 'secp160r2',
    'secp192k1', 'secp192r1', 'prime192v1',
    'secp224k1', 'secp224r1', 
    'secp256k1', 'secp256r1', 'prime256v1',
    'secp384r1', 'secp521r1',
    'brainpoolp256r1', 'brainpoolp384r1', 'brainpoolp512r1',
    'curve25519', 'curve448',
    
    # Generic TLS cipher suite components
    'gcm', 'ccm', 'cbc', 'ecb', 'cfb', 'ofb', 'ctr',
    'hmac', 'mac', 'aead', 'prf',
    
    # FFDHE groups (standard DH parameters)
    'ffdhe_2048', 'ffdhe_3072', 'ffdhe_4096', 'ffdhe_6144', 'ffdhe_8192',
    'ffdhe2048', 'ffdhe3072', 'ffdhe4096', 'ffdhe6144', 'ffdhe8192',
    
    # Key derivation functions
    'pbkdf', 'pbkdf2', 'pbkdfv2', 'scrypt', 'argon2', 'bcrypt',
    'hkdf', 'kdf', 'prf',
    
    # Generic protocol terms
    'handshake', 'certificate', 'cipher', 'digest', 'signature',
    'public', 'private', 'secret', 'session', 'ticket',
    
    # Random looking short patterns from the output
    'm3fu3', 'mmfu33', 'u33f', 'y77n', 'c63w', 'fnt7', 'kb8a', 'ny77',
    'p09y', 'ph88', 'rk99',
    
    # Generic base encodings
    'base64', 'base32', 'base16', 'hex',
    
    # Standard TLS extensions
    'sni', 'alpn', 'npn', 'ocsp', 'sct',
    
    # Generic crypto operations
    'encrypt', 'decrypt', 'sign', 'verify', 'hash', 'digest',
    
    # Version-agnostic patterns
    'tls_aes_128_gcm_sha256', 'tls_aes_256_gcm_sha384',
    'tls_chacha20_poly1305_sha256',
    'tls_aes_128_ccm_sha256', 'tls_aes_128_ccm_8_sha256',
    
    # Other generic terms
    'exponent1', 'exponent2', 'coefficient',
    'modulus', 'prime1', 'prime2',
    
    # Generic hex strings (likely test vectors)
    'ed8d916c171f0688d7e7cca547ab3ab2',
    'ffffffffffffffffffffffff99def836146bc9b1b4d22831',
    
    # Generic certificate/encoding terms
    'pem', 'der', 'pkcs', 'pkcs1', 'pkcs7', 'pkcs8', 'pkcs12',
    'x509', 'asn1', 'oid',
    
    # Generic algorithm combinations
    'pbewithsha1and128bitrc4', 'pbewithsha1and40bitrc4',
}

def is_wolfssl_specific(pattern: str) -> bool:
    """Check if pattern is wolfSSL-specific"""
    pattern_lower = pattern.lower()
    
    # Keep wolfSSL-specific patterns
    if any(x in pattern_lower for x in ['wolf', '_wc_', 'wc_', 'wolfssl', 'wolfcrypt']):
        return True
    
    # Remove if it's a generic crypto pattern
    if pattern_lower in GENERIC_CRYPTO_PATTERNS:
        return False
    
    # Remove very short patterns (likely false positives)
    if len(pattern) <= 4:
        return False
    
    # Remove patterns that are just numbers/hex
    if all(c in '0123456789abcdef' for c in pattern_lower):
        return False
    
    # Default to keeping specific-looking patterns
    return True

def clean_wolfssl_signatures():
    """Clean wolfSSL signature file"""
    signatures_file = Path(__file__).parent.parent / 'signatures' / 'wolfssl.json'
    
    print(f"Cleaning wolfSSL signatures: {signatures_file}")
    
    with open(signatures_file, 'r') as f:
        data = json.load(f)
    
    original_count = len(data.get('signatures', []))
    cleaned_signatures = []
    removed_patterns = []
    
    for sig in data.get('signatures', []):
        pattern = sig.get('pattern', '')
        
        if is_wolfssl_specific(pattern):
            cleaned_signatures.append(sig)
        else:
            removed_patterns.append(pattern)
            print(f"  Removing generic: {pattern}")
    
    # Update the data
    data['signatures'] = cleaned_signatures
    
    # Update metadata
    if 'signature_metadata' in data:
        data['signature_metadata']['signature_count'] = len(cleaned_signatures)
        data['signature_metadata']['updated'] = '2025-01-06T00:00:00Z'
        data['signature_metadata']['cleaned'] = True
        data['signature_metadata']['cleaning_version'] = '4.0-crypto-specific'
        if 'notes' not in data['signature_metadata']:
            data['signature_metadata']['notes'] = ''
        data['signature_metadata']['notes'] = 'Removed generic crypto patterns that appear in all SSL libraries. Kept only wolfSSL-specific patterns.'
    
    # Write back
    with open(signatures_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    removed_count = len(removed_patterns)
    print(f"\nSummary:")
    print(f"  Original patterns: {original_count}")
    print(f"  Removed: {removed_count} ({removed_count/original_count*100:.1f}%)")
    print(f"  Remaining: {len(cleaned_signatures)}")
    
    # Show what's left
    print(f"\nRemaining wolfSSL-specific patterns (first 20):")
    for sig in cleaned_signatures[:20]:
        print(f"  - {sig['pattern']}")

if __name__ == "__main__":
    clean_wolfssl_signatures()