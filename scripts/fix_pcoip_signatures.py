#!/usr/bin/env python3
"""
Fix PCoIP SDK overly generic signatures that cause false positives
"""

import sqlite3
import zstandard as zstd
from pathlib import Path

def fix_pcoip_signatures():
    """Remove overly generic PCoIP SDK signatures"""
    
    db_path = Path.home() / '.binarysniffer' / 'signatures.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Patterns that are too generic and could match non-PCoIP code
    bad_patterns = [
        # Single letters or very short generic terms
        'p', 'P', 'c', 'C', 'o', 'O', 'i', 'I',
        # Generic programming terms
        'client', 'server', 'session', 'connection', 'socket',
        'buffer', 'packet', 'data', 'message', 'protocol',
        'stream', 'channel', 'port', 'host', 'address',
        'send', 'recv', 'receive', 'transmit', 'write', 'read',
        'init', 'destroy', 'create', 'delete', 'free',
        'start', 'stop', 'pause', 'resume', 'reset',
        'open', 'close', 'connect', 'disconnect', 'bind',
        'error', 'warning', 'info', 'debug', 'trace',
        'encode', 'decode', 'compress', 'decompress',
        'encrypt', 'decrypt', 'hash', 'verify', 'sign',
        # Common networking terms
        'tcp', 'udp', 'ip', 'ipv4', 'ipv6', 'http', 'https',
        'ssl', 'tls', 'dns', 'dhcp', 'nat', 'vpn',
        # Generic types
        'int', 'char', 'void', 'bool', 'float', 'double',
        'string', 'array', 'list', 'map', 'set', 'queue',
        # Too short prefixes  
        'pc_', 'pco_', 
        # Generic function patterns
        'get_', 'set_', 'is_', 'has_', 'can_',
        '_init', '_exit', '_free', '_alloc',
        # Common library functions
        'malloc', 'calloc', 'realloc', 'free', 'memcpy', 'memset',
        'strcpy', 'strncpy', 'strcat', 'strlen', 'strcmp',
        'printf', 'sprintf', 'fprintf', 'snprintf',
        'fopen', 'fclose', 'fread', 'fwrite', 'fseek',
    ]
    
    # Additional check for patterns that are too generic
    def is_too_generic(pattern):
        """Check if a pattern is too generic"""
        pattern_lower = pattern.lower()
        
        # Too short (less than 6 chars) unless it has pcoip prefix
        if len(pattern) < 6 and not pattern_lower.startswith('pcoip'):
            return True
            
        # Common C/C++ keywords or standard library functions
        c_keywords = {'auto', 'break', 'case', 'const', 'continue', 'default',
                     'do', 'else', 'enum', 'extern', 'for', 'goto', 'if',
                     'inline', 'register', 'return', 'sizeof', 'static',
                     'struct', 'switch', 'typedef', 'union', 'unsigned',
                     'volatile', 'while', 'class', 'namespace', 'template',
                     'public', 'private', 'protected', 'virtual', 'override'}
        
        if pattern_lower in c_keywords:
            return True
            
        # Generic networking/protocol terms without pcoip prefix
        generic_terms = {'protocol', 'packet', 'frame', 'header', 'payload',
                        'transport', 'network', 'session', 'application',
                        'bandwidth', 'latency', 'throughput', 'quality',
                        'codec', 'encoder', 'decoder', 'compression'}
        
        if pattern_lower in generic_terms:
            return True
            
        # Patterns that are just numbers or underscores
        if pattern.replace('_', '').isdigit():
            return True
            
        return False
    
    # Get PCoIP SDK component ID
    cursor.execute("SELECT id, name FROM components WHERE name LIKE '%PCoIP%'")
    pcoip_components = cursor.fetchall()
    
    for component_id, component_name in pcoip_components:
        print(f"\nProcessing {component_name} (ID: {component_id})")
        
        # Count current signatures
        cursor.execute("SELECT COUNT(*) FROM signatures WHERE component_id = ?", (component_id,))
        before_count = cursor.fetchone()[0]
        print(f"Current signature count: {before_count}")
        
        # Remove bad signatures
        decompressor = zstd.ZstdDecompressor()
        removed = 0
        kept_signatures = []
        
        cursor.execute("SELECT id, signature_compressed FROM signatures WHERE component_id = ?", (component_id,))
        signatures = cursor.fetchall()
        
        for sig_id, sig_compressed in signatures:
            if sig_compressed:
                sig = decompressor.decompress(sig_compressed).decode('utf-8')
                
                # Check if this is a bad pattern
                is_bad = False
                
                # Check exact matches
                if sig in bad_patterns:
                    is_bad = True
                    print(f"  Removing exact match: '{sig}'")
                    
                # Check if it's too generic
                elif is_too_generic(sig):
                    is_bad = True
                    print(f"  Removing generic: '{sig}'")
                    
                # Check case-insensitive matches for short patterns
                elif len(sig) <= 10:
                    sig_lower = sig.lower()
                    for bad in bad_patterns:
                        if sig_lower == bad.lower():
                            is_bad = True
                            print(f"  Removing case match: '{sig}'")
                            break
                
                if is_bad:
                    cursor.execute("DELETE FROM signatures WHERE id = ?", (sig_id,))
                    removed += 1
                else:
                    # Keep good signatures like pcoip_client_*, PCOIP_*, etc.
                    if 'pcoip' in sig.lower() or sig.startswith('PCOIP'):
                        kept_signatures.append(sig)
        
        conn.commit()
        
        # Count after removal
        cursor.execute("SELECT COUNT(*) FROM signatures WHERE component_id = ?", (component_id,))
        after_count = cursor.fetchone()[0]
        
        print(f"\nRemoved {removed} bad signatures")
        print(f"New signature count: {after_count}")
        if before_count > 0:
            print(f"Reduction: {before_count - after_count} signatures ({(1 - after_count/before_count)*100:.1f}%)")
        
        if kept_signatures[:10]:
            print(f"Sample kept signatures: {', '.join(kept_signatures[:10])}")
    
    conn.close()

if __name__ == '__main__':
    fix_pcoip_signatures()