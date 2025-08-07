#!/usr/bin/env python3
"""
Fix Microsoft OLE false positive signatures
"""

import sqlite3
import zstandard as zstd
from pathlib import Path

def fix_microsoft_signatures():
    """Remove overly generic Microsoft OLE signatures"""
    
    db_path = Path.home() / '.binarysniffer' / 'signatures.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Patterns that are too generic and cause false positives
    bad_patterns = [
        'arshal',  # Too generic, matches marshal functions in many libraries
        'arshal64',
        'arshalExt',
        'Marshal',  # Also too generic alone
        'Unmarshal',  # Too generic alone
        'VARIANT',  # Can appear in many contexts
    ]
    
    # Get Microsoft OLE component ID
    cursor.execute("SELECT id FROM components WHERE name LIKE '%Microsoft OLE%'")
    component_id = cursor.fetchone()[0]
    
    print(f"Found Microsoft OLE component with ID: {component_id}")
    
    # Count current signatures
    cursor.execute("SELECT COUNT(*) FROM signatures WHERE component_id = ?", (component_id,))
    before_count = cursor.fetchone()[0]
    print(f"Current signature count: {before_count}")
    
    # Remove bad signatures
    decompressor = zstd.ZstdDecompressor()
    removed = 0
    
    cursor.execute("SELECT id, signature_compressed FROM signatures WHERE component_id = ?", (component_id,))
    signatures = cursor.fetchall()
    
    for sig_id, sig_compressed in signatures:
        if sig_compressed:
            sig = decompressor.decompress(sig_compressed).decode('utf-8')
            
            # Check if this is a bad pattern
            for bad_pattern in bad_patterns:
                if sig == bad_pattern or (len(sig) <= 10 and bad_pattern.lower() in sig.lower()):
                    print(f"Removing bad signature: '{sig}'")
                    cursor.execute("DELETE FROM signatures WHERE id = ?", (sig_id,))
                    removed += 1
                    break
    
    conn.commit()
    
    # Count after removal
    cursor.execute("SELECT COUNT(*) FROM signatures WHERE component_id = ?", (component_id,))
    after_count = cursor.fetchone()[0]
    
    print(f"\nRemoved {removed} bad signatures")
    print(f"New signature count: {after_count}")
    print(f"Reduction: {before_count - after_count} signatures ({(1 - after_count/before_count)*100:.1f}%)")
    
    conn.close()

if __name__ == '__main__':
    fix_microsoft_signatures()