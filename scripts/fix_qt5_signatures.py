#!/usr/bin/env python3
"""
Fix Qt5 overly generic signatures that could cause legal issues
"""

import sqlite3
import zstandard as zstd
from pathlib import Path

def fix_qt5_signatures():
    """Remove overly generic Qt5 signatures"""
    
    db_path = Path.home() / '.binarysniffer' / 'signatures.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Patterns that are too generic and could match non-Qt code
    bad_patterns = [
        # Single letters or very short generic terms
        'Q', 'Qt', 'qt',
        # Generic programming terms
        'Widget', 'Object', 'Event', 'Thread', 'Signal', 'Slot',
        'Timer', 'List', 'Map', 'Vector', 'String', 'Data',
        'Button', 'Label', 'Text', 'View', 'Model', 'Item',
        'Layout', 'Dialog', 'Window', 'Frame', 'Box',
        'Action', 'Menu', 'Bar', 'Tool', 'Status',
        # Generic method names
        'init', 'destroy', 'create', 'delete', 'update',
        'paint', 'draw', 'render', 'show', 'hide',
        'move', 'resize', 'click', 'press', 'release',
        'open', 'close', 'read', 'write', 'save', 'load',
        # Too short prefixes
        'q_', 'Q_',
    ]
    
    # Get Qt5 component IDs
    cursor.execute("SELECT id, name FROM components WHERE name LIKE '%Qt%'")
    qt_components = cursor.fetchall()
    
    for component_id, component_name in qt_components:
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
                    
                # Check if it's too short and generic
                elif len(sig) <= 5 and not sig.startswith('Q'):
                    is_bad = True
                    
                # Check if it's a generic term without Qt prefix
                elif len(sig) <= 10:
                    sig_lower = sig.lower()
                    for bad in bad_patterns:
                        if sig_lower == bad.lower():
                            is_bad = True
                            break
                
                if is_bad:
                    print(f"  Removing: '{sig}'")
                    cursor.execute("DELETE FROM signatures WHERE id = ?", (sig_id,))
                    removed += 1
                else:
                    # Keep good signatures like QWidget, QApplication, etc.
                    if sig.startswith('Q') and len(sig) > 3:
                        kept_signatures.append(sig)
        
        conn.commit()
        
        # Count after removal
        cursor.execute("SELECT COUNT(*) FROM signatures WHERE component_id = ?", (component_id,))
        after_count = cursor.fetchone()[0]
        
        print(f"Removed {removed} bad signatures")
        print(f"New signature count: {after_count}")
        if before_count > 0:
            print(f"Reduction: {before_count - after_count} signatures ({(1 - after_count/before_count)*100:.1f}%)")
        
        if kept_signatures[:5]:
            print(f"Sample kept signatures: {', '.join(kept_signatures[:5])}")
    
    conn.close()

if __name__ == '__main__':
    fix_qt5_signatures()