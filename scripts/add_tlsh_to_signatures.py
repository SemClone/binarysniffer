#!/usr/bin/env python3
"""
Optional script to add TLSH hashes to existing signatures.
This is NOT required - existing signatures work fine without TLSH.
TLSH is an additive feature for fuzzy matching.
"""

import json
import sys
from pathlib import Path
import argparse

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from binarysniffer.hashing.tlsh_hasher import TLSHHasher


def add_tlsh_to_signature(sig_file: Path, dry_run: bool = True) -> bool:
    """
    Add TLSH hash to a signature file if possible.
    
    Args:
        sig_file: Path to signature JSON file
        dry_run: If True, don't modify files
        
    Returns:
        True if TLSH was added/would be added
    """
    hasher = TLSHHasher()
    
    if not hasher.enabled:
        print("Error: TLSH not available. Install with: pip install python-tlsh")
        return False
    
    try:
        with open(sig_file, 'r') as f:
            data = json.load(f)
        
        # Check if already has TLSH
        if 'tlsh_hash' in data:
            print(f"  Already has TLSH: {sig_file.name}")
            return False
        
        # Get patterns
        patterns = []
        if 'signatures' in data:
            patterns = [s['pattern'] for s in data['signatures']]
        elif 'symbols' in data:
            patterns = data['symbols']
        
        if len(patterns) < 10:
            print(f"  Too few patterns ({len(patterns)}): {sig_file.name}")
            return False
        
        # Generate TLSH
        tlsh_hash = hasher.hash_features(patterns)
        
        if not tlsh_hash:
            print(f"  Could not generate TLSH: {sig_file.name}")
            return False
        
        # Add TLSH to data
        data['tlsh_hash'] = tlsh_hash
        
        component = data.get('component', {}).get('name', 'Unknown')
        print(f"  ✓ Generated TLSH for {component}: {tlsh_hash[:32]}...")
        
        if not dry_run:
            # Save updated file
            with open(sig_file, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"    Saved: {sig_file.name}")
        else:
            print(f"    [DRY RUN] Would save: {sig_file.name}")
        
        return True
        
    except Exception as e:
        print(f"  Error processing {sig_file.name}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Add TLSH hashes to existing signatures (OPTIONAL)"
    )
    parser.add_argument(
        "path",
        nargs='?',
        default="signatures",
        help="Path to signature file or directory (default: signatures/)"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually modify files (default is dry run)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Limit number of files to process"
    )
    
    args = parser.parse_args()
    
    path = Path(args.path)
    dry_run = not args.apply
    
    if dry_run:
        print("DRY RUN MODE - No files will be modified")
        print("Use --apply to actually update files")
        print()
    
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = list(path.glob("*.json"))
        if args.limit:
            files = files[:args.limit]
    else:
        print(f"Error: {path} not found")
        sys.exit(1)
    
    print(f"Processing {len(files)} signature files...")
    print("=" * 60)
    
    updated = 0
    for sig_file in files:
        if add_tlsh_to_signature(sig_file, dry_run):
            updated += 1
    
    print("=" * 60)
    print(f"Summary: {updated}/{len(files)} signatures can be updated with TLSH")
    
    if dry_run and updated > 0:
        print("\nTo apply changes, run with --apply flag")


if __name__ == "__main__":
    main()