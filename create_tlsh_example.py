#!/usr/bin/env python3
"""
Example script to create TLSH signatures for binary files

This script demonstrates how to:
1. Generate TLSH hashes for known binaries
2. Create a TLSH signature database
3. Test fuzzy matching

Usage:
    python create_tlsh_example.py
"""

import logging
from pathlib import Path
from binarysniffer.hashing.tlsh_hasher import TLSHHasher, TLSHSignatureStore

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_example_tlsh_database():
    """Create an example TLSH signature database"""

    # Initialize hasher and store
    hasher = TLSHHasher()
    store = TLSHSignatureStore()

    if not hasher.enabled:
        print("❌ TLSH not available. Install with: pip install python-tlsh")
        return

    print("🔍 Creating example TLSH signature database...")

    # Example: Find some binaries on the system to hash
    common_binaries = [
        "/usr/bin/curl",
        "/usr/bin/openssl",
        "/usr/lib/libssl.dylib",
        "/usr/lib/libcrypto.dylib",
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
    ]

    signatures_added = 0

    for binary_path in common_binaries:
        path = Path(binary_path)
        if path.exists() and path.is_file():
            print(f"  📋 Processing: {path}")

            # Generate TLSH hash
            tlsh_hash = hasher.hash_file(path)
            if tlsh_hash:
                # Extract component name from path
                component_name = path.stem
                if component_name.startswith("lib"):
                    component_name = component_name[3:]  # Remove "lib" prefix

                # Add to store
                store.add_signature(
                    component=component_name,
                    version="system",
                    tlsh_hash=tlsh_hash,
                    metadata={
                        "source_path": str(path),
                        "file_size": path.stat().st_size,
                        "description": f"System binary: {path.name}",
                        "created_by": "example_script"
                    }
                )

                signatures_added += 1
                print(f"    ✅ Hash: {tlsh_hash}")
            else:
                print(f"    ❌ Could not generate TLSH hash")
        else:
            print(f"  ⏭️  Skipping (not found): {path}")

    if signatures_added > 0:
        print(f"\n✅ Created TLSH database with {signatures_added} signatures")
        print(f"📁 Location: {store.storage_path}")
        print(f"💡 Test it with: binarysniffer analyze <binary_file> (without --fast)")

        # Show example usage
        print("\n📖 Example commands:")
        print("  # Analyze with TLSH fuzzy matching enabled")
        print("  binarysniffer analyze /usr/bin/curl")
        print("  binarysniffer analyze some_binary --tlsh-threshold 50")
        print("")
        print("  # Check TLSH signature database")
        print(f"  cat {store.storage_path}")
    else:
        print("❌ No signatures were created")

def generate_hash_for_file(file_path: str):
    """Generate TLSH hash for a specific file"""
    hasher = TLSHHasher()

    if not hasher.enabled:
        print("❌ TLSH not available. Install with: pip install python-tlsh")
        return

    path = Path(file_path)
    if not path.exists():
        print(f"❌ File not found: {file_path}")
        return

    print(f"🔍 Generating TLSH hash for: {path}")
    tlsh_hash = hasher.hash_file(path)

    if tlsh_hash:
        print(f"✅ TLSH Hash: {tlsh_hash}")

        # Show how to add it to database
        print("\n📝 To add this to your TLSH database:")
        print("```python")
        print("from binarysniffer.hashing.tlsh_hasher import TLSHSignatureStore")
        print("store = TLSHSignatureStore()")
        print("store.add_signature(")
        print(f'    component="YourComponent",')
        print(f'    version="1.0.0",')
        print(f'    tlsh_hash="{tlsh_hash}",')
        print(f'    metadata={{"source_path": "{path}", "license": "MIT"}}')
        print(")")
        print("```")
    else:
        print("❌ Could not generate TLSH hash (file too small or incompatible)")

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        # Generate hash for specific file
        generate_hash_for_file(sys.argv[1])
    else:
        # Create example database
        create_example_tlsh_database()