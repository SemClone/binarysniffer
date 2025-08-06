#!/usr/bin/env python3
"""
Create signatures from binaries or source code

Usage:
    python create_signatures.py --binary /path/to/binary --name "Component Name" --output signatures/component.json
    python create_signatures.py --source /path/to/source --name "Component Name" --output signatures/component.json
"""

import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from binarysniffer.signatures.symbol_extractor import SymbolExtractor
from binarysniffer.signatures.validator import SignatureValidator
from binarysniffer.signatures.generator import SignatureGenerator


def create_signature_from_binary(
    binary_path: Path,
    component_name: str,
    version: str = "unknown",
    license_name: str = "",
    publisher: str = "",
    description: str = ""
) -> Dict:
    """
    Create signature from a binary file
    """
    print(f"Extracting symbols from {binary_path}...")
    
    # Extract symbols from binary
    symbols_data = SymbolExtractor.extract_symbols_from_binary(binary_path)
    
    print(f"Found {len(symbols_data['functions'])} functions, {len(symbols_data['objects'])} objects")
    
    # Generate signatures using symbol extractor
    signatures_by_component = SymbolExtractor.generate_signatures_from_binary(
        binary_path, 
        component_name
    )
    
    # Get the signatures for our component
    component_signatures = []
    if component_name in signatures_by_component:
        patterns = signatures_by_component[component_name]
    else:
        # If no specific component found, use all signatures
        patterns = []
        for sigs in signatures_by_component.values():
            patterns.extend(sigs)
    
    # Convert patterns to signature format
    for pattern in patterns[:50]:  # Limit to 50 signatures
        # Determine confidence based on pattern type
        confidence = 0.9  # Default high confidence for symbol-based patterns
        
        # Version strings get highest confidence
        if 'version' in pattern.lower() or 'ver_string' in pattern.lower():
            confidence = 0.95
        # Full function names get high confidence
        elif '(' in pattern or '_' in pattern and len(pattern) > 10:
            confidence = 0.9
        # Prefixes get slightly lower confidence
        elif pattern.endswith('_') and len(pattern) < 10:
            confidence = 0.85
        
        # Validate the signature
        if SignatureValidator.is_valid_signature(pattern, confidence):
            sig_type = "string_pattern"
            if pattern.endswith('_'):
                sig_type = "prefix_pattern"
            elif '(' in pattern:
                sig_type = "function_pattern"
            
            component_signatures.append({
                "id": f"{component_name.lower().replace(' ', '_')}_{len(component_signatures)}",
                "type": sig_type,
                "pattern": pattern,
                "confidence": confidence,
                "context": "binary_symbol",
                "platforms": ["all"]
            })
    
    # Build signature file
    signature_file = {
        "component": {
            "name": component_name,
            "version": version,
            "category": "imported",
            "platforms": ["all"],
            "languages": ["native"],
            "description": description or f"Signatures for {component_name}",
            "license": license_name,
            "publisher": publisher
        },
        "signature_metadata": {
            "version": "1.0.0",
            "created": datetime.now().isoformat() + "Z",
            "updated": datetime.now().isoformat() + "Z",
            "signature_count": len(component_signatures),
            "confidence_threshold": 0.7,
            "source": "binary_analysis",
            "extraction_method": "symbol_extraction"
        },
        "signatures": component_signatures
    }
    
    print(f"Generated {len(component_signatures)} valid signatures")
    
    return signature_file


def create_signature_from_source(
    source_path: Path,
    component_name: str,
    version: str = "unknown",
    license_name: str = "",
    publisher: str = "",
    description: str = "",
    recursive: bool = True
) -> Dict:
    """
    Create signature from source code
    """
    print(f"Analyzing source code in {source_path}...")
    
    generator = SignatureGenerator()
    
    # Generate signature from source
    raw_signature = generator.generate_from_path(
        path=source_path,
        package_name=component_name,
        publisher=publisher,
        license_name=license_name,
        version=version,
        description=description,
        recursive=recursive,
        min_confidence=0.7,
        min_symbols=5,
        include_strings=False,  # Don't include random strings
        include_constants=True,
        include_functions=True,
        include_imports=True
    )
    
    # Convert to our signature format
    component_signatures = []
    
    for symbol in raw_signature.get("symbols", []):
        # Validate the signature
        if SignatureValidator.is_valid_signature(symbol, 0.8):
            # Determine pattern type
            sig_type = "string_pattern"
            if symbol.endswith('_'):
                sig_type = "prefix_pattern"
            elif '::' in symbol or '.' in symbol:
                sig_type = "namespace_pattern"
            elif symbol.isupper():
                sig_type = "constant_pattern"
            
            component_signatures.append({
                "id": f"{component_name.lower().replace(' ', '_')}_{len(component_signatures)}",
                "type": sig_type,
                "pattern": symbol,
                "confidence": 0.8,
                "context": "source_code",
                "platforms": ["all"]
            })
    
    # Build signature file
    signature_file = {
        "component": {
            "name": component_name,
            "version": version,
            "category": "imported",
            "platforms": ["all"],
            "languages": ["unknown"],
            "description": description or f"Signatures for {component_name}",
            "license": license_name,
            "publisher": publisher
        },
        "signature_metadata": {
            "version": "1.0.0",
            "created": datetime.now().isoformat() + "Z",
            "updated": datetime.now().isoformat() + "Z",
            "signature_count": len(component_signatures),
            "confidence_threshold": 0.7,
            "source": "source_analysis",
            "extraction_method": "ast_parsing",
            "source_stats": raw_signature.get("metadata", {}).get("statistics", {})
        },
        "signatures": component_signatures
    }
    
    print(f"Generated {len(component_signatures)} valid signatures")
    
    return signature_file


def main():
    parser = argparse.ArgumentParser(
        description="Create signatures from binaries or source code"
    )
    
    # Input options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--binary", 
        type=Path,
        help="Path to binary file to analyze"
    )
    input_group.add_argument(
        "--source",
        type=Path,
        help="Path to source code directory or file"
    )
    
    # Component information
    parser.add_argument(
        "--name",
        required=True,
        help="Component name (e.g., 'FFmpeg', 'OpenSSL')"
    )
    parser.add_argument(
        "--version",
        default="unknown",
        help="Component version"
    )
    parser.add_argument(
        "--license",
        default="",
        help="License (e.g., 'MIT', 'Apache-2.0', 'GPL-3.0')"
    )
    parser.add_argument(
        "--publisher",
        default="",
        help="Publisher/Author name"
    )
    parser.add_argument(
        "--description",
        default="",
        help="Component description"
    )
    
    # Output
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output signature file path (e.g., signatures/ffmpeg.json)"
    )
    
    # Options
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Don't analyze subdirectories (for source code)"
    )
    
    args = parser.parse_args()
    
    # Create signature
    if args.binary:
        if not args.binary.exists():
            print(f"Error: Binary file not found: {args.binary}")
            sys.exit(1)
        
        signature = create_signature_from_binary(
            binary_path=args.binary,
            component_name=args.name,
            version=args.version,
            license_name=args.license,
            publisher=args.publisher,
            description=args.description
        )
    else:  # args.source
        if not args.source.exists():
            print(f"Error: Source path not found: {args.source}")
            sys.exit(1)
        
        signature = create_signature_from_source(
            source_path=args.source,
            component_name=args.name,
            version=args.version,
            license_name=args.license,
            publisher=args.publisher,
            description=args.description,
            recursive=not args.no_recursive
        )
    
    # Validate signature quality
    sig_count = signature["signature_metadata"]["signature_count"]
    if sig_count < 3:
        print(f"Warning: Only {sig_count} signatures generated. Consider analyzing more files.")
    
    # Save signature file
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(signature, f, indent=2, ensure_ascii=False)
    
    print(f"\nSignature file saved to: {args.output}")
    
    # Show summary
    print("\nSummary:")
    print(f"  Component: {args.name} v{args.version}")
    print(f"  Signatures: {sig_count}")
    print(f"  License: {args.license or 'Not specified'}")
    print(f"  Publisher: {args.publisher or 'Not specified'}")
    
    # Show example signatures
    print("\nExample signatures:")
    for sig in signature["signatures"][:5]:
        print(f"  - [{sig['type']}] {sig['pattern']} (conf: {sig['confidence']})")


if __name__ == "__main__":
    main()