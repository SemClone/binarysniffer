#!/usr/bin/env python3
"""
Convert BSA signature files to the new BinarySniffer JSON format.
This will process all BSA signatures and create proper signature files.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

def convert_bsa_to_new_format(bsa_data: Dict[str, Any], filename: str) -> Dict[str, Any]:
    """Convert BSA format to new BinarySniffer format"""
    
    # Extract metadata
    package_name = bsa_data.get("package", filename.replace(".json", "").replace("-", " ").title())
    publisher = bsa_data.get("publisher", "Unknown")
    license_info = bsa_data.get("license", "Unknown")
    symbols = bsa_data.get("symbols", [])
    updated = bsa_data.get("updated", "2022-06-12")
    
    # Determine category based on package name
    category = "imported"
    if any(keyword in package_name.lower() for keyword in ["android", "sdk", "mobile"]):
        category = "mobile-sdk"
    elif any(keyword in package_name.lower() for keyword in ["apache", "google", "facebook"]):
        category = "enterprise-library"
    elif any(keyword in package_name.lower() for keyword in ["ffmpeg", "codec", "media", "video", "audio"]):
        category = "media-processing"
    elif any(keyword in package_name.lower() for keyword in ["json", "xml", "parser"]):
        category = "data-processing"
    elif any(keyword in package_name.lower() for keyword in ["network", "http", "web"]):
        category = "networking"
    
    # Determine platforms and languages based on context
    platforms = ["all"]
    languages = ["unknown"]
    
    if "android" in package_name.lower():
        platforms = ["android"]
        languages = ["java", "kotlin"]
    elif "ios" in package_name.lower():
        platforms = ["ios"]
        languages = ["swift", "objective-c"]
    elif any(keyword in package_name.lower() for keyword in ["java", "jackson", "apache", "google"]):
        platforms = ["java"]
        languages = ["java"]
    elif any(keyword in package_name.lower() for keyword in ["go", "golang"]):
        platforms = ["all"]
        languages = ["go"]
    elif any(keyword in package_name.lower() for keyword in ["js", "javascript", "node"]):
        platforms = ["web", "node"]
        languages = ["javascript"]
    elif any(keyword in package_name.lower() for keyword in ["c++", "cpp", "ffmpeg", "webkit"]):
        platforms = ["all"]
        languages = ["c", "c++"]
    
    # Convert symbols to signature entries
    signatures = []
    for i, symbol in enumerate(symbols):
        if not symbol or len(symbol) < 3:  # Skip empty or very short symbols
            continue
            
        # Determine confidence based on symbol characteristics
        confidence = 0.7  # Default
        if len(symbol) > 10:
            confidence = 0.8
        if any(keyword in symbol.lower() for keyword in [package_name.lower().split()[0], publisher.lower()]):
            confidence = 0.9
        if symbol.startswith(("com_", "org_", "lib", "av_", "google_", "facebook_")):
            confidence = 0.85
            
        # Determine context based on symbol pattern
        context = "unknown"
        if any(pattern in symbol.lower() for pattern in ["init", "create", "alloc"]):
            context = "initialization"
        elif any(pattern in symbol.lower() for pattern in ["parse", "decode", "encode"]):
            context = "processing"
        elif any(pattern in symbol.lower() for pattern in ["button", "view", "dialog", "ui"]):
            context = "user_interface"
        elif any(pattern in symbol.lower() for pattern in ["network", "http", "url"]):
            context = "networking"
        elif any(pattern in symbol.lower() for pattern in ["log", "debug", "error"]):
            context = "logging"
        elif symbol.startswith("com_"):
            context = "resource_identifier"
        elif symbol.startswith(("lib", "av_")):
            context = "library_function"
        
        signature_entry = {
            "id": f"{filename.replace('.json', '').replace('-', '_')}_{i}",
            "type": "string_pattern",
            "pattern": symbol,
            "confidence": confidence,
            "context": context,
            "platforms": platforms
        }
        
        signatures.append(signature_entry)
    
    # Create the new format
    new_format = {
        "component": {
            "name": package_name,
            "version": "unknown",
            "category": category,
            "platforms": platforms,
            "languages": languages,
            "description": f"Signatures for {package_name} - {publisher}",
            "license": license_info,
            "publisher": publisher
        },
        "signature_metadata": {
            "version": "1.0.0",
            "created": datetime.now().isoformat() + "Z",
            "updated": f"{updated}T00:00:00Z",
            "signature_count": len(signatures),
            "confidence_threshold": 0.7,
            "source": "converted_from_bsa_format",
            "original_file": filename
        },
        "signatures": signatures
    }
    
    return new_format

def main():
    # Paths
    project_root = Path(__file__).parent.parent
    bsa_dir = project_root / "signatures" / "BSA-Signatures-Experimental-main" / "signatures"
    output_dir = project_root / "signatures"
    
    if not bsa_dir.exists():
        print(f"BSA signatures directory not found: {bsa_dir}")
        sys.exit(1)
    
    print(f"Converting BSA signatures from: {bsa_dir}")
    print(f"Output directory: {output_dir}")
    
    converted_count = 0
    total_signatures = 0
    
    # Process each BSA signature file
    for bsa_file in bsa_dir.glob("*.json"):
        try:
            print(f"Converting {bsa_file.name}...")
            
            # Load BSA format
            with open(bsa_file, 'r', encoding='utf-8') as f:
                bsa_data = json.load(f)
            
            # Convert to new format
            new_data = convert_bsa_to_new_format(bsa_data, bsa_file.name)
            
            # Save to output directory with BSA prefix to avoid conflicts
            output_file = output_dir / f"bsa-{bsa_file.name}"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(new_data, f, indent=2, ensure_ascii=False)
            
            converted_count += 1
            total_signatures += len(new_data["signatures"])
            
            print(f"  ✅ {bsa_file.name} → {output_file.name} ({len(new_data['signatures'])} signatures)")
            
        except Exception as e:
            print(f"  ❌ Error converting {bsa_file.name}: {e}")
    
    # Update manifest
    manifest_file = output_dir / "manifest.json"
    if manifest_file.exists():
        with open(manifest_file, 'r') as f:
            manifest = json.load(f)
    else:
        manifest = {
            "version": "1.3.0",
            "signature_format_version": "1.0",
            "total_signatures": 0,
            "signature_files": [],
            "categories": []
        }
    
    # Add BSA signatures to manifest
    bsa_categories = set()
    for bsa_file in bsa_dir.glob("*.json"):
        output_file = output_dir / f"bsa-{bsa_file.name}"
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                
                bsa_categories.add(data["component"]["category"])
                
                manifest["signature_files"].append({
                    "filename": f"bsa-{bsa_file.name}",
                    "version": "1.0.0",
                    "component": data["component"]["name"],
                    "description": data["component"]["description"],
                    "signature_count": data["signature_metadata"]["signature_count"],
                    "platforms": data["component"]["platforms"],
                    "languages": data["component"]["languages"],
                    "source": "BSA_conversion"
                })
            except Exception as e:
                print(f"Warning: Could not add {bsa_file.name} to manifest: {e}")
    
    manifest["version"] = "1.3.0"
    manifest["last_updated"] = datetime.now().isoformat() + "Z"
    manifest["total_signatures"] = total_signatures
    manifest["categories"].extend(list(bsa_categories))
    manifest["categories"] = list(set(manifest["categories"]))  # Remove duplicates
    
    # Save updated manifest
    with open(manifest_file, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    
    print(f"\n🎉 Conversion complete!")
    print(f"  - {converted_count} BSA signature files converted")
    print(f"  - {total_signatures} total signatures processed")
    print(f"  - Manifest updated: {manifest_file}")
    print(f"  - Categories: {', '.join(sorted(bsa_categories))}")

if __name__ == "__main__":
    main()