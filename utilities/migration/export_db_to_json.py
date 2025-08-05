#!/usr/bin/env python3
"""
Export signatures from the SQLite database to individual JSON files.
This will help migrate to the new signature distribution system.
"""

import sqlite3
import json
import sys
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

def export_signatures_to_json(db_path: Path, output_dir: Path) -> None:
    """Export signatures from SQLite database to individual JSON files."""
    
    if not db_path.exists():
        print(f"Database file not found: {db_path}")
        sys.exit(1)
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Connect to database
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Enable dict-like access to rows
    cursor = conn.cursor()
    
    try:
        # Get table structure first
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        print(f"Found tables: {[t[0] for t in tables]}")
        
        # Check if we have a signatures table
        cursor.execute("PRAGMA table_info(signatures);")
        columns = cursor.fetchall()
        if not columns:
            print("No 'signatures' table found. Checking other tables...")
            # List all tables and their columns
            for table in tables:
                table_name = table[0]
                cursor.execute(f"PRAGMA table_info({table_name});")
                table_columns = cursor.fetchall()
                print(f"\nTable '{table_name}' columns:")
                for col in table_columns:
                    print(f"  - {col[1]} ({col[2]})")
            return
        
        print(f"Signatures table columns: {[col[1] for col in columns]}")
        
        # Get components table first
        cursor.execute("SELECT * FROM components LIMIT 5;")
        sample_components = cursor.fetchall()
        print(f"Sample components: {[dict(c) for c in sample_components]}")
        
        # Get all signatures grouped by component using JOIN
        cursor.execute("""
            SELECT c.name as component_name, COUNT(*) as signature_count 
            FROM signatures s
            JOIN components c ON s.component_id = c.id
            GROUP BY c.name
        """)
        components = cursor.fetchall()
        
        print(f"Found {len(components)} components:")
        for comp in components:
            print(f"  - {comp[0]}: {comp[1]} signatures")
        
        # Export each component to a separate JSON file
        for component_row in components:
            component_name = component_row[0]
            if not component_name:
                continue
                
            print(f"\nExporting {component_name}...")
            
            # Get all signatures for this component with JOIN
            cursor.execute("""
                SELECT s.*, c.name as component_name, c.version, c.license
                FROM signatures s
                JOIN components c ON s.component_id = c.id
                WHERE c.name = ? 
                ORDER BY s.confidence DESC
            """, (component_name,))
            
            signatures = cursor.fetchall()
            
            # Get component metadata
            first_sig = signatures[0] if signatures else {}
            component_version = dict(first_sig).get("version", "unknown")
            component_license = dict(first_sig).get("license", "unknown")
            
            # Convert to our JSON format
            signature_data = {
                "component": {
                    "name": component_name,
                    "version": component_version,
                    "category": "imported",
                    "platforms": ["all"],
                    "languages": ["unknown"],
                    "description": f"Imported from legacy database - {component_name}",
                    "license": component_license
                },
                "signature_metadata": {
                    "version": "1.0.0",
                    "created": datetime.now().isoformat() + "Z",
                    "signature_count": len(signatures),
                    "confidence_threshold": 0.7,
                    "source": "migrated_from_sqlite_db"
                },
                "signatures": []
            }
            
            # Convert each signature
            for i, sig in enumerate(signatures):
                sig_dict = dict(sig)
                
                # Decompress signature if needed
                signature_content = sig_dict.get("signature_compressed", "")
                if not signature_content:
                    signature_content = sig_dict.get("signature", "")
                
                # Create signature entry
                signature_entry = {
                    "id": f"{component_name.lower().replace(' ', '_').replace('-', '_')}_{i}",
                    "type": sig_dict.get("sig_type", "string_pattern"),
                    "pattern": signature_content,
                    "confidence": float(sig_dict.get("confidence", 0.8)),
                    "context": "imported",
                    "platforms": ["all"],
                    "signature_hash": sig_dict.get("signature_hash", "")
                }
                
                # Add any additional fields we might have
                if sig_dict.get("file_name"):
                    signature_entry["source_file"] = sig_dict["file_name"]
                if sig_dict.get("line_number"):
                    signature_entry["line_number"] = sig_dict["line_number"]
                if sig_dict.get("context"):
                    signature_entry["additional_context"] = sig_dict["context"]
                    
                signature_data["signatures"].append(signature_entry)
            
            # Save to JSON file
            filename = component_name.lower().replace(" ", "-").replace("_", "-") + ".json"
            output_file = output_dir / filename
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(signature_data, f, indent=2, ensure_ascii=False)
            
            print(f"  Exported {len(signatures)} signatures to {filename}")
        
        # Create updated manifest
        manifest = {
            "version": "1.2.0",
            "signature_format_version": "1.0",
            "last_updated": datetime.now().isoformat() + "Z",
            "total_signatures": sum(comp[1] for comp in components),
            "signature_files": [],
            "categories": list(set(comp[0].split("-")[0] if "-" in comp[0] else "other" for comp in components)),
            "source": "Exported from legacy SQLite database"
        }
        
        # Add signature file entries
        for component_row in components:
            component_name = component_row[0]
            filename = component_name.lower().replace(" ", "-").replace("_", "-") + ".json"
            
            manifest["signature_files"].append({
                "filename": filename,
                "version": "1.0.0",
                "component": component_name,
                "description": f"Signatures for {component_name}",
                "signature_count": component_row[1],
                "platforms": ["all"],
                "languages": ["unknown"]
            })
        
        # Save manifest
        manifest_file = output_dir / "manifest.json"
        with open(manifest_file, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False)
        
        print(f"\nExport complete!")
        print(f"  - {len(components)} component files created")
        print(f"  - {manifest['total_signatures']} total signatures exported")
        print(f"  - Manifest updated: {manifest_file}")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        conn.close()

def main():
    # Paths
    project_root = Path(__file__).parent.parent
    db_path = project_root / "binarysniffer" / "extractors" / "data" / "signatures.db"
    output_dir = project_root / "signatures"
    
    print(f"Exporting signatures from: {db_path}")
    print(f"Output directory: {output_dir}")
    
    export_signatures_to_json(db_path, output_dir)

if __name__ == "__main__":
    main()