"""
Package inventory extraction utilities.

Provides functions to enumerate and export file listings from archives and packages
with comprehensive analysis including hashes, MIME types, and component detection.
"""

import json
import csv
import mimetypes
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


def extract_package_inventory(file_path: Path, analyzer=None, analyze_contents: bool = False,
                             include_hashes: bool = False, include_fuzzy_hashes: bool = False,
                             detect_components: bool = False) -> Dict[str, Any]:
    """
    Extract inventory of files from a package/archive with comprehensive analysis.
    
    Args:
        file_path: Path to the package file
        analyzer: Optional analyzer instance to use for component detection
        analyze_contents: Extract and analyze file contents (slower but more comprehensive)
        include_hashes: Include cryptographic hashes (MD5, SHA1, SHA256)
        include_fuzzy_hashes: Include fuzzy hashes (TLSH, ssdeep)
        detect_components: Run component detection on files
        
    Returns:
        Dictionary containing comprehensive package inventory
    """
    import zipfile
    import tarfile
    import hashlib
    
    inventory = {
        "package_path": str(file_path),
        "package_name": file_path.name,
        "package_size": file_path.stat().st_size if file_path.exists() else 0,
        "files": [],
        "summary": {
            "total_files": 0,
            "total_size": 0,
            "file_types": {},
            "components_detected": set() if detect_components else None
        }
    }
    
    # Create temporary directory for extraction if needed
    temp_dir = None
    if analyze_contents and (include_hashes or include_fuzzy_hashes or detect_components):
        temp_dir = tempfile.mkdtemp(prefix="binarysniffer_inventory_")
    
    try:
        # Determine archive type and extract file listing
        if zipfile.is_zipfile(file_path):
            # Handle ZIP-based archives (ZIP, JAR, APK, etc.)
            inventory["package_type"] = "zip"
            with zipfile.ZipFile(file_path, 'r') as zf:
                for info in zf.infolist():
                    file_entry = {
                        "path": info.filename,  # This is already the relative path within the archive
                        "size": info.file_size,
                        "compressed_size": info.compress_size,
                        "compression_method": info.compress_type,
                        "compression_ratio": round(1 - (info.compress_size / info.file_size), 3) if info.file_size > 0 else 0,
                        "modified": str(info.date_time),
                        "crc": hex(info.CRC) if info.CRC else '',
                        "is_directory": info.is_dir() if hasattr(info, 'is_dir') else info.filename.endswith('/')
                    }
                    
                    # Add MIME type
                    mime_type, _ = mimetypes.guess_type(info.filename)
                    file_entry["mime_type"] = mime_type or "application/octet-stream"
                    
                    # Process file contents if requested and not a directory
                    if not file_entry["is_directory"] and analyze_contents:
                        try:
                            # Extract file to temp directory
                            if temp_dir:
                                extracted_path = Path(temp_dir) / info.filename
                                extracted_path.parent.mkdir(parents=True, exist_ok=True)
                                
                                # Extract single file
                                with zf.open(info) as source:
                                    file_data = source.read()
                                    with open(extracted_path, 'wb') as target:
                                        target.write(file_data)
                                
                                # Calculate hashes if requested
                                if include_hashes or include_fuzzy_hashes:
                                    from binarysniffer.utils.file_metadata import calculate_file_hashes
                                    try:
                                        hashes = calculate_file_hashes(extracted_path, include_fuzzy=include_fuzzy_hashes)
                                        file_entry["hashes"] = hashes
                                    except Exception as e:
                                        logger.debug(f"Failed to calculate hashes for {info.filename}: {e}")
                                
                                # Run component detection if requested
                                if detect_components and analyzer:
                                    try:
                                        result = analyzer.analyze_file(extracted_path, confidence_threshold=0.5)
                                        if result.matches:
                                            file_entry["components"] = [
                                                {
                                                    "name": match.component,
                                                    "confidence": round(match.confidence, 3),
                                                    "license": match.license
                                                }
                                                for match in result.matches
                                            ]
                                            # Add to summary
                                            for match in result.matches:
                                                inventory["summary"]["components_detected"].add(match.component)
                                        
                                        # Add feature count
                                        file_entry["features_extracted"] = result.features_extracted
                                    except Exception as e:
                                        logger.debug(f"Failed to analyze {info.filename}: {e}")
                        except Exception as e:
                            logger.debug(f"Failed to process {info.filename}: {e}")
                    
                    # Add to inventory
                    inventory["files"].append(file_entry)
                    
                    # Update summary
                    if not file_entry["is_directory"]:
                        inventory["summary"]["total_files"] += 1
                        inventory["summary"]["total_size"] += file_entry["size"]
                        
                        # Track file types
                        ext = Path(file_entry["path"]).suffix.lower()
                        if ext:
                            inventory["summary"]["file_types"][ext] = \
                                inventory["summary"]["file_types"].get(ext, 0) + 1
            
            # Check for specific package types
            if file_path.suffix.lower() == '.apk':
                inventory["package_type"] = "android"
                # Try to extract APK metadata
                try:
                    from binarysniffer.extractors.archive import ArchiveExtractor
                    extractor = ArchiveExtractor()
                    features = extractor.extract(file_path)
                    if hasattr(features, 'metadata') and features.metadata:
                        if 'app_name' in features.metadata:
                            inventory["app_name"] = features.metadata['app_name']
                        if 'package_name' in features.metadata:
                            inventory["package_id"] = features.metadata['package_name']
                        if 'version' in features.metadata:
                            inventory["version"] = features.metadata['version']
                except:
                    pass
            elif file_path.suffix.lower() == '.jar':
                inventory["package_type"] = "java"
            elif file_path.suffix.lower() == '.war':
                inventory["package_type"] = "java_web"
                
        elif tarfile.is_tarfile(file_path):
            # Handle TAR-based archives
            inventory["package_type"] = "tar"
            with tarfile.open(file_path, 'r') as tf:
                for member in tf.getmembers():
                    file_entry = {
                        "path": member.name,  # This is already the relative path within the archive
                        "size": member.size,
                        "compressed_size": 0,  # TAR doesn't compress individual files
                        "compression_method": "stored",
                        "compression_ratio": 0,
                        "modified": str(member.mtime),
                        "crc": "",
                        "is_directory": member.isdir()
                    }
                    
                    # Add MIME type
                    mime_type, _ = mimetypes.guess_type(member.name)
                    file_entry["mime_type"] = mime_type or "application/octet-stream"
                    
                    # Process file contents if requested and not a directory
                    if not file_entry["is_directory"] and analyze_contents and member.isfile():
                        try:
                            # Extract file to temp directory
                            if temp_dir:
                                extracted_path = Path(temp_dir) / member.name
                                extracted_path.parent.mkdir(parents=True, exist_ok=True)
                                
                                # Extract single file
                                tf.extract(member, temp_dir)
                                
                                # Calculate hashes if requested
                                if include_hashes or include_fuzzy_hashes:
                                    from binarysniffer.utils.file_metadata import calculate_file_hashes
                                    try:
                                        hashes = calculate_file_hashes(extracted_path, include_fuzzy=include_fuzzy_hashes)
                                        file_entry["hashes"] = hashes
                                    except Exception as e:
                                        logger.debug(f"Failed to calculate hashes for {member.name}: {e}")
                                
                                # Run component detection if requested
                                if detect_components and analyzer:
                                    try:
                                        result = analyzer.analyze_file(extracted_path, confidence_threshold=0.5)
                                        if result.matches:
                                            file_entry["components"] = [
                                                {
                                                    "name": match.component,
                                                    "confidence": round(match.confidence, 3),
                                                    "license": match.license
                                                }
                                                for match in result.matches
                                            ]
                                            # Add to summary
                                            for match in result.matches:
                                                inventory["summary"]["components_detected"].add(match.component)
                                        
                                        # Add feature count
                                        file_entry["features_extracted"] = result.features_extracted
                                    except Exception as e:
                                        logger.debug(f"Failed to analyze {member.name}: {e}")
                        except Exception as e:
                            logger.debug(f"Failed to process {member.name}: {e}")
                    
                    # Add to inventory
                    inventory["files"].append(file_entry)
                    
                    # Update summary
                    if not file_entry["is_directory"]:
                        inventory["summary"]["total_files"] += 1
                        inventory["summary"]["total_size"] += file_entry["size"]
                        
                        # Track file types
                        ext = Path(file_entry["path"]).suffix.lower()
                        if ext:
                            inventory["summary"]["file_types"][ext] = \
                                inventory["summary"]["file_types"].get(ext, 0) + 1
        else:
            inventory["error"] = "Unsupported archive format"
    
    except Exception as e:
        logger.error(f"Failed to extract inventory from {file_path}: {e}")
        inventory["error"] = str(e)
    
    finally:
        # Clean up temporary directory
        if temp_dir and Path(temp_dir).exists():
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.debug(f"Failed to clean up temp directory: {e}")
    
    # Convert components set to list for JSON serialization
    if inventory["summary"]["components_detected"] is not None:
        inventory["summary"]["components_detected"] = list(inventory["summary"]["components_detected"])
    
    return inventory


def export_inventory_json(inventory: Dict[str, Any], output_path: Path):
    """Export inventory to JSON format."""
    with open(output_path, 'w') as f:
        json.dump(inventory, f, indent=2, default=str)


def export_inventory_csv(inventory: Dict[str, Any], output_path: Path):
    """Export inventory to CSV format with comprehensive data."""
    # Determine all possible fieldnames from the data
    fieldnames = [
        'path', 'size', 'compressed_size', 'compression_ratio', 'compression_method',
        'mime_type', 'modified', 'crc', 'is_directory', 'features_extracted'
    ]
    
    # Check if we have hash data
    has_hashes = any('hashes' in f for f in inventory.get('files', []))
    if has_hashes:
        # Add hash fields
        fieldnames.extend(['md5', 'sha1', 'sha256', 'tlsh', 'ssdeep'])
    
    # Check if we have component data
    has_components = any('components' in f for f in inventory.get('files', []))
    if has_components:
        fieldnames.extend(['components_detected', 'top_component', 'top_confidence'])
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        
        for file_entry in inventory.get('files', []):
            row = file_entry.copy()
            
            # Flatten hash data if present
            if 'hashes' in file_entry:
                for hash_type, hash_value in file_entry['hashes'].items():
                    row[hash_type] = hash_value
            
            # Flatten component data if present
            if 'components' in file_entry and file_entry['components']:
                row['components_detected'] = len(file_entry['components'])
                row['top_component'] = file_entry['components'][0]['name']
                row['top_confidence'] = file_entry['components'][0]['confidence']
            
            writer.writerow(row)


def export_inventory_tree(inventory: Dict[str, Any], output_path: Path):
    """Export inventory as a directory tree structure."""
    from collections import defaultdict
    
    # Build tree structure
    tree = defaultdict(list)
    for file_entry in inventory.get('files', []):
        path = Path(file_entry['path'])
        parent = str(path.parent) if path.parent != Path('.') else ''
        tree[parent].append({
            'name': path.name,
            'size': file_entry['size'],
            'is_dir': file_entry['is_directory']
        })
    
    # Write tree to file
    with open(output_path, 'w') as f:
        f.write(f"Package: {inventory['package_name']}\n")
        f.write(f"Size: {inventory['package_size']:,} bytes\n")
        f.write(f"Total files: {inventory['summary']['total_files']}\n")
        f.write(f"Total uncompressed size: {inventory['summary']['total_size']:,} bytes\n")
        f.write("\n")
        
        def write_tree(parent='', indent=0):
            if parent in tree:
                for item in sorted(tree[parent], key=lambda x: (not x['is_dir'], x['name'])):
                    prefix = '  ' * indent + ('📁 ' if item['is_dir'] else '📄 ')
                    size_str = f" ({item['size']:,} bytes)" if not item['is_dir'] else ""
                    f.write(f"{prefix}{item['name']}{size_str}\n")
                    if item['is_dir']:
                        child_path = Path(parent) / item['name'] if parent else item['name']
                        write_tree(str(child_path), indent + 1)
        
        write_tree()


def get_package_inventory_summary(file_path: Path) -> str:
    """
    Get a summary of package contents.
    
    Args:
        file_path: Path to the package
        
    Returns:
        String summary of package contents
    """
    inventory = extract_package_inventory(file_path)
    
    if 'error' in inventory:
        return f"Error: {inventory['error']}"
    
    summary_lines = [
        f"Package: {inventory['package_name']}",
        f"Type: {inventory.get('package_type', 'Unknown')}",
        f"Size: {inventory['package_size']:,} bytes",
        f"Total files: {inventory['summary']['total_files']}",
        f"Uncompressed size: {inventory['summary']['total_size']:,} bytes"
    ]
    
    if inventory['summary']['file_types']:
        summary_lines.append("\nFile types:")
        for ext, count in sorted(inventory['summary']['file_types'].items(), 
                                key=lambda x: x[1], reverse=True)[:10]:
            summary_lines.append(f"  {ext}: {count} files")
    
    return '\n'.join(summary_lines)