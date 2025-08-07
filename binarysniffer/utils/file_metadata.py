"""
File metadata extraction utilities.

Provides functions to calculate hashes and extract metadata from files.
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    HAS_TLSH = False
    logger.debug("TLSH not available for fuzzy hashing")

try:
    import ssdeep
    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False
    logger.debug("ssdeep not available for fuzzy hashing")


def calculate_file_hashes(file_path: Path, include_fuzzy: bool = True) -> Dict[str, str]:
    """
    Calculate various hashes for a file.
    
    Args:
        file_path: Path to the file
        include_fuzzy: Whether to include fuzzy hashes (TLSH, ssdeep)
        
    Returns:
        Dictionary of hash type to hash value
    """
    hashes = {}
    
    try:
        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Calculate standard cryptographic hashes
        hashes['md5'] = hashlib.md5(content).hexdigest()
        hashes['sha1'] = hashlib.sha1(content).hexdigest()
        hashes['sha256'] = hashlib.sha256(content).hexdigest()
        
        # Calculate fuzzy hashes if available and requested
        if include_fuzzy:
            if HAS_TLSH and len(content) >= 50:  # TLSH needs min 50 bytes
                try:
                    tlsh_hash = tlsh.hash(content)
                    if tlsh_hash:  # TLSH returns empty string if it can't hash
                        hashes['tlsh'] = tlsh_hash
                except Exception as e:
                    logger.debug(f"Failed to calculate TLSH: {e}")
            
            if HAS_SSDEEP:
                try:
                    hashes['ssdeep'] = ssdeep.hash(content)
                except Exception as e:
                    logger.debug(f"Failed to calculate ssdeep: {e}")
    
    except Exception as e:
        logger.error(f"Failed to calculate hashes for {file_path}: {e}")
    
    return hashes


def get_file_metadata(file_path: Path, include_hashes: bool = True, include_fuzzy: bool = True) -> Dict[str, Any]:
    """
    Extract comprehensive file metadata.
    
    Args:
        file_path: Path to the file
        include_hashes: Whether to include hash calculations
        include_fuzzy: Whether to include fuzzy hashes
        
    Returns:
        Dictionary of metadata
    """
    metadata = {}
    
    try:
        file_path = Path(file_path)
        stat = file_path.stat()
        
        # Basic file info
        metadata['name'] = file_path.name
        metadata['path'] = str(file_path.absolute())
        metadata['size'] = stat.st_size
        metadata['modified'] = stat.st_mtime
        
        # Calculate hashes if requested
        if include_hashes:
            metadata['hashes'] = calculate_file_hashes(file_path, include_fuzzy)
        
    except Exception as e:
        logger.error(f"Failed to get metadata for {file_path}: {e}")
        metadata['error'] = str(e)
    
    return metadata