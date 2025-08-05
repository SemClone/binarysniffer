"""
MinHash LSH index implementation
"""

import os
import struct
import mmap
import logging
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

import xxhash

from ..utils.hashing import MinHash


logger = logging.getLogger(__name__)


class MinHashIndex:
    """
    MinHash LSH index using memory-mapped files for efficiency.
    """
    
    def __init__(self, index_path: Path, num_perm: int = 128, bands: int = 16):
        """
        Initialize MinHash index.
        
        Args:
            index_path: Path to index file
            num_perm: Number of MinHash permutations
            bands: Number of LSH bands
        """
        self.index_path = Path(index_path)
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.num_perm = num_perm
        self.bands = bands
        self.rows = num_perm // bands
        
        self.index_file = None
        self.index_map: Dict[int, Tuple[int, int]] = {}
        
        # Load existing index if available
        if self.index_path.exists():
            self._load_index()
    
    def is_initialized(self) -> bool:
        """Check if index is initialized"""
        return self.index_path.exists() and len(self.index_map) > 0
    
    def build_index(self, signatures: List[Tuple[int, bytes]]):
        """
        Build MinHash index from signatures.
        
        Args:
            signatures: List of (signature_id, minhash_bytes) tuples
        """
        logger.info(f"Building MinHash index with {len(signatures)} signatures")
        
        # Create band hash -> signature IDs mapping
        band_buckets = defaultdict(list)
        
        for sig_id, minhash_bytes in signatures:
            # Convert bytes back to MinHash
            minhash = MinHash.from_bytes(minhash_bytes, self.num_perm)
            
            # Hash each band
            for band in range(self.bands):
                start = band * self.rows
                end = start + self.rows
                
                # Create band hash
                band_data = struct.pack(f'{self.rows}Q', *minhash.hashvalues[start:end])
                band_hash = xxhash.xxh64(band_data).intdigest()
                
                band_buckets[band_hash].append(sig_id)
        
        # Write to file
        self._write_index(band_buckets)
        
        logger.info(f"Index built with {len(band_buckets)} buckets")
    
    def query(self, query_minhash: MinHash, threshold: float = 0.5) -> Set[int]:
        """
        Query for similar signatures.
        
        Args:
            query_minhash: MinHash to search for
            threshold: Similarity threshold (not used in LSH, but kept for API compatibility)
            
        Returns:
            Set of signature IDs that might be similar
        """
        if not self.index_map:
            return set()
        
        candidates = set()
        
        # Hash each band of the query
        for band in range(self.bands):
            start = band * self.rows
            end = start + self.rows
            
            # Create band hash
            band_data = struct.pack(f'{self.rows}Q', *query_minhash.hashvalues[start:end])
            band_hash = xxhash.xxh64(band_data).intdigest()
            
            # Look up in index
            if band_hash in self.index_map:
                sig_ids = self._read_bucket(band_hash)
                candidates.update(sig_ids)
        
        return candidates
    
    def _write_index(self, band_buckets: Dict[int, List[int]]):
        """Write index to file"""
        with open(self.index_path, 'wb') as f:
            # Write header
            f.write(struct.pack('<I', len(band_buckets)))  # Number of buckets
            
            # Calculate offsets
            offset = 4 + len(band_buckets) * 16  # Header + index table
            
            # Build index map
            self.index_map.clear()
            for band_hash, sig_ids in band_buckets.items():
                self.index_map[band_hash] = (offset, len(sig_ids))
                offset += len(sig_ids) * 4
            
            # Write index table
            for band_hash, (offset, count) in self.index_map.items():
                f.write(struct.pack('<QII', band_hash, offset, count))
            
            # Write signature IDs
            for band_hash, sig_ids in band_buckets.items():
                for sig_id in sig_ids:
                    f.write(struct.pack('<I', sig_id))
    
    def _load_index(self):
        """Load index from file"""
        try:
            with open(self.index_path, 'rb') as f:
                # Read header
                num_buckets = struct.unpack('<I', f.read(4))[0]
                
                # Read index table
                self.index_map.clear()
                for _ in range(num_buckets):
                    band_hash, offset, count = struct.unpack('<QII', f.read(16))
                    self.index_map[band_hash] = (offset, count)
            
            logger.debug(f"Loaded index with {len(self.index_map)} buckets")
        except Exception as e:
            logger.error(f"Failed to load index: {e}")
            self.index_map.clear()
    
    def _read_bucket(self, band_hash: int) -> List[int]:
        """Read signature IDs from a bucket"""
        if band_hash not in self.index_map:
            return []
        
        offset, count = self.index_map[band_hash]
        sig_ids = []
        
        try:
            # Use memory mapping for efficient access
            if self.index_file is None:
                self.index_file = open(self.index_path, 'rb')
            
            self.index_file.seek(offset)
            
            # Read signature IDs
            for _ in range(count):
                sig_id = struct.unpack('<I', self.index_file.read(4))[0]
                sig_ids.append(sig_id)
        
        except Exception as e:
            logger.error(f"Failed to read bucket: {e}")
        
        return sig_ids
    
    def close(self):
        """Close index file"""
        if self.index_file:
            self.index_file.close()
            self.index_file = None
    
    def __del__(self):
        """Cleanup on deletion"""
        self.close()