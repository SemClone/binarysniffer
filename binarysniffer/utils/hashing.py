"""
Hashing utilities for signature generation and matching
"""

import hashlib
import struct
from typing import List, Union, Tuple
import xxhash


def compute_sha256(data: Union[str, bytes]) -> str:
    """Compute SHA256 hash of data"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def compute_xxhash(data: Union[str, bytes]) -> int:
    """Compute xxHash64 of data"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return xxhash.xxh64(data).intdigest()


class MinHash:
    """
    MinHash implementation for similarity detection.
    """
    
    def __init__(self, num_perm: int = 128, seed: int = 1):
        """
        Initialize MinHash.
        
        Args:
            num_perm: Number of permutation functions
            seed: Random seed for hash functions
        """
        self.num_perm = num_perm
        self.seed = seed
        self.hashvalues = self._init_hashvalues()
    
    def _init_hashvalues(self) -> List[int]:
        """Initialize hash values to maximum"""
        return [2**64 - 1] * self.num_perm
    
    def _hash(self, data: bytes, perm: int) -> int:
        """Generate hash for given permutation"""
        # Use xxhash with different seeds for each permutation
        return xxhash.xxh64(data, seed=self.seed + perm).intdigest()
    
    def update(self, data: Union[str, bytes]):
        """Update MinHash with new data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        for i in range(self.num_perm):
            hash_val = self._hash(data, i)
            if hash_val < self.hashvalues[i]:
                self.hashvalues[i] = hash_val
    
    def update_batch(self, data_list: List[Union[str, bytes]]):
        """Update MinHash with multiple data items"""
        for data in data_list:
            self.update(data)
    
    def jaccard(self, other: "MinHash") -> float:
        """Calculate Jaccard similarity with another MinHash"""
        if self.num_perm != other.num_perm:
            raise ValueError("MinHash objects must have same num_perm")
        
        matches = sum(1 for a, b in zip(self.hashvalues, other.hashvalues) if a == b)
        return matches / self.num_perm
    
    def to_bytes(self) -> bytes:
        """Convert MinHash to bytes for storage"""
        # Pack as 16 bytes (128 bits) by taking first 16 hash values
        # and using lower 8 bits of each
        if self.num_perm < 16:
            raise ValueError("num_perm must be at least 16 for byte conversion")
        
        result = bytearray(16)
        for i in range(16):
            result[i] = self.hashvalues[i] & 0xFF
        
        return bytes(result)
    
    @classmethod
    def from_bytes(cls, data: bytes, num_perm: int = 128) -> "MinHash":
        """Create MinHash from bytes"""
        if len(data) != 16:
            raise ValueError("Data must be 16 bytes")
        
        minhash = cls(num_perm=num_perm)
        # Restore first 16 values from bytes
        for i in range(16):
            minhash.hashvalues[i] = data[i]
        
        return minhash


class LSHIndex:
    """
    Locality-Sensitive Hashing index for MinHash.
    """
    
    def __init__(self, num_perm: int = 128, bands: int = 16):
        """
        Initialize LSH index.
        
        Args:
            num_perm: Number of MinHash permutations
            bands: Number of bands for LSH
        """
        self.num_perm = num_perm
        self.bands = bands
        self.rows = num_perm // bands
        self.buckets = [{} for _ in range(bands)]
    
    def add(self, key: str, minhash: MinHash):
        """Add MinHash to index"""
        for band in range(self.bands):
            start = band * self.rows
            end = start + self.rows
            
            # Create band hash
            band_values = tuple(minhash.hashvalues[start:end])
            band_hash = hash(band_values)
            
            if band_hash not in self.buckets[band]:
                self.buckets[band][band_hash] = []
            
            self.buckets[band][band_hash].append(key)
    
    def query(self, minhash: MinHash) -> List[str]:
        """Query for similar MinHashes"""
        candidates = set()
        
        for band in range(self.bands):
            start = band * self.rows
            end = start + self.rows
            
            # Create band hash
            band_values = tuple(minhash.hashvalues[start:end])
            band_hash = hash(band_values)
            
            if band_hash in self.buckets[band]:
                candidates.update(self.buckets[band][band_hash])
        
        return list(candidates)
    
    def clear(self):
        """Clear the index"""
        self.buckets = [{} for _ in range(self.bands)]


def compute_minhash_for_strings(strings: List[str], num_perm: int = 128) -> MinHash:
    """
    Compute MinHash for a list of strings.
    
    Args:
        strings: List of strings to hash
        num_perm: Number of permutations
        
    Returns:
        MinHash object
    """
    minhash = MinHash(num_perm=num_perm)
    minhash.update_batch(strings)
    return minhash