"""
Tests for hashing utilities
"""

import pytest

from binarysniffer.utils.hashing import (
    compute_sha256,
    compute_xxhash,
    MinHash,
    LSHIndex,
    compute_minhash_for_strings
)


class TestHashingUtils:
    """Test hashing utility functions"""
    
    def test_sha256_string(self):
        """Test SHA256 hashing of strings"""
        hash1 = compute_sha256("hello")
        hash2 = compute_sha256("hello")
        hash3 = compute_sha256("world")
        
        assert hash1 == hash2  # Same input, same hash
        assert hash1 != hash3  # Different input, different hash
        assert len(hash1) == 64  # SHA256 is 64 hex chars
    
    def test_sha256_bytes(self):
        """Test SHA256 hashing of bytes"""
        hash1 = compute_sha256(b"hello")
        hash2 = compute_sha256("hello")
        
        assert hash1 == hash2  # String and bytes should give same result
    
    def test_xxhash(self):
        """Test xxHash64"""
        hash1 = compute_xxhash("test")
        hash2 = compute_xxhash("test")
        hash3 = compute_xxhash("different")
        
        assert hash1 == hash2
        assert hash1 != hash3
        assert isinstance(hash1, int)
    
    def test_minhash_basic(self):
        """Test basic MinHash functionality"""
        mh1 = MinHash(num_perm=128)
        mh2 = MinHash(num_perm=128)
        
        # Add same data
        data = ["hello", "world", "test"]
        for item in data:
            mh1.update(item)
            mh2.update(item)
        
        # Should have perfect similarity
        assert mh1.jaccard(mh2) == 1.0
    
    def test_minhash_similarity(self):
        """Test MinHash similarity calculation"""
        mh1 = MinHash(num_perm=128)
        mh2 = MinHash(num_perm=128)
        
        # Add overlapping data
        set1 = ["apple", "banana", "cherry", "date"]
        set2 = ["banana", "cherry", "date", "elderberry"]
        
        for item in set1:
            mh1.update(item)
        for item in set2:
            mh2.update(item)
        
        # Jaccard similarity should be 3/5 = 0.6
        similarity = mh1.jaccard(mh2)
        assert 0.4 < similarity < 0.8  # Allow some variance due to approximation
    
    def test_minhash_batch_update(self):
        """Test batch update of MinHash"""
        mh1 = MinHash(num_perm=128)
        mh2 = MinHash(num_perm=128)
        
        data = ["one", "two", "three"]
        
        # Update one by one
        for item in data:
            mh1.update(item)
        
        # Update in batch
        mh2.update_batch(data)
        
        # Should be identical
        assert mh1.jaccard(mh2) == 1.0
    
    def test_minhash_serialization(self):
        """Test MinHash to/from bytes"""
        mh1 = MinHash(num_perm=128)
        mh1.update_batch(["test", "data", "serialization"])
        
        # Convert to bytes
        data = mh1.to_bytes()
        assert len(data) == 16  # Should be 16 bytes
        
        # Convert back
        mh2 = MinHash.from_bytes(data, num_perm=128)
        
        # First 16 hash values should match
        for i in range(16):
            assert mh1.hashvalues[i] & 0xFF == mh2.hashvalues[i]
    
    def test_lsh_index(self):
        """Test LSH index functionality"""
        # Use more bands with fewer rows for lower similarity threshold
        # 32 bands of 4 rows each makes it more likely to find matches
        index = LSHIndex(num_perm=128, bands=32)
        
        # Create MinHashes for different sets with higher similarity
        sets = {
            "set1": ["apple", "banana", "cherry", "date", "elderberry"],
            "set2": ["apple", "banana", "cherry", "date", "fig"],  # 80% similar to set1
            "set3": ["completely", "different", "items", "here", "nothing"]
        }
        
        minhashes = {}
        for key, items in sets.items():
            mh = MinHash(num_perm=128)
            mh.update_batch(items)
            minhashes[key] = mh
            index.add(key, mh)
        
        # Query with very similar set (80% overlap with set1 and set2)
        query_mh = MinHash(num_perm=128)
        query_mh.update_batch(["apple", "banana", "cherry", "date", "grape"])
        
        candidates = index.query(query_mh)
        
        # Should find set1 and/or set2 as candidates
        assert len(candidates) > 0, "Should find at least one similar set"
        assert "set1" in candidates or "set2" in candidates
        # Should probably not find set3 (completely different)
        # Note: LSH is probabilistic, so we can't guarantee set3 won't appear
    
    def test_compute_minhash_for_strings(self):
        """Test convenience function for computing MinHash"""
        strings = ["function1", "variable2", "constant3"]
        
        mh = compute_minhash_for_strings(strings, num_perm=64)
        
        assert len(mh.hashvalues) == 64
        assert all(isinstance(h, int) for h in mh.hashvalues)