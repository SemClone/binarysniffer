"""
Tiered Bloom Filter implementation for quick signature checking
"""

import logging
from pathlib import Path

# Use deterministic bloom filter for consistent results across Python processes
from .bloom_deterministic import TieredDeterministicBloomFilter

from ..utils.hashing import compute_sha256


logger = logging.getLogger(__name__)


class TieredBloomFilter(TieredDeterministicBloomFilter):
    """
    Three-tier bloom filter system for efficient signature checking.
    
    This is now a wrapper around TieredDeterministicBloomFilter to ensure
    consistent behavior across different Python processes with different
    PYTHONHASHSEED values.
    
    Tier 1: High confidence signatures (0.1% false positive)
    Tier 2: Medium confidence signatures (1% false positive)  
    Tier 3: Low confidence signatures (10% false positive)
    """
    
    def check_string(self, string: str):
        """
        Check if string exists in any tier.
        
        The parent class expects raw strings, but the progressive matcher
        passes SHA256 hashes. We need to handle both cases.
        """
        # If it looks like a SHA256 hash (64 hex chars), use it directly
        if len(string) == 64 and all(c in '0123456789abcdef' for c in string.lower()):
            return super().check_string(string)
        else:
            # Otherwise, compute the SHA256 hash first
            string_hash = compute_sha256(string)
            return super().check_string(string_hash)
    
    def add_string(self, string: str, tier: str = 'tier2'):
        """
        Add string to specified tier.
        
        For consistency with existing code, we compute SHA256 hash if needed.
        """
        # If it looks like a SHA256 hash, use it directly
        if len(string) == 64 and all(c in '0123456789abcdef' for c in string.lower()):
            super().add_string(string, tier)
        else:
            # Otherwise, compute the SHA256 hash first
            string_hash = compute_sha256(string)
            super().add_string(string_hash, tier)