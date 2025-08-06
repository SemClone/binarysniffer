"""
Deterministic Bloom Filter implementation that doesn't rely on Python's hash()
"""

import hashlib
import math
import pickle
import logging
from pathlib import Path
from typing import Optional, List, Tuple

logger = logging.getLogger(__name__)


class DeterministicBloomFilter:
    """
    A deterministic bloom filter implementation using cryptographic hash functions.
    This ensures consistent behavior across different Python processes.
    """
    
    def __init__(self, capacity: int, error_rate: float = 0.01):
        """
        Initialize bloom filter.
        
        Args:
            capacity: Expected number of elements
            error_rate: Desired false positive rate
        """
        self.capacity = capacity
        self.error_rate = error_rate
        
        # Calculate optimal bit array size and number of hash functions
        self.bit_size = self._optimal_bit_size(capacity, error_rate)
        self.num_hashes = self._optimal_num_hashes(self.bit_size, capacity)
        
        # Use bytearray for the bit array
        self.bit_array = bytearray((self.bit_size + 7) // 8)
        self.count = 0
        
        logger.debug(f"Created bloom filter: capacity={capacity}, bits={self.bit_size}, hashes={self.num_hashes}")
    
    def _optimal_bit_size(self, n: int, p: float) -> int:
        """Calculate optimal bit array size"""
        if n <= 0:
            n = 1
        if p <= 0 or p >= 1:
            raise ValueError("Error rate must be between 0 and 1")
        return int(-n * math.log(p) / (math.log(2) ** 2))
    
    def _optimal_num_hashes(self, m: int, n: int) -> int:
        """Calculate optimal number of hash functions"""
        if n <= 0:
            n = 1
        return max(1, int((m / n) * math.log(2)))
    
    def _get_hash_values(self, item: str) -> List[int]:
        """
        Generate hash values for an item using SHA-256.
        Uses double hashing technique for efficiency.
        """
        # Convert to bytes
        item_bytes = item.encode('utf-8')
        
        # Generate two base hashes using SHA-256
        hash1 = hashlib.sha256(item_bytes).digest()
        hash2 = hashlib.sha256(hash1).digest()
        
        # Convert to integers
        h1 = int.from_bytes(hash1[:8], 'big')
        h2 = int.from_bytes(hash2[:8], 'big')
        
        # Generate k hash values using double hashing
        # h(i) = h1 + i * h2
        hashes = []
        for i in range(self.num_hashes):
            hashes.append((h1 + i * h2) % self.bit_size)
        
        return hashes
    
    def add(self, item: str):
        """Add an item to the bloom filter"""
        for bit_pos in self._get_hash_values(item):
            byte_pos = bit_pos // 8
            bit_offset = bit_pos % 8
            self.bit_array[byte_pos] |= (1 << bit_offset)
        self.count += 1
    
    def __contains__(self, item: str) -> bool:
        """Check if an item might be in the bloom filter"""
        for bit_pos in self._get_hash_values(item):
            byte_pos = bit_pos // 8
            bit_offset = bit_pos % 8
            if not (self.bit_array[byte_pos] & (1 << bit_offset)):
                return False
        return True
    
    def __len__(self) -> int:
        """Return the number of items added"""
        return self.count
    
    def save(self, filepath: Path):
        """Save bloom filter to file"""
        data = {
            'capacity': self.capacity,
            'error_rate': self.error_rate,
            'bit_size': self.bit_size,
            'num_hashes': self.num_hashes,
            'bit_array': bytes(self.bit_array),
            'count': self.count
        }
        with open(filepath, 'wb') as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
    
    @classmethod
    def load(cls, filepath: Path) -> "DeterministicBloomFilter":
        """Load bloom filter from file"""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        bf = cls.__new__(cls)
        bf.capacity = data['capacity']
        bf.error_rate = data['error_rate']
        bf.bit_size = data['bit_size']
        bf.num_hashes = data['num_hashes']
        bf.bit_array = bytearray(data['bit_array'])
        bf.count = data['count']
        
        return bf


class TieredDeterministicBloomFilter:
    """
    Three-tier deterministic bloom filter system.
    """
    
    def __init__(self, data_dir: Path):
        """Initialize tiered bloom filters"""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.tiers = {}
        self._load_filters()
    
    def _load_filters(self):
        """Load bloom filters from disk"""
        tier_configs = {
            'tier1': {'capacity': 100000, 'error_rate': 0.001},
            'tier2': {'capacity': 500000, 'error_rate': 0.01},
            'tier3': {'capacity': 1000000, 'error_rate': 0.1}
        }
        
        for tier_name, config in tier_configs.items():
            filter_path = self.data_dir / f"{tier_name}_det.bloom"
            
            if filter_path.exists():
                try:
                    self.tiers[tier_name] = DeterministicBloomFilter.load(filter_path)
                    logger.debug(f"Loaded {tier_name} deterministic bloom filter")
                except Exception as e:
                    logger.error(f"Failed to load {tier_name}: {e}")
                    self.tiers[tier_name] = DeterministicBloomFilter(**config)
            else:
                self.tiers[tier_name] = DeterministicBloomFilter(**config)
                logger.debug(f"Created new {tier_name} deterministic bloom filter")
    
    def check_string(self, string: str) -> Optional[str]:
        """Check if string exists in any tier"""
        for tier_name in ['tier1', 'tier2', 'tier3']:
            if tier_name in self.tiers and string in self.tiers[tier_name]:
                return tier_name
        return None
    
    def add_string(self, string: str, tier: str = 'tier2'):
        """Add string to specified tier"""
        if tier not in self.tiers:
            raise ValueError(f"Invalid tier: {tier}")
        self.tiers[tier].add(string)
    
    def save(self):
        """Save all bloom filters to disk"""
        for tier_name, bloom_filter in self.tiers.items():
            filter_path = self.data_dir / f"{tier_name}_det.bloom"
            try:
                bloom_filter.save(filter_path)
                logger.debug(f"Saved {tier_name} deterministic bloom filter")
            except Exception as e:
                logger.error(f"Failed to save {tier_name}: {e}")
    
    def is_initialized(self) -> bool:
        """Check if bloom filters are initialized"""
        for tier_name in ['tier1', 'tier2', 'tier3']:
            filter_path = self.data_dir / f"{tier_name}_det.bloom"
            if not filter_path.exists():
                return False
        return all(len(f) > 0 for f in self.tiers.values() if f)
    
    def clear(self):
        """Clear all bloom filters"""
        self.tiers.clear()
        self._load_filters()
    
    def get_stats(self) -> dict:
        """Get statistics about bloom filters"""
        stats = {}
        for tier_name, bloom_filter in self.tiers.items():
            stats[tier_name] = {
                'capacity': bloom_filter.capacity,
                'count': len(bloom_filter),
                'error_rate': bloom_filter.error_rate
            }
        return stats