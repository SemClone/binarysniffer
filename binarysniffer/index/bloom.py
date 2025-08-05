"""
Tiered Bloom Filter implementation for quick signature checking
"""

import os
import pickle
import logging
from pathlib import Path
from typing import Optional, Dict

from pybloom_live import BloomFilter

from ..utils.hashing import compute_sha256


logger = logging.getLogger(__name__)


class TieredBloomFilter:
    """
    Three-tier bloom filter system for efficient signature checking.
    
    Tier 1: High confidence signatures (0.1% false positive)
    Tier 2: Medium confidence signatures (1% false positive)  
    Tier 3: Low confidence signatures (10% false positive)
    """
    
    def __init__(self, data_dir: Path):
        """
        Initialize tiered bloom filters.
        
        Args:
            data_dir: Directory to store bloom filter files
        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.tiers: Dict[str, BloomFilter] = {}
        self._load_filters()
    
    def _load_filters(self):
        """Load bloom filters from disk"""
        tier_configs = {
            'tier1': {'capacity': 100000, 'error_rate': 0.001},
            'tier2': {'capacity': 500000, 'error_rate': 0.01},
            'tier3': {'capacity': 1000000, 'error_rate': 0.1}
        }
        
        for tier_name, config in tier_configs.items():
            filter_path = self.data_dir / f"{tier_name}.bloom"
            
            if filter_path.exists():
                try:
                    with open(filter_path, 'rb') as f:
                        self.tiers[tier_name] = pickle.load(f)
                    logger.debug(f"Loaded {tier_name} bloom filter")
                except Exception as e:
                    logger.error(f"Failed to load {tier_name}: {e}")
                    # Create new filter
                    self.tiers[tier_name] = BloomFilter(**config)
            else:
                # Create new filter
                self.tiers[tier_name] = BloomFilter(**config)
                logger.debug(f"Created new {tier_name} bloom filter")
    
    def check_string(self, string: str) -> Optional[str]:
        """
        Check if string exists in any tier.
        
        Args:
            string: String to check
            
        Returns:
            Tier name if found ('tier1', 'tier2', 'tier3'), None otherwise
        """
        string_hash = compute_sha256(string)
        
        # Check tiers in order
        for tier_name in ['tier1', 'tier2', 'tier3']:
            if tier_name in self.tiers and string_hash in self.tiers[tier_name]:
                return tier_name
        
        return None
    
    def add_string(self, string: str, tier: str = 'tier2'):
        """
        Add string to specified tier.
        
        Args:
            string: String to add
            tier: Tier name ('tier1', 'tier2', 'tier3')
        """
        if tier not in self.tiers:
            raise ValueError(f"Invalid tier: {tier}")
        
        string_hash = compute_sha256(string)
        self.tiers[tier].add(string_hash)
    
    def save(self):
        """Save bloom filters to disk"""
        for tier_name, bloom_filter in self.tiers.items():
            filter_path = self.data_dir / f"{tier_name}.bloom"
            
            try:
                with open(filter_path, 'wb') as f:
                    pickle.dump(bloom_filter, f, protocol=pickle.HIGHEST_PROTOCOL)
                logger.debug(f"Saved {tier_name} bloom filter")
            except Exception as e:
                logger.error(f"Failed to save {tier_name}: {e}")
    
    def is_initialized(self) -> bool:
        """Check if bloom filters are initialized"""
        # Check if all tier files exist
        for tier_name in ['tier1', 'tier2', 'tier3']:
            filter_path = self.data_dir / f"{tier_name}.bloom"
            if not filter_path.exists():
                return False
        
        # Check if filters have content
        return all(len(f) > 0 for f in self.tiers.values() if f)
    
    def clear(self):
        """Clear all bloom filters"""
        self.tiers.clear()
        self._load_filters()
    
    def get_stats(self) -> Dict[str, Dict[str, int]]:
        """Get statistics about bloom filters"""
        stats = {}
        
        for tier_name, bloom_filter in self.tiers.items():
            stats[tier_name] = {
                'capacity': bloom_filter.capacity,
                'count': len(bloom_filter),
                'error_rate': bloom_filter.error_rate
            }
        
        return stats