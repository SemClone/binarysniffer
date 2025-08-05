"""
Progressive matching implementation with three-tier strategy
"""

import time
import logging
from typing import List, Dict, Any, Set
from pathlib import Path

from ..core.config import Config
from ..core.results import ComponentMatch
from ..extractors.base import ExtractedFeatures
from ..storage.database import SignatureDatabase
from ..index.bloom import TieredBloomFilter
from ..index.minhash import MinHashIndex
from ..utils.hashing import compute_minhash_for_strings, compute_sha256


logger = logging.getLogger(__name__)


class ProgressiveMatcher:
    """
    Three-tier progressive matching:
    1. Bloom filters for quick elimination
    2. MinHash LSH for similarity search  
    3. Detailed database matching
    """
    
    def __init__(self, config: Config):
        """Initialize matcher with configuration"""
        self.config = config
        self.db = SignatureDatabase(config.db_path)
        self.bloom_filter = TieredBloomFilter(config.bloom_filter_dir)
        self.minhash_index = MinHashIndex(
            config.index_dir / "minhash.idx",
            num_perm=config.minhash_permutations,
            bands=config.minhash_bands
        )
        self.last_analysis_time = 0.0
        
        # Initialize indexes if needed
        self._ensure_indexes()
    
    def match(
        self,
        features: ExtractedFeatures,
        threshold: float = 0.5,
        deep: bool = False
    ) -> List[ComponentMatch]:
        """
        Perform progressive matching on extracted features.
        
        Args:
            features: Extracted features from file
            threshold: Minimum confidence threshold
            deep: Enable deep analysis mode
            
        Returns:
            List of component matches
        """
        start_time = time.time()
        matches = []
        
        # Get all unique features
        all_features = list(features.unique_features)
        if not all_features:
            self.last_analysis_time = time.time() - start_time
            return matches
        
        logger.debug(f"Matching {len(all_features)} features")
        
        # Tier 1: Bloom filter check
        bloom_candidates = self._bloom_filter_check(all_features)
        logger.debug(f"Bloom filter candidates: {len(bloom_candidates)}")
        
        if not bloom_candidates and not deep:
            self.last_analysis_time = time.time() - start_time
            return matches
        
        # Tier 2: MinHash similarity search
        minhash_candidates = self._minhash_search(all_features, threshold)
        logger.debug(f"MinHash candidates: {len(minhash_candidates)}")
        
        # Combine candidates
        all_candidates = bloom_candidates.union(minhash_candidates)
        
        if not all_candidates:
            self.last_analysis_time = time.time() - start_time
            return matches
        
        # Tier 3: Detailed database matching
        matches = self._detailed_matching(all_candidates, features, threshold)
        
        self.last_analysis_time = time.time() - start_time
        return matches
    
    def _bloom_filter_check(self, features: List[str]) -> Set[str]:
        """Check features against bloom filters"""
        candidates = set()
        
        # Check each feature
        for feature in features[:1000]:  # Limit for performance
            tier = self.bloom_filter.check_string(feature)
            if tier:
                # Add feature hash as candidate
                candidates.add(compute_sha256(feature))
        
        return candidates
    
    def _minhash_search(self, features: List[str], threshold: float) -> Set[str]:
        """Search for similar signatures using MinHash LSH"""
        candidates = set()
        
        # Compute MinHash for features
        minhash = compute_minhash_for_strings(
            features,
            num_perm=self.config.minhash_permutations
        )
        
        # Query LSH index
        similar_ids = self.minhash_index.query(minhash, threshold)
        
        # Convert to signature hashes
        for sig_id in similar_ids:
            candidates.add(str(sig_id))
        
        return candidates
    
    def _detailed_matching(
        self,
        candidates: Set[str],
        features: ExtractedFeatures,
        threshold: float
    ) -> List[ComponentMatch]:
        """Perform detailed matching against database"""
        matches = []
        seen_components = set()
        
        # Create feature lookup for fast checking
        feature_set = features.unique_features
        
        # Check each candidate
        for candidate_hash in candidates:
            # Look up in database
            sig_data = self.db.search_by_hash(candidate_hash)
            if not sig_data:
                continue
            
            # Calculate match score
            score = self._calculate_match_score(sig_data, feature_set)
            
            if score >= threshold:
                component_key = f"{sig_data['name']}@{sig_data['version']}"
                
                # Avoid duplicate components
                if component_key not in seen_components:
                    seen_components.add(component_key)
                    
                    match = ComponentMatch(
                        component=component_key,
                        ecosystem=sig_data.get('ecosystem', 'unknown'),
                        confidence=score,
                        license=sig_data.get('license'),
                        match_type=self._sig_type_to_string(sig_data.get('sig_type', 1)),
                        evidence={
                            'signature_id': sig_data['id'],
                            'match_method': 'progressive'
                        }
                    )
                    matches.append(match)
        
        # Sort by confidence
        matches.sort(key=lambda m: m.confidence, reverse=True)
        
        return matches
    
    def _calculate_match_score(
        self,
        sig_data: Dict[str, Any],
        feature_set: Set[str]
    ) -> float:
        """Calculate match score between signature and features"""
        # Base confidence from signature
        base_confidence = sig_data.get('confidence', 0.5)
        
        # Adjust based on signature type
        sig_type = sig_data.get('sig_type', 1)
        type_weight = {
            1: 1.0,   # string
            2: 1.2,   # function
            3: 1.1,   # constant
            4: 0.9    # pattern
        }.get(sig_type, 1.0)
        
        # Simple presence check for now
        # In a real implementation, this would be more sophisticated
        return base_confidence * type_weight
    
    def _sig_type_to_string(self, sig_type: int) -> str:
        """Convert signature type to string"""
        return {
            1: "string",
            2: "function",
            3: "constant",
            4: "pattern"
        }.get(sig_type, "unknown")
    
    def _ensure_indexes(self):
        """Ensure indexes are initialized"""
        # Check if bloom filters exist
        if not self.bloom_filter.is_initialized():
            logger.info("Initializing bloom filters...")
            self._build_bloom_filters()
        
        # Check if MinHash index exists
        if not self.minhash_index.is_initialized():
            logger.info("Initializing MinHash index...")
            self._build_minhash_index()
    
    def _build_bloom_filters(self):
        """Build bloom filters from database"""
        logger.info("Building bloom filters from signature database...")
        
        try:
            # Get all signatures from database
            signatures = self.db.get_all_signatures()
            
            if not signatures:
                logger.warning("No signatures found in database")
                return
            
            # Add each signature to bloom filter
            count = 0
            for sig_id, component_id, sig_compressed, sig_type, confidence, minhash in signatures:
                if sig_compressed:
                    # Decompress signature
                    import zstandard as zstd
                    dctx = zstd.ZstdDecompressor()
                    signature = dctx.decompress(sig_compressed).decode('utf-8')
                    
                    # Add to bloom filter
                    self.bloom_filter.add_string(signature)
                    count += 1
            
            # Save bloom filter
            self.bloom_filter.save()
            logger.info(f"Added {count} signatures to bloom filter")
            
        except Exception as e:
            logger.error(f"Error building bloom filters: {e}")
    
    def _build_minhash_index(self):
        """Build MinHash index from database"""
        logger.info("Building MinHash index from signature database...")
        
        try:
            # Get all signatures with minhashes from database
            signatures = self.db.get_all_signatures()
            
            if not signatures:
                logger.warning("No signatures found in database")
                return
            
            # Collect signatures with valid minhashes
            minhash_signatures = []
            for sig_id, component_id, sig_compressed, sig_type, confidence, minhash in signatures:
                if minhash:
                    minhash_signatures.append((sig_id, minhash))
            
            if minhash_signatures:
                # Build the index
                self.minhash_index.build_index(minhash_signatures)
                logger.info(f"Built MinHash index with {len(minhash_signatures)} signatures")
            else:
                logger.warning("No signatures with MinHash values found")
                
        except Exception as e:
            logger.error(f"Error building MinHash index: {e}")