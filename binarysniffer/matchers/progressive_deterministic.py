"""
Deterministic progressive matching implementation
"""

import time
import logging
from typing import List, Dict, Any, Set, Tuple
from pathlib import Path
from collections import defaultdict

from ..core.config import Config
from ..core.results import ComponentMatch
from ..extractors.base import ExtractedFeatures
from ..storage.database import SignatureDatabase
from ..index.minhash import MinHashIndex
from ..utils.hashing import compute_minhash_for_strings, compute_sha256


logger = logging.getLogger(__name__)


class DeterministicProgressiveMatcher:
    """
    Deterministic progressive matching without bloom filters.
    
    Uses a prefix-based hash index for fast candidate selection:
    1. Hash prefix index for quick candidate selection
    2. MinHash LSH for similarity search  
    3. Detailed database matching
    """
    
    def __init__(self, config: Config):
        """Initialize matcher with configuration"""
        self.config = config
        self.db = SignatureDatabase(config.db_path)
        self.minhash_index = MinHashIndex(
            config.index_dir / "minhash.idx",
            num_perm=config.minhash_permutations,
            bands=config.minhash_bands
        )
        self.last_analysis_time = 0.0
        
        # Build hash prefix index for fast lookup
        self.hash_prefix_index = None
        self.prefix_length = 8  # Use first 8 chars of SHA256 hash
        self._build_hash_index()
        
        # Initialize MinHash index if needed
        if not self.minhash_index.is_initialized():
            logger.info("Initializing MinHash index...")
            self._build_minhash_index()
    
    def match(
        self,
        features: ExtractedFeatures,
        threshold: float = 0.5,
        deep: bool = False
    ) -> List[ComponentMatch]:
        """
        Perform deterministic progressive matching on extracted features.
        
        Args:
            features: Extracted features from file
            threshold: Minimum confidence threshold
            deep: Enable deep analysis mode
            
        Returns:
            List of component matches
        """
        start_time = time.time()
        matches = []
        
        # Get all unique features (sorted for deterministic order)
        all_features = sorted(features.unique_features)
        if not all_features:
            self.last_analysis_time = time.time() - start_time
            return matches
        
        logger.info(f"Matching {len(all_features)} features")
        
        # Tier 1: Hash prefix index lookup
        hash_candidates = self._hash_index_lookup(all_features)
        logger.info(f"Hash index candidates: {len(hash_candidates)}")
        
        # Tier 2: MinHash similarity search
        minhash_candidates = self._minhash_search(all_features, threshold)
        logger.info(f"MinHash candidates: {len(minhash_candidates)}")
        
        # Combine candidates
        all_candidates = hash_candidates.union(minhash_candidates)
        
        if not all_candidates:
            self.last_analysis_time = time.time() - start_time
            return matches
        
        # Tier 3: Detailed database matching
        matches = self._detailed_matching(all_candidates, features, threshold)
        
        self.last_analysis_time = time.time() - start_time
        return matches
    
    def _build_hash_index(self):
        """Build hash prefix index from database"""
        logger.info("Building hash prefix index...")
        
        self.hash_prefix_index = defaultdict(set)
        
        try:
            # Get all signatures from database
            signatures = self.db.get_all_signatures()
            
            if not signatures:
                logger.warning("No signatures found in database")
                return
            
            # Build prefix index
            count = 0
            for sig_id, component_id, sig_compressed, sig_type, confidence, minhash in signatures:
                if sig_compressed:
                    # Decompress signature
                    import zstandard as zstd
                    dctx = zstd.ZstdDecompressor()
                    signature = dctx.decompress(sig_compressed).decode('utf-8')
                    
                    # Compute hash and store prefix mapping
                    sig_hash = compute_sha256(signature)
                    prefix = sig_hash[:self.prefix_length]
                    self.hash_prefix_index[prefix].add(sig_hash)
                    count += 1
            
            logger.info(f"Built hash index with {count} signatures, {len(self.hash_prefix_index)} unique prefixes")
            
        except Exception as e:
            logger.error(f"Error building hash index: {e}")
    
    def _hash_index_lookup(self, features: List[str]) -> Set[str]:
        """Look up features in hash prefix index"""
        candidates = set()
        
        if not self.hash_prefix_index:
            return candidates
        
        # Check each feature's hash prefix
        for feature in features[:100000]:  # Limit for performance
            feature_hash = compute_sha256(feature)
            prefix = feature_hash[:self.prefix_length]
            
            # If prefix exists in index, add all signatures with that prefix
            if prefix in self.hash_prefix_index:
                candidates.update(self.hash_prefix_index[prefix])
        
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
        
        # Check each candidate (sorted for deterministic order)
        for candidate_hash in sorted(candidates):
            # Look up in database
            sig_data = self.db.search_by_hash(candidate_hash)
            if not sig_data:
                continue
            
            # Calculate match score
            score = self._calculate_match_score(sig_data, feature_set)
            
            if score >= threshold:
                # Don't append version if it's 'unknown' or None
                version = sig_data.get('version')
                if version and version != 'unknown':
                    component_key = f"{sig_data['name']}@{version}"
                else:
                    component_key = sig_data['name']
                
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
        
        # Sort by confidence, then by component name for deterministic order
        matches.sort(key=lambda m: (-m.confidence, m.component))
        
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
        return base_confidence * type_weight
    
    def _sig_type_to_string(self, sig_type: int) -> str:
        """Convert signature type to string"""
        return {
            1: "string",
            2: "function",
            3: "constant",
            4: "pattern"
        }.get(sig_type, "unknown")
    
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