"""
TLSH (Trend Micro Locality Sensitive Hash) support for fuzzy matching
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Tuple
import json

try:
    import tlsh
    HAS_TLSH = True
except ImportError:
    HAS_TLSH = False
    tlsh = None

logger = logging.getLogger(__name__)


class TLSHHasher:
    """Generate and compare TLSH hashes for fuzzy matching"""
    
    # TLSH distance thresholds for similarity levels
    IDENTICAL_THRESHOLD = 0      # Exact match
    VERY_SIMILAR_THRESHOLD = 30  # Very similar (likely same component, minor changes)
    SIMILAR_THRESHOLD = 70        # Similar (possibly same component, moderate changes)
    RELATED_THRESHOLD = 100       # Related (might be same family/library)
    MAX_DISTANCE = 300            # Maximum meaningful distance
    
    def __init__(self):
        """Initialize TLSH hasher"""
        if not HAS_TLSH:
            logger.warning("TLSH not available. Install with: pip install python-tlsh")
            self.enabled = False
        else:
            self.enabled = True
            logger.debug("TLSH hasher initialized")
    
    def hash_file(self, file_path: Path) -> Optional[str]:
        """
        Generate TLSH hash for a file.
        
        Args:
            file_path: Path to file
            
        Returns:
            TLSH hash string or None if failed
        """
        if not self.enabled:
            return None
        
        try:
            # TLSH requires at least 256 bytes of data
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) < 256:
                logger.debug(f"File too small for TLSH: {file_path} ({len(data)} bytes)")
                return None
            
            # Generate hash
            hash_value = tlsh.hash(data)
            
            # TLSH returns empty string if it can't generate hash
            if not hash_value:
                logger.debug(f"TLSH could not generate hash for {file_path}")
                return None
            
            return hash_value
            
        except Exception as e:
            logger.error(f"Error generating TLSH hash for {file_path}: {e}")
            return None
    
    def hash_data(self, data: bytes) -> Optional[str]:
        """
        Generate TLSH hash for raw data.
        
        Args:
            data: Raw bytes to hash
            
        Returns:
            TLSH hash string or None if failed
        """
        if not self.enabled:
            return None
        
        try:
            if len(data) < 256:
                logger.debug(f"Data too small for TLSH: {len(data)} bytes")
                return None
            
            hash_value = tlsh.hash(data)
            
            if not hash_value:
                return None
            
            return hash_value
            
        except Exception as e:
            logger.error(f"Error generating TLSH hash: {e}")
            return None
    
    def hash_features(self, features: List[str]) -> Optional[str]:
        """
        Generate TLSH hash from extracted features.
        
        Args:
            features: List of extracted features/strings
            
        Returns:
            TLSH hash string or None if failed
        """
        if not self.enabled or not features:
            return None
        
        # Concatenate features into a single byte stream
        # Sort for consistency
        sorted_features = sorted(set(features))
        data = '\n'.join(sorted_features).encode('utf-8', errors='ignore')
        
        return self.hash_data(data)
    
    def compare(self, hash1: str, hash2: str) -> int:
        """
        Compare two TLSH hashes and return distance.
        
        Args:
            hash1: First TLSH hash
            hash2: Second TLSH hash
            
        Returns:
            Distance between hashes (0 = identical, higher = more different)
            Returns MAX_DISTANCE if comparison fails
        """
        if not self.enabled:
            return self.MAX_DISTANCE
        
        if not hash1 or not hash2:
            return self.MAX_DISTANCE
        
        try:
            distance = tlsh.diff(hash1, hash2)
            return min(distance, self.MAX_DISTANCE)
        except Exception as e:
            logger.error(f"Error comparing TLSH hashes: {e}")
            return self.MAX_DISTANCE
    
    def similarity_score(self, hash1: str, hash2: str) -> float:
        """
        Calculate similarity score between two hashes.
        
        Args:
            hash1: First TLSH hash
            hash2: Second TLSH hash
            
        Returns:
            Similarity score between 0.0 (different) and 1.0 (identical)
        """
        distance = self.compare(hash1, hash2)
        
        if distance >= self.MAX_DISTANCE:
            return 0.0
        
        # Convert distance to similarity score
        # Using exponential decay for more intuitive scores
        score = max(0.0, 1.0 - (distance / self.MAX_DISTANCE))
        return score
    
    def get_similarity_level(self, hash1: str, hash2: str) -> str:
        """
        Get human-readable similarity level.
        
        Args:
            hash1: First TLSH hash
            hash2: Second TLSH hash
            
        Returns:
            Similarity level string
        """
        distance = self.compare(hash1, hash2)
        
        if distance <= self.IDENTICAL_THRESHOLD:
            return "identical"
        elif distance <= self.VERY_SIMILAR_THRESHOLD:
            return "very_similar"
        elif distance <= self.SIMILAR_THRESHOLD:
            return "similar"
        elif distance <= self.RELATED_THRESHOLD:
            return "related"
        else:
            return "different"
    
    def find_similar(
        self,
        target_hash: str,
        candidate_hashes: Dict[str, str],
        threshold: int = None
    ) -> List[Tuple[str, int, float]]:
        """
        Find similar hashes from a collection.
        
        Args:
            target_hash: Hash to search for
            candidate_hashes: Dict of {identifier: hash}
            threshold: Maximum distance threshold (default: SIMILAR_THRESHOLD)
            
        Returns:
            List of (identifier, distance, similarity_score) tuples, sorted by distance
        """
        if not self.enabled or not target_hash:
            return []
        
        if threshold is None:
            threshold = self.SIMILAR_THRESHOLD
        
        results = []
        
        for identifier, candidate_hash in candidate_hashes.items():
            if not candidate_hash:
                continue
            
            distance = self.compare(target_hash, candidate_hash)
            
            if distance <= threshold:
                score = self.similarity_score(target_hash, candidate_hash)
                results.append((identifier, distance, score))
        
        # Sort by distance (ascending)
        results.sort(key=lambda x: x[1])
        
        return results
    
    def cluster_hashes(
        self,
        hashes: Dict[str, str],
        threshold: int = None
    ) -> List[List[str]]:
        """
        Cluster similar hashes together.
        
        Args:
            hashes: Dict of {identifier: hash}
            threshold: Maximum distance for clustering (default: VERY_SIMILAR_THRESHOLD)
            
        Returns:
            List of clusters, each cluster is a list of identifiers
        """
        if not self.enabled or not hashes:
            return []
        
        if threshold is None:
            threshold = self.VERY_SIMILAR_THRESHOLD
        
        # Simple greedy clustering
        clusters = []
        processed = set()
        
        for id1, hash1 in hashes.items():
            if id1 in processed or not hash1:
                continue
            
            cluster = [id1]
            processed.add(id1)
            
            for id2, hash2 in hashes.items():
                if id2 in processed or not hash2 or id2 == id1:
                    continue
                
                distance = self.compare(hash1, hash2)
                if distance <= threshold:
                    cluster.append(id2)
                    processed.add(id2)
            
            clusters.append(cluster)
        
        return clusters


class TLSHSignatureStore:
    """Store and manage TLSH signatures for components"""
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize TLSH signature store.
        
        Args:
            storage_path: Path to store TLSH signatures (default: ~/.binarysniffer/tlsh_signatures.json)
        """
        if storage_path is None:
            storage_path = Path.home() / '.binarysniffer' / 'tlsh_signatures.json'
        
        self.storage_path = storage_path
        self.hasher = TLSHHasher()
        self.signatures = self._load_signatures()
    
    def _load_signatures(self) -> Dict[str, Dict]:
        """Load TLSH signatures from storage"""
        if not self.storage_path.exists():
            return {}
        
        try:
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading TLSH signatures: {e}")
            return {}
    
    def _save_signatures(self):
        """Save TLSH signatures to storage"""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w') as f:
                json.dump(self.signatures, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving TLSH signatures: {e}")
    
    def add_signature(
        self,
        component: str,
        version: str,
        tlsh_hash: str,
        metadata: Optional[Dict] = None
    ):
        """
        Add a TLSH signature for a component.
        
        Args:
            component: Component name
            version: Component version
            tlsh_hash: TLSH hash value
            metadata: Optional metadata
        """
        if not tlsh_hash:
            return
        
        key = f"{component}_{version}"
        
        self.signatures[key] = {
            'component': component,
            'version': version,
            'hash': tlsh_hash,
            'metadata': metadata or {}
        }
        
        self._save_signatures()
    
    def find_matches(
        self,
        target_hash: str,
        threshold: int = None
    ) -> List[Dict]:
        """
        Find matching components for a target hash.
        
        Args:
            target_hash: TLSH hash to search for
            threshold: Maximum distance threshold
            
        Returns:
            List of matching components with similarity info
        """
        if not self.hasher.enabled or not target_hash:
            return []
        
        # Build candidate hash dict
        candidates = {
            key: sig['hash']
            for key, sig in self.signatures.items()
            if sig.get('hash')
        }
        
        # Find similar hashes
        similar = self.hasher.find_similar(target_hash, candidates, threshold)
        
        # Build result with component info
        results = []
        for key, distance, score in similar:
            sig = self.signatures[key]
            results.append({
                'component': sig['component'],
                'version': sig['version'],
                'distance': distance,
                'similarity_score': score,
                'similarity_level': self.hasher.get_similarity_level(target_hash, sig['hash']),
                'metadata': sig.get('metadata', {})
            })
        
        return results
    
    def get_signature(self, component: str, version: str) -> Optional[str]:
        """
        Get TLSH signature for a specific component version.
        
        Args:
            component: Component name
            version: Component version
            
        Returns:
            TLSH hash or None
        """
        key = f"{component}_{version}"
        sig = self.signatures.get(key)
        return sig['hash'] if sig else None