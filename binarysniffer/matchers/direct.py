"""
Direct string matching for better detection rates
"""

import time
import json
import logging
from typing import List, Dict, Any, Set
from collections import defaultdict

from ..core.config import Config
from ..core.results import ComponentMatch
from ..extractors.base import ExtractedFeatures
from ..storage.database import SignatureDatabase
from ..signatures.validator import SignatureValidator

logger = logging.getLogger(__name__)


class DirectMatcher:
    """
    Direct string matching against signatures for improved detection.
    This bypasses bloom filters and MinHash for direct pattern matching.
    """
    
    def __init__(self, config: Config):
        """Initialize matcher with configuration"""
        self.config = config
        self.db = SignatureDatabase(config.db_path)
        self.last_analysis_time = 0.0
        
        # Cache all signatures in memory for fast matching
        self._load_signatures()
        
        # Pre-compute signature lengths for optimization
        self.sig_lengths = {sig['id']: len(sig['pattern']) for sig in self.signatures}
        
        # Group signatures by length for efficient matching
        self.sigs_by_length = defaultdict(list)
        for sig in self.signatures:
            length = len(sig['pattern'])
            self.sigs_by_length[length].append(sig)
    
    def _load_signatures(self):
        """Load all signatures into memory for fast matching"""
        self.signatures = []
        self.component_map = {}
        
        try:
            # Get all signatures from database
            all_sigs = self.db.get_all_signatures()
            total_sigs = 0
            valid_sigs = 0
            
            for sig_id, component_id, sig_compressed, sig_type, confidence, minhash in all_sigs:
                if sig_compressed:
                    # Decompress signature
                    import zstandard as zstd
                    dctx = zstd.ZstdDecompressor()
                    signature = dctx.decompress(sig_compressed).decode('utf-8')
                    total_sigs += 1
                    
                    # Validate signature quality before storing
                    if SignatureValidator.is_valid_signature(signature, confidence):
                        valid_sigs += 1
                        # Store signature info
                        self.signatures.append({
                            'id': sig_id,
                            'component_id': component_id,
                            'pattern': signature.lower(),  # Case-insensitive matching
                            'sig_type': sig_type,
                            'confidence': confidence
                        })
                    
                    # Map component IDs for later lookup
                    if component_id not in self.component_map:
                        # Query component info directly
                        with self.db._get_connection() as conn:
                            cursor = conn.execute(
                                "SELECT name, version, ecosystem, license, metadata FROM components WHERE id = ?",
                                (component_id,)
                            )
                            row = cursor.fetchone()
                            if row:
                                metadata = json.loads(row[4]) if row[4] else {}
                                self.component_map[component_id] = {
                                    'name': row[0],
                                    'version': row[1],
                                    'ecosystem': row[2] or metadata.get('ecosystem', 'unknown'),
                                    'license': row[3],  # License is a separate column
                                    'metadata': metadata
                                }
            
            logger.debug(f"Loaded {valid_sigs} valid signatures out of {total_sigs} total (filtered {total_sigs - valid_sigs} generic patterns)")
            
        except Exception as e:
            logger.error(f"Error loading signatures: {e}")
            self.signatures = []
    
    def match(
        self,
        features: ExtractedFeatures,
        threshold: float = 0.3,
        deep: bool = False
    ) -> List[ComponentMatch]:
        """
        Perform direct string matching on extracted features.
        
        Args:
            features: Extracted features from file
            threshold: Minimum confidence threshold (lowered default)
            deep: Enable deep analysis mode
            
        Returns:
            List of component matches
        """
        start_time = time.time()
        matches = []
        component_scores = defaultdict(list)
        
        # Get all strings from features (sorted for deterministic processing)
        all_strings = sorted(features.strings + features.functions + features.constants + features.symbols)
        
        if not all_strings:
            self.last_analysis_time = time.time() - start_time
            return matches
        
        # Convert to lowercase for matching
        string_set = {s.lower() for s in all_strings if s and len(s) >= 3}
        
        logger.debug(f"Direct matching against {len(string_set)} unique strings")
        
        # Pre-filter strings for substring matching (exclude very short/generic ones)
        generic_terms = self._get_generic_terms()
        valid_strings = sorted([s for s in string_set if len(s) >= 6 and s not in generic_terms])
        
        # Create a set of all substrings for faster matching
        # Only for strings up to a reasonable length to avoid memory explosion
        substring_set = set()
        for s in valid_strings:
            if len(s) <= 50:  # Limit substring generation
                for i in range(len(s)):
                    for j in range(i + 5, min(i + 30, len(s) + 1)):
                        substring_set.add(s[i:j])
        
        # Process signatures in length order for cache efficiency
        for length in sorted(self.sigs_by_length.keys()):
            for sig in self.sigs_by_length[length]:
                pattern = sig['pattern']
                
                # Check for exact match first (fast)
                if pattern in string_set:
                    component_scores[sig['component_id']].append({
                        'sig_id': sig['id'],
                        'confidence': sig['confidence'],
                        'sig_type': sig['sig_type'],
                        'pattern': pattern,
                        'matched_string': pattern  # exact match
                    })
                    continue
                
                # Skip if pattern is too short or generic
                if length < 5 or self._contains_only_generic_terms(pattern):
                    continue
                
                # Fast substring check using pre-computed set
                if length <= 30 and pattern in substring_set:
                    # Find which string contains this pattern
                    for string in valid_strings:
                        if pattern in string:
                            component_scores[sig['component_id']].append({
                                'sig_id': sig['id'],
                                'confidence': sig['confidence'] * 0.8,
                                'sig_type': sig['sig_type'],
                                'pattern': pattern,
                                'matched_string': string
                            })
                            break  # Only need one match per pattern
        
        # Aggregate scores by component (sorted for deterministic order)
        for component_id, sig_matches in sorted(component_scores.items()):
            if component_id not in self.component_map:
                continue
            
            comp_info = self.component_map[component_id]
            
            # Calculate aggregate confidence
            # Use average of top matches, with bonus for multiple matches
            sig_matches.sort(key=lambda x: x['confidence'], reverse=True)
            top_matches = sig_matches[:10]  # Consider top 10 matches
            
            if not top_matches:
                continue
            
            # Base confidence is average of top matches
            avg_confidence = sum(m['confidence'] for m in top_matches) / len(top_matches)
            
            # Bonus for multiple matches (up to 20% bonus)
            match_bonus = min(0.2, len(sig_matches) * 0.02)
            final_confidence = min(1.0, avg_confidence + match_bonus)
            
            if final_confidence >= threshold:
                # Determine match type
                sig_types = [m['sig_type'] for m in top_matches]
                match_type = self._get_match_type(sig_types)
                
                # Don't append version if it's 'unknown' or None
                version = comp_info.get('version')
                if version and version != 'unknown':
                    component_name = f"{comp_info['name']}@{version}"
                else:
                    component_name = comp_info['name']
                
                # Collect matched patterns for evidence
                matched_patterns = []
                for m in sig_matches[:20]:  # Limit to top 20 for readability
                    matched_patterns.append({
                        'pattern': m.get('pattern', ''),
                        'matched_string': m.get('matched_string', ''),
                        'confidence': m['confidence']
                    })
                
                match = ComponentMatch(
                    component=component_name,
                    ecosystem=comp_info.get('ecosystem', 'unknown'),
                    confidence=final_confidence,
                    license=comp_info.get('license'),
                    match_type=match_type,
                    evidence={
                        'signatures_matched': len(sig_matches),
                        'match_method': 'direct string matching',
                        'file_path': features.file_path,  # Add file path for tracking
                        'confidence_score': f"{final_confidence:.1%}",
                        'matched_patterns': matched_patterns
                    }
                )
                matches.append(match)
        
        # Sort by confidence, then by component name for deterministic order
        matches.sort(key=lambda m: (-m.confidence, m.component))
        
        self.last_analysis_time = time.time() - start_time
        logger.debug(f"Direct matching found {len(matches)} components in {self.last_analysis_time:.3f}s")
        
        return matches
    
    def _get_match_type(self, sig_types: List[int]) -> str:
        """Determine match type from signature types"""
        type_map = {
            1: "string",
            2: "function", 
            3: "constant",
            4: "pattern"
        }
        
        # Get most common type
        if sig_types:
            most_common = max(set(sig_types), key=sig_types.count)
            return type_map.get(most_common, "unknown")
        
        return "unknown"
    
    def _get_generic_terms(self) -> Set[str]:
        """Get set of generic programming terms to avoid in matching"""
        return {
            'create', 'destroy', 'init', 'exit', 'open', 'close', 'read', 'write',
            'get', 'set', 'add', 'remove', 'delete', 'update', 'insert', 'find',
            'search', 'sort', 'copy', 'move', 'compare', 'equals', 'hash', 'string',
            'buffer', 'array', 'list', 'map', 'vector', 'queue', 'stack', 'tree',
            'error', 'debug', 'info', 'warn', 'fatal', 'trace', 'log', 'print',
            'alloc', 'free', 'malloc', 'calloc', 'realloc', 'new', 'delete',
            'lock', 'unlock', 'mutex', 'thread', 'process', 'signal', 'handle',
            'start', 'stop', 'begin', 'end', 'first', 'last', 'next', 'prev',
            'size', 'count', 'length', 'empty', 'clear', 'reset', 'check', 'valid',
            'load', 'save', 'parse', 'format', 'encode', 'decode', 'convert',
            'connect', 'disconnect', 'send', 'receive', 'request', 'response',
            'client', 'server', 'host', 'port', 'address', 'socket', 'stream',
            'file', 'path', 'name', 'type', 'mode', 'flag', 'option', 'config',
            'value', 'key', 'data', 'info', 'meta', 'param', 'arg', 'result',
            'input', 'output', 'return', 'yield', 'throw', 'catch', 'finally',
            'class', 'object', 'instance', 'method', 'function', 'property',
            'public', 'private', 'protected', 'static', 'const', 'virtual',
            'abstract', 'interface', 'impl', 'base', 'derived', 'parent', 'child',
            'module', 'package', 'library', 'framework', 'component', 'service',
            'manager', 'handler', 'controller', 'view', 'model', 'factory',
            'builder', 'singleton', 'proxy', 'adapter', 'decorator', 'observer',
            'iterator', 'visitor', 'command', 'strategy', 'state', 'template',
            'context', 'store', 'cache', 'pool', 'buffer', 'queue', 'channel',
            'event', 'listener', 'callback', 'delegate', 'action', 'task', 'job',
            'work', 'item', 'element', 'node', 'edge', 'vertex', 'link', 'chain',
            'group', 'cluster', 'set', 'collection', 'container', 'wrapper',
            'helper', 'util', 'common', 'shared', 'global', 'local', 'temp',
            'filter', 'transform', 'reduce', 'aggregate', 'merge', 'split', 'join'
        }
    
    def _contains_only_generic_terms(self, pattern: str) -> bool:
        """Check if a pattern contains only generic terms"""
        # Split pattern by common separators
        parts = []
        current = ""
        for char in pattern.lower():
            if char in '_-.:':
                if current:
                    parts.append(current)
                    current = ""
            else:
                current += char
        if current:
            parts.append(current)
        
        if not parts:
            return True
        
        generic_terms = self._get_generic_terms()
        
        # If all parts are generic terms, the pattern is too generic
        return all(part in generic_terms for part in parts if part)