"""
SQLite database management for signature storage
"""

import sqlite3
import json
import logging
import struct
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from contextlib import contextmanager
import zstandard as zstd

from ..utils.hashing import compute_sha256


logger = logging.getLogger(__name__)


class SignatureDatabase:
    """
    SQLite-based signature storage with compression and indexing.
    """
    
    def __init__(self, db_path: Path):
        """
        Initialize signature database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            conn.executescript("""
                -- Components table
                CREATE TABLE IF NOT EXISTS components (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT,
                    ecosystem TEXT,
                    license TEXT,
                    weight REAL DEFAULT 1.0,
                    metadata TEXT,
                    UNIQUE(name, version, ecosystem)
                );
                
                -- Signatures table with compression
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY,
                    component_id INTEGER NOT NULL,
                    signature_hash TEXT NOT NULL,
                    signature_compressed BLOB,
                    sig_type INTEGER,
                    confidence REAL DEFAULT 0.5,
                    minhash BLOB,
                    FOREIGN KEY (component_id) REFERENCES components(id)
                );
                
                -- Trigram index for substring matching
                CREATE TABLE IF NOT EXISTS trigrams (
                    trigram TEXT NOT NULL,
                    signature_id INTEGER NOT NULL,
                    position INTEGER,
                    PRIMARY KEY (trigram, signature_id, position),
                    FOREIGN KEY (signature_id) REFERENCES signatures(id)
                );
                
                -- Clustering information
                CREATE TABLE IF NOT EXISTS clusters (
                    id INTEGER PRIMARY KEY,
                    centroid_hash TEXT UNIQUE,
                    member_count INTEGER,
                    confidence_threshold REAL
                );
                
                CREATE TABLE IF NOT EXISTS cluster_members (
                    cluster_id INTEGER,
                    signature_id INTEGER,
                    PRIMARY KEY (cluster_id, signature_id),
                    FOREIGN KEY (cluster_id) REFERENCES clusters(id),
                    FOREIGN KEY (signature_id) REFERENCES signatures(id)
                );
                
                -- Metadata table
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                
                -- Create indexes
                CREATE INDEX IF NOT EXISTS idx_sig_hash ON signatures(signature_hash);
                CREATE INDEX IF NOT EXISTS idx_sig_component ON signatures(component_id);
                CREATE INDEX IF NOT EXISTS idx_sig_confidence ON signatures(confidence);
                CREATE INDEX IF NOT EXISTS idx_trigram_lookup ON trigrams(trigram);
                
                -- Set pragmas for performance
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA cache_size = -64000;  -- 64MB cache
                PRAGMA temp_store = MEMORY;
            """)
            
            # Set initial metadata
            self._set_metadata(conn, "version", "1.0.0")
            self._set_metadata(conn, "created", str(Path.cwd()))
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with proper cleanup"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def is_initialized(self) -> bool:
        """Check if database is properly initialized"""
        if not self.db_path.exists():
            return False
        
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM components")
                count = cursor.fetchone()[0]
                return count > 0
        except Exception:
            return False
    
    def add_component(
        self,
        name: str,
        version: Optional[str] = None,
        ecosystem: Optional[str] = None,
        license: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> int:
        """Add a component to the database"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT OR REPLACE INTO components 
                (name, version, ecosystem, license, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name,
                version,
                ecosystem,
                license,
                json.dumps(metadata) if metadata else None
            ))
            return cursor.lastrowid
    
    def add_signature(
        self,
        component_id: int,
        signature: str,
        sig_type: int,
        confidence: float,
        minhash: bytes
    ) -> int:
        """Add a signature to the database"""
        # Compress signature
        compressor = zstd.ZstdCompressor(level=9)
        compressed = compressor.compress(signature.encode('utf-8'))
        sig_hash = compute_sha256(signature)
        
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO signatures 
                (component_id, signature_hash, signature_compressed, sig_type, confidence, minhash)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                component_id,
                sig_hash,
                compressed,
                sig_type,
                confidence,
                minhash
            ))
            
            sig_id = cursor.lastrowid
            
            # Add trigrams for substring matching
            self._add_trigrams(conn, sig_id, signature)
            
            return sig_id
    
    def _add_trigrams(self, conn: sqlite3.Connection, sig_id: int, signature: str):
        """Add trigrams for a signature"""
        trigrams = []
        sig_lower = signature.lower()
        
        for i in range(len(sig_lower) - 2):
            trigram = sig_lower[i:i+3]
            if trigram.isalnum():  # Only alphanumeric trigrams
                trigrams.append((trigram, sig_id, i))
        
        if trigrams:
            conn.executemany(
                "INSERT OR IGNORE INTO trigrams (trigram, signature_id, position) VALUES (?, ?, ?)",
                trigrams
            )
    
    def search_by_hash(self, sig_hash: str) -> Optional[Dict[str, Any]]:
        """Search for signature by hash"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT s.*, c.name, c.version, c.ecosystem, c.license
                FROM signatures s
                JOIN components c ON s.component_id = c.id
                WHERE s.signature_hash = ?
            """, (sig_hash,))
            
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    def search_by_trigrams(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Search signatures using trigram index"""
        query_lower = query.lower()
        trigrams = [query_lower[i:i+3] for i in range(len(query_lower) - 2)]
        trigrams = [t for t in trigrams if t.isalnum()]
        
        if not trigrams:
            return []
        
        with self._get_connection() as conn:
            # Find signatures containing all trigrams
            placeholders = ','.join('?' * len(trigrams))
            cursor = conn.execute(f"""
                SELECT signature_id, COUNT(DISTINCT trigram) as match_count
                FROM trigrams
                WHERE trigram IN ({placeholders})
                GROUP BY signature_id
                HAVING match_count = ?
                ORDER BY signature_id
                LIMIT ?
            """, trigrams + [len(trigrams), limit])
            
            sig_ids = [row['signature_id'] for row in cursor]
            
            if not sig_ids:
                return []
            
            # Get full signature data
            placeholders = ','.join('?' * len(sig_ids))
            cursor = conn.execute(f"""
                SELECT s.*, c.name, c.version, c.ecosystem, c.license
                FROM signatures s
                JOIN components c ON s.component_id = c.id
                WHERE s.id IN ({placeholders})
            """, sig_ids)
            
            return [dict(row) for row in cursor]
    
    def get_minhashes_batch(self, sig_ids: List[int]) -> Dict[int, bytes]:
        """Get MinHash values for multiple signatures"""
        if not sig_ids:
            return {}
        
        with self._get_connection() as conn:
            placeholders = ','.join('?' * len(sig_ids))
            cursor = conn.execute(f"""
                SELECT id, minhash
                FROM signatures
                WHERE id IN ({placeholders})
            """, sig_ids)
            
            return {row['id']: row['minhash'] for row in cursor}
    
    def load_from_xmdb(self, xmdb_path: Path) -> int:
        """
        Load signatures from XMDB format file.
        
        Returns:
            Number of signatures loaded
        """
        logger.info(f"Loading signatures from {xmdb_path}")
        
        with open(xmdb_path, 'rb') as f:
            # Read header
            magic = f.read(4)
            if magic != b'XMDB':
                raise ValueError(f"Invalid XMDB file: {xmdb_path}")
            
            version = struct.unpack('<I', f.read(4))[0]
            comp_count = struct.unpack('<I', f.read(4))[0]
            sig_count = struct.unpack('<I', f.read(4))[0]
            compression_type = struct.unpack('<B', f.read(1))[0]
            f.read(47)  # Skip reserved
            
            logger.info(f"XMDB version {version}: {comp_count} components, {sig_count} signatures")
            
            # Read components
            components = {}
            for _ in range(comp_count):
                comp_id = struct.unpack('<I', f.read(4))[0]
                name_len = struct.unpack('<H', f.read(2))[0]
                name = f.read(name_len).decode('utf-8')
                version_len = struct.unpack('<H', f.read(2))[0]
                version = f.read(version_len).decode('utf-8') if version_len > 0 else None
                meta_len = struct.unpack('<I', f.read(4))[0]
                metadata = f.read(meta_len).decode('utf-8') if meta_len > 0 else None
                
                # Add to database
                db_id = self.add_component(name, version, metadata=json.loads(metadata) if metadata else None)
                components[comp_id] = db_id
            
            # Read signatures
            decompressor = zstd.ZstdDecompressor()
            loaded = 0
            
            with self._get_connection() as conn:
                for _ in range(sig_count):
                    comp_id = struct.unpack('<I', f.read(4))[0]
                    sig_type = struct.unpack('<B', f.read(1))[0]
                    confidence = struct.unpack('<f', f.read(4))[0]
                    minhash = f.read(16)
                    sig_len = struct.unpack('<I', f.read(4))[0]
                    sig_compressed = f.read(sig_len)
                    
                    # Decompress signature
                    if compression_type == 1:  # zstd
                        signature = decompressor.decompress(sig_compressed).decode('utf-8')
                    else:
                        signature = sig_compressed.decode('utf-8')
                    
                    # Add to database
                    self.add_signature(
                        components[comp_id],
                        signature,
                        sig_type,
                        confidence,
                        minhash
                    )
                    loaded += 1
                    
                    if loaded % 1000 == 0:
                        logger.debug(f"Loaded {loaded}/{sig_count} signatures")
        
        logger.info(f"Successfully loaded {loaded} signatures")
        return loaded
    
    def get_all_signatures(self) -> List[Tuple[int, int, bytes, int, float, bytes]]:
        """Get all signatures from database for index building"""
        with self._get_connection() as conn:
            cursor = conn.execute("""
                SELECT id, component_id, signature_compressed, sig_type, confidence, minhash
                FROM signatures
                ORDER BY id
            """)
            return [(row['id'], row['component_id'], row['signature_compressed'], 
                     row['sig_type'], row['confidence'], row['minhash']) 
                    for row in cursor]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self._get_connection() as conn:
            stats = {}
            
            # Component count
            cursor = conn.execute("SELECT COUNT(*) FROM components")
            stats['component_count'] = cursor.fetchone()[0]
            
            # Signature count
            cursor = conn.execute("SELECT COUNT(*) FROM signatures")
            stats['signature_count'] = cursor.fetchone()[0]
            
            # Signature types
            cursor = conn.execute("""
                SELECT sig_type, COUNT(*) as count
                FROM signatures
                GROUP BY sig_type
            """)
            stats['signature_types'] = {row['sig_type']: row['count'] for row in cursor}
            
            # Database size
            stats['database_size'] = self.db_path.stat().st_size
            
            # Metadata
            cursor = conn.execute("SELECT key, value FROM metadata ORDER BY key")
            stats['metadata'] = {row['key']: row['value'] for row in cursor}
            
            return stats
    
    def _set_metadata(self, conn: sqlite3.Connection, key: str, value: str):
        """Set metadata value"""
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value)
        )
    
    def vacuum(self):
        """Optimize database storage"""
        with self._get_connection() as conn:
            conn.execute("VACUUM")
            conn.execute("ANALYZE")
        logger.info("Database optimized")