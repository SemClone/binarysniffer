#!/usr/bin/env python3
"""
Simple signature migration script without heavy dependencies
"""

import json
import sqlite3
import hashlib
from pathlib import Path
import argparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_database(db_path: str):
    """Create the signatures database schema"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS components (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        version TEXT DEFAULT '',
        publisher TEXT DEFAULT '',
        license TEXT DEFAULT '',
        ecosystem TEXT DEFAULT 'native',
        description TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        component_id INTEGER NOT NULL,
        signature_hash TEXT NOT NULL,
        signature_compressed BLOB,
        sig_type INTEGER DEFAULT 1,
        confidence REAL DEFAULT 0.5,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (component_id) REFERENCES components (id)
    )
    ''')
    
    # Create indexes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_signatures_hash ON signatures(signature_hash)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_signatures_component ON signatures(component_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_components_name ON components(name)')
    
    conn.commit()
    return conn


def add_component(conn, name, publisher="", license_info=""):
    """Add a component and return its ID"""
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO components (name, publisher, license)
    VALUES (?, ?, ?)
    ''', (name, publisher, license_info))
    conn.commit()
    return cursor.lastrowid


def add_signature(conn, component_id, signature, confidence=0.7):
    """Add a signature"""
    # Create hash of signature for indexing
    sig_hash = hashlib.sha256(signature.encode('utf-8')).hexdigest()
    
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO signatures (component_id, signature_hash, sig_type, confidence)
    VALUES (?, ?, 1, ?)
    ''', (component_id, sig_hash, confidence))
    conn.commit()
    
    # Also store in trigrams table for substring matching
    add_trigrams(conn, cursor.lastrowid, signature)


def add_trigrams(conn, signature_id, signature):
    """Add trigrams for substring matching"""
    cursor = conn.cursor()
    
    # Create trigrams table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS trigrams (
        signature_id INTEGER,
        trigram TEXT,
        FOREIGN KEY (signature_id) REFERENCES signatures (id)
    )
    ''')
    
    # Generate trigrams
    trigrams = set()
    for i in range(len(signature) - 2):
        trigram = signature[i:i+3].lower()
        if len(trigram) == 3:
            trigrams.add(trigram)
    
    # Insert trigrams
    for trigram in trigrams:
        cursor.execute('''
        INSERT INTO trigrams (signature_id, trigram)
        VALUES (?, ?)
        ''', (signature_id, trigram))
    
    conn.commit()


def migrate_bsa_file(conn, json_file: Path):
    """Migrate a single BSA JSON file"""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        package = data.get('package', json_file.stem)
        publisher = data.get('publisher', '')
        license_info = data.get('license', '')
        symbols = data.get('symbols', [])
        
        if not symbols:
            logger.warning(f"No symbols in {json_file}")
            return 0
        
        # Add component
        component_id = add_component(conn, package, publisher, license_info)
        logger.info(f"Added component: {package} (ID: {component_id})")
        
        # Add signatures
        added = 0
        for symbol in symbols:
            if isinstance(symbol, str) and len(symbol) >= 3:
                add_signature(conn, component_id, symbol)
                added += 1
        
        logger.info(f"Added {added} signatures for {package}")
        return added
        
    except Exception as e:
        logger.error(f"Error processing {json_file}: {e}")
        return 0


def main():
    parser = argparse.ArgumentParser(description='Simple BSA signature migration')
    parser.add_argument('signatures_dir', help='Directory with BSA JSON files')
    parser.add_argument('--db-path', default='data/signatures.db',
                       help='Output database path')
    parser.add_argument('--limit', type=int, help='Limit files processed')
    
    args = parser.parse_args()
    
    # Create database directory
    db_path = Path(args.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create database
    logger.info(f"Creating database at {db_path}")
    conn = create_database(str(db_path))
    
    # Find JSON files
    signatures_dir = Path(args.signatures_dir)
    json_files = list(signatures_dir.glob('*.json'))
    
    if args.limit:
        json_files = json_files[:args.limit]
    
    logger.info(f"Processing {len(json_files)} files")
    
    # Migrate files
    total_signatures = 0
    for json_file in json_files:
        logger.info(f"Processing {json_file.name}")
        count = migrate_bsa_file(conn, json_file)
        total_signatures += count
    
    # Create indexes
    cursor = conn.cursor()
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_trigrams ON trigrams(trigram)')
    conn.commit()
    
    # Print stats
    cursor.execute('SELECT COUNT(*) FROM components')
    component_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM signatures')
    signature_count = cursor.fetchone()[0]
    
    logger.info(f"Migration complete!")
    logger.info(f"Components: {component_count}")
    logger.info(f"Signatures: {signature_count}")
    
    conn.close()


if __name__ == '__main__':
    main()