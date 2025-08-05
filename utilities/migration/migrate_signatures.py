#!/usr/bin/env python3
"""
Script to migrate BSA signatures to our database format
"""

import json
import logging
from pathlib import Path
import sys
import argparse
from typing import Dict, List, Any

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from binarysniffer.storage.database import SignatureDatabase
from binarysniffer.utils.hashing import compute_minhash_for_strings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def load_bsa_signature(signature_file: Path) -> Dict[str, Any]:
    """Load a BSA signature file"""
    try:
        with open(signature_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading {signature_file}: {e}")
        return {}


def migrate_signature(db: SignatureDatabase, signature_data: Dict[str, Any], 
                     source_file: str) -> bool:
    """Migrate a single signature to our database"""
    try:
        # Extract metadata
        package = signature_data.get('package', 'Unknown')
        publisher = signature_data.get('publisher', 'Unknown')
        license_info = signature_data.get('license', '')
        updated = signature_data.get('updated', '')
        symbols = signature_data.get('symbols', [])
        
        if not symbols:
            logger.warning(f"No symbols in {source_file}")
            return False
        
        # Create component record
        component_data = {
            'name': package,
            'version': '',  # BSA doesn't have version info
            'publisher': publisher,
            'license': license_info,
            'ecosystem': 'native',  # Most BSA signatures are for native libraries
            'description': f'Migrated from BSA: {source_file}',
            'updated': updated
        }
        
        component_id = db.add_component(component_data)
        logger.info(f"Added component {package} with ID {component_id}")
        
        # Add signatures for each symbol
        added_count = 0
        
        for symbol in symbols:
            if not symbol or len(symbol) < 3:  # Skip very short symbols
                continue
                
            try:
                # Create MinHash for the symbol
                minhash = compute_minhash_for_strings([symbol])
                
                # Add signature
                db.add_signature(
                    component_id=component_id,
                    signature=symbol,
                    sig_type=1,  # String signature type
                    confidence=0.7,  # Default confidence for BSA signatures
                    minhash=minhash.to_bytes()
                )
                added_count += 1
                
            except Exception as e:
                logger.debug(f"Error processing symbol {symbol}: {e}")
                continue
        
        logger.info(f"Added {added_count} signatures for {package}")
        return added_count > 0
        
    except Exception as e:
        logger.error(f"Error migrating signature from {source_file}: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description='Migrate BSA signatures to database')
    parser.add_argument('signatures_dir', 
                       help='Directory containing BSA signature JSON files')
    parser.add_argument('--db-path', default='data/signatures.db',
                       help='Path to signature database')
    parser.add_argument('--limit', type=int, default=None,
                       help='Limit number of files to process (for testing)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Ensure database directory exists
    db_path = Path(args.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize database
    logger.info(f"Initializing database at {db_path}")
    db = SignatureDatabase(str(db_path))
    
    # Find signature files
    signatures_dir = Path(args.signatures_dir)
    if not signatures_dir.exists():
        logger.error(f"Signatures directory not found: {signatures_dir}")
        return 1
    
    signature_files = list(signatures_dir.glob('*.json'))
    if not signature_files:
        logger.error(f"No JSON files found in {signatures_dir}")
        return 1
    
    logger.info(f"Found {len(signature_files)} signature files")
    
    if args.limit:
        signature_files = signature_files[:args.limit]
        logger.info(f"Processing first {len(signature_files)} files")
    
    # Migrate signatures
    success_count = 0
    error_count = 0
    
    for signature_file in signature_files:
        logger.info(f"Processing {signature_file.name}")
        
        # Load signature
        signature_data = load_bsa_signature(signature_file)
        if not signature_data:
            error_count += 1
            continue
        
        # Migrate to database
        if migrate_signature(db, signature_data, signature_file.name):
            success_count += 1
        else:
            error_count += 1
    
    # Build indexes
    logger.info("Building database indexes...")
    db.build_indexes()
    
    # Print summary
    logger.info(f"Migration complete!")
    logger.info(f"Successfully migrated: {success_count}")
    logger.info(f"Errors: {error_count}")
    logger.info(f"Database: {db_path}")
    
    # Print database stats
    stats = db.get_stats()
    logger.info(f"Database stats:")
    logger.info(f"  Components: {stats.get('components', 0)}")
    logger.info(f"  Signatures: {stats.get('signatures', 0)}")
    
    return 0 if error_count == 0 else 1


if __name__ == '__main__':
    sys.exit(main())