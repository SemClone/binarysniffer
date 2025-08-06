"""
Signature management for packaged and remote signatures
"""

import json
import logging
import tempfile
import urllib.request
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..storage.database import SignatureDatabase
from ..core.config import Config
from ..utils.hashing import compute_minhash_for_strings

logger = logging.getLogger(__name__)


class SignatureManager:
    """Manage signatures from package and remote sources"""
    
    def __init__(self, config: Config, db: SignatureDatabase):
        """
        Initialize signature manager.
        
        Args:
            config: BinarySniffer configuration
            db: Signature database instance
        """
        self.config = config
        self.db = db
        # Point to the signatures directory (try multiple possible locations)
        self.package_signatures_dir = self._find_signatures_directory()
        self.manifest_path = config.data_dir / "manifest.json"
    
    def ensure_database_synced(self) -> bool:
        """
        Ensure database is synced with packaged signatures.
        
        Returns:
            True if sync was performed
        """
        try:
            packaged_version = self._get_packaged_version()
            db_version = self._get_database_version()
            
            logger.info(f"Packaged signatures version: {packaged_version}")
            logger.info(f"Database version: {db_version}")
            
            if self._version_newer(packaged_version, db_version):
                logger.info("Importing packaged signatures...")
                self._import_packaged_signatures()
                self._update_database_version(packaged_version)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error syncing database: {e}")
            return False
    
    def import_packaged_signatures(self, force: bool = False) -> int:
        """
        Import all packaged signature files.
        
        Args:
            force: Force reimport even if already imported
            
        Returns:
            Number of signatures imported
        """
        imported = 0
        
        if not self.package_signatures_dir.exists():
            logger.warning("No packaged signatures directory found")
            return 0
        
        for json_file in self.package_signatures_dir.glob("*.json"):
            if json_file.name == "manifest.json":
                continue
                
            try:
                logger.info(f"Importing {json_file.name}")
                count = self._import_signature_file(json_file, force=force)
                imported += count
                
            except Exception as e:
                logger.error(f"Error importing {json_file}: {e}")
        
        # Database indexes are automatically managed
        if imported > 0:
            logger.info("Import completed successfully")
        
        logger.info(f"Imported {imported} signatures from package")
        return imported
    
    def download_from_github(
        self, 
        repo_url: str = "https://api.github.com/repos/oscarvalenzuelab/semantic-copycat-binarysniffer",
        target_dir: Optional[Path] = None
    ) -> int:
        """
        Download signatures from GitHub repository.
        
        Args:
            repo_url: GitHub API URL for repository
            target_dir: Directory to save downloaded files
            
        Returns:
            Number of files downloaded
        """
        if target_dir is None:
            target_dir = self.config.data_dir / "downloaded_signatures"
        
        target_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # Get contents of signatures directory
            contents_url = f"{repo_url}/contents/signatures"
            
            with urllib.request.urlopen(contents_url) as response:
                contents = json.loads(response.read().decode())
            
            downloaded = 0
            
            for item in contents:
                if item["type"] == "file" and item["name"].endswith(".json"):
                    # Download file
                    file_url = item["download_url"]
                    local_path = target_dir / item["name"]
                    
                    logger.info(f"Downloading {item['name']}")
                    urllib.request.urlretrieve(file_url, local_path)
                    downloaded += 1
            
            logger.info(f"Downloaded {downloaded} signature files from GitHub")
            return downloaded
            
        except Exception as e:
            logger.error(f"Error downloading from GitHub: {e}")
            return 0
    
    def import_directory(self, directory: Path, force: bool = False) -> int:
        """
        Import all JSON signature files from directory.
        
        Args:
            directory: Directory containing JSON files
            force: Force reimport existing signatures
            
        Returns:
            Number of signatures imported
        """
        if not directory.exists():
            logger.error(f"Directory not found: {directory}")
            return 0
        
        imported = 0
        
        for json_file in directory.glob("*.json"):
            try:
                count = self._import_signature_file(json_file, force=force)
                imported += count
                
            except Exception as e:
                logger.error(f"Error importing {json_file}: {e}")
        
        # Database indexes are automatically managed
        
        return imported
    
    def rebuild_database(self, include_github: bool = True) -> Dict[str, int]:
        """
        Rebuild database from scratch.
        
        Args:
            include_github: Whether to download from GitHub first
            
        Returns:
            Statistics about rebuild
        """
        logger.info("Rebuilding signature database from scratch...")
        
        # Clear existing database
        self._clear_database()
        
        stats = {
            "packaged": 0,
            "github": 0,
            "total": 0
        }
        
        # Import packaged signatures
        stats["packaged"] = self.import_packaged_signatures(force=True)
        
        # Download and import from GitHub
        if include_github:
            download_dir = self.config.data_dir / "temp_download"
            try:
                download_count = self.download_from_github(target_dir=download_dir)
                if download_count > 0:
                    stats["github"] = self.import_directory(download_dir, force=True)
                
                # Clean up download directory
                if download_dir.exists():
                    import shutil
                    shutil.rmtree(download_dir)
                    
            except Exception as e:
                logger.error(f"Error with GitHub download: {e}")
        
        stats["total"] = stats["packaged"] + stats["github"]
        
        # Update version
        self._update_database_version(self._get_packaged_version())
        
        logger.info(f"Database rebuild complete: {stats}")
        return stats
    
    def get_signature_info(self) -> Dict[str, Any]:
        """Get information about current signatures"""
        return {
            "database_version": self._get_database_version(),
            "packaged_version": self._get_packaged_version(),
            "sync_needed": self._version_newer(
                self._get_packaged_version(), 
                self._get_database_version()
            ),
            "signature_count": self._count_signatures(),
            "component_count": self._count_components(),
            "last_updated": self._get_last_update()
        }
    
    def _import_signature_file(self, json_file: Path, force: bool = False) -> int:
        """Import single signature file using new JSON format"""
        with open(json_file, 'r', encoding='utf-8') as f:
            signature_data = json.load(f)
        
        # Extract component info from new format
        component_info = signature_data.get("component", {})
        package_name = component_info.get("name", json_file.stem)
        
        # Check if already imported (unless forcing)
        if not force and self._signature_exists(package_name):
            logger.debug(f"Signature already exists: {package_name}")
            return 0
        
        # Create component using new format
        component_data = {
            'name': package_name,
            'version': component_info.get('version', ''),
            'publisher': component_info.get('publisher', ''),
            'license': component_info.get('license', ''),
            'ecosystem': component_info.get('ecosystem', 'native'),
            'description': component_info.get('description', ''),
            'metadata': json.dumps({
                'category': component_info.get('category', 'unknown'),
                'platforms': component_info.get('platforms', []), 
                'languages': component_info.get('languages', []),
                'signature_metadata': signature_data.get('signature_metadata', {})
            })
        }
        
        component_id = self.db.add_component(
            name=component_data['name'],
            version=component_data['version'],
            ecosystem=component_data['ecosystem'],
            license=component_data['license'],
            metadata=json.loads(component_data['metadata']) if component_data['metadata'] else None
        )
        
        # Add signatures from new format
        signatures = signature_data.get("signatures", [])
        imported_count = 0
        
        for sig_entry in signatures:
            pattern = sig_entry.get("pattern", "")
            if pattern and len(pattern) >= 3:  # Only import non-empty patterns
                confidence = float(sig_entry.get("confidence", 0.7))
                sig_type = sig_entry.get("type", "string_pattern")
                
                # Map signature type to integer
                type_mapping = {
                    "string_pattern": 1,
                    "byte_pattern": 2,
                    "function_name": 1,
                    1: 1,  # Handle integer types from exports
                    2: 2
                }
                sig_type_int = type_mapping.get(sig_type, 1)
                
                # Compute minhash for the signature
                minhash_obj = compute_minhash_for_strings([pattern])
                minhash = minhash_obj.to_bytes()
                
                self.db.add_signature(
                    component_id=component_id,
                    signature=pattern,
                    sig_type=sig_type_int,
                    confidence=confidence,
                    minhash=minhash
                )
                imported_count += 1
        
        logger.debug(f"Imported {package_name}: {imported_count} signatures")
        return imported_count
    
    def _get_packaged_version(self) -> str:
        """Get version of packaged signatures"""
        manifest_file = self.package_signatures_dir / "manifest.json"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r') as f:
                    manifest = json.load(f)
                return manifest.get("version", "1.0.0")
            except Exception:
                pass
        return "1.0.0"
    
    def _get_database_version(self) -> str:
        """Get current database version"""
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path, 'r') as f:
                    manifest = json.load(f)
                return manifest.get("database_version", "0.0.0")
            except Exception:
                pass
        return "0.0.0"
    
    def _update_database_version(self, version: str):
        """Update database version in manifest"""
        manifest = {}
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path, 'r') as f:
                    manifest = json.load(f)
            except Exception:
                pass
        
        manifest.update({
            "database_version": version,
            "last_sync": datetime.now().isoformat(),
            "sync_source": "packaged"
        })
        
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
    
    def _version_newer(self, version1: str, version2: str) -> bool:
        """Check if version1 is newer than version2"""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            return v1_parts > v2_parts
        except Exception:
            return version1 != version2
    
    def _signature_exists(self, package_name: str) -> bool:
        """Check if signature for package already exists"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM components WHERE name = ?",
                (package_name,)
            )
            return cursor.fetchone()[0] > 0
    
    def _clear_database(self):
        """Clear all signature data from database"""
        with self.db._get_connection() as conn:
            conn.executescript("""
                DELETE FROM trigrams;
                DELETE FROM signatures;
                DELETE FROM components;
                VACUUM;
            """)
    
    def _count_signatures(self) -> int:
        """Count total signatures in database"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM signatures")
            return cursor.fetchone()[0]
    
    def _count_components(self) -> int:
        """Count total components in database"""
        with self.db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM components")
            return cursor.fetchone()[0]
    
    def _get_last_update(self) -> Optional[str]:
        """Get last update timestamp"""
        if self.manifest_path.exists():
            try:
                with open(self.manifest_path, 'r') as f:
                    manifest = json.load(f)
                return manifest.get("last_sync")
            except Exception:
                pass
        return None
    
    def _find_signatures_directory(self) -> Path:
        """Find signatures directory in various possible install locations"""
        import sys
        import site
        
        # Possible locations to check (in order of preference)
        candidates = [
            # 1. Development location (relative to this file)
            Path(__file__).parent.parent.parent / "signatures",
            
            # 2. User site-packages parallel directory (common for pip user installs)
            Path(site.USER_BASE) / "signatures",
            
            # 3. Next to the package in site-packages
            Path(__file__).parent.parent.parent / "signatures",
            
            # 4. Installed data files location (pip install)
            Path(sys.prefix) / "signatures",
            
            # 5. User site location  
            Path(sys.prefix) / "local" / "signatures",
            
            # 6. Alternative pip locations
            Path(__file__).parent / "data",
            
            # 7. Virtual environment location
            Path(sys.executable).parent.parent / "signatures" if hasattr(sys, 'real_prefix') or hasattr(sys, 'base_prefix') else None,
            
            # 8. macOS user install location (Python 3.9)
            Path.home() / "Library" / "Python" / "3.9" / "signatures",
            
            # 9. Generic user library location
            Path.home() / ".local" / "lib" / "python3.9" / "signatures"
        ]
        
        # Filter out None values and check each location
        for candidate in filter(None, candidates):
            if candidate.exists() and candidate.is_dir():
                # Verify it contains signature files
                if any(candidate.glob("*.json")):
                    logger.debug(f"Found signatures directory at: {candidate}")
                    return candidate
        
        # Fallback to development location even if it doesn't exist
        fallback = Path(__file__).parent.parent.parent / "signatures"
        logger.warning(f"No signatures directory found. Using fallback: {fallback}")
        return fallback
    
    def _import_packaged_signatures(self):
        """Import all packaged signatures"""
        return self.import_packaged_signatures(force=False)