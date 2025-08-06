"""
Configuration management for BinarySniffer
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict


logger = logging.getLogger(__name__)


@dataclass
class Config:
    _logging_setup = False
    """
    Configuration for BinarySniffer.
    
    Can be loaded from:
    1. Default values
    2. Configuration file (~/.binarysniffer/config.json)
    3. Environment variables (BINARYSNIFFER_*)
    4. Programmatic override
    """
    
    # Paths
    data_dir: Path = field(default_factory=lambda: Path.home() / ".binarysniffer")
    
    # Signature sources
    signature_sources: List[str] = field(default_factory=lambda: [
        "https://signatures.binarysniffer.io/core.xmdb",
        "https://signatures.binarysniffer.io/extended.xmdb"
    ])
    
    # Performance settings
    cache_size_mb: int = 100
    parallel_workers: int = 4
    chunk_size: int = 1000
    max_file_size_mb: int = 500
    
    # Analysis settings
    min_confidence: float = 0.5
    min_string_length: int = 5
    max_strings_per_file: int = 10000
    
    # Matching settings
    minhash_permutations: int = 128
    minhash_bands: int = 16
    bloom_filter_error_rate: float = 0.001
    
    # Update settings
    auto_update: bool = True
    update_check_interval_days: int = 7
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing"""
        
        # Ensure Path objects
        if isinstance(self.data_dir, str):
            self.data_dir = Path(self.data_dir)
        
        # Load from file if exists
        config_file = self.data_dir / "config.json"
        if config_file.exists():
            self._load_from_file(config_file)
        
        # Override with environment variables
        self._load_from_env()
        
        # Setup logging only once globally
        if not Config._logging_setup:
            self._setup_logging()
            Config._logging_setup = True
    
    @property
    def db_path(self) -> Path:
        """Path to signature database"""
        return self.data_dir / "signatures.db"
    
    @property
    def bloom_filter_dir(self) -> Path:
        """Path to bloom filter directory"""
        return self.data_dir / "bloom_filters"
    
    @property
    def index_dir(self) -> Path:
        """Path to index directory"""
        return self.data_dir / "index"
    
    @property
    def cache_dir(self) -> Path:
        """Path to cache directory"""
        return self.data_dir / "cache"
    
    def _load_from_file(self, config_file: Path):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
            
            for key, value in data.items():
                if hasattr(self, key):
                    if key == 'data_dir':
                        value = Path(value)
                    setattr(self, key, value)
            
            logger.debug(f"Loaded configuration from {config_file}")
        except Exception as e:
            logger.warning(f"Failed to load config file: {e}")
    
    def _load_from_env(self):
        """Load configuration from environment variables"""
        env_prefix = "BINARYSNIFFER_"
        
        for key in self.__dataclass_fields__:
            env_key = f"{env_prefix}{key.upper()}"
            if env_key in os.environ:
                value = os.environ[env_key]
                
                # Type conversion
                field_type = self.__dataclass_fields__[key].type
                try:
                    if field_type == bool:
                        value = value.lower() in ('true', '1', 'yes')
                    elif field_type == int:
                        value = int(value)
                    elif field_type == float:
                        value = float(value)
                    elif field_type == Path:
                        value = Path(value)
                    elif field_type == List[str]:
                        value = value.split(',')
                    
                    setattr(self, key, value)
                    logger.debug(f"Set {key} from environment variable")
                except ValueError as e:
                    logger.warning(f"Invalid value for {env_key}: {e}")
    
    def _setup_logging(self):
        """Setup logging configuration"""
        # Use simple format for WARNING and below, detailed for INFO and above
        level = getattr(logging, self.log_level.upper())
        if level <= logging.WARNING:
            # Clean output for normal usage
            log_format = "%(message)s"
        else:
            # Detailed format for debugging
            log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        
        # Get all binarysniffer loggers
        bs_logger = logging.getLogger("binarysniffer")
        bs_logger.setLevel(level)
        
        # Clear any existing handlers first
        bs_logger.handlers.clear()
        
        # Add single console handler with duplicate filter
        from ..utils.logging import DuplicateFilter
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(log_format))
        console_handler.addFilter(DuplicateFilter())
        bs_logger.addHandler(console_handler)
        
        # Prevent propagation to avoid duplicates
        bs_logger.propagate = False
        
        # File handler if specified
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setFormatter(logging.Formatter(log_format))
            bs_logger.addHandler(file_handler)
        
        # Clear root logger handlers to prevent any duplicates
        logging.root.handlers.clear()
    
    def save(self, config_file: Optional[Path] = None):
        """
        Save configuration to file.
        
        Args:
            config_file: Path to save config. If None, uses default location.
        """
        if config_file is None:
            config_file = self.data_dir / "config.json"
        
        # Ensure directory exists
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict and handle Path objects
        data = {}
        for key, value in asdict(self).items():
            if isinstance(value, Path):
                value = str(value)
            data[key] = value
        
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Saved configuration to {config_file}")
    
    @classmethod
    def load(cls, config_file: Path) -> "Config":
        """
        Load configuration from file.
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            Config object
        """
        config = cls()
        config._load_from_file(config_file)
        return config
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        return {
            k: str(v) if isinstance(v, Path) else v
            for k, v in asdict(self).items()
        }