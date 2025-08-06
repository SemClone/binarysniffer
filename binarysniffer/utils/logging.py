"""
Logging utilities to prevent duplicate messages
"""

import logging
from typing import Set


class DuplicateFilter(logging.Filter):
    """Filter to prevent duplicate log messages"""
    
    def __init__(self):
        super().__init__()
        self.logged_messages: Set[str] = set()
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter out duplicate messages"""
        # Create a unique key for this log record
        key = f"{record.name}:{record.levelno}:{record.msg}"
        
        # Check if we've seen this exact message before
        if key in self.logged_messages:
            return False
        
        # Add to seen messages
        self.logged_messages.add(key)
        return True


def setup_logging(log_level: str = "INFO", log_format: str = None):
    """Setup logging with duplicate prevention"""
    if log_format is None:
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Get the binarysniffer logger
    logger = logging.getLogger("binarysniffer")
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create console handler with duplicate filter
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(log_format))
    console_handler.addFilter(DuplicateFilter())
    
    # Add handler
    logger.addHandler(console_handler)
    
    # Prevent propagation
    logger.propagate = False
    
    # Also clear root logger handlers to prevent any interference
    logging.root.handlers.clear()