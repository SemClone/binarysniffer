"""
Signature generation from source code and binaries
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from datetime import datetime

from ..extractors.factory import ExtractorFactory
from ..core.config import Config
from ..hashing.tlsh_hasher import TLSHHasher

logger = logging.getLogger(__name__)


class SignatureGenerator:
    """Generate signature files from source code and binaries"""
    
    def __init__(self, config: Optional[Config] = None):
        """
        Initialize signature generator.
        
        Args:
            config: BinarySniffer configuration
        """
        self.config = config or Config()
        self.extractor_factory = ExtractorFactory()
        self.tlsh_hasher = TLSHHasher()
    
    def generate_from_path(
        self,
        path: Path,
        package_name: str,
        publisher: str = "",
        license_name: str = "",
        version: str = "",
        ecosystem: str = "native",
        description: str = "",
        recursive: bool = True,
        min_confidence: float = 0.5,
        min_symbols: int = 3,
        include_strings: bool = False,
        include_constants: bool = True,
        include_functions: bool = True,
        include_imports: bool = True
    ) -> Dict[str, Any]:
        """
        Generate signature from file or directory.
        
        Args:
            path: Path to analyze
            package_name: Name of the component
            publisher: Publisher/maintainer name
            license_name: License identifier
            version: Component version
            ecosystem: Package ecosystem (native, npm, maven, etc.)
            description: Component description
            recursive: Analyze directories recursively
            min_confidence: Minimum confidence for including symbols
            min_symbols: Minimum number of symbols required
            include_strings: Include string literals
            include_constants: Include constant definitions
            include_functions: Include function names
            include_imports: Include import statements
            
        Returns:
            Signature dictionary ready for JSON export
        """
        logger.info(f"Generating signature for {path}")
        
        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")
        
        # Collect all symbols from files
        all_symbols = set()
        all_functions = set()
        all_constants = set()
        all_imports = set()
        all_strings = set()
        
        files_processed = 0
        
        if path.is_file():
            files_to_process = [path]
        else:
            if recursive:
                files_to_process = list(path.rglob('*'))
            else:
                files_to_process = list(path.iterdir())
            files_to_process = [f for f in files_to_process if f.is_file()]
        
        # Process each file
        for file_path in files_to_process:
            try:
                # Extract features
                features = self.extractor_factory.extract(file_path)
                
                if include_functions:
                    all_functions.update(features.functions)
                
                if include_constants:
                    all_constants.update(features.constants)
                
                if include_imports:
                    all_imports.update(features.imports)
                
                if include_strings:
                    # Filter out very short or very long strings
                    filtered_strings = [s for s in features.strings 
                                      if 5 <= len(s) <= 100]
                    all_strings.update(filtered_strings)
                
                # Add general symbols
                all_symbols.update(features.symbols)
                
                files_processed += 1
                
            except Exception as e:
                logger.debug(f"Error processing {file_path}: {e}")
                continue
        
        # Combine all symbols
        combined_symbols = set()
        combined_symbols.update(all_functions)
        combined_symbols.update(all_constants)
        combined_symbols.update(all_imports)
        combined_symbols.update(all_symbols)
        
        if include_strings:
            # Only include high-quality strings
            quality_strings = self._filter_quality_strings(all_strings)
            combined_symbols.update(quality_strings)
        
        # Filter symbols by quality
        filtered_symbols = self._filter_symbols(
            combined_symbols, 
            min_confidence=min_confidence
        )
        
        # Check minimum symbol requirement
        if len(filtered_symbols) < min_symbols:
            logger.warning(
                f"Only {len(filtered_symbols)} symbols found, "
                f"minimum required: {min_symbols}"
            )
        
        # Build signature
        # Generate TLSH hash from the filtered symbols
        tlsh_hash = None
        if self.tlsh_hasher.enabled and filtered_symbols:
            tlsh_hash = self.tlsh_hasher.hash_features(list(filtered_symbols))
            if tlsh_hash:
                logger.info(f"Generated TLSH hash for signature: {tlsh_hash[:16]}...")
        
        signature = {
            "publisher": publisher,
            "updated": datetime.now().strftime("%Y-%m-%d"),
            "package": package_name,
            "version": version,
            "license": license_name,
            "ecosystem": ecosystem,
            "description": description or f"Auto-generated signature for {package_name}",
            "symbols": sorted(list(filtered_symbols)),
            "metadata": {
                "signature_type": "auto-generated",
                "generator_version": "1.1.0",
                "files_processed": files_processed,
                "generation_date": datetime.now().isoformat(),
                "generation_options": {
                    "min_confidence": min_confidence,
                    "min_symbols": min_symbols,
                    "include_strings": include_strings,
                    "include_constants": include_constants,
                    "include_functions": include_functions,
                    "include_imports": include_imports,
                    "recursive": recursive
                },
                "statistics": {
                    "total_symbols": len(combined_symbols),
                    "filtered_symbols": len(filtered_symbols),
                    "functions": len(all_functions),
                    "constants": len(all_constants),
                    "imports": len(all_imports),
                    "strings": len(all_strings)
                }
            }
        }
        
        # Add TLSH hash if available
        if tlsh_hash:
            signature["tlsh_hash"] = tlsh_hash
        
        logger.info(
            f"Generated signature with {len(filtered_symbols)} symbols "
            f"from {files_processed} files"
        )
        
        return signature
    
    def save_signature(self, signature: Dict[str, Any], output_path: Path):
        """
        Save signature to JSON file.
        
        Args:
            signature: Signature dictionary
            output_path: Path to save JSON file
        """
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(signature, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Signature saved to {output_path}")
    
    def validate_signature(
        self, 
        signature: Dict[str, Any], 
        test_paths: List[Path] = None
    ) -> Dict[str, Any]:
        """
        Validate generated signature quality.
        
        Args:
            signature: Signature to validate
            test_paths: Optional paths to test signature against
            
        Returns:
            Validation results
        """
        results = {
            "valid": True,
            "warnings": [],
            "errors": [],
            "metrics": {}
        }
        
        # Check required fields
        required_fields = ["publisher", "package", "symbols"]
        for field in required_fields:
            if not signature.get(field):
                results["errors"].append(f"Missing required field: {field}")
                results["valid"] = False
        
        # Check symbol quality
        symbols = signature.get("symbols", [])
        if len(symbols) < 3:
            results["warnings"].append(f"Only {len(symbols)} symbols, consider minimum 3")
        
        # Check for very generic symbols
        generic_symbols = ["init", "main", "test", "data", "value", "result"]
        generic_count = sum(1 for s in symbols if s.lower() in generic_symbols)
        if generic_count > len(symbols) * 0.5:
            results["warnings"].append(
                f"{generic_count} generic symbols found, "
                "consider more specific identifiers"
            )
        
        # Metrics
        results["metrics"] = {
            "symbol_count": len(symbols),
            "avg_symbol_length": sum(len(s) for s in symbols) / len(symbols) if symbols else 0,
            "unique_prefixes": len(set(s[:3] for s in symbols if len(s) >= 3)),
            "generic_ratio": generic_count / len(symbols) if symbols else 0
        }
        
        # Test against files if provided
        if test_paths:
            test_results = self._test_signature(signature, test_paths)
            results["test_results"] = test_results
        
        return results
    
    def _filter_symbols(self, symbols: Set[str], min_confidence: float) -> List[str]:
        """Filter symbols by quality and confidence"""
        filtered = []
        
        for symbol in symbols:
            # Skip very short or very long symbols
            if len(symbol) < 3 or len(symbol) > 100:
                continue
            
            # Skip common generic terms
            if symbol.lower() in ['main', 'init', 'test', 'data', 'null', 'true', 'false']:
                continue
            
            # Skip pure numbers
            if symbol.isdigit():
                continue
            
            # Calculate basic confidence score
            confidence = self._calculate_symbol_confidence(symbol)
            if confidence >= min_confidence:
                filtered.append(symbol)
        
        return filtered
    
    def _calculate_symbol_confidence(self, symbol: str) -> float:
        """Calculate confidence score for a symbol"""
        score = 0.5  # Base score
        
        # Longer symbols are generally more specific
        if len(symbol) > 10:
            score += 0.2
        elif len(symbol) > 6:
            score += 0.1
        
        # CamelCase or snake_case suggests intentional naming
        if any(c.isupper() for c in symbol[1:]) or '_' in symbol:
            score += 0.2
        
        # Contains numbers suggests versioning or specific identifiers
        if any(c.isdigit() for c in symbol):
            score += 0.1
        
        # Starts with uppercase (class names, constants)
        if symbol[0].isupper():
            score += 0.1
        
        return min(score, 1.0)
    
    def _filter_quality_strings(self, strings: Set[str]) -> Set[str]:
        """Filter string literals for high-quality identifiers"""
        filtered = set()
        
        for string in strings:
            # Skip very common strings
            if string in ['true', 'false', 'null', 'undefined', 'error', 'success']:
                continue
            
            # Skip URLs and file paths
            if any(x in string.lower() for x in ['http', '.com', '.org', '/', '\\']):
                continue
            
            # Skip log messages and user text
            if any(x in string.lower() for x in ['error:', 'warning:', 'info:', 'debug:']):
                continue
            
            # Include if looks like identifier or version string
            if (string.replace('.', '').replace('_', '').replace('-', '').isalnum() and
                not string.isdigit()):
                filtered.add(string)
        
        return filtered
    
    def _test_signature(self, signature: Dict[str, Any], test_paths: List[Path]) -> Dict[str, Any]:
        """Test signature against provided files"""
        symbols = set(signature.get("symbols", []))
        results = {
            "files_tested": 0,
            "symbols_found": 0,
            "match_rate": 0.0,
            "file_matches": []
        }
        
        for test_path in test_paths:
            if not test_path.exists():
                continue
            
            try:
                features = self.extractor_factory.extract(test_path)
                all_extracted = set()
                all_extracted.update(features.functions)
                all_extracted.update(features.constants)
                all_extracted.update(features.imports)
                all_extracted.update(features.symbols)
                all_extracted.update(features.strings)
                
                matches = symbols.intersection(all_extracted)
                
                results["file_matches"].append({
                    "file": str(test_path),
                    "matches": len(matches),
                    "total_symbols": len(symbols),
                    "match_rate": len(matches) / len(symbols) if symbols else 0
                })
                
                results["files_tested"] += 1
                results["symbols_found"] += len(matches)
                
            except Exception as e:
                logger.debug(f"Error testing against {test_path}: {e}")
        
        if results["files_tested"] > 0:
            results["match_rate"] = results["symbols_found"] / (len(symbols) * results["files_tested"])
        
        return results