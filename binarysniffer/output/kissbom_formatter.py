"""
KISS BOM (Keep It Simple Software Bill of Materials) formatter.

Provides a lightweight, human-readable SBOM format that's easy to understand
and parse without complex specifications.
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..core.results import AnalysisResult, ComponentMatch
from .. import __version__


class KissBomFormatter:
    """Format analysis results as KISS BOM."""
    
    def format_results(self, 
                      results: List[AnalysisResult], 
                      format_type: str = "json",
                      include_optional: bool = False) -> str:
        """
        Format results as KISS BOM.
        
        Args:
            results: List of analysis results
            format_type: Output format ("json" or "table")
            include_optional: Include optional fields
            
        Returns:
            Formatted KISS BOM string
        """
        if not results:
            return self._empty_result(format_type)
        
        if format_type == "json":
            return self._format_json(results, include_optional)
        elif format_type == "table":
            return self._format_table(results)
        else:
            raise ValueError(f"Unknown KISS BOM format: {format_type}")
    
    def _empty_result(self, format_type: str) -> str:
        """Return empty result in requested format."""
        if format_type == "json":
            return json.dumps({
                "spec": "kissbom",
                "version": "0.1.0",
                "created": datetime.utcnow().isoformat() + "Z",
                "tool": {
                    "name": "binarysniffer",
                    "version": __version__
                },
                "components": [],
                "summary": {
                    "total_components": 0
                }
            }, indent=2)
        else:
            return "# No components detected"
    
    def _format_json(self, results: List[AnalysisResult], include_optional: bool = False) -> str:
        """Format as JSON KISS BOM."""
        # Single file or multiple files?
        if len(results) == 1:
            kissbom = self._single_file_json(results[0], include_optional)
        else:
            kissbom = self._multi_file_json(results, include_optional)
        
        return json.dumps(kissbom, indent=2, default=str)
    
    def _single_file_json(self, result: AnalysisResult, include_optional: bool) -> Dict[str, Any]:
        """Create KISS BOM for single file."""
        file_path = Path(result.file_path)
        
        # Calculate file hash if file exists
        file_hash = None
        file_size = None
        if file_path.exists():
            try:
                file_size = file_path.stat().st_size
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
            except Exception:
                pass
        
        # Build component list
        components = []
        licenses = set()
        high_confidence = 0
        
        for match in result.matches:
            licenses.add(match.license or "Unknown")
            if match.confidence >= 0.8:
                high_confidence += 1
            
            # Extract evidence count from evidence dict if available
            evidence_count = len(match.evidence.get('matched_patterns', [])) if match.evidence else 0
            if evidence_count == 0 and hasattr(match, 'evidence_count'):
                evidence_count = match.evidence_count
            
            component = {
                "name": match.component,
                "version": match.version or "unknown",
                "license": match.license or "Unknown",
                "confidence": round(match.confidence * 100, 1),
                "evidence": f"{evidence_count} patterns matched" if evidence_count else "patterns matched",
                "location": match.file_path if hasattr(match, 'file_path') else str(file_path.name)
            }
            
            # Add optional fields if requested
            if include_optional and hasattr(match, 'metadata') and match.metadata:
                component["optional"] = match.metadata
            
            components.append(component)
        
        kissbom = {
            "spec": "kissbom",
            "version": "0.1.0",
            "created": datetime.utcnow().isoformat() + "Z",
            "tool": {
                "name": "binarysniffer",
                "version": __version__
            },
            "target": {
                "name": str(file_path.name),
                "path": str(file_path),
            },
            "components": components,
            "summary": {
                "total_components": len(components),
                "high_confidence": high_confidence,
                "licenses": sorted(list(licenses)),
                "scan_time": f"{result.analysis_time:.2f}s" if hasattr(result, 'analysis_time') else "unknown"
            }
        }
        
        # Add file size and hash if available
        if file_size is not None:
            kissbom["target"]["size"] = file_size
        if file_hash:
            kissbom["target"]["hash"] = {"sha256": file_hash}
        
        return kissbom
    
    def _multi_file_json(self, results: List[AnalysisResult], include_optional: bool) -> Dict[str, Any]:
        """Create aggregated KISS BOM for multiple files."""
        all_components = {}
        all_licenses = set()
        targets = []
        total_scan_time = 0.0
        
        for result in results:
            file_path = Path(result.file_path)
            target_components = 0
            
            for match in result.matches:
                comp_key = (match.component, match.version or "unknown")
                if comp_key not in all_components:
                    all_components[comp_key] = {
                        "name": match.component,
                        "version": match.version or "unknown",
                        "license": match.license or "Unknown",
                        "confidence": match.confidence * 100,
                        "evidence": f"{match.evidence_count} patterns" if hasattr(match, 'evidence_count') else "patterns",
                        "locations": []
                    }
                
                all_components[comp_key]["locations"].append(str(file_path.name))
                all_licenses.add(match.license or "Unknown")
                target_components += 1
            
            targets.append({
                "name": str(file_path.name),
                "components": target_components
            })
            
            if hasattr(result, 'analysis_time'):
                total_scan_time += result.analysis_time
        
        # Count common components
        common_components = sum(1 for comp in all_components.values() if len(comp["locations"]) > 1)
        
        kissbom = {
            "spec": "kissbom",
            "version": "0.1.0",
            "created": datetime.utcnow().isoformat() + "Z",
            "tool": {
                "name": "binarysniffer",
                "version": __version__
            },
            "targets": targets,
            "all_components": list(all_components.values()),
            "summary": {
                "total_files": len(results),
                "total_components": len(all_components),
                "common_components": common_components,
                "licenses": sorted(list(all_licenses)),
                "total_scan_time": f"{total_scan_time:.2f}s"
            }
        }
        
        return kissbom
    
    def _format_table(self, results: List[AnalysisResult]) -> str:
        """Format as simple table."""
        lines = []
        
        # Header
        if len(results) == 1:
            file_path = Path(results[0].file_path)
            lines.extend([
                f"# KISS BOM for {file_path.name}",
                f"# Generated by binarysniffer {__version__} on {datetime.utcnow().strftime('%Y-%m-%d')}",
                ""
            ])
        else:
            lines.extend([
                f"# KISS BOM for {len(results)} files",
                f"# Generated by binarysniffer {__version__} on {datetime.utcnow().strftime('%Y-%m-%d')}",
                ""
            ])
        
        # Table header
        lines.extend([
            "Component              | Version | License      | Confidence | Location",
            "-----------------------|---------|--------------|------------|------------------"
        ])
        
        # Components
        total_components = 0
        all_licenses = set()
        
        for result in results:
            file_name = Path(result.file_path).name
            for match in result.matches:
                # Truncate component name if too long
                component_name = match.component
                if len(component_name) > 22:
                    component_name = component_name[:19] + "..."
                
                # Truncate version if too long
                version = match.version or "unknown"
                if len(version) > 7:
                    version = version[:4] + "..."
                
                # Truncate license if too long
                license_str = match.license or "Unknown"
                if len(license_str) > 12:
                    license_str = license_str[:9] + "..."
                
                # Format location
                location = match.file_path if hasattr(match, 'file_path') else file_name
                if len(location) > 18:
                    location = "..." + location[-15:]
                
                lines.append(
                    f"{component_name:22} | "
                    f"{version:7} | "
                    f"{license_str:12} | "
                    f"{match.confidence*100:6.1f}%    | "
                    f"{location}"
                )
                
                total_components += 1
                all_licenses.add(match.license or "Unknown")
        
        # Summary
        lines.extend([
            "",
            f"Total: {total_components} components found",
            f"Licenses: {', '.join(sorted(all_licenses))}"
        ])
        
        return "\n".join(lines)
    
    def format_file(self, result: AnalysisResult, output_path: Optional[Path] = None, 
                    format_type: str = "json", include_optional: bool = False) -> str:
        """
        Format and optionally save results for a single file.
        
        Args:
            result: Analysis result for a single file
            output_path: Optional path to save the output
            format_type: Output format ("json" or "table")
            include_optional: Include optional fields
            
        Returns:
            Formatted KISS BOM string
        """
        output = self.format_results([result], format_type, include_optional)
        
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(output)
            
        return output