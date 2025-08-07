"""
CycloneDX SBOM formatter for BinarySniffer analysis results.

Exports analysis results in CycloneDX format for integration with
security and compliance toolchains.
"""

import json
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import hashlib

from ..core.results import AnalysisResult, ComponentMatch, BatchAnalysisResult
from .. import __version__


class CycloneDxFormatter:
    """Format analysis results as CycloneDX SBOM"""
    
    SPEC_VERSION = "1.5"
    
    def __init__(self):
        self.serial_number = f"urn:uuid:{uuid.uuid4()}"
    
    def format_results(
        self,
        results: BatchAnalysisResult,
        format_type: str = "json",
        include_evidence: bool = True,
        include_features: bool = False
    ) -> str:
        """
        Format analysis results as CycloneDX SBOM.
        
        Args:
            results: Batch analysis results to format
            format_type: Output format ('json' or 'xml' - only json supported currently)
            include_evidence: Include detection evidence in SBOM
            include_features: Include extracted features for signature recreation
            
        Returns:
            Formatted SBOM string
        """
        if format_type == "json":
            return self._format_json(results, include_evidence, include_features)
        else:
            raise ValueError(f"Format type '{format_type}' not supported. Use 'json'.")
    
    def _format_json(
        self,
        batch_result: BatchAnalysisResult,
        include_evidence: bool,
        include_features: bool
    ) -> str:
        """Generate CycloneDX JSON format"""
        
        # Build SBOM structure
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": self.SPEC_VERSION,
            "serialNumber": self.serial_number,
            "version": 1,
            "metadata": self._create_metadata(batch_result),
            "components": []
        }
        
        # Track unique components across all files
        seen_components = {}
        
        # Process each file's results
        for file_path, result in batch_result.results.items():
            if result.error:
                continue
                
            # Add components from this file
            for match in result.matches:
                comp_key = self._get_component_key(match)
                
                if comp_key not in seen_components:
                    # First time seeing this component
                    component = self._create_component(match, result, include_evidence)
                    seen_components[comp_key] = component
                    sbom["components"].append(component)
                else:
                    # Component already exists, add this occurrence
                    self._add_occurrence(seen_components[comp_key], match, result)
        
        # Add dependencies if we can infer them
        if self._has_dependencies(batch_result):
            sbom["dependencies"] = self._create_dependencies(sbom["components"])
        
        # Add extracted features if requested (for signature recreation)
        if include_features:
            sbom["annotations"] = self._create_feature_annotations(batch_result)
        
        return json.dumps(sbom, indent=2, default=str)
    
    def _create_metadata(self, batch_result: BatchAnalysisResult) -> Dict[str, Any]:
        """Create SBOM metadata section"""
        metadata = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "BinarySniffer",
                    "name": "binarysniffer",
                    "version": __version__
                }
            ],
            "authors": [
                {
                    "name": "BinarySniffer Analysis"
                }
            ]
        }
        
        # If analyzing a single file, make it the primary component
        if len(batch_result.results) == 1:
            file_path = list(batch_result.results.keys())[0]
            result = batch_result.results[file_path]
            
            metadata["component"] = {
                "type": self._get_component_type(result.file_type),
                "name": Path(file_path).name,
                "bom-ref": f"target-{self._sanitize_ref(file_path)}"
            }
            
            # Add hashes if available
            if result.file_hashes:
                metadata["component"]["hashes"] = self._format_hashes(result.file_hashes)
        
        # Add properties for analysis statistics
        metadata["properties"] = [
            {
                "name": "binarysniffer:total_files",
                "value": str(batch_result.total_files)
            },
            {
                "name": "binarysniffer:total_matches",
                "value": str(batch_result.total_matches)
            },
            {
                "name": "binarysniffer:analysis_time",
                "value": f"{batch_result.total_time:.2f}s"
            }
        ]
        
        return metadata
    
    def _create_component(
        self,
        match: ComponentMatch,
        result: AnalysisResult,
        include_evidence: bool
    ) -> Dict[str, Any]:
        """Create a CycloneDX component from a match"""
        
        # Generate component reference
        bom_ref = self._generate_bom_ref(match)
        
        component = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": match.name,
            "publisher": match.evidence.get('publisher', 'Unknown')
        }
        
        # Add version if available
        if match.version and match.version != 'unknown':
            component["version"] = match.version
        
        # Add license
        if match.license:
            component["licenses"] = [
                {
                    "license": {
                        "name": match.license
                    }
                }
            ]
        
        # Add purl if we can generate one
        purl = self._generate_purl(match)
        if purl:
            component["purl"] = purl
        
        # Add evidence/confidence
        if include_evidence:
            component["evidence"] = {
                "confidence": match.confidence,
                "occurrences": [
                    {
                        "location": match.evidence.get('file_path', result.file_path),
                        "evidence": self._format_evidence(match)
                    }
                ]
            }
        
        # Add properties for additional metadata
        properties = []
        
        properties.append({
            "name": "binarysniffer:confidence",
            "value": f"{match.confidence:.3f}"
        })
        
        properties.append({
            "name": "binarysniffer:match_type",
            "value": match.match_type
        })
        
        if 'signatures_matched' in match.evidence:
            properties.append({
                "name": "binarysniffer:signatures_matched",
                "value": str(match.evidence['signatures_matched'])
            })
        
        if 'tlsh_distance' in match.evidence:
            properties.append({
                "name": "binarysniffer:tlsh_distance",
                "value": str(match.evidence['tlsh_distance'])
            })
        
        component["properties"] = properties
        
        return component
    
    def _add_occurrence(
        self,
        component: Dict[str, Any],
        match: ComponentMatch,
        result: AnalysisResult
    ):
        """Add another occurrence to an existing component"""
        if "evidence" in component and "occurrences" in component["evidence"]:
            # Add new occurrence
            component["evidence"]["occurrences"].append({
                "location": match.evidence.get('file_path', result.file_path),
                "evidence": self._format_evidence(match)
            })
            
            # Update confidence if this one is higher
            if match.confidence > component["evidence"]["confidence"]:
                component["evidence"]["confidence"] = match.confidence
    
    def _format_evidence(self, match: ComponentMatch) -> str:
        """Format match evidence as a string"""
        parts = []
        
        if 'signatures_matched' in match.evidence:
            parts.append(f"{match.evidence['signatures_matched']} patterns matched")
        
        if 'match_method' in match.evidence:
            parts.append(f"via {match.evidence['match_method']}")
        
        if 'tlsh_distance' in match.evidence:
            parts.append(f"TLSH distance: {match.evidence['tlsh_distance']}")
        
        if 'matched_patterns' in match.evidence and match.evidence['matched_patterns']:
            # Include a sample of matched patterns
            sample_patterns = match.evidence['matched_patterns'][:3]
            patterns_str = ', '.join(p.get('signature', '')[:30] for p in sample_patterns)
            parts.append(f"patterns: {patterns_str}...")
        
        return "; ".join(parts) if parts else "Component detected"
    
    def _format_hashes(self, file_hashes: Dict[str, str]) -> List[Dict[str, str]]:
        """Format file hashes for CycloneDX"""
        hashes = []
        
        # Map our hash names to CycloneDX algorithm names
        hash_mapping = {
            'md5': 'MD5',
            'sha1': 'SHA-1',
            'sha256': 'SHA-256',
            'sha512': 'SHA-512',
            'tlsh': 'TLSH',
            'ssdeep': 'SSDEEP'
        }
        
        for hash_type, hash_value in file_hashes.items():
            if hash_type in hash_mapping:
                hashes.append({
                    "alg": hash_mapping[hash_type],
                    "content": hash_value
                })
        
        return hashes
    
    def _generate_bom_ref(self, match: ComponentMatch) -> str:
        """Generate a unique BOM reference for a component"""
        # Use component name and version for uniqueness
        ref_base = f"{match.name}@{match.version or 'unknown'}"
        return f"pkg:{self._sanitize_ref(ref_base)}"
    
    def _generate_purl(self, match: ComponentMatch) -> Optional[str]:
        """Generate Package URL (purl) if possible"""
        ecosystem = match.ecosystem.lower()
        name = match.name.lower().replace(' ', '-')
        version = match.version if match.version and match.version != 'unknown' else None
        
        # Map ecosystems to purl types
        if ecosystem == 'maven':
            # Assume group ID from name if it contains dots
            if '.' in name:
                parts = name.split('.')
                group = '.'.join(parts[:-1])
                artifact = parts[-1]
            else:
                group = 'unknown'
                artifact = name
            
            purl = f"pkg:maven/{group}/{artifact}"
            if version:
                purl += f"@{version}"
            return purl
            
        elif ecosystem == 'npm':
            purl = f"pkg:npm/{name}"
            if version:
                purl += f"@{version}"
            return purl
            
        elif ecosystem == 'pypi':
            purl = f"pkg:pypi/{name}"
            if version:
                purl += f"@{version}"
            return purl
            
        elif ecosystem in ('native', 'c', 'cpp'):
            # Generic for native libraries
            purl = f"pkg:generic/{name}"
            if version:
                purl += f"@{version}"
            return purl
        
        return None
    
    def _get_component_key(self, match: ComponentMatch) -> str:
        """Get a unique key for a component"""
        return f"{match.name}@{match.version or 'unknown'}@{match.ecosystem}"
    
    def _get_component_type(self, file_type: str) -> str:
        """Map file type to CycloneDX component type"""
        type_mapping = {
            'android': 'application',
            'ios': 'application',
            'apk': 'application',
            'ipa': 'application',
            'jar': 'library',
            'war': 'application',
            'ear': 'application',
            'binary': 'library',
            'source': 'library',
            'archive': 'library'
        }
        
        return type_mapping.get(file_type, 'library')
    
    def _sanitize_ref(self, ref: str) -> str:
        """Sanitize a string for use as a BOM reference"""
        # Replace problematic characters
        sanitized = ref.replace('/', '-').replace('\\', '-').replace(' ', '-')
        sanitized = sanitized.replace('@', '-').replace('#', '-')
        return sanitized.lower()
    
    def _has_dependencies(self, batch_result: BatchAnalysisResult) -> bool:
        """Check if we have enough information to infer dependencies"""
        # For now, we don't infer dependencies
        # This could be enhanced in the future
        return False
    
    def _create_dependencies(self, components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create dependency relationships"""
        # Placeholder for future dependency inference
        dependencies = []
        
        for component in components:
            dependencies.append({
                "ref": component["bom-ref"],
                "dependsOn": []
            })
        
        return dependencies
    
    def _create_feature_annotations(self, batch_result: BatchAnalysisResult) -> List[Dict[str, Any]]:
        """
        Create annotations containing extracted features for signature recreation.
        This allows users to understand what was detected and potentially create
        new signatures.
        """
        annotations = []
        
        for file_path, result in batch_result.results.items():
            if result.error or not result.extracted_features:
                continue
            
            # Create annotation with extracted features
            annotation = {
                "bom-ref": f"features-{self._sanitize_ref(file_path)}",
                "subjects": [f"target-{self._sanitize_ref(file_path)}"],
                "annotator": {
                    "name": "binarysniffer",
                    "version": __version__
                },
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "text": f"Extracted {result.features_extracted} features from {Path(file_path).name}"
            }
            
            # Add sample features if available
            if result.extracted_features and result.extracted_features.by_extractor:
                features_data = {
                    "total_features": result.features_extracted,
                    "extractors": {}
                }
                
                for extractor_name, extractor_data in result.extracted_features.by_extractor.items():
                    if 'features_by_type' in extractor_data:
                        # Include a sample of features
                        sample = {}
                        for feature_type, features in extractor_data['features_by_type'].items():
                            if features:
                                # Include first 10 features of each type
                                sample[feature_type] = features[:10]
                        
                        if sample:
                            features_data["extractors"][extractor_name] = sample
                
                # Store as JSON in annotation
                annotation["data"] = json.dumps(features_data, indent=2)
            
            annotations.append(annotation)
        
        return annotations