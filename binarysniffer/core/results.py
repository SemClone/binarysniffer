"""
Result classes for analysis output
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
import json


@dataclass
class ComponentMatch:
    """Represents a matched OSS component"""
    
    component: str  # e.g., "ffmpeg@4.4.0"
    ecosystem: str  # e.g., "native", "npm", "maven"
    confidence: float  # 0.0 to 1.0
    license: Optional[str] = None
    match_type: str = "unknown"  # string, function, constant, pattern
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def name(self) -> str:
        """Extract component name without version"""
        if '@' in self.component:
            return self.component.split('@')[0]
        return self.component
    
    @property
    def version(self) -> Optional[str]:
        """Extract version if present"""
        if '@' in self.component:
            return self.component.split('@')[1]
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "component": self.component,
            "ecosystem": self.ecosystem,
            "confidence": round(self.confidence, 4),
            "license": self.license,
            "match_type": self.match_type,
            "evidence": self.evidence
        }


@dataclass
class ExtractedFeaturesSummary:
    """Summary of extracted features for debugging"""
    total_count: int
    by_extractor: Dict[str, Dict[str, Any]]  # extractor_name -> {count, features_by_type}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_count": self.total_count,
            "by_extractor": self.by_extractor
        }


@dataclass
class AnalysisResult:
    """Results from analyzing a single file"""
    
    file_path: str
    file_size: int
    file_type: str
    matches: List[ComponentMatch]
    analysis_time: float  # seconds
    features_extracted: int
    confidence_threshold: float
    error: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    extracted_features: Optional[ExtractedFeaturesSummary] = None  # For --show-features flag
    file_hashes: Optional[Dict[str, str]] = None  # For --include-hashes flag
    
    @property
    def has_matches(self) -> bool:
        """Check if any matches were found"""
        return len(self.matches) > 0
    
    @property
    def high_confidence_matches(self) -> List[ComponentMatch]:
        """Get matches with confidence >= 0.8"""
        return [m for m in self.matches if m.confidence >= 0.8]
    
    @property
    def unique_components(self) -> List[str]:
        """Get unique component names"""
        return list(set(m.component for m in self.matches))
    
    @property
    def licenses(self) -> List[str]:
        """Get all detected licenses"""
        licenses = [m.license for m in self.matches if m.license]
        return list(set(licenses))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "file_type": self.file_type,
            "matches": [m.to_dict() for m in self.matches],
            "analysis_time": round(self.analysis_time, 3),
            "features_extracted": self.features_extracted,
            "confidence_threshold": self.confidence_threshold,
            "error": self.error,
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "total_matches": len(self.matches),
                "high_confidence_matches": len(self.high_confidence_matches),
                "unique_components": len(self.unique_components),
                "licenses": self.licenses
            }
        }
        
        # Add extracted features if present
        if self.extracted_features:
            result["extracted_features"] = self.extracted_features.to_dict()
        
        # Add file hashes if present
        if self.file_hashes:
            result["file_hashes"] = self.file_hashes
        
        return result
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def create_error(cls, file_path: str, error_message: str) -> "AnalysisResult":
        """Create an error result"""
        return cls(
            file_path=file_path,
            file_size=0,
            file_type="unknown",
            matches=[],
            analysis_time=0.0,
            features_extracted=0,
            confidence_threshold=0.0,
            error=error_message
        )


@dataclass
class BatchAnalysisResult:
    """Results from analyzing multiple files"""
    
    results: Dict[str, AnalysisResult]
    total_files: int
    successful_files: int
    failed_files: int
    total_time: float
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def total_matches(self) -> int:
        """Get total number of matches across all files"""
        total = 0
        for result in self.results.values():
            if not result.error:
                total += len(result.matches)
        return total
    
    @property
    def all_components(self) -> List[str]:
        """Get all unique components found"""
        components = set()
        for result in self.results.values():
            if not result.error:
                components.update(result.unique_components)
        return sorted(list(components))
    
    @property
    def all_licenses(self) -> List[str]:
        """Get all unique licenses found"""
        licenses = set()
        for result in self.results.values():
            if not result.error:
                licenses.update(result.licenses)
        return sorted(list(licenses))
    
    @property
    def component_frequency(self) -> Dict[str, int]:
        """Get frequency of each component"""
        freq = {}
        for result in self.results.values():
            if not result.error:
                for component in result.unique_components:
                    freq[component] = freq.get(component, 0) + 1
        return dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "results": {
                path: result.to_dict() 
                for path, result in self.results.items()
            },
            "summary": {
                "total_files": self.total_files,
                "successful_files": self.successful_files,
                "failed_files": self.failed_files,
                "total_time": round(self.total_time, 3),
                "timestamp": self.timestamp.isoformat(),
                "all_components": self.all_components,
                "all_licenses": self.all_licenses,
                "component_frequency": self.component_frequency
            }
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_results(cls, results: Dict[str, AnalysisResult], total_time: float) -> "BatchAnalysisResult":
        """Create from analysis results"""
        successful = sum(1 for r in results.values() if not r.error)
        failed = sum(1 for r in results.values() if r.error)
        
        return cls(
            results=results,
            total_files=len(results),
            successful_files=successful,
            failed_files=failed,
            total_time=total_time
        )