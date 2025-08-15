"""
Risk Scoring Engine for ML Model Security Analysis

This module calculates risk scores based on detected threats,
patterns, and behavioral indicators.
"""

from typing import List, Dict, Set, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

from .patterns import MaliciousPatterns, ThreatPattern, ThreatSeverity

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Overall risk assessment levels"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MALFORMED = "MALFORMED"


@dataclass
class SecurityIndicator:
    """Represents a security finding"""
    type: str
    severity: ThreatSeverity
    detail: str
    location: str
    mitre_technique: str = ""
    confidence: float = 1.0


@dataclass
class RiskAssessment:
    """Complete risk assessment for a model"""
    score: int  # 0-100
    level: RiskLevel
    summary: str
    indicators: List[SecurityIndicator] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "risk_assessment": {
                "score": self.score,
                "level": self.level.value,
                "summary": self.summary
            },
            "indicators": [
                {
                    "type": ind.type,
                    "severity": ind.severity.value,
                    "detail": ind.detail,
                    "location": ind.location,
                    "mitre": ind.mitre_technique,
                    "confidence": ind.confidence
                }
                for ind in self.indicators
            ],
            "recommendations": self.recommendations,
            "metadata": self.metadata
        }


class RiskScorer:
    """
    Risk scoring engine that analyzes extracted features
    and calculates comprehensive risk assessment.
    """
    
    # Severity score weights
    SEVERITY_SCORES = {
        ThreatSeverity.CRITICAL: 40,
        ThreatSeverity.HIGH: 25,
        ThreatSeverity.MEDIUM: 15,
        ThreatSeverity.LOW: 5,
        ThreatSeverity.INFO: 1
    }
    
    # Risk level thresholds
    RISK_THRESHOLDS = {
        RiskLevel.CRITICAL: 80,
        RiskLevel.HIGH: 60,
        RiskLevel.MEDIUM: 40,
        RiskLevel.LOW: 20,
        RiskLevel.SAFE: 0
    }
    
    def __init__(self):
        """Initialize risk scorer"""
        self.patterns = MaliciousPatterns()
    
    def calculate_risk(self, 
                      features: Set[str],
                      file_path: str = "",
                      metadata: Dict[str, Any] = None) -> RiskAssessment:
        """
        Calculate comprehensive risk assessment for extracted features
        
        Args:
            features: Set of extracted feature strings
            file_path: Path to the analyzed file
            metadata: Additional metadata about the file
            
        Returns:
            Complete risk assessment
        """
        indicators = []
        risk_score = 0
        threat_categories = set()
        metadata = metadata or {}
        
        # Check for malformed file indicators
        if self._is_malformed(features):
            return self._create_malformed_assessment(features, file_path)
        
        # Analyze features for threats
        for feature in features:
            feature_indicators = self._analyze_feature(feature, file_path)
            indicators.extend(feature_indicators)
            
            for indicator in feature_indicators:
                # Add to risk score
                risk_score += self.SEVERITY_SCORES.get(indicator.severity, 0)
                threat_categories.add(indicator.type)
        
        # Check for specific high-risk patterns
        if self._has_code_execution(features):
            risk_score += 20
            
        if self._has_network_exfiltration(features):
            risk_score += 15
            
        if self._has_obfuscation(features):
            risk_score += 10
            
        if self._has_persistence(features):
            risk_score += 15
        
        # Apply multipliers for combined threats
        if len(threat_categories) >= 3:
            risk_score = int(risk_score * 1.2)
            
        if "code_execution" in threat_categories and "network" in threat_categories:
            risk_score = int(risk_score * 1.3)
        
        # Cap at 100
        risk_score = min(risk_score, 100)
        
        # Determine risk level
        risk_level = self._calculate_risk_level(risk_score)
        
        # Generate summary
        summary = self._generate_summary(risk_level, threat_categories, len(indicators))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_level, threat_categories, indicators)
        
        # Add metadata
        metadata.update({
            "threat_categories": list(threat_categories),
            "total_indicators": len(indicators),
            "file_path": file_path
        })
        
        return RiskAssessment(
            score=risk_score,
            level=risk_level,
            summary=summary,
            indicators=indicators,
            recommendations=recommendations,
            metadata=metadata
        )
    
    def _analyze_feature(self, feature: str, file_path: str) -> List[SecurityIndicator]:
        """Analyze a single feature for threats"""
        indicators = []
        
        # Check against malicious patterns
        matches = MaliciousPatterns.check_pattern(feature)
        
        for pattern, position in matches:
            indicator = SecurityIndicator(
                type=pattern.category,
                severity=pattern.severity,
                detail=pattern.description,
                location=f"{file_path}:feature:{feature[:50]}",
                mitre_technique=pattern.mitre_technique
            )
            indicators.append(indicator)
        
        # Check for specific pickle threats
        if "pickle" in feature.lower():
            if any(danger in feature.lower() for danger in ["exec", "eval", "system", "__reduce__"]):
                indicators.append(SecurityIndicator(
                    type="pickle_exploit",
                    severity=ThreatSeverity.CRITICAL,
                    detail="Pickle arbitrary code execution pattern",
                    location=f"{file_path}:pickle",
                    mitre_technique="T1203"
                ))
        
        # Check for suspicious opcodes
        if "opcode:" in feature:
            opcode = feature.split("opcode:")[-1].split()[0] if "opcode:" in feature else ""
            if opcode in ["GLOBAL", "REDUCE", "BUILD", "INST"]:
                if any(danger in feature for danger in ["os.system", "subprocess", "eval", "exec"]):
                    indicators.append(SecurityIndicator(
                        type="dangerous_opcode",
                        severity=ThreatSeverity.HIGH,
                        detail=f"Dangerous opcode with suspicious import: {opcode}",
                        location=f"{file_path}:opcode:{opcode}",
                        mitre_technique="T1027"
                    ))
        
        return indicators
    
    def _is_malformed(self, features: Set[str]) -> bool:
        """Check if file appears malformed"""
        malformed_indicators = [
            "pickle_parse_error",
            "malformed_pickle",
            "invalid_opcode",
            "corrupted_file",
            "invalid_format"
        ]
        return any(ind in str(features).lower() for ind in malformed_indicators)
    
    def _create_malformed_assessment(self, features: Set[str], file_path: str) -> RiskAssessment:
        """Create assessment for malformed file"""
        return RiskAssessment(
            score=0,
            level=RiskLevel.MALFORMED,
            summary="File appears to be malformed or corrupted",
            indicators=[
                SecurityIndicator(
                    type="malformed_file",
                    severity=ThreatSeverity.HIGH,
                    detail="File structure is invalid or corrupted",
                    location=file_path
                )
            ],
            recommendations=[
                "Do not load this file",
                "Verify file integrity",
                "Check for tampering or corruption"
            ],
            metadata={"malformed": True}
        )
    
    def _has_code_execution(self, features: Set[str]) -> bool:
        """Check for code execution capabilities"""
        exec_patterns = ["os.system", "subprocess", "eval", "exec", "__import__", "compile"]
        features_str = " ".join(features).lower()
        return any(pattern in features_str for pattern in exec_patterns)
    
    def _has_network_exfiltration(self, features: Set[str]) -> bool:
        """Check for network exfiltration capabilities"""
        network_patterns = ["socket", "urllib", "requests", "http", "ftp", "ssh", "telnet"]
        features_str = " ".join(features).lower()
        return any(pattern in features_str for pattern in network_patterns)
    
    def _has_obfuscation(self, features: Set[str]) -> bool:
        """Check for obfuscation techniques"""
        obfusc_patterns = ["base64", "zlib", "marshal", "codecs", "binascii", "xor", "rot13"]
        features_str = " ".join(features).lower()
        return any(pattern in features_str for pattern in obfusc_patterns)
    
    def _has_persistence(self, features: Set[str]) -> bool:
        """Check for persistence mechanisms"""
        persist_patterns = ["crontab", "systemctl", "rc.local", "registry", "schtasks", "launchctl"]
        features_str = " ".join(features).lower()
        return any(pattern in features_str for pattern in persist_patterns)
    
    def _calculate_risk_level(self, score: int) -> RiskLevel:
        """Calculate risk level from score"""
        if score >= self.RISK_THRESHOLDS[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.RISK_THRESHOLDS[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.RISK_THRESHOLDS[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif score >= self.RISK_THRESHOLDS[RiskLevel.LOW]:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _generate_summary(self, level: RiskLevel, categories: Set[str], indicator_count: int) -> str:
        """Generate risk summary"""
        if level == RiskLevel.CRITICAL:
            return f"CRITICAL: Malicious code detected ({indicator_count} indicators)"
        elif level == RiskLevel.HIGH:
            return f"HIGH RISK: Suspicious patterns detected in {len(categories)} categories"
        elif level == RiskLevel.MEDIUM:
            return f"MEDIUM RISK: Potentially unsafe patterns found"
        elif level == RiskLevel.LOW:
            return f"LOW RISK: Minor security concerns identified"
        elif level == RiskLevel.MALFORMED:
            return "MALFORMED: File structure is invalid"
        else:
            return "SAFE: No significant security issues detected"
    
    def _generate_recommendations(self, level: RiskLevel, categories: Set[str], 
                                 indicators: List[SecurityIndicator]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("DO NOT LOAD this model without sandboxing")
            recommendations.append("Verify the source and integrity of this model")
            
        if "code_execution" in categories:
            recommendations.append("Model contains code execution capabilities - use SafeTensors format instead")
            
        if "network" in categories:
            recommendations.append("Model has network capabilities - monitor for data exfiltration")
            
        if "obfuscation" in categories:
            recommendations.append("Obfuscation detected - may be hiding malicious behavior")
            
        if level == RiskLevel.MEDIUM:
            recommendations.append("Review detected patterns before loading")
            recommendations.append("Consider using a sandboxed environment")
            
        if level == RiskLevel.LOW:
            recommendations.append("Monitor model behavior during execution")
            
        if level == RiskLevel.SAFE:
            recommendations.append("Model appears safe for use")
            
        # Add specific mitigations for critical indicators
        for indicator in indicators:
            if indicator.severity == ThreatSeverity.CRITICAL:
                if "pickle" in indicator.type:
                    recommendations.append("Convert to SafeTensors format to eliminate pickle risks")
                if "shell" in indicator.type:
                    recommendations.append("Potential reverse shell - block network access")
                    
        return list(set(recommendations))  # Remove duplicates