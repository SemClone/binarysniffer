"""
BinarySniffer Security Module for ML Model Threat Detection

This module provides comprehensive security analysis for ML models,
detecting malicious code, backdoors, and supply chain attacks.
"""

from .patterns import MaliciousPatterns
from .risk_scorer import RiskScorer, RiskAssessment
from .pickle_analyzer import PickleSecurityAnalyzer
from .obfuscation import ObfuscationDetector
from .validators import ModelIntegrityValidator

__all__ = [
    'MaliciousPatterns',
    'RiskScorer',
    'RiskAssessment',
    'PickleSecurityAnalyzer',
    'ObfuscationDetector',
    'ModelIntegrityValidator'
]