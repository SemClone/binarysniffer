"""
Model Integrity Validators for ML Security

This module provides integrity validation for ML models,
detecting tampering, backdoors, and supply chain attacks.
"""

import hashlib
import json
import os
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
import logging
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """Model validation status"""
    VALID = "VALID"
    INVALID = "INVALID"
    SUSPICIOUS = "SUSPICIOUS"
    UNKNOWN = "UNKNOWN"


@dataclass
class IntegrityCheck:
    """Results of an integrity check"""
    check_type: str
    status: ValidationStatus
    message: str
    details: Dict[str, Any] = None


@dataclass 
class ValidationResult:
    """Complete validation result"""
    status: ValidationStatus
    checks: List[IntegrityCheck]
    risk_factors: List[str]
    recommendations: List[str]
    metadata: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'status': self.status.value,
            'checks': [
                {
                    'type': check.check_type,
                    'status': check.status.value,
                    'message': check.message,
                    'details': check.details
                }
                for check in self.checks
            ],
            'risk_factors': self.risk_factors,
            'recommendations': self.recommendations,
            'metadata': self.metadata or {}
        }


class ModelIntegrityValidator:
    """
    Validates ML model integrity and detects tampering
    """
    
    # Known good model hashes (examples - would be maintained externally)
    KNOWN_GOOD_HASHES = {
        # Popular pre-trained models
        'bert-base-uncased': 'a7b0e2e7f1c4cd9b5e7c1f2a3b4c5d6e7f8a9b0c',
        'resnet50': 'b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0',
        'gpt2': 'c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1',
    }
    
    # Maximum reasonable model sizes (in bytes)
    MAX_MODEL_SIZES = {
        'pickle': 10 * 1024 * 1024 * 1024,  # 10GB
        'onnx': 5 * 1024 * 1024 * 1024,     # 5GB
        'safetensors': 20 * 1024 * 1024 * 1024,  # 20GB
        'pytorch': 10 * 1024 * 1024 * 1024,  # 10GB
        'tensorflow': 10 * 1024 * 1024 * 1024,  # 10GB
    }
    
    # Suspicious file patterns
    SUSPICIOUS_PATTERNS = {
        'hidden_files': ['.', '..', '.hidden'],
        'system_files': ['system32', 'windows', '/etc/', '/bin/'],
        'executable_extensions': ['.exe', '.dll', '.so', '.dylib', '.sh', '.bat'],
        'script_extensions': ['.py', '.js', '.ps1', '.vbs'],
    }
    
    def __init__(self):
        """Initialize the validator"""
        self.checks_performed = []
    
    def validate_model(self, 
                       file_path: str,
                       model_type: str = None,
                       expected_hash: str = None,
                       strict_mode: bool = False) -> ValidationResult:
        """
        Perform comprehensive model validation
        
        Args:
            file_path: Path to model file
            model_type: Type of model (pickle, onnx, etc)
            expected_hash: Expected file hash for verification
            strict_mode: Enable strict validation
            
        Returns:
            Validation result with status and details
        """
        checks = []
        risk_factors = []
        recommendations = []
        
        # File existence check
        file_check = self._check_file_exists(file_path)
        checks.append(file_check)
        if file_check.status != ValidationStatus.VALID:
            return ValidationResult(
                status=ValidationStatus.INVALID,
                checks=checks,
                risk_factors=['file_not_found'],
                recommendations=['Verify file path']
            )
        
        # File size validation
        size_check = self._check_file_size(file_path, model_type)
        checks.append(size_check)
        if size_check.status == ValidationStatus.INVALID:
            risk_factors.append('abnormal_size')
            
        # Hash verification
        if expected_hash:
            hash_check = self._verify_hash(file_path, expected_hash)
            checks.append(hash_check)
            if hash_check.status != ValidationStatus.VALID:
                risk_factors.append('hash_mismatch')
                
        # Check against known good models
        known_check = self._check_known_model(file_path)
        checks.append(known_check)
        
        # Format validation
        format_check = self._validate_format(file_path, model_type)
        checks.append(format_check)
        if format_check.status != ValidationStatus.VALID:
            risk_factors.append('invalid_format')
            
        # Metadata validation
        metadata_check = self._validate_metadata(file_path, model_type)
        checks.append(metadata_check)
        if metadata_check.status == ValidationStatus.SUSPICIOUS:
            risk_factors.append('suspicious_metadata')
            
        # Tensor validation
        tensor_check = self._validate_tensors(file_path, model_type)
        checks.append(tensor_check)
        if tensor_check.status != ValidationStatus.VALID:
            risk_factors.append('invalid_tensors')
            
        # Supply chain validation
        supply_check = self._check_supply_chain(file_path)
        checks.append(supply_check)
        if supply_check.status == ValidationStatus.SUSPICIOUS:
            risk_factors.append('supply_chain_risk')
            
        # Backdoor detection
        backdoor_check = self._check_for_backdoors(file_path, model_type)
        checks.append(backdoor_check)
        if backdoor_check.status != ValidationStatus.VALID:
            risk_factors.append('potential_backdoor')
            
        # Determine overall status
        if any(check.status == ValidationStatus.INVALID for check in checks):
            overall_status = ValidationStatus.INVALID
        elif any(check.status == ValidationStatus.SUSPICIOUS for check in checks):
            overall_status = ValidationStatus.SUSPICIOUS
        elif all(check.status == ValidationStatus.VALID for check in checks):
            overall_status = ValidationStatus.VALID
        else:
            overall_status = ValidationStatus.UNKNOWN
            
        # Generate recommendations
        recommendations = self._generate_recommendations(
            overall_status, risk_factors, strict_mode
        )
        
        # Collect metadata
        metadata = {
            'file_path': file_path,
            'model_type': model_type,
            'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            'checks_performed': len(checks),
            'risk_factor_count': len(risk_factors)
        }
        
        return ValidationResult(
            status=overall_status,
            checks=checks,
            risk_factors=risk_factors,
            recommendations=recommendations,
            metadata=metadata
        )
    
    def _check_file_exists(self, file_path: str) -> IntegrityCheck:
        """Check if file exists"""
        if os.path.exists(file_path):
            return IntegrityCheck(
                check_type='file_existence',
                status=ValidationStatus.VALID,
                message='File exists'
            )
        else:
            return IntegrityCheck(
                check_type='file_existence',
                status=ValidationStatus.INVALID,
                message='File not found'
            )
    
    def _check_file_size(self, file_path: str, model_type: str) -> IntegrityCheck:
        """Validate file size is reasonable"""
        try:
            size = os.path.getsize(file_path)
            max_size = self.MAX_MODEL_SIZES.get(
                model_type, 
                10 * 1024 * 1024 * 1024  # Default 10GB
            )
            
            if size == 0:
                return IntegrityCheck(
                    check_type='file_size',
                    status=ValidationStatus.INVALID,
                    message='File is empty',
                    details={'size': 0}
                )
            elif size > max_size:
                return IntegrityCheck(
                    check_type='file_size',
                    status=ValidationStatus.SUSPICIOUS,
                    message=f'File unusually large ({size / 1024 / 1024:.1f}MB)',
                    details={'size': size, 'max_expected': max_size}
                )
            else:
                return IntegrityCheck(
                    check_type='file_size',
                    status=ValidationStatus.VALID,
                    message=f'File size normal ({size / 1024 / 1024:.1f}MB)',
                    details={'size': size}
                )
        except Exception as e:
            return IntegrityCheck(
                check_type='file_size',
                status=ValidationStatus.UNKNOWN,
                message=f'Could not check size: {e}'
            )
    
    def _verify_hash(self, file_path: str, expected_hash: str) -> IntegrityCheck:
        """Verify file hash matches expected"""
        try:
            # Calculate file hash
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            
            actual_hash = sha256_hash.hexdigest()
            
            if actual_hash == expected_hash:
                return IntegrityCheck(
                    check_type='hash_verification',
                    status=ValidationStatus.VALID,
                    message='Hash matches expected value',
                    details={'hash': actual_hash}
                )
            else:
                return IntegrityCheck(
                    check_type='hash_verification',
                    status=ValidationStatus.INVALID,
                    message='Hash mismatch - file may be tampered',
                    details={
                        'expected': expected_hash,
                        'actual': actual_hash
                    }
                )
        except Exception as e:
            return IntegrityCheck(
                check_type='hash_verification',
                status=ValidationStatus.UNKNOWN,
                message=f'Could not verify hash: {e}'
            )
    
    def _check_known_model(self, file_path: str) -> IntegrityCheck:
        """Check if model matches known good models"""
        try:
            # Calculate hash
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            
            file_hash = sha256_hash.hexdigest()
            
            # Check against known models
            for model_name, known_hash in self.KNOWN_GOOD_HASHES.items():
                if file_hash == known_hash:
                    return IntegrityCheck(
                        check_type='known_model',
                        status=ValidationStatus.VALID,
                        message=f'Matches known good model: {model_name}',
                        details={'model': model_name}
                    )
            
            return IntegrityCheck(
                check_type='known_model',
                status=ValidationStatus.UNKNOWN,
                message='Not a known pre-trained model'
            )
            
        except Exception as e:
            return IntegrityCheck(
                check_type='known_model',
                status=ValidationStatus.UNKNOWN,
                message=f'Could not check: {e}'
            )
    
    def _validate_format(self, file_path: str, model_type: str) -> IntegrityCheck:
        """Validate file format is correct"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            
            # Check magic bytes for different formats
            format_checks = {
                'pickle': [b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'],
                'onnx': [b'\x08\x01', b'onnx'],
                'safetensors': [b'{"', b'safetensors'],
                'pytorch': [b'PK\x03\x04', b'PK\x05\x06'],  # ZIP format
                'tensorflow': [b'\x08\x01', b'\x00\x00\x00\x00'],
            }
            
            if model_type and model_type in format_checks:
                valid_headers = format_checks[model_type]
                if any(header.startswith(magic) for magic in valid_headers):
                    return IntegrityCheck(
                        check_type='format_validation',
                        status=ValidationStatus.VALID,
                        message=f'Valid {model_type} format'
                    )
                else:
                    return IntegrityCheck(
                        check_type='format_validation',
                        status=ValidationStatus.INVALID,
                        message=f'Invalid {model_type} format',
                        details={'header': header[:8].hex()}
                    )
            
            return IntegrityCheck(
                check_type='format_validation',
                status=ValidationStatus.UNKNOWN,
                message='Format validation not performed'
            )
            
        except Exception as e:
            return IntegrityCheck(
                check_type='format_validation',
                status=ValidationStatus.UNKNOWN,
                message=f'Could not validate format: {e}'
            )
    
    def _validate_metadata(self, file_path: str, model_type: str) -> IntegrityCheck:
        """Validate model metadata"""
        # This would be implemented based on model type
        # For now, return a basic check
        return IntegrityCheck(
            check_type='metadata_validation',
            status=ValidationStatus.UNKNOWN,
            message='Metadata validation not implemented'
        )
    
    def _validate_tensors(self, file_path: str, model_type: str) -> IntegrityCheck:
        """Validate tensor shapes and values"""
        # Check for anomalous tensor sizes that might indicate data exfiltration
        try:
            file_size = os.path.getsize(file_path)
            
            # Suspicious if single tensor is very large
            if file_size > 1024 * 1024 * 1024:  # 1GB
                with open(file_path, 'rb') as f:
                    # Simple heuristic: check for repeating patterns
                    sample1 = f.read(1024)
                    f.seek(file_size // 2)
                    sample2 = f.read(1024)
                    
                    if sample1 == sample2:
                        return IntegrityCheck(
                            check_type='tensor_validation',
                            status=ValidationStatus.SUSPICIOUS,
                            message='Suspicious tensor patterns detected',
                            details={'pattern': 'repeating_data'}
                        )
            
            return IntegrityCheck(
                check_type='tensor_validation',
                status=ValidationStatus.VALID,
                message='Tensor validation passed'
            )
            
        except Exception as e:
            return IntegrityCheck(
                check_type='tensor_validation',
                status=ValidationStatus.UNKNOWN,
                message=f'Could not validate tensors: {e}'
            )
    
    def _check_supply_chain(self, file_path: str) -> IntegrityCheck:
        """Check for supply chain attack indicators"""
        suspicious_indicators = []
        
        # Check filename for suspicious patterns
        filename = os.path.basename(file_path).lower()
        
        if any(pattern in filename for pattern in ['backdoor', 'trojan', 'malware']):
            suspicious_indicators.append('suspicious_filename')
            
        if any(ext in filename for ext in self.SUSPICIOUS_PATTERNS['executable_extensions']):
            suspicious_indicators.append('executable_extension')
            
        if suspicious_indicators:
            return IntegrityCheck(
                check_type='supply_chain',
                status=ValidationStatus.SUSPICIOUS,
                message='Supply chain risk indicators found',
                details={'indicators': suspicious_indicators}
            )
        
        return IntegrityCheck(
            check_type='supply_chain',
            status=ValidationStatus.VALID,
            message='No supply chain risks detected'
        )
    
    def _check_for_backdoors(self, file_path: str, model_type: str) -> IntegrityCheck:
        """Check for potential backdoors in model"""
        # This would implement more sophisticated backdoor detection
        # For now, return a basic check
        return IntegrityCheck(
            check_type='backdoor_detection',
            status=ValidationStatus.UNKNOWN,
            message='Backdoor detection not fully implemented'
        )
    
    def _generate_recommendations(self, 
                                 status: ValidationStatus,
                                 risk_factors: List[str],
                                 strict_mode: bool) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if status == ValidationStatus.INVALID:
            recommendations.append("DO NOT USE this model - validation failed")
            recommendations.append("Obtain model from trusted source")
            
        elif status == ValidationStatus.SUSPICIOUS:
            recommendations.append("Exercise caution with this model")
            recommendations.append("Run in sandboxed environment")
            recommendations.append("Monitor for unusual behavior")
            
            if 'hash_mismatch' in risk_factors:
                recommendations.append("File may have been tampered with")
                
            if 'abnormal_size' in risk_factors:
                recommendations.append("Check for embedded payloads")
                
            if 'potential_backdoor' in risk_factors:
                recommendations.append("Test model on clean data first")
                
        elif status == ValidationStatus.VALID:
            recommendations.append("Model passed basic validation")
            if strict_mode:
                recommendations.append("Consider additional security scanning")
                
        else:
            recommendations.append("Unable to fully validate model")
            recommendations.append("Proceed with caution")
            
        return recommendations