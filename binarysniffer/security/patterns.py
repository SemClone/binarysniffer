"""
Malicious Pattern Database for ML Model Security Analysis

This module contains patterns for detecting malicious code,
backdoors, and supply chain attacks in ML models.
"""

from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ThreatPattern:
    """Represents a malicious pattern"""
    pattern: str
    category: str
    severity: ThreatSeverity
    description: str
    mitre_technique: str = ""


class MaliciousPatterns:
    """
    Central repository for malicious patterns in ML models.
    Patterns based on real-world attacks and security research.
    """
    
    # Critical imports that enable arbitrary code execution
    CRITICAL_IMPORTS = [
        ThreatPattern("os.system", "code_execution", ThreatSeverity.CRITICAL, 
                     "Direct system command execution", "T1059"),
        ThreatPattern("subprocess.Popen", "code_execution", ThreatSeverity.CRITICAL,
                     "Process spawning capability", "T1059"),
        ThreatPattern("subprocess.run", "code_execution", ThreatSeverity.CRITICAL,
                     "Process execution capability", "T1059"),
        ThreatPattern("subprocess.call", "code_execution", ThreatSeverity.CRITICAL,
                     "Process calling capability", "T1059"),
        ThreatPattern("eval", "code_execution", ThreatSeverity.CRITICAL,
                     "Dynamic code evaluation", "T1027"),
        ThreatPattern("exec", "code_execution", ThreatSeverity.CRITICAL,
                     "Dynamic code execution", "T1027"),
        ThreatPattern("compile", "code_execution", ThreatSeverity.HIGH,
                     "Code compilation capability", "T1027"),
        ThreatPattern("__import__", "code_execution", ThreatSeverity.HIGH,
                     "Dynamic module importing", "T1129"),
        ThreatPattern("importlib.import_module", "code_execution", ThreatSeverity.HIGH,
                     "Dynamic module loading", "T1129"),
    ]
    
    # Network operations that could exfiltrate data
    NETWORK_OPERATIONS = [
        ThreatPattern("socket.socket", "network", ThreatSeverity.HIGH,
                     "Raw socket creation", "T1095"),
        ThreatPattern("urllib.request", "network", ThreatSeverity.HIGH,
                     "HTTP request capability", "T1071"),
        ThreatPattern("urllib.urlopen", "network", ThreatSeverity.HIGH,
                     "URL opening capability", "T1071"),
        ThreatPattern("requests.get", "network", ThreatSeverity.MEDIUM,
                     "HTTP GET capability", "T1071"),
        ThreatPattern("requests.post", "network", ThreatSeverity.HIGH,
                     "HTTP POST capability for data exfiltration", "T1041"),
        ThreatPattern("paramiko.SSHClient", "network", ThreatSeverity.HIGH,
                     "SSH connection capability", "T1021.004"),
        ThreatPattern("ftplib.FTP", "network", ThreatSeverity.HIGH,
                     "FTP connection capability", "T1071.002"),
        ThreatPattern("smtplib.SMTP", "network", ThreatSeverity.MEDIUM,
                     "Email sending capability", "T1071.003"),
        ThreatPattern("telnetlib.Telnet", "network", ThreatSeverity.HIGH,
                     "Telnet connection capability", "T1021"),
    ]
    
    # Shell and reverse shell indicators
    SHELL_INDICATORS = [
        ThreatPattern("/bin/sh", "shell", ThreatSeverity.CRITICAL,
                     "Unix shell path", "T1059.004"),
        ThreatPattern("/bin/bash", "shell", ThreatSeverity.CRITICAL,
                     "Bash shell path", "T1059.004"),
        ThreatPattern("/bin/zsh", "shell", ThreatSeverity.CRITICAL,
                     "Z shell path", "T1059.004"),
        ThreatPattern("cmd.exe", "shell", ThreatSeverity.CRITICAL,
                     "Windows command prompt", "T1059.003"),
        ThreatPattern("powershell.exe", "shell", ThreatSeverity.CRITICAL,
                     "PowerShell executable", "T1059.001"),
        ThreatPattern("nc -e", "shell", ThreatSeverity.CRITICAL,
                     "Netcat reverse shell", "T1059"),
        ThreatPattern("reverse_tcp", "shell", ThreatSeverity.CRITICAL,
                     "Reverse TCP connection", "T1571"),
        ThreatPattern("bind_shell", "shell", ThreatSeverity.CRITICAL,
                     "Bind shell backdoor", "T1571"),
        ThreatPattern("meterpreter", "shell", ThreatSeverity.CRITICAL,
                     "Meterpreter payload", "T1203"),
        ThreatPattern("0.0.0.0", "shell", ThreatSeverity.MEDIUM,
                     "Bind to all interfaces", "T1571"),
    ]
    
    # Obfuscation and encoding patterns
    OBFUSCATION_PATTERNS = [
        ThreatPattern("base64.b64decode", "obfuscation", ThreatSeverity.MEDIUM,
                     "Base64 decoding", "T1027.001"),
        ThreatPattern("base64.b64encode", "obfuscation", ThreatSeverity.LOW,
                     "Base64 encoding", "T1027.001"),
        ThreatPattern("zlib.decompress", "obfuscation", ThreatSeverity.MEDIUM,
                     "Zlib decompression", "T1027.002"),
        ThreatPattern("gzip.decompress", "obfuscation", ThreatSeverity.MEDIUM,
                     "Gzip decompression", "T1027.002"),
        ThreatPattern("marshal.loads", "obfuscation", ThreatSeverity.HIGH,
                     "Marshal deserialization", "T1027"),
        ThreatPattern("codecs.decode", "obfuscation", ThreatSeverity.MEDIUM,
                     "Codec decoding", "T1027"),
        ThreatPattern("binascii.unhexlify", "obfuscation", ThreatSeverity.MEDIUM,
                     "Hex decoding", "T1027"),
        ThreatPattern("rot13", "obfuscation", ThreatSeverity.LOW,
                     "ROT13 encoding", "T1027"),
        ThreatPattern("xor", "obfuscation", ThreatSeverity.MEDIUM,
                     "XOR encryption", "T1027"),
    ]
    
    # File system operations
    FILE_OPERATIONS = [
        ThreatPattern("open(", "file_ops", ThreatSeverity.LOW,
                     "File opening", "T1005"),
        ThreatPattern("os.remove", "file_ops", ThreatSeverity.MEDIUM,
                     "File deletion", "T1485"),
        ThreatPattern("os.unlink", "file_ops", ThreatSeverity.MEDIUM,
                     "File unlinking", "T1485"),
        ThreatPattern("shutil.rmtree", "file_ops", ThreatSeverity.HIGH,
                     "Directory deletion", "T1485"),
        ThreatPattern("os.walk", "file_ops", ThreatSeverity.MEDIUM,
                     "Directory traversal", "T1083"),
        ThreatPattern("glob.glob", "file_ops", ThreatSeverity.LOW,
                     "File pattern matching", "T1083"),
        ThreatPattern("os.chmod", "file_ops", ThreatSeverity.MEDIUM,
                     "Permission modification", "T1222"),
        ThreatPattern("os.chown", "file_ops", ThreatSeverity.MEDIUM,
                     "Ownership modification", "T1222"),
    ]
    
    # Cryptomining indicators
    CRYPTOMINING = [
        ThreatPattern("xmrig", "cryptomining", ThreatSeverity.HIGH,
                     "XMRig miner", "T1496"),
        ThreatPattern("minergate", "cryptomining", ThreatSeverity.HIGH,
                     "MinerGate miner", "T1496"),
        ThreatPattern("coinhive", "cryptomining", ThreatSeverity.HIGH,
                     "Coinhive miner", "T1496"),
        ThreatPattern("cryptonight", "cryptomining", ThreatSeverity.HIGH,
                     "CryptoNight algorithm", "T1496"),
        ThreatPattern("stratum+tcp", "cryptomining", ThreatSeverity.HIGH,
                     "Mining pool protocol", "T1496"),
        ThreatPattern("monero", "cryptomining", ThreatSeverity.MEDIUM,
                     "Monero cryptocurrency", "T1496"),
        ThreatPattern("bitcoin", "cryptomining", ThreatSeverity.LOW,
                     "Bitcoin reference", "T1496"),
    ]
    
    # Persistence mechanisms
    PERSISTENCE = [
        ThreatPattern("crontab", "persistence", ThreatSeverity.HIGH,
                     "Cron job manipulation", "T1053.003"),
        ThreatPattern("systemctl", "persistence", ThreatSeverity.HIGH,
                     "Systemd service control", "T1543.002"),
        ThreatPattern("rc.local", "persistence", ThreatSeverity.HIGH,
                     "Boot script modification", "T1037.004"),
        ThreatPattern("HKEY_", "persistence", ThreatSeverity.HIGH,
                     "Windows registry access", "T1547.001"),
        ThreatPattern("schtasks", "persistence", ThreatSeverity.HIGH,
                     "Windows task scheduler", "T1053.005"),
        ThreatPattern("launchctl", "persistence", ThreatSeverity.HIGH,
                     "macOS launch daemon", "T1543.001"),
    ]
    
    # Known exploit patterns
    KNOWN_EXPLOITS = [
        ThreatPattern("pickle.__reduce__", "exploit", ThreatSeverity.CRITICAL,
                     "Pickle RCE via __reduce__", "T1203"),
        ThreatPattern("pickle_reverse_shell", "exploit", ThreatSeverity.CRITICAL,
                     "Known pickle reverse shell", "T1203"),
        ThreatPattern("tensorflow.py_func", "exploit", ThreatSeverity.HIGH,
                     "TensorFlow arbitrary code execution", "T1203"),
        ThreatPattern("torch.load", "exploit", ThreatSeverity.HIGH,
                     "PyTorch unsafe loading", "T1203"),
        ThreatPattern("numpy.load", "exploit", ThreatSeverity.MEDIUM,
                     "NumPy pickle loading", "T1203"),
    ]
    
    @classmethod
    def get_all_patterns(cls) -> List[ThreatPattern]:
        """Get all threat patterns"""
        all_patterns = []
        all_patterns.extend(cls.CRITICAL_IMPORTS)
        all_patterns.extend(cls.NETWORK_OPERATIONS)
        all_patterns.extend(cls.SHELL_INDICATORS)
        all_patterns.extend(cls.OBFUSCATION_PATTERNS)
        all_patterns.extend(cls.FILE_OPERATIONS)
        all_patterns.extend(cls.CRYPTOMINING)
        all_patterns.extend(cls.PERSISTENCE)
        all_patterns.extend(cls.KNOWN_EXPLOITS)
        return all_patterns
    
    
    @classmethod
    def check_pattern(cls, text: str) -> List[Tuple[ThreatPattern, int]]:
        """
        Check text for malicious patterns
        Returns list of (pattern, position) tuples
        """
        matches = []
        text_lower = text.lower()
        
        for pattern in cls.get_all_patterns():
            pattern_lower = pattern.pattern.lower()
            pos = text_lower.find(pattern_lower)
            if pos != -1:
                matches.append((pattern, pos))
        
        return matches
    
    @classmethod
    def get_pattern_signature(cls, pattern: ThreatPattern) -> Dict[str, any]:
        """Convert pattern to signature format"""
        return {
            "pattern": f"malicious:{pattern.pattern}",
            "confidence": 0.99 if pattern.severity == ThreatSeverity.CRITICAL else 0.90,
            "category": pattern.category,
            "severity": pattern.severity.value,
            "description": pattern.description,
            "mitre": pattern.mitre_technique
        }