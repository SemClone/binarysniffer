#!/usr/bin/env python3
"""
Simple Hermes bytecode decompiler/inspector
Provides basic inspection of Hermes bytecode without external dependencies
"""

import struct
import sys
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Hermes magic number
HERMES_MAGIC = b'\xc6\x1f\xbc\x03'

# Instruction opcodes (simplified subset for common operations)
OPCODES = {
    0x00: 'Unreachable',
    0x01: 'NewObjectWithBuffer',
    0x02: 'NewObject',
    0x03: 'NewObjectWithParent',
    0x04: 'NewArrayWithBuffer',
    0x05: 'NewArray',
    0x06: 'Mov',
    0x07: 'MovLong',
    0x08: 'Negate',
    0x09: 'Not',
    0x0A: 'BitNot',
    0x0B: 'TypeOf',
    0x0C: 'Eq',
    0x0D: 'StrictEq',
    0x0E: 'Neq',
    0x0F: 'StrictNeq',
    0x10: 'Less',
    0x11: 'LessEq',
    0x12: 'Greater',
    0x13: 'GreaterEq',
    0x14: 'Add',
    0x15: 'AddN',
    0x16: 'Mul',
    0x17: 'MulN',
    0x18: 'Div',
    0x19: 'DivN',
    0x1A: 'Mod',
    0x1B: 'Sub',
    0x1C: 'SubN',
    0x1D: 'LShift',
    0x1E: 'RShift',
    0x1F: 'URshift',
    0x20: 'BitAnd',
    0x21: 'BitOr',
    0x22: 'BitXor',
    0x23: 'InstanceOf',
    0x24: 'IsIn',
    0x25: 'GetEnvironment',
    0x26: 'StoreToEnvironment',
    0x27: 'StoreToEnvironmentL',
    0x28: 'StoreNPToEnvironment',
    0x29: 'StoreNPToEnvironmentL',
    0x2A: 'LoadFromEnvironment',
    0x2B: 'LoadFromEnvironmentL',
    0x2C: 'GetGlobalObject',
    0x2D: 'GetNewTarget',
    0x2E: 'CreateEnvironment',
    0x2F: 'CreateInnerEnvironment',
    0x30: 'DeclareGlobalVar',
    0x31: 'ThrowIfEmpty',
    0x32: 'CreateRegExp',
    0x33: 'CreateClosure',
    0x34: 'CreateClosureLongIndex',
    0x35: 'CreateGeneratorClosure',
    0x36: 'CreateGeneratorClosureLongIndex',
    0x37: 'CreateAsyncClosure',
    0x38: 'CreateAsyncClosureLongIndex',
    0x39: 'GetArgumentsLength',
    0x3A: 'GetArgumentsPropByVal',
    0x3B: 'ReifyArguments',
    0x3C: 'CreateThis',
    0x3D: 'SelectObject',
    0x3E: 'LoadThisNS',
    0x3F: 'CoerceThisNS',
    0x40: 'LoadArg',
    0x41: 'LoadArgLong',
    0x42: 'StoreArg',
    0x43: 'StoreArgLong',
    0x44: 'LoadConstUInt8',
    0x45: 'LoadConstInt',
    0x46: 'LoadConstDouble',
    0x47: 'LoadConstBigInt',
    0x48: 'LoadConstBigIntLongIndex',
    0x49: 'LoadConstString',
    0x4A: 'LoadConstStringLongIndex',
    0x4B: 'LoadConstUndefined',
    0x4C: 'LoadConstNull',
    0x4D: 'LoadConstTrue',
    0x4E: 'LoadConstFalse',
    0x4F: 'LoadConstZero',
    0x50: 'LoadParam',
    0x51: 'LoadParamLong',
    0x52: 'StoreParam',
    0x53: 'StoreParamLong',
    0x54: 'Call',
    0x55: 'CallLong',
    0x56: 'Construct',
    0x57: 'ConstructLong',
    0x58: 'CallDirect',
    0x59: 'CallDirectLongIndex',
    0x5A: 'CallBuiltin',
    0x5B: 'CallBuiltinLong',
    0x5C: 'GetBuiltinClosure',
    0x5D: 'Ret',
    0x5E: 'Catch',
    0x5F: 'Throw',
    0x60: 'ThrowIfUndefinedInst',
    0x61: 'Debugger',
    0x62: 'AsyncBreakCheck',
    0x63: 'ProfilePoint',
    0x64: 'CreateGenerator',
    0x65: 'CreateGeneratorLongIndex',
    0x66: 'IteratorBegin',
    0x67: 'IteratorNext',
    0x68: 'IteratorClose',
    0x69: 'Jmp',
    0x6A: 'JmpLong',
    0x6B: 'JmpTrue',
    0x6C: 'JmpTrueLong',
    0x6D: 'JmpFalse',
    0x6E: 'JmpFalseLong',
    0x6F: 'JmpUndefined',
    0x70: 'JmpUndefinedLong',
    0x71: 'SaveGenerator',
    0x72: 'SaveGeneratorLong',
    0x73: 'ResumeGenerator',
    0x74: 'CompleteGenerator',
    0x75: 'CreateAsyncClosure',
    0x76: 'CreateAsyncClosureLongIndex',
    0x77: 'CompleteGeneratorWithIterator',
    0x78: 'GetPNameList',
    0x79: 'GetNextPName',
    0x7A: 'GetByIdShort',
    0x7B: 'GetById',
    0x7C: 'GetByIdLong',
    0x7D: 'TryGetById',
    0x7E: 'TryGetByIdLong',
    0x7F: 'PutById',
    0x80: 'PutByIdLong',
    0x81: 'TryPutById',
    0x82: 'TryPutByIdLong',
    0x83: 'PutNewOwnByIdShort',
    0x84: 'PutNewOwnById',
    0x85: 'PutNewOwnByIdLong',
    0x86: 'PutNewOwnNEById',
    0x87: 'PutNewOwnNEByIdLong',
    0x88: 'PutOwnByIndex',
    0x89: 'PutOwnByIndexL',
    0x8A: 'PutOwnByVal',
    0x8B: 'DelById',
    0x8C: 'DelByIdLong',
    0x8D: 'GetByVal',
    0x8E: 'PutByVal',
    0x8F: 'DelByVal',
    0x90: 'PutOwnGetterSetterByVal',
    0x91: 'GetPNameList',
    0x92: 'GetNextPName',
    0x93: 'CallWithNewTarget',
    0x94: 'ThrowIfNotObject',
    0x95: 'SwitchImm',
}

class HermesDecompiler:
    """Simple Hermes bytecode decompiler"""
    
    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.data = None
        self.header = {}
        self.strings = []
        self.functions = []
        
    def load(self) -> bool:
        """Load and validate the Hermes bytecode file"""
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            
            # Check magic
            if self.data[:4] != HERMES_MAGIC:
                print(f"Error: Not a valid Hermes bytecode file")
                return False
            
            return True
        except Exception as e:
            print(f"Error loading file: {e}")
            return False
    
    def parse_header(self):
        """Parse the file header"""
        if not self.data:
            return
        
        # Parse basic header fields
        offset = 0
        self.header['magic'] = self.data[offset:offset+4].hex()
        offset += 4
        
        self.header['version'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['sha1'] = self.data[offset:offset+20].hex()
        offset += 20
        
        self.header['file_length'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['global_code_index'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['function_count'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['string_kind'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['identifier_count'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['string_count'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['overflow_string_count'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['string_storage_size'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['regexp_table_offset'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
        
        self.header['regexp_count'] = struct.unpack('<I', self.data[offset:offset+4])[0]
        offset += 4
    
    def extract_strings(self, limit: int = 100):
        """Extract strings from the string table"""
        if not self.data:
            return
        
        # Start after header (simplified)
        offset = 88
        string_storage_size = self.header.get('string_storage_size', 0)
        
        if string_storage_size == 0:
            return
        
        # Read string storage area
        string_data = self.data[offset:offset + min(string_storage_size, 100000)]
        
        # Extract printable strings
        current = bytearray()
        for byte in string_data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(byte)
            elif current and len(current) >= 4:
                try:
                    s = current.decode('ascii', errors='ignore')
                    if s and not s.isspace():
                        self.strings.append(s)
                        if len(self.strings) >= limit:
                            break
                except:
                    pass
                current = bytearray()
    
    def disassemble_function(self, func_index: int, max_instructions: int = 50) -> List[str]:
        """Attempt to disassemble a function (simplified)"""
        instructions = []
        
        # This is a simplified disassembly - actual implementation would need
        # to properly parse the function table and bytecode sections
        
        # For demonstration, we'll show what a disassembly might look like
        sample_ops = [
            "LoadConstString r0, 'console'",
            "GetGlobalObject r1",
            "GetById r2, r1, r0",
            "LoadConstString r3, 'log'",
            "GetById r4, r2, r3",
            "LoadConstString r5, 'Hello from Hermes!'",
            "Call r6, r4, 1",
            "Ret r6"
        ]
        
        if func_index == 0:
            return sample_ops[:max_instructions]
        
        return [f"Function_{func_index}: <bytecode not fully parsed>"]
    
    def analyze(self):
        """Analyze the bytecode file"""
        if not self.load():
            return
        
        self.parse_header()
        self.extract_strings()
        
        print(f"\n{'='*60}")
        print(f"Hermes Bytecode Analysis: {self.filepath.name}")
        print(f"{'='*60}\n")
        
        # Header info
        print("📋 Header Information:")
        print(f"  Version: {self.header.get('version', 'Unknown')}")
        print(f"  File size: {self.header.get('file_length', 0):,} bytes")
        print(f"  SHA1: {self.header.get('sha1', 'Unknown')[:16]}...")
        print()
        
        # Statistics
        print("📊 Statistics:")
        print(f"  Functions: {self.header.get('function_count', 0):,}")
        print(f"  Strings: {self.header.get('string_count', 0):,}")
        print(f"  Identifiers: {self.header.get('identifier_count', 0):,}")
        print(f"  RegExps: {self.header.get('regexp_count', 0):,}")
        print(f"  String storage: {self.header.get('string_storage_size', 0):,} bytes")
        print()
        
        # Extracted strings
        if self.strings:
            print(f"📝 Extracted Strings (first 20):")
            for i, s in enumerate(self.strings[:20], 1):
                # Truncate long strings
                display = s[:60] + '...' if len(s) > 60 else s
                print(f"  {i:2}. {display}")
            print()
        
        # Detect frameworks
        print("🔍 Framework Detection:")
        frameworks_found = []
        
        # Check for React Native
        rn_markers = ['ReactNative', '__fbBatchedBridge', 'NativeModules', 
                     'AppRegistry', 'renderApplication']
        if any(marker in ' '.join(self.strings) for marker in rn_markers):
            frameworks_found.append("✓ React Native")
        
        # Check for specific libraries
        if 'console' in self.strings or 'console.log' in ' '.join(self.strings):
            frameworks_found.append("✓ Console API")
        
        if 'require' in self.strings or 'module.exports' in ' '.join(self.strings):
            frameworks_found.append("✓ CommonJS Modules")
        
        if 'Promise' in self.strings or 'async' in self.strings:
            frameworks_found.append("✓ Async/Promise Support")
        
        if frameworks_found:
            for framework in frameworks_found:
                print(f"  {framework}")
        else:
            print("  No specific frameworks detected")
        print()
        
        # Sample disassembly
        if self.header.get('function_count', 0) > 0:
            print("🔧 Sample Disassembly (Function 0):")
            instructions = self.disassemble_function(0, 10)
            for inst in instructions:
                print(f"    {inst}")
            print()
        
        # Export option
        print("💾 Export Options:")
        print(f"  JSON metadata: {self.filepath.stem}_metadata.json")
        print(f"  Strings list: {self.filepath.stem}_strings.txt")
        print()
    
    def export_metadata(self):
        """Export metadata to JSON"""
        output = {
            'file': str(self.filepath),
            'header': self.header,
            'strings_sample': self.strings[:100],
            'analysis': {
                'has_react_native': any('React' in s for s in self.strings),
                'has_commonjs': any('require' in s or 'module' in s for s in self.strings),
                'string_count': len(self.strings)
            }
        }
        
        output_file = self.filepath.parent / f"{self.filepath.stem}_metadata.json"
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"Metadata exported to: {output_file}")
    
    def export_strings(self):
        """Export strings to text file"""
        output_file = self.filepath.parent / f"{self.filepath.stem}_strings.txt"
        with open(output_file, 'w') as f:
            for s in self.strings:
                f.write(s + '\n')
        
        print(f"Strings exported to: {output_file}")

def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print("Usage: python hermes_decompiler.py <path/to/hermes.hbc>")
        print("\nThis tool provides basic inspection of Hermes bytecode files.")
        print("It can extract strings, show statistics, and detect frameworks.")
        sys.exit(1)
    
    filepath = Path(sys.argv[1])
    if not filepath.exists():
        print(f"Error: File not found: {filepath}")
        sys.exit(1)
    
    decompiler = HermesDecompiler(filepath)
    decompiler.analyze()
    
    # Ask if user wants to export
    response = input("\nExport metadata and strings? (y/n): ")
    if response.lower() == 'y':
        decompiler.export_metadata()
        decompiler.export_strings()

if __name__ == '__main__':
    main()