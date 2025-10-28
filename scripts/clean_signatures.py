#!/usr/bin/env python3
"""
Clean signatures by removing overly generic patterns that cause false positives.
"""

import json
import sys
from pathlib import Path
from typing import Set

# Common generic patterns that should be filtered
GENERIC_PATTERNS = {
    # C standard library functions
    'free', 'malloc', 'calloc', 'realloc', 'memcpy', 'memset', 'memmove', 'memcmp',
    'strcpy', 'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp', 'strlen',
    'printf', 'sprintf', 'fprintf', 'scanf', 'fscanf', 'fopen', 'fclose', 'fread', 'fwrite',
    'exit', 'abort', 'atexit', 'system', 'getenv', 'setenv',
    
    # Math functions
    'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'sinh', 'cosh', 'tanh', 'atan2',
    'exp', 'log', 'log10', 'pow', 'sqrt', 'ceil', 'floor', 'fabs', 'cbrt',
    
    # Common programming terms
    'name', 'type', 'data', 'value', 'size', 'count', 'index', 'param', 'params',
    'error', 'warning', 'info', 'debug', 'trace', 'fatal',
    'true', 'false', 'null', 'none', 'void', 'auto',
    'public', 'private', 'protected', 'static', 'const', 'final',
    'class', 'struct', 'enum', 'interface', 'namespace',
    'function', 'method', 'property', 'field', 'variable',
    'get', 'set', 'add', 'remove', 'delete', 'create', 'destroy',
    'init', 'setup', 'cleanup', 'start', 'stop', 'run', 'exec',
    'open', 'close', 'read', 'write', 'seek', 'tell',
    'push', 'pop', 'peek', 'clear', 'reset',
    'copy', 'move', 'swap', 'compare', 'equal',
    'load', 'save', 'store', 'fetch',
    'lock', 'unlock', 'wait', 'signal', 'notify',
    'send', 'recv', 'receive', 'transmit',
    'encode', 'decode', 'encrypt', 'decrypt',
    'parse', 'format', 'convert', 'transform',
    'render', 'draw', 'paint', 'display', 'show', 'hide',
    'enable', 'disable', 'toggle', 'switch',
    'begin', 'end', 'first', 'last', 'next', 'prev', 'previous',
    'parent', 'child', 'root', 'leaf', 'node',
    'list', 'array', 'vector', 'map', 'set', 'queue', 'stack',
    'key', 'value', 'pair', 'entry', 'item', 'element',
    'source', 'target', 'dest', 'destination',
    'input', 'output', 'result', 'return',
    'handle', 'pointer', 'reference', 'address',
    'buffer', 'cache', 'pool', 'heap', 'stack',
    'thread', 'process', 'task', 'job', 'worker',
    'event', 'message', 'signal', 'callback',
    'config', 'settings', 'options', 'preferences',
    'user', 'group', 'role', 'permission',
    'file', 'path', 'directory', 'folder',
    'string', 'text', 'char', 'byte', 'word',
    'int', 'float', 'double', 'bool', 'boolean',
    'date', 'time', 'timestamp', 'duration',
    'width', 'height', 'depth', 'length',
    'color', 'bitmap', 'image', 'texture',
    'state', 'status', 'mode', 'flag',
    'version', 'build', 'release', 'patch',
    'test', 'check', 'verify', 'validate',
    'sync', 'async', 'wait', 'done',
    'post', 'call', 'invoke', 'apply',
    'blob', 'break', 'table', 'sort', 'find'
}

# Common IL/bytecode instructions
IL_INSTRUCTIONS = {
    'ldarg', 'ldloc', 'ldstr', 'ldc', 'stloc', 'starg', 'stfld', 'ldfld',
    'call', 'calli', 'callvirt', 'ret', 'br', 'brtrue', 'brfalse', 'beq',
    'cpblk', 'cpobj', 'isinst', 'castclass', 'box', 'unbox', 'throw',
    'leave', 'endfinally', 'dup', 'pop', 'jmp', 'switch'
}

# Month names
MONTHS = {'jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
          'january', 'february', 'march', 'april', 'june', 'july', 'august', 'september', 'october', 'november', 'december'}

def should_filter_pattern(pattern: str) -> bool:
    """Check if a pattern should be filtered out."""
    
    pattern_lower = pattern.lower()
    
    # Filter common generic patterns
    if pattern_lower in GENERIC_PATTERNS:
        return True
    
    # Filter IL instructions
    if pattern_lower in IL_INSTRUCTIONS:
        return True
        
    # Filter month names
    if pattern_lower in MONTHS:
        return True
    
    # Filter patterns that are too short (less than 4 chars)
    # But keep if they have special chars or underscores (likely prefixes)
    if len(pattern) < 4:
        if not any(c in pattern for c in ['_', '-', '::', '.']):
            return True
    
    # Filter pure numeric or short hex patterns
    if pattern.replace('0', '').replace('1', '').replace('2', '').replace('3', '').replace('4', '') \
             .replace('5', '').replace('6', '').replace('7', '').replace('8', '').replace('9', '') \
             .replace('a', '').replace('b', '').replace('c', '').replace('d', '').replace('e', '').replace('f', '') \
             .replace('A', '').replace('B', '').replace('C', '').replace('D', '').replace('E', '').replace('F', '') == '':
        if len(pattern) < 8:  # Short hex patterns are too generic
            return True
    
    # Filter patterns that are just uppercase versions of generic terms
    if pattern.isupper() and pattern_lower in GENERIC_PATTERNS:
        return True
    
    # Keep pattern if it passes all filters
    return False

def clean_signature_file(file_path: Path, dry_run: bool = False) -> dict:
    """Clean a signature file by removing generic patterns."""
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Handle both formats
    if 'component' in data:
        component = data['component']['name']
        signatures = data.get('signatures', [])
        
        # Filter signatures
        original_count = len(signatures)
        filtered_signatures = []
        removed_patterns = []
        
        for sig in signatures:
            pattern = sig.get('pattern', '')
            if should_filter_pattern(pattern):
                removed_patterns.append(pattern)
            else:
                filtered_signatures.append(sig)
        
        if not dry_run and removed_patterns:
            data['signatures'] = filtered_signatures
            data['signature_metadata']['signature_count'] = len(filtered_signatures)
            
            # Save the cleaned file
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
        
        return {
            'file': file_path.name,
            'component': component,
            'original_count': original_count,
            'filtered_count': len(filtered_signatures),
            'removed_count': len(removed_patterns),
            'removed_patterns': removed_patterns[:20]  # Show first 20
        }
    
    elif 'symbols' in data:
        # Handle symbol format
        component = data.get('package_name', file_path.stem)
        symbols = data.get('symbols', [])
        
        original_count = len(symbols)
        filtered_symbols = [s for s in symbols if not should_filter_pattern(s)]
        removed_patterns = [s for s in symbols if should_filter_pattern(s)]
        
        if not dry_run and removed_patterns:
            data['symbols'] = filtered_symbols
            
            # Save the cleaned file
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
        
        return {
            'file': file_path.name,
            'component': component,
            'original_count': original_count,
            'filtered_count': len(filtered_symbols),
            'removed_count': len(removed_patterns),
            'removed_patterns': removed_patterns[:20]
        }
    
    return None

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Clean signature files by removing generic patterns')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be removed without modifying files')
    parser.add_argument('--target', help='Clean only specific file(s), comma-separated')
    args = parser.parse_args()
    
    signatures_dir = Path('/Users/ovalenzuela/Projects/SEMCL.ONE/binarysniffer/signatures')
    
    # Files to clean
    if args.target:
        target_files = [signatures_dir / f for f in args.target.split(',')]
    else:
        # Focus on the worst offenders
        target_files = [
            signatures_dir / 'dotnet-core.json',
            signatures_dir / 'pcoip.json',
            signatures_dir / 'wolfssl.json',
            signatures_dir / 'foxit-pdf-sdk.json',
            signatures_dir / 'qt5.json',
            signatures_dir / 'ffmpeg-enhanced.json'
        ]
    
    print(f"Cleaning signature files ({'DRY RUN' if args.dry_run else 'APPLYING CHANGES'}):")
    print("=" * 80)
    
    total_removed = 0
    
    for file_path in target_files:
        if not file_path.exists():
            print(f"File not found: {file_path.name}")
            continue
            
        result = clean_signature_file(file_path, dry_run=args.dry_run)
        if result:
            print(f"\n{result['file']} ({result['component']})")
            print(f"  Original signatures: {result['original_count']}")
            print(f"  After filtering: {result['filtered_count']}")
            print(f"  Removed: {result['removed_count']}")
            if result['removed_patterns']:
                print(f"  Examples removed: {', '.join(result['removed_patterns'][:10])}")
            total_removed += result['removed_count']
    
    print("\n" + "=" * 80)
    print(f"Total patterns removed: {total_removed}")
    
    if args.dry_run:
        print("\nThis was a DRY RUN. To apply changes, run without --dry-run")
    else:
        print("\nChanges have been applied to signature files")

if __name__ == '__main__':
    main()