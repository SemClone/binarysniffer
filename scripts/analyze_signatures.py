#!/usr/bin/env python3
"""
Analyze signatures for overly generic patterns that cause false positives.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Common generic patterns that should be filtered
GENERIC_PATTERNS = {
    # C standard library functions
    'free', 'malloc', 'calloc', 'realloc', 'memcpy', 'memset', 'memmove', 'memcmp',
    'strcpy', 'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp', 'strlen',
    'printf', 'sprintf', 'fprintf', 'scanf', 'fscanf', 'fopen', 'fclose', 'fread', 'fwrite',
    'exit', 'abort', 'atexit', 'system', 'getenv', 'setenv',
    
    # Math functions
    'sin', 'cos', 'tan', 'asin', 'acos', 'atan', 'sinh', 'cosh', 'tanh',
    'exp', 'log', 'log10', 'pow', 'sqrt', 'ceil', 'floor', 'fabs',
    
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
    'begin', 'end', 'first', 'last', 'next', 'prev',
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
    'post', 'call', 'invoke', 'apply'
}

def analyze_signature_file(file_path: Path):
    """Analyze a signature file for problematic patterns."""
    
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Handle both formats
    if 'component' in data:
        component = data['component']['name']
        signatures = data.get('signatures', [])
    elif 'symbols' in data:
        component = data.get('package_name', file_path.stem)
        # Convert symbols to signature format
        signatures = [{'pattern': s} for s in data.get('symbols', [])]
    else:
        return None
    
    if not signatures:
        return None
    
    problematic = []
    for sig in signatures:
        pattern = sig.get('pattern', '')
        
        # Check if pattern is too generic
        if pattern.lower() in GENERIC_PATTERNS:
            problematic.append(pattern)
            continue
            
        # Check if pattern is too short (less than 4 chars)
        if len(pattern) < 4:
            problematic.append(pattern)
            continue
            
        # Check if pattern is just numbers or hex
        if pattern.replace('0', '').replace('1', '').replace('2', '').replace('3', '').replace('4', '') \
                 .replace('5', '').replace('6', '').replace('7', '').replace('8', '').replace('9', '') \
                 .replace('a', '').replace('b', '').replace('c', '').replace('d', '').replace('e', '').replace('f', '') == '':
            if len(pattern) < 8:  # Short hex patterns are too generic
                problematic.append(pattern)
                continue
    
    if problematic:
        return {
            'file': file_path.name,
            'component': component,
            'total_signatures': len(signatures),
            'problematic_count': len(problematic),
            'problematic_patterns': problematic[:20]  # Show first 20
        }
    
    return None

def main():
    signatures_dir = Path('/Users/ovalenzuela/Projects/semantic-copycat-binarysniffer/signatures')
    
    results = []
    for json_file in signatures_dir.glob('*.json'):
        if json_file.name == 'manifest.json' or json_file.name == 'template.json':
            continue
            
        result = analyze_signature_file(json_file)
        if result:
            results.append(result)
    
    # Sort by problematic count
    results.sort(key=lambda x: x['problematic_count'], reverse=True)
    
    print("Signature files with problematic patterns:")
    print("=" * 80)
    
    for result in results[:10]:  # Show top 10 worst offenders
        print(f"\n{result['file']} ({result['component']})")
        print(f"  Total signatures: {result['total_signatures']}")
        print(f"  Problematic patterns: {result['problematic_count']}")
        print(f"  Examples: {', '.join(result['problematic_patterns'][:10])}")
    
    print("\n" + "=" * 80)
    print(f"Total files analyzed: {len(list(signatures_dir.glob('*.json'))) - 2}")
    print(f"Files with problems: {len(results)}")
    
    # Show worst offenders that likely caused FFmpeg false positives
    print("\nLikely culprits for FFmpeg false positives:")
    for result in results:
        if result['component'] in ['.NET Core Runtime', 'Foxit PDF SDK', 'PCoIP SDK', 'wolfSSL', 'Qt5 Framework']:
            print(f"  - {result['component']}: {result['problematic_count']} generic patterns")

if __name__ == '__main__':
    main()