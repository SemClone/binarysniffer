#!/usr/bin/env python3
"""
Aggressive signature cleanup to remove patterns causing false positives
"""

import json
import shutil
from pathlib import Path
from collections import defaultdict

class AggressiveSignatureCleaner:
    def __init__(self, signatures_dir: Path):
        self.signatures_dir = signatures_dir
        self.stats = defaultdict(int)
        
        # Expanded list of generic terms that cause false positives
        self.GENERIC_TERMS = {
            # Single common words
            'trace', 'context', 'class', 'store', 'error', 'factor', 'process',
            'filter', 'handler', 'builder', 'factory', 'manager', 'service',
            'client', 'server', 'request', 'response', 'message', 'parser',
            'writer', 'reader', 'buffer', 'stream', 'file', 'data', 'info',
            'debug', 'warning', 'fatal', 'config', 'option', 'setting', 'value',
            'key', 'name', 'type', 'size', 'length', 'count', 'index', 'offset',
            'start', 'end', 'begin', 'finish', 'init', 'close', 'open', 'create',
            'delete', 'remove', 'add', 'get', 'set', 'put', 'post', 'update',
            'check', 'validate', 'verify', 'test', 'run', 'execute', 'call',
            'invoke', 'handle', 'process', 'parse', 'format', 'convert', 'encode',
            'decode', 'serialize', 'deserialize', 'read', 'write', 'load', 'save',
            'copy', 'move', 'compare', 'equals', 'contains', 'find', 'search',
            'match', 'replace', 'split', 'join', 'trim', 'strip', 'clean',
            'clear', 'reset', 'free', 'alloc', 'malloc', 'calloc', 'realloc',
            'new', 'delete', 'dispose', 'destroy', 'release', 'retain', 'lock',
            'unlock', 'wait', 'notify', 'signal', 'send', 'receive', 'connect',
            'disconnect', 'bind', 'listen', 'accept', 'reject', 'allow', 'deny',
            'enable', 'disable', 'start', 'stop', 'pause', 'resume', 'cancel',
            'abort', 'retry', 'timeout', 'expire', 'refresh', 'renew', 'extend',
            'limit', 'max', 'min', 'average', 'sum', 'total', 'count', 'number',
            'amount', 'quantity', 'volume', 'weight', 'height', 'width', 'depth',
            'color', 'style', 'font', 'text', 'string', 'char', 'byte', 'bit',
            'flag', 'state', 'status', 'mode', 'level', 'phase', 'step', 'stage',
            'queue', 'stack', 'list', 'array', 'vector', 'map', 'set', 'table',
            'tree', 'graph', 'node', 'edge', 'vertex', 'path', 'route', 'link',
            'chain', 'group', 'cluster', 'pool', 'cache', 'store', 'repository',
            'database', 'schema', 'model', 'entity', 'object', 'instance', 'class',
            'interface', 'abstract', 'concrete', 'impl', 'base', 'derived', 'parent',
            'child', 'root', 'leaf', 'branch', 'trunk', 'head', 'tail', 'first',
            'last', 'next', 'prev', 'current', 'default', 'custom', 'user', 'system',
            'admin', 'guest', 'anonymous', 'public', 'private', 'protected', 'internal',
            'external', 'local', 'remote', 'global', 'static', 'dynamic', 'const',
            'volatile', 'mutable', 'immutable', 'final', 'sealed', 'virtual', 'override',
            'super', 'this', 'self', 'that', 'other', 'any', 'all', 'none', 'some',
            'each', 'every', 'many', 'few', 'several', 'multiple', 'single', 'double',
            'triple', 'quad', 'penta', 'hexa', 'octa', 'deca', 'kilo', 'mega', 'giga',
            'tera', 'peta', 'nano', 'micro', 'milli', 'centi', 'deci', 'hecto',
            'common', 'shared', 'unique', 'specific', 'general', 'special', 'normal',
            'standard', 'custom', 'default', 'optional', 'required', 'mandatory',
            'thread', 'mutex', 'semaphore', 'barrier', 'latch', 'future', 'promise',
            'task', 'job', 'work', 'action', 'operation', 'command', 'query', 'result',
            'output', 'input', 'parameter', 'argument', 'return', 'yield', 'throw',
            'catch', 'finally', 'try', 'except', 'raise', 'assert', 'ensure', 'require',
            'guarantee', 'contract', 'precondition', 'postcondition', 'invariant',
            'property', 'attribute', 'field', 'member', 'method', 'function', 'procedure',
            'routine', 'callback', 'delegate', 'event', 'listener', 'observer', 'subscriber',
            'publisher', 'producer', 'consumer', 'provider', 'supplier', 'factory',
            'singleton', 'prototype', 'builder', 'adapter', 'proxy', 'decorator',
            'facade', 'bridge', 'composite', 'flyweight', 'chain', 'command', 'iterator',
            'mediator', 'memento', 'observer', 'state', 'strategy', 'template', 'visitor',
            'interpreter', 'expression', 'statement', 'declaration', 'definition',
            'assignment', 'comparison', 'arithmetic', 'logical', 'bitwise', 'shift',
            'cast', 'convert', 'coerce', 'promote', 'demote', 'truncate', 'round',
            'floor', 'ceil', 'abs', 'sign', 'sqrt', 'pow', 'exp', 'log', 'sin', 'cos',
            'tan', 'asin', 'acos', 'atan', 'sinh', 'cosh', 'tanh', 'random', 'seed',
            'uuid', 'guid', 'hash', 'digest', 'checksum', 'crc', 'md5', 'sha', 'hmac',
            'encrypt', 'decrypt', 'cipher', 'key', 'iv', 'salt', 'nonce', 'padding',
            'signature', 'certificate', 'token', 'session', 'cookie', 'header', 'body',
            'payload', 'metadata', 'annotation', 'decorator', 'attribute', 'tag', 'label',
            'identifier', 'namespace', 'package', 'module', 'library', 'framework',
            'platform', 'environment', 'runtime', 'compiler', 'interpreter', 'linker',
            'loader', 'debugger', 'profiler', 'tracer', 'monitor', 'watcher', 'guard',
            'sentinel', 'canary', 'dummy', 'mock', 'stub', 'fake', 'spy', 'double',
            'fixture', 'scaffold', 'harness', 'suite', 'case', 'scenario', 'example',
            'sample', 'demo', 'tutorial', 'guide', 'manual', 'reference', 'documentation',
            'comment', 'note', 'todo', 'fixme', 'hack', 'workaround', 'patch', 'hotfix',
            'bugfix', 'feature', 'enhancement', 'improvement', 'optimization', 'refactor',
            'cleanup', 'migration', 'upgrade', 'downgrade', 'rollback', 'backup', 'restore',
            'export', 'import', 'sync', 'async', 'concurrent', 'parallel', 'sequential',
            'serial', 'batch', 'bulk', 'stream', 'pipe', 'channel', 'socket', 'port',
            'address', 'url', 'uri', 'urn', 'path', 'query', 'fragment', 'scheme',
            'protocol', 'host', 'domain', 'subdomain', 'tld', 'ip', 'ipv4', 'ipv6',
            'tcp', 'udp', 'http', 'https', 'ftp', 'sftp', 'ssh', 'telnet', 'smtp',
            'pop', 'imap', 'dns', 'dhcp', 'arp', 'icmp', 'ping', 'traceroute',
            'netstat', 'ifconfig', 'route', 'iptables', 'firewall', 'nat', 'vpn',
            'proxy', 'gateway', 'router', 'switch', 'hub', 'bridge', 'modem', 'nic',
            'mac', 'ethernet', 'wifi', 'bluetooth', 'nfc', 'rfid', 'gps', 'gsm',
            'cdma', 'lte', '3g', '4g', '5g', 'edge', 'gprs', 'hspa', 'wimax',
            'satellite', 'radio', 'antenna', 'transmitter', 'receiver', 'amplifier',
            'filter', 'mixer', 'oscillator', 'modulator', 'demodulator', 'encoder',
            'decoder', 'codec', 'compression', 'decompression', 'zip', 'unzip', 'tar',
            'gzip', 'bzip', 'lzma', 'lz4', 'zstd', 'snappy', 'deflate', 'inflate',
            'base64', 'hex', 'binary', 'ascii', 'unicode', 'utf8', 'utf16', 'utf32',
            'charset', 'encoding', 'locale', 'language', 'country', 'region', 'timezone',
            'date', 'time', 'datetime', 'timestamp', 'epoch', 'year', 'month', 'day',
            'hour', 'minute', 'second', 'millisecond', 'microsecond', 'nanosecond',
            'week', 'weekday', 'weekend', 'holiday', 'calendar', 'schedule', 'cron',
            'timer', 'alarm', 'reminder', 'notification', 'alert', 'warning', 'error',
            'exception', 'fault', 'failure', 'success', 'ok', 'cancel', 'abort', 'retry',
            'skip', 'ignore', 'continue', 'break', 'return', 'exit', 'quit', 'halt',
            'terminate', 'kill', 'signal', 'interrupt', 'suspend', 'resume', 'wake',
            'sleep', 'hibernate', 'shutdown', 'reboot', 'restart', 'reload', 'refresh',
            'update', 'upgrade', 'patch', 'fix', 'repair', 'recover', 'restore', 'reset',
            'clear', 'clean', 'purge', 'flush', 'drain', 'empty', 'fill', 'populate',
            'seed', 'generate', 'create', 'make', 'build', 'construct', 'assemble',
            'compile', 'link', 'package', 'bundle', 'archive', 'compress', 'extract',
            'install', 'uninstall', 'deploy', 'undeploy', 'publish', 'unpublish',
            'subscribe', 'unsubscribe', 'register', 'unregister', 'login', 'logout',
            'signin', 'signout', 'authenticate', 'authorize', 'grant', 'revoke', 'deny',
            'allow', 'block', 'whitelist', 'blacklist', 'filter', 'sanitize', 'escape',
            'unescape', 'quote', 'unquote', 'wrap', 'unwrap', 'pack', 'unpack', 'marshal',
            'unmarshal', 'pickle', 'unpickle', 'freeze', 'thaw', 'clone', 'copy', 'duplicate',
            'replicate', 'mirror', 'shadow', 'backup', 'archive', 'snapshot', 'checkpoint',
            'milestone', 'release', 'version', 'revision', 'commit', 'branch', 'tag',
            'merge', 'rebase', 'cherry-pick', 'squash', 'amend', 'revert', 'undo', 'redo',
            'history', 'log', 'audit', 'trace', 'track', 'monitor', 'watch', 'observe',
            'inspect', 'examine', 'analyze', 'evaluate', 'assess', 'measure', 'calculate',
            'compute', 'estimate', 'predict', 'forecast', 'project', 'plan', 'schedule',
            'organize', 'arrange', 'sort', 'order', 'rank', 'classify', 'categorize',
            'group', 'cluster', 'segment', 'partition', 'split', 'divide', 'separate',
            'combine', 'merge', 'join', 'unite', 'integrate', 'aggregate', 'consolidate',
            'summarize', 'abstract', 'extract', 'distill', 'refine', 'purify', 'filter',
            'transform', 'translate', 'transcode', 'transpile', 'interpret', 'execute',
            'evaluate', 'apply', 'invoke', 'call', 'trigger', 'fire', 'emit', 'broadcast',
            'multicast', 'unicast', 'anycast', 'publish', 'subscribe', 'notify', 'alert',
            'inform', 'report', 'announce', 'declare', 'proclaim', 'advertise', 'promote',
            'market', 'sell', 'buy', 'trade', 'exchange', 'swap', 'barter', 'negotiate',
            'bargain', 'deal', 'offer', 'bid', 'ask', 'propose', 'suggest', 'recommend',
            'advise', 'consult', 'counsel', 'guide', 'direct', 'instruct', 'teach',
            'train', 'educate', 'learn', 'study', 'research', 'investigate', 'explore',
            'discover', 'find', 'locate', 'identify', 'recognize', 'detect', 'sense',
            'perceive', 'observe', 'notice', 'spot', 'glimpse', 'glance', 'peek', 'peep',
            'stare', 'gaze', 'look', 'see', 'view', 'watch', 'monitor', 'survey', 'scan',
            'search', 'seek', 'hunt', 'pursue', 'chase', 'follow', 'track', 'trace',
            'trail', 'shadow', 'stalk', 'spy', 'eavesdrop', 'intercept', 'capture',
            'record', 'log', 'journal', 'diary', 'chronicle', 'document', 'archive',
            'preserve', 'conserve', 'maintain', 'sustain', 'support', 'uphold', 'defend',
            'protect', 'guard', 'shield', 'armor', 'fortify', 'strengthen', 'reinforce',
            'bolster', 'buttress', 'brace', 'prop', 'shore', 'underpin', 'foundation',
            'base', 'ground', 'root', 'anchor', 'fix', 'secure', 'fasten', 'attach',
            'bind', 'tie', 'link', 'connect', 'join', 'unite', 'merge', 'fuse', 'weld',
            'solder', 'glue', 'paste', 'stick', 'adhere', 'cling', 'grip', 'grasp',
            'hold', 'clutch', 'clasp', 'clench', 'squeeze', 'pinch', 'compress', 'press',
            'push', 'pull', 'drag', 'draw', 'tug', 'yank', 'jerk', 'twitch', 'shake',
            'vibrate', 'oscillate', 'swing', 'sway', 'rock', 'roll', 'spin', 'rotate',
            'revolve', 'turn', 'twist', 'bend', 'flex', 'curve', 'arc', 'loop', 'coil',
            'spiral', 'helix', 'zigzag', 'meander', 'wander', 'roam', 'drift', 'float',
            'hover', 'levitate', 'fly', 'soar', 'glide', 'swoop', 'dive', 'plunge',
            'plummet', 'fall', 'drop', 'sink', 'descend', 'lower', 'decline', 'decrease',
            'reduce', 'diminish', 'shrink', 'contract', 'compress', 'condense', 'concentrate',
            'dilute', 'thin', 'weaken', 'soften', 'loosen', 'relax', 'ease', 'calm',
            'soothe', 'comfort', 'console', 'reassure', 'encourage', 'inspire', 'motivate',
            'stimulate', 'excite', 'arouse', 'provoke', 'incite', 'inflame', 'ignite',
            'spark', 'fuel', 'feed', 'nourish', 'sustain', 'maintain', 'preserve',
            'conserve', 'save', 'store', 'keep', 'retain', 'hold', 'possess', 'own',
            'have', 'get', 'obtain', 'acquire', 'gain', 'earn', 'win', 'achieve', 'attain',
            'reach', 'arrive', 'come', 'go', 'leave', 'depart', 'exit', 'enter', 'access',
            'approach', 'near', 'close', 'far', 'distant', 'remote', 'local', 'global',
            'universal', 'general', 'specific', 'particular', 'individual', 'personal',
            'private', 'public', 'common', 'shared', 'collective', 'group', 'team',
            'community', 'society', 'organization', 'institution', 'company', 'corporation',
            'business', 'enterprise', 'venture', 'project', 'program', 'initiative',
            'campaign', 'mission', 'goal', 'objective', 'target', 'aim', 'purpose',
            'reason', 'cause', 'effect', 'result', 'outcome', 'consequence', 'impact',
            'influence', 'affect', 'change', 'modify', 'alter', 'adjust', 'adapt',
            'customize', 'personalize', 'tailor', 'fit', 'suit', 'match', 'correspond',
            'relate', 'associate', 'connect', 'link', 'bind', 'tie', 'join', 'unite',
            'merge', 'combine', 'integrate', 'incorporate', 'include', 'contain', 'comprise',
            'consist', 'compose', 'form', 'shape', 'mold', 'cast', 'forge', 'craft',
            'create', 'make', 'produce', 'generate', 'yield', 'output', 'deliver', 'provide',
            'supply', 'offer', 'present', 'submit', 'propose', 'suggest', 'recommend',
            'advise', 'counsel', 'guide', 'direct', 'lead', 'manage', 'control', 'govern',
            'rule', 'regulate', 'oversee', 'supervise', 'monitor', 'track', 'follow',
            'pursue', 'seek', 'search', 'find', 'discover', 'uncover', 'reveal', 'expose',
            'disclose', 'divulge', 'share', 'communicate', 'convey', 'transmit', 'send',
            'receive', 'accept', 'reject', 'decline', 'refuse', 'deny', 'forbid', 'prohibit',
            'ban', 'block', 'prevent', 'stop', 'halt', 'cease', 'end', 'finish', 'complete',
            'conclude', 'terminate', 'close', 'shut', 'seal', 'lock', 'secure', 'protect',
            'defend', 'guard', 'shield', 'cover', 'hide', 'conceal', 'mask', 'disguise',
            'camouflage', 'cloak', 'veil', 'shroud', 'obscure', 'blur', 'fade', 'dim',
            'darken', 'shadow', 'shade', 'tint', 'color', 'paint', 'dye', 'stain', 'mark',
            'label', 'tag', 'brand', 'stamp', 'print', 'write', 'inscribe', 'engrave',
            'etch', 'carve', 'sculpt', 'chisel', 'cut', 'slice', 'chop', 'dice', 'mince',
            'shred', 'tear', 'rip', 'split', 'crack', 'break', 'shatter', 'smash', 'crush',
            'grind', 'mill', 'pound', 'beat', 'whip', 'stir', 'mix', 'blend', 'combine',
            'merge', 'fuse', 'melt', 'dissolve', 'liquefy', 'evaporate', 'condense',
            'solidify', 'crystallize', 'freeze', 'thaw', 'heat', 'cool', 'warm', 'chill',
            'boil', 'simmer', 'steam', 'bake', 'roast', 'grill', 'fry', 'saute', 'broil',
            'toast', 'burn', 'char', 'scorch', 'singe', 'smoke', 'cure', 'dry', 'dehydrate',
            'rehydrate', 'moisten', 'wet', 'soak', 'saturate', 'drench', 'flood', 'submerge',
            'immerse', 'dip', 'plunge', 'dive', 'sink', 'float', 'swim', 'wade', 'splash',
            'spray', 'sprinkle', 'shower', 'rain', 'pour', 'drip', 'leak', 'seep', 'ooze',
            'flow', 'stream', 'river', 'current', 'tide', 'wave', 'ripple', 'bubble',
            'foam', 'froth', 'fizz', 'sparkle', 'glitter', 'shimmer', 'shine', 'glow',
            'radiate', 'emit', 'reflect', 'refract', 'diffract', 'scatter', 'disperse',
            'spread', 'distribute', 'allocate', 'assign', 'delegate', 'transfer', 'move',
            'shift', 'slide', 'glide', 'roll', 'tumble', 'topple', 'tip', 'tilt', 'lean',
            'slant', 'slope', 'incline', 'decline', 'ascend', 'descend', 'climb', 'scale',
            'mount', 'dismount', 'board', 'embark', 'disembark', 'land', 'dock', 'anchor',
            'moor', 'berth', 'park', 'stop', 'halt', 'pause', 'wait', 'delay', 'postpone',
            'defer', 'suspend', 'cancel', 'abort', 'terminate', 'end', 'finish', 'complete',
            'accomplish', 'achieve', 'succeed', 'fail', 'lose', 'win', 'draw', 'tie',
            'score', 'point', 'goal', 'target', 'aim', 'shoot', 'fire', 'launch', 'throw',
            'toss', 'pitch', 'hurl', 'fling', 'cast', 'drop', 'release', 'let go', 'catch',
            'grab', 'seize', 'snatch', 'take', 'give', 'hand', 'pass', 'deliver', 'transfer',
            'exchange', 'trade', 'swap', 'switch', 'replace', 'substitute', 'alternate',
            'rotate', 'cycle', 'loop', 'repeat', 'iterate', 'recurse', 'nest', 'embed',
            'encapsulate', 'wrap', 'package', 'bundle', 'group', 'collect', 'gather',
            'accumulate', 'amass', 'hoard', 'stockpile', 'store', 'warehouse', 'inventory',
            'stock', 'supply', 'provision', 'equip', 'outfit', 'furnish', 'decorate',
            'adorn', 'embellish', 'ornament', 'beautify', 'enhance', 'improve', 'upgrade',
            'update', 'modernize', 'renovate', 'restore', 'repair', 'fix', 'mend', 'patch'
        }
        
        # Additional problematic patterns that match substrings
        self.PROBLEMATIC_SUBSTRING_PATTERNS = set()
    
    def is_problematic_pattern(self, pattern: str) -> bool:
        """Check if a pattern is likely to cause false positives"""
        pattern_lower = pattern.lower()
        
        # Check if pattern is just a generic term
        if pattern_lower in self.GENERIC_TERMS:
            return True
        
        # Check if pattern ends with a generic term (indicating substring matching)
        for term in self.GENERIC_TERMS:
            if pattern_lower.endswith(term) and len(pattern_lower) > len(term) + 3:
                # Pattern like "conscrypt_trace_h_" matching "trace"
                self.PROBLEMATIC_SUBSTRING_PATTERNS.add(pattern)
                return True
        
        # Check for patterns that are generic term + common suffix/prefix
        generic_with_affixes = {
            'newcontext', 'oldcontext', 'getcontext', 'setcontext', 'hascontext',
            'newclass', 'oldclass', 'getclass', 'setclass', 'hasclass',
            'newerror', 'olderror', 'geterror', 'seterror', 'haserror',
            'newstore', 'oldstore', 'getstore', 'setstore', 'hasstore',
            'newfactory', 'oldfactory', 'getfactory', 'setfactory', 'hasfactory',
            'newprocess', 'oldprocess', 'getprocess', 'setprocess', 'hasprocess',
            'testclass', 'testcontext', 'testerror', 'teststore', 'testfactory',
            'httpcontext', 'httpclass', 'httperror', 'httpstore', 'httpfactory',
            'httpprocessor', 'httphandler', 'httpfilter', 'httprequest', 'httpresponse'
        }
        
        if pattern_lower in generic_with_affixes:
            return True
        
        # Check for patterns that contain only generic terms
        words = pattern_lower.split('_')
        if all(word in self.GENERIC_TERMS for word in words if word):
            return True
        
        return False
    
    def clean_signature_file(self, file_path: Path) -> int:
        """Clean a single signature file and return number of patterns removed"""
        print(f"\nProcessing {file_path.name}...")
        
        # Backup original
        backup_path = file_path.with_suffix('.json.backup2')
        if not backup_path.exists():
            shutil.copy2(file_path, backup_path)
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        original_count = len(data.get('signatures', []))
        cleaned_signatures = []
        removed_patterns = []
        
        for sig in data.get('signatures', []):
            pattern = sig.get('pattern', '')
            
            if self.is_problematic_pattern(pattern):
                removed_patterns.append(pattern)
                self.stats['removed'] += 1
                self.stats[f'removed_from_{file_path.stem}'] += 1
            else:
                cleaned_signatures.append(sig)
                self.stats['kept'] += 1
        
        # Update signatures
        data['signatures'] = cleaned_signatures
        
        # Update metadata
        if 'signature_metadata' in data:
            data['signature_metadata']['signature_count'] = len(cleaned_signatures)
            data['signature_metadata']['cleaned'] = True
            data['signature_metadata']['cleaning_version'] = '2.0'
        
        # Write back
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        removed_count = original_count - len(cleaned_signatures)
        if removed_count > 0:
            print(f"  Removed {removed_count} patterns from {file_path.name}")
            print(f"  Examples: {removed_patterns[:5]}")
        
        return removed_count
    
    def clean_all_signatures(self):
        """Clean all signature files"""
        print("Starting aggressive signature cleanup...")
        print(f"Identified {len(self.GENERIC_TERMS)} generic terms to filter")
        
        total_removed = 0
        
        for json_file in sorted(self.signatures_dir.glob("*.json")):
            if json_file.name == "manifest.json" or json_file.name == "template.json":
                continue
            
            removed = self.clean_signature_file(json_file)
            total_removed += removed
        
        print(f"\n=== Cleanup Summary ===")
        print(f"Total patterns removed: {total_removed}")
        print(f"Total patterns kept: {self.stats['kept']}")
        print(f"Problematic substring patterns found: {len(self.PROBLEMATIC_SUBSTRING_PATTERNS)}")
        
        if self.PROBLEMATIC_SUBSTRING_PATTERNS:
            print("\nExamples of problematic substring patterns:")
            for pattern in list(self.PROBLEMATIC_SUBSTRING_PATTERNS)[:10]:
                print(f"  - {pattern}")
        
        # Show which components had the most removals
        print("\nComponents with most removals:")
        component_removals = [(k.replace('removed_from_', ''), v) 
                            for k, v in self.stats.items() 
                            if k.startswith('removed_from_')]
        component_removals.sort(key=lambda x: x[1], reverse=True)
        
        for comp, count in component_removals[:10]:
            if count > 0:
                print(f"  {comp}: {count} patterns removed")

def main():
    import sys
    
    if len(sys.argv) > 1:
        signatures_dir = Path(sys.argv[1])
    else:
        signatures_dir = Path(__file__).parent.parent / "signatures"
    
    if not signatures_dir.exists():
        print(f"Error: Signatures directory not found: {signatures_dir}")
        sys.exit(1)
    
    cleaner = AggressiveSignatureCleaner(signatures_dir)
    cleaner.clean_all_signatures()

if __name__ == "__main__":
    main()
