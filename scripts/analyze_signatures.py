#!/usr/bin/env python3
"""
Analyze all signature files to identify generic patterns causing false positives.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from binarysniffer.signatures.validator import SignatureValidator


class SignatureAnalyzer:
    """Analyze signature quality and identify problematic patterns."""
    
    def __init__(self):
        self.generic_patterns = set()
        self.component_signatures = defaultdict(list)
        self.pattern_components = defaultdict(set)
        self.pattern_counts = Counter()
        self.short_patterns = []
        self.common_words = []
        self.problematic_signatures = defaultdict(list)
        
    def analyze_signature_file(self, file_path: Path) -> Dict:
        """Analyze a single signature file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            component = data.get('component', {})
            component_name = component.get('name', 'Unknown')
            signatures = data.get('signatures', [])
            
            stats = {
                'file': file_path.name,
                'component': component_name,
                'total_signatures': len(signatures),
                'valid_signatures': 0,
                'invalid_signatures': 0,
                'generic_patterns': [],
                'short_patterns': [],
                'common_words': [],
                'confidence_distribution': defaultdict(int)
            }
            
            for sig in signatures:
                pattern = sig.get('pattern', '')
                confidence = sig.get('confidence', 0.5)
                
                # Track all patterns
                self.component_signatures[component_name].append(pattern)
                self.pattern_components[pattern].add(component_name)
                self.pattern_counts[pattern] += 1
                
                # Check validity
                is_valid = SignatureValidator.is_valid_signature(pattern, confidence)
                
                if is_valid:
                    stats['valid_signatures'] += 1
                else:
                    stats['invalid_signatures'] += 1
                    self.problematic_signatures[component_name].append({
                        'pattern': pattern,
                        'confidence': confidence,
                        'reason': self._get_invalidity_reason(pattern)
                    })
                
                # Categorize problems
                if len(pattern) < 6:
                    stats['short_patterns'].append(pattern)
                    self.short_patterns.append((component_name, pattern))
                    
                if pattern.lower() in SignatureValidator.GENERIC_WORDS:
                    stats['common_words'].append(pattern)
                    self.common_words.append((component_name, pattern))
                    
                if self._is_generic_pattern(pattern):
                    stats['generic_patterns'].append(pattern)
                    self.generic_patterns.add(pattern)
                
                # Track confidence distribution
                conf_bucket = f"{int(confidence * 10) / 10:.1f}"
                stats['confidence_distribution'][conf_bucket] += 1
            
            return stats
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")
            return None
    
    def _is_generic_pattern(self, pattern: str) -> bool:
        """Check if a pattern is too generic."""
        pattern_lower = pattern.lower()
        
        # Check common programming terms
        generic_terms = {
            'get', 'set', 'init', 'create', 'delete', 'update', 'read', 'write',
            'open', 'close', 'start', 'stop', 'begin', 'end', 'load', 'save',
            'test', 'check', 'verify', 'validate', 'process', 'handle',
            'error', 'warning', 'info', 'debug', 'log', 'print',
            'string', 'number', 'array', 'list', 'map', 'dict',
            'true', 'false', 'null', 'none', 'empty'
        }
        
        if pattern_lower in generic_terms:
            return True
            
        # Check if it's a single common word
        if pattern_lower.isalpha() and len(pattern) < 8 and pattern_lower in SignatureValidator.GENERIC_WORDS:
            return True
            
        return False
    
    def _get_invalidity_reason(self, pattern: str) -> str:
        """Get the reason why a pattern is invalid."""
        if len(pattern) < 6:
            return "too_short"
        elif pattern.lower() in SignatureValidator.GENERIC_WORDS:
            return "common_word"
        elif self._is_generic_pattern(pattern):
            return "generic_pattern"
        else:
            return "other"
    
    def find_cross_component_patterns(self) -> List[Tuple[str, Set[str]]]:
        """Find patterns that appear in multiple components."""
        cross_patterns = []
        for pattern, components in self.pattern_components.items():
            if len(components) > 1:
                cross_patterns.append((pattern, components))
        
        # Sort by number of components (most problematic first)
        cross_patterns.sort(key=lambda x: len(x[1]), reverse=True)
        return cross_patterns
    
    def generate_report(self, signatures_dir: Path) -> None:
        """Generate a comprehensive report of signature analysis."""
        print("\n" + "="*80)
        print("SIGNATURE QUALITY ANALYSIS REPORT")
        print("="*80)
        
        # Analyze all signature files
        all_stats = []
        for sig_file in sorted(signatures_dir.glob("*.json")):
            if sig_file.name == "manifest.json" or sig_file.name == "template.json":
                continue
            stats = self.analyze_signature_file(sig_file)
            if stats:
                all_stats.append(stats)
        
        # Overall statistics
        total_signatures = sum(s['total_signatures'] for s in all_stats)
        total_valid = sum(s['valid_signatures'] for s in all_stats)
        total_invalid = sum(s['invalid_signatures'] for s in all_stats)
        
        print(f"\nOVERALL STATISTICS:")
        print(f"  Total signature files: {len(all_stats)}")
        print(f"  Total signatures: {total_signatures:,}")
        print(f"  Valid signatures: {total_valid:,} ({total_valid/total_signatures*100:.1f}%)")
        print(f"  Invalid signatures: {total_invalid:,} ({total_invalid/total_signatures*100:.1f}%)")
        
        # Most problematic components
        print(f"\n\nMOST PROBLEMATIC COMPONENTS (by invalid signature count):")
        problem_components = [(name, len(sigs)) for name, sigs in self.problematic_signatures.items()]
        problem_components.sort(key=lambda x: x[1], reverse=True)
        
        for name, count in problem_components[:10]:
            print(f"  {name}: {count} invalid signatures")
            # Show examples
            examples = self.problematic_signatures[name][:3]
            for ex in examples:
                print(f"    - '{ex['pattern']}' ({ex['reason']})")
        
        # Cross-component patterns (causing false positives)
        print(f"\n\nCROSS-COMPONENT PATTERNS (appearing in multiple components):")
        cross_patterns = self.find_cross_component_patterns()
        
        for pattern, components in cross_patterns[:20]:
            if len(components) > 2:  # Only show patterns in 3+ components
                print(f"  '{pattern}' appears in {len(components)} components:")
                comp_list = list(components)[:5]  # Show max 5 components
                print(f"    {', '.join(comp_list)}")
                if len(components) > 5:
                    print(f"    ... and {len(components) - 5} more")
        
        # Generic patterns
        print(f"\n\nGENERIC PATTERNS FOUND: {len(self.generic_patterns)}")
        for pattern in sorted(list(self.generic_patterns))[:20]:
            components = self.pattern_components[pattern]
            print(f"  '{pattern}' (in {len(components)} components)")
        
        # Specific problematic case: Apache HTTP Core in FFmpeg
        print(f"\n\nSPECIFIC INVESTIGATION: Apache HTTP Core patterns in other components")
        
        # Load Apache HTTP Core signatures
        httpcore_file = signatures_dir / "bsa-apache-httpcore.json"
        if httpcore_file.exists():
            with open(httpcore_file, 'r') as f:
                httpcore_data = json.load(f)
            
            httpcore_patterns = {sig['pattern'] for sig in httpcore_data.get('signatures', [])}
            
            # Check which patterns appear in other components
            for pattern in httpcore_patterns:
                if pattern in self.pattern_components:
                    components = self.pattern_components[pattern]
                    if len(components) > 1:
                        other_comps = components - {'Apache HTTP Core'}
                        if other_comps:
                            print(f"  '{pattern}' also appears in: {', '.join(other_comps)}")
        
        # Recommendations
        print(f"\n\nRECOMMENDATIONS:")
        print(f"1. Remove {len(self.generic_patterns)} generic patterns")
        print(f"2. Review {len(cross_patterns)} cross-component patterns")
        print(f"3. Increase confidence thresholds for short patterns")
        print(f"4. Add component-specific prefixes to generic patterns")
        print(f"5. Filter out common programming terms")
        
        # Generate cleanup list
        print(f"\n\nCLEANUP TARGETS:")
        cleanup_patterns = set()
        
        # Add patterns that appear in 5+ components
        for pattern, components in cross_patterns:
            if len(components) >= 5:
                cleanup_patterns.add(pattern)
        
        # Add generic patterns
        cleanup_patterns.update(self.generic_patterns)
        
        # Add very short patterns
        for _, pattern in self.short_patterns:
            if len(pattern) < 4:
                cleanup_patterns.add(pattern)
        
        print(f"Total patterns to remove: {len(cleanup_patterns)}")
        
        # Save cleanup list
        cleanup_file = signatures_dir.parent / "signature_cleanup.json"
        cleanup_data = {
            "patterns_to_remove": sorted(list(cleanup_patterns)),
            "cross_component_patterns": [
                {
                    "pattern": pattern,
                    "components": sorted(list(components)),
                    "count": len(components)
                }
                for pattern, components in cross_patterns[:50]
            ],
            "generic_patterns": sorted(list(self.generic_patterns)),
            "statistics": {
                "total_signatures": total_signatures,
                "invalid_signatures": total_invalid,
                "cleanup_target_count": len(cleanup_patterns)
            }
        }
        
        with open(cleanup_file, 'w') as f:
            json.dump(cleanup_data, f, indent=2)
        
        print(f"\nCleanup data saved to: {cleanup_file}")


def main():
    """Main entry point."""
    project_root = Path(__file__).parent.parent
    signatures_dir = project_root / "signatures"
    
    if not signatures_dir.exists():
        print(f"Error: Signatures directory not found at {signatures_dir}")
        sys.exit(1)
    
    analyzer = SignatureAnalyzer()
    analyzer.generate_report(signatures_dir)


if __name__ == "__main__":
    main()