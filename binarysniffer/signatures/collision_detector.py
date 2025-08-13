"""
Cross-signature collision detection for improving signature quality
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class SignatureCollisionDetector:
    """Detects patterns that appear across multiple component signatures"""
    
    def __init__(self, signatures_dir: Optional[Path] = None):
        """
        Initialize collision detector.
        
        Args:
            signatures_dir: Directory containing signature JSON files
        """
        self.signatures_dir = signatures_dir or Path(__file__).parent.parent.parent / "signatures"
        self.component_patterns = {}  # component_name -> set of patterns
        self.pattern_components = defaultdict(set)  # pattern -> set of component names
        self._load_existing_signatures()
    
    def _load_existing_signatures(self):
        """Load all existing signatures from JSON files"""
        if not self.signatures_dir.exists():
            logger.warning(f"Signatures directory not found: {self.signatures_dir}")
            return
        
        json_files = list(self.signatures_dir.glob("*.json"))
        logger.info(f"Loading {len(json_files)} signature files for collision detection")
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Extract component name
                component_name = data.get('component', {}).get('name', json_file.stem)
                
                # Extract patterns
                patterns = set()
                
                # Handle different signature formats
                if 'signatures' in data:
                    # New format with signature objects
                    for sig in data['signatures']:
                        if 'pattern' in sig:
                            patterns.add(sig['pattern'])
                elif 'symbols' in data:
                    # Old format with direct symbols array
                    patterns.update(data['symbols'])
                
                if patterns:
                    self.component_patterns[component_name] = patterns
                    # Build reverse index
                    for pattern in patterns:
                        self.pattern_components[pattern].add(component_name)
                
            except Exception as e:
                logger.debug(f"Error loading {json_file}: {e}")
    
    def check_collisions(self, patterns: List[str], 
                        component_name: Optional[str] = None) -> Dict[str, List[str]]:
        """
        Check which patterns collide with existing signatures.
        
        Args:
            patterns: List of patterns to check
            component_name: Name of component being created (to exclude self)
            
        Returns:
            Dictionary mapping patterns to list of components they appear in
        """
        collisions = {}
        
        for pattern in patterns:
            if pattern in self.pattern_components:
                # Get components that have this pattern
                components = self.pattern_components[pattern].copy()
                
                # Exclude self if component name provided
                if component_name and component_name in components:
                    components.remove(component_name)
                
                if components:
                    collisions[pattern] = sorted(list(components))
        
        return collisions
    
    def analyze_collision_severity(self, collisions: Dict[str, List[str]]) -> Dict[str, str]:
        """
        Analyze how severe each collision is.
        
        Returns severity levels:
        - 'critical': Pattern appears in 5+ unrelated components (likely generic)
        - 'high': Pattern appears in 3-4 components
        - 'medium': Pattern appears in 2 components from different families
        - 'low': Pattern appears in 2 related components (e.g., ffmpeg/libav)
        """
        severity_map = {}
        
        # Define related component families
        related_families = [
            {'ffmpeg', 'libav', 'avcodec', 'avformat', 'avutil', 'swscale', 'swresample'},
            {'openssl', 'libressl', 'boringssl', 'crypto', 'ssl'},
            {'gstreamer', 'gst-plugins', 'glib', 'gobject'},
            {'qt', 'qt5', 'qt6', 'qtcore', 'qtgui'},
            {'boost', 'boost-system', 'boost-thread', 'boost-filesystem'},
            {'apache', 'apache-commons', 'apache-http'},
        ]
        
        for pattern, components in collisions.items():
            component_count = len(components)
            
            if component_count >= 5:
                severity_map[pattern] = 'critical'
            elif component_count >= 3:
                severity_map[pattern] = 'high'
            elif component_count == 2:
                # Check if components are related
                components_lower = {c.lower() for c in components}
                is_related = False
                
                for family in related_families:
                    matching = sum(1 for c in components_lower 
                                 for f in family if f in c)
                    if matching >= 2:
                        is_related = True
                        break
                
                severity_map[pattern] = 'low' if is_related else 'medium'
            else:
                severity_map[pattern] = 'low'
        
        return severity_map
    
    def get_collision_report(self, patterns: List[str], 
                            component_name: Optional[str] = None) -> Dict:
        """
        Generate a comprehensive collision report.
        
        Returns:
            Report with collisions, severity analysis, and recommendations
        """
        collisions = self.check_collisions(patterns, component_name)
        
        if not collisions:
            return {
                'has_collisions': False,
                'collision_count': 0,
                'patterns_checked': len(patterns),
                'message': 'No collisions detected with existing signatures'
            }
        
        severity_map = self.analyze_collision_severity(collisions)
        
        # Count by severity
        severity_counts = defaultdict(int)
        for severity in severity_map.values():
            severity_counts[severity] += 1
        
        # Identify most problematic patterns
        critical_patterns = [p for p, s in severity_map.items() if s == 'critical']
        high_patterns = [p for p, s in severity_map.items() if s == 'high']
        
        return {
            'has_collisions': True,
            'collision_count': len(collisions),
            'patterns_checked': len(patterns),
            'collisions': collisions,
            'severity_map': severity_map,
            'severity_counts': dict(severity_counts),
            'critical_patterns': critical_patterns[:10],  # Top 10
            'high_patterns': high_patterns[:10],
            'recommendations': self._generate_recommendations(severity_counts, collisions)
        }
    
    def _generate_recommendations(self, severity_counts: Dict[str, int], 
                                 collisions: Dict[str, List[str]]) -> List[str]:
        """Generate actionable recommendations based on collision analysis"""
        recommendations = []
        
        if severity_counts.get('critical', 0) > 0:
            recommendations.append(
                f"Remove {severity_counts['critical']} critical patterns that appear "
                "in 5+ components (likely generic)"
            )
        
        if severity_counts.get('high', 0) > 5:
            recommendations.append(
                "Consider removing high-collision patterns appearing in 3-4 components"
            )
        
        if severity_counts.get('medium', 0) > 10:
            recommendations.append(
                "Review medium-severity collisions for potential false positives"
            )
        
        # Check for specific problematic patterns
        for pattern, components in collisions.items():
            if len(components) >= 10:
                recommendations.append(
                    f"Pattern '{pattern}' appears in {len(components)} components - "
                    "strongly consider removing"
                )
                break  # Just show one example
        
        if not recommendations:
            if severity_counts.get('low', 0) > 0:
                recommendations.append(
                    "Low-severity collisions detected with related components - "
                    "this is usually acceptable"
                )
        
        return recommendations
    
    def filter_colliding_patterns(self, patterns: List[str], 
                                 severity_threshold: str = 'high',
                                 component_name: Optional[str] = None) -> Tuple[List[str], List[str]]:
        """
        Filter out patterns that collide above a severity threshold.
        
        Args:
            patterns: List of patterns to filter
            severity_threshold: Remove patterns at or above this severity
                               ('low', 'medium', 'high', 'critical')
            component_name: Name of component being created
            
        Returns:
            Tuple of (kept_patterns, removed_patterns)
        """
        severity_levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        threshold_level = severity_levels.get(severity_threshold, 3)
        
        collisions = self.check_collisions(patterns, component_name)
        severity_map = self.analyze_collision_severity(collisions)
        
        kept = []
        removed = []
        
        for pattern in patterns:
            if pattern in severity_map:
                pattern_level = severity_levels.get(severity_map[pattern], 0)
                if pattern_level >= threshold_level:
                    removed.append(pattern)
                else:
                    kept.append(pattern)
            else:
                kept.append(pattern)
        
        return kept, removed
    
    def interactive_review(self, patterns: List[str], 
                          component_name: Optional[str] = None) -> List[str]:
        """
        Interactive review of colliding patterns.
        
        Args:
            patterns: List of patterns to review
            component_name: Name of component being created
            
        Returns:
            List of patterns after user review
        """
        from rich.console import Console
        from rich.table import Table
        from rich.prompt import Confirm
        
        console = Console()
        
        collisions = self.check_collisions(patterns, component_name)
        if not collisions:
            console.print("[green]No collisions detected![/green]")
            return patterns
        
        severity_map = self.analyze_collision_severity(collisions)
        
        # Group by severity for review
        by_severity = defaultdict(list)
        for pattern, severity in severity_map.items():
            by_severity[severity].append(pattern)
        
        kept_patterns = []
        removed_patterns = []
        
        # Review critical and high severity
        for severity in ['critical', 'high']:
            if severity not in by_severity:
                continue
            
            console.print(f"\n[bold red]Reviewing {severity.upper()} severity collisions:[/bold red]")
            
            for pattern in by_severity[severity]:
                components = collisions[pattern]
                
                # Show collision details
                table = Table(title=f"Pattern: '{pattern}'")
                table.add_column("Appears in", style="yellow")
                for comp in components[:5]:  # Show first 5
                    table.add_row(comp)
                if len(components) > 5:
                    table.add_row(f"... and {len(components)-5} more")
                
                console.print(table)
                
                # Ask user
                keep = Confirm.ask(
                    f"Keep this pattern? (appears in {len(components)} components)",
                    default=False if severity == 'critical' else True
                )
                
                if keep:
                    kept_patterns.append(pattern)
                else:
                    removed_patterns.append(pattern)
        
        # Auto-keep medium and low severity
        for severity in ['medium', 'low']:
            kept_patterns.extend(by_severity.get(severity, []))
        
        # Add non-colliding patterns
        for pattern in patterns:
            if pattern not in collisions:
                kept_patterns.append(pattern)
        
        # Summary
        console.print(f"\n[bold]Review Summary:[/bold]")
        console.print(f"  Kept: {len(kept_patterns)} patterns")
        console.print(f"  Removed: {len(removed_patterns)} patterns")
        
        if removed_patterns:
            console.print(f"\n[yellow]Removed patterns:[/yellow]")
            for p in removed_patterns[:10]:
                console.print(f"  - {p}")
            if len(removed_patterns) > 10:
                console.print(f"  ... and {len(removed_patterns)-10} more")
        
        return kept_patterns