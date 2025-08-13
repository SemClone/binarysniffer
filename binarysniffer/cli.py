"""
Command-line interface for BinarySniffer
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from tabulate import tabulate

from .core.analyzer_enhanced import EnhancedBinarySniffer
from .core.config import Config
from .core.results import BatchAnalysisResult
from .signatures.generator import SignatureGenerator
from .__init__ import __version__


console = Console()
logger = logging.getLogger(__name__)


class CustomGroup(click.Group):
    """Custom group to show version in help"""
    def format_help(self, ctx, formatter):
        formatter.write_text(f"BinarySniffer v{__version__} - Detect OSS components in binaries\n")
        formatter.write_text("A high-performance CLI tool for detecting open source components")
        formatter.write_text("through semantic signature matching.\n")
        super().format_help(ctx, formatter)


@click.group(cls=CustomGroup, context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(version=__version__, prog_name="binarysniffer")
@click.option('--config', type=click.Path(exists=True), help='Path to configuration file')
@click.option('--data-dir', type=click.Path(), help='Override data directory')
@click.option('-v', '--verbose', count=True, help='Increase verbosity (-v for INFO, -vv for DEBUG)')
@click.option('--log-level', type=click.Choice(['ERROR', 'WARNING', 'INFO', 'DEBUG'], case_sensitive=False), 
              help='Set logging level explicitly')
@click.option('--non-deterministic', is_flag=True, help='Disable deterministic mode (allows Python hash randomization)')
@click.pass_context
def cli(ctx, config, data_dir, verbose, log_level, non_deterministic):
    """
    Semantic Copycat BinarySniffer - Detect OSS components in binaries
    """
    # Determine logging level
    if log_level:
        # Explicit log level takes precedence
        final_log_level = log_level.upper()
    else:
        # Use verbosity flags (-v, -vv)
        log_levels = {0: "WARNING", 1: "INFO", 2: "DEBUG"}
        final_log_level = log_levels.get(min(verbose, 2), "WARNING")
    
    # Load configuration
    if config:
        cfg = Config.load(Path(config))
    else:
        cfg = Config()
    
    # Override log level from CLI
    cfg.log_level = final_log_level
    
    # Override data directory if specified
    if data_dir:
        cfg.data_dir = Path(data_dir)
    
    # Store in context
    ctx.obj = {
        'config': cfg,
        'sniffer': None  # Lazy load
    }


@cli.command()
@click.argument('path', type=click.Path(exists=True))
# Basic options
@click.option('-r', '--recursive', is_flag=True, help='Analyze directories recursively')
@click.option('-t', '--threshold', type=float, default=0.5, show_default=True,
              help='Confidence threshold (0.0-1.0)')
@click.option('-p', '--patterns', multiple=True, 
              help='File patterns to match (e.g., *.exe, *.so)')
# Output options
@click.option('-o', '--output', type=click.Path(), 
              help='Save results to file (format auto-detected from extension)')
@click.option('-f', '--format', 
              type=click.Choice(['table', 'json', 'csv', 'cyclonedx', 'cdx', 'sbom', 'kissbom', 'kiss'], case_sensitive=False),
              default='table', show_default=True,
              help='Output format (sbom/cyclonedx for SBOM, kiss/kissbom for KISS BOM)')
# Performance options
@click.option('--deep', is_flag=True, 
              help='Deep analysis mode (slower, more thorough)')
@click.option('--fast', is_flag=True,
              help='Fast mode (skip TLSH fuzzy matching)')
@click.option('--parallel/--no-parallel', default=True, show_default=True,
              help='Enable parallel processing for directories')
# Hash options
@click.option('--with-hashes', is_flag=True,
              help='Include all hashes (MD5, SHA1, SHA256, TLSH, ssdeep)')
@click.option('--basic-hashes', is_flag=True,
              help='Include only basic hashes (MD5, SHA1, SHA256)')
# Filtering options
@click.option('--min-matches', type=int, default=0,
              help='Minimum pattern matches to show component')
# License options
@click.option('--license-focus', is_flag=True,
              help='Focus on license detection and compliance')
@click.option('--license-only', is_flag=True,
              help='Only detect licenses, skip component detection')
# Debug options
@click.option('--show-evidence', is_flag=True,
              help='Show detailed match evidence')
@click.option('--show-features', is_flag=True,
              help='Display extracted features (for debugging)')
@click.option('--save-features', type=click.Path(),
              help='Save features to JSON (for signature creation)')
# Advanced options (hidden from basic help)
@click.option('--tlsh-threshold', type=int, default=70, hidden=True,
              help='TLSH distance threshold (0-300, lower=more similar)')
@click.option('--feature-limit', type=int, default=20, hidden=True,
              help='Number of features to display per category')
# Legacy options (deprecated but kept for compatibility)
@click.option('--verbose-evidence', '-ve', is_flag=True, hidden=True,
              help='[Deprecated] Use --show-evidence')
@click.option('--min-patterns', '-m', type=int, hidden=True,
              help='[Deprecated] Use --min-matches')
@click.option('--include-hashes', is_flag=True, hidden=True,
              help='[Deprecated] Use --with-hashes')
@click.option('--include-fuzzy-hashes', is_flag=True, hidden=True,
              help='[Deprecated] Use --with-hashes')
@click.option('--use-tlsh/--no-tlsh', default=True, hidden=True,
              help='[Deprecated] Use --fast to disable')
@click.pass_context
def analyze(ctx, path, recursive, threshold, patterns, output, format, deep, fast, parallel,
            with_hashes, basic_hashes, min_matches, license_focus, license_only,
            show_evidence, show_features, save_features,
            tlsh_threshold, feature_limit, verbose_evidence, min_patterns, include_hashes, 
            include_fuzzy_hashes, use_tlsh):
    """
    Analyze files for open source components.
    
    \b
    EXAMPLES:
        # Basic analysis
        binarysniffer analyze app.apk
        binarysniffer analyze project/ -r
        
        # Output formats
        binarysniffer analyze app.apk -o report.json    # Auto-detect JSON
        binarysniffer analyze app.apk --sbom -o sbom.json
        binarysniffer analyze app.apk -f csv -o results.csv
        
        # Performance modes
        binarysniffer analyze large.bin --fast          # Quick scan
        binarysniffer analyze app.apk --deep            # Thorough analysis
        
        # With hashes
        binarysniffer analyze file.exe --with-hashes -o report.json
        
        # Filtering
        binarysniffer analyze . -r -p "*.so" -p "*.dll"
        binarysniffer analyze app.apk -t 0.8            # High confidence only
        binarysniffer analyze lib.so --min-matches 5    # 5+ pattern matches
    """
    # Initialize sniffer (always use enhanced mode for better detection)
    if ctx.obj['sniffer'] is None:
        ctx.obj['sniffer'] = EnhancedBinarySniffer(ctx.obj['config'])
    
    sniffer = ctx.obj['sniffer']
    
    # Set defaults for new options
    threshold = threshold or ctx.obj['config'].min_confidence
    
    # Handle deprecated options with warnings
    if verbose_evidence:
        console.print("[yellow]Warning: --verbose-evidence is deprecated, using --show-evidence[/yellow]")
        show_evidence = True
    
    if min_patterns and min_patterns > 0:
        console.print("[yellow]Warning: --min-patterns is deprecated, using --min-matches[/yellow]")
        min_matches = min_patterns
    
    if include_hashes or include_fuzzy_hashes:
        console.print("[yellow]Warning: --include-hashes/--include-fuzzy-hashes are deprecated, using --with-hashes[/yellow]")
        with_hashes = True
    
    # Handle new hash options
    if basic_hashes:
        include_hashes = True
        include_fuzzy_hashes = False
    elif with_hashes:
        include_hashes = True
        include_fuzzy_hashes = True
    else:
        include_hashes = False
        include_fuzzy_hashes = False
    
    # Handle performance modes
    if fast:
        use_tlsh = False
        deep = False
    elif deep:
        use_tlsh = True
    
    # Auto-detect format from output filename if not specified
    if output and format == 'table':
        output_path = Path(output)
        if output_path.suffix.lower() == '.json':
            format = 'json'
        elif output_path.suffix.lower() == '.csv':
            format = 'csv'
        elif output_path.suffix.lower() in ('.sbom', '.cdx'):
            format = 'cyclonedx'
        elif output_path.suffix.lower() in ('.kissbom', '.kiss', '.bom'):
            format = 'kissbom'
    
    # Handle format aliases
    if format == 'sbom':
        format = 'cyclonedx'
    
    path = Path(path)
    
    # Check for updates if auto-update is enabled
    if ctx.obj['config'].auto_update:
        if sniffer.check_updates():
            console.print("[yellow]Updates available. Run 'binarysniffer update' to get latest signatures.[/yellow]")
    
    start_time = time.time()
    
    try:
        if path.is_file():
            # Single file analysis
            # Enable show_features if show_evidence is set (to get archive contents)
            effective_show_features = show_features or show_evidence
            with console.status(f"Analyzing {path.name}..."):
                result = sniffer.analyze_file(
                    path, threshold, deep, effective_show_features,
                    use_tlsh=use_tlsh, tlsh_threshold=tlsh_threshold,
                    include_hashes=include_hashes,
                    include_fuzzy_hashes=include_fuzzy_hashes
                )
            results = {str(path): result}
            # Create BatchAnalysisResult for single file
            batch_result = BatchAnalysisResult(
                results=results,
                total_files=1,
                successful_files=1 if not result.error else 0,
                failed_files=1 if result.error else 0,
                total_time=time.time() - start_time
            )
        else:
            # Directory analysis
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                task = progress.add_task("Analyzing files...", total=None)
                
                batch_result = sniffer.analyze_directory(
                    path,
                    recursive=recursive,
                    file_patterns=list(patterns) if patterns else None,
                    confidence_threshold=threshold,
                    parallel=parallel
                )
                results = batch_result.results
                
                progress.update(task, completed=len(results))
        
        # Add license detection if requested
        if license_focus or license_only:
            # Perform license analysis
            license_result = sniffer.analyze_licenses(path, include_dependencies=True)
            
            if license_only:
                # Replace results with only license information
                console.print("\n[bold]License Detection Results:[/bold]")
                output_license_table(license_result, check_compatibility=True, show_files=False)
                return
            else:
                # Add license information to existing results
                console.print("\n[bold cyan]Additional License Information:[/bold cyan]")
                if license_result['licenses_detected']:
                    console.print(f"Detected licenses: {', '.join(license_result['licenses_detected'])}")
                    
                    # Add license information to each result
                    for file_path, result in batch_result.results.items():
                        # Check if this file has license detections
                        file_licenses = []
                        for license_id, details in license_result.get('license_details', {}).items():
                            if file_path in details.get('files', []):
                                file_licenses.append(license_id)
                        
                        # Add to result metadata
                        if file_licenses and not result.error:
                            if not hasattr(result, 'detected_licenses'):
                                result.detected_licenses = file_licenses
                else:
                    console.print("[yellow]No licenses detected[/yellow]")
        
        # Add file hashes if requested
        if include_hashes or include_fuzzy_hashes:
            from binarysniffer.utils.file_metadata import calculate_file_hashes
            for file_path, result in results.items():
                if not result.error:
                    try:
                        hashes = calculate_file_hashes(Path(file_path), include_fuzzy=include_fuzzy_hashes)
                        # Add hashes to the result - we'll need to update the AnalysisResult class
                        if not hasattr(result, 'file_hashes'):
                            result.file_hashes = hashes
                    except Exception as e:
                        logger.debug(f"Failed to calculate hashes for {file_path}: {e}")
        
        # Update batch result with timing if needed
        if not hasattr(batch_result, 'total_time'):
            batch_result.total_time = time.time() - start_time
        
        # Save features to file if requested
        if save_features:
            save_extracted_features(batch_result, save_features)
        
        # Output results
        if format == 'json':
            output_json(batch_result, output, min_matches, show_evidence)
        elif format == 'csv':
            output_csv(batch_result, output, min_matches)
        elif format in ('cyclonedx', 'cdx'):
            output_cyclonedx(batch_result, output, show_features)
        elif format in ('kissbom', 'kiss'):
            # Determine KISS BOM format type
            kiss_format = 'json'  # Default
            if output and output.endswith('.txt'):
                kiss_format = 'table'
            output_kissbom(batch_result, output, kiss_format)
        else:
            output_table(batch_result, min_matches, show_evidence, show_features, feature_limit)
        
        # Summary - only show for table format or when output to file
        if format == 'table' or output:
            console.print(f"\n[green]Analysis complete![/green]")
            console.print(f"Files analyzed: {batch_result.total_files}")
            console.print(f"Components found: {len(batch_result.all_components)}")
            console.print(f"Time elapsed: {batch_result.total_time:.2f}s")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("Analysis failed")
        sys.exit(1)


@cli.command()
@click.argument('package_path', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), help='Output file (format auto-detected from extension)')
@click.option('-f', '--format', type=click.Choice(['json', 'csv', 'tree', 'summary']), default='summary',
              show_default=True, help='Output format')
@click.option('--analyze', is_flag=True, help='Deep analysis (extract and analyze contents)')
@click.option('--with-hashes', is_flag=True, help='Include all hashes (MD5, SHA1, SHA256, TLSH, ssdeep)')
@click.option('--with-components', is_flag=True, help='Detect OSS components in files')
@click.option('-v', '--verbose', is_flag=True, help='Detailed output')
# Legacy options
@click.option('--include-hashes', is_flag=True, hidden=True, help='[Deprecated] Use --with-hashes')
@click.option('--include-fuzzy-hashes', is_flag=True, hidden=True, help='[Deprecated] Use --with-hashes')
@click.option('--detect-components', is_flag=True, hidden=True, help='[Deprecated] Use --with-components')
def inventory(package_path, output, format, analyze, with_hashes, with_components, verbose,
              include_hashes, include_fuzzy_hashes, detect_components):
    """
    Extract and export file inventory from a package/archive.
    
    \b
    EXAMPLES:
        # Quick summary
        binarysniffer inventory app.apk
        
        # Export with auto-format detection
        binarysniffer inventory app.apk -o inventory.json
        binarysniffer inventory app.jar -o files.csv
        
        # Deep analysis with hashes
        binarysniffer inventory app.apk --analyze --with-hashes -o full.json
        
        # With component detection
        binarysniffer inventory lib.jar --with-components -o components.csv
    """
    # Handle deprecated options
    if include_hashes or include_fuzzy_hashes:
        console.print("[yellow]Warning: --include-hashes/--include-fuzzy-hashes are deprecated, using --with-hashes[/yellow]")
        with_hashes = True
    
    if detect_components:
        console.print("[yellow]Warning: --detect-components is deprecated, using --with-components[/yellow]")
        with_components = True
    
    # Auto-detect format from output filename
    if output and format == 'summary':
        output_path = Path(output)
        if output_path.suffix.lower() == '.json':
            format = 'json'
        elif output_path.suffix.lower() == '.csv':
            format = 'csv'
        elif output_path.suffix.lower() == '.txt':
            format = 'tree'
    from binarysniffer.utils.inventory import (
        extract_package_inventory, 
        export_inventory_json,
        export_inventory_csv,
        export_inventory_tree,
        get_package_inventory_summary
    )
    
    package_path = Path(package_path)
    
    # Create analyzer if needed for component detection
    analyzer = None
    if detect_components:
        from binarysniffer.core.analyzer_enhanced import EnhancedBinarySniffer
        analyzer = EnhancedBinarySniffer()
    
    if format == 'summary':
        # Show summary
        summary = get_package_inventory_summary(package_path)
        console.print(summary)
    else:
        # Extract full inventory with analysis options
        status_msg = f"Extracting inventory from {package_path.name}..."
        if analyze:
            status_msg = f"Analyzing and extracting inventory from {package_path.name}..."
        
        with console.status(status_msg):
            inventory = extract_package_inventory(
                package_path,
                analyzer=analyzer,
                analyze_contents=analyze,
                include_hashes=with_hashes,
                include_fuzzy_hashes=with_hashes,  # Both included when --with-hashes
                detect_components=with_components
            )
        
        if 'error' in inventory:
            console.print(f"[red]Error: {inventory['error']}[/red]")
            return
        
        if output:
            output_path = Path(output)
            if format == 'json':
                export_inventory_json(inventory, output_path)
            elif format == 'csv':
                export_inventory_csv(inventory, output_path)
            elif format == 'tree':
                export_inventory_tree(inventory, output_path)
            console.print(f"[green]Inventory exported to {output_path}[/green]")
        else:
            # Print to console
            if format == 'json':
                console.print(json.dumps(inventory, indent=2, default=str))
            elif format == 'csv':
                # Print CSV to console - use same export function logic
                from io import StringIO
                import csv
                csv_buffer = StringIO()
                
                # Determine fieldnames based on available data
                fieldnames = ['path', 'size', 'compressed_size', 'compression_ratio', 
                            'compression_method', 'mime_type', 'modified', 'crc', 'is_directory']
                
                # Add optional fields if present
                if any('features_extracted' in f for f in inventory.get('files', [])):
                    fieldnames.append('features_extracted')
                if any('hashes' in f for f in inventory.get('files', [])):
                    fieldnames.extend(['md5', 'sha1', 'sha256', 'tlsh', 'ssdeep'])
                if any('components' in f for f in inventory.get('files', [])):
                    fieldnames.extend(['components_detected', 'top_component', 'top_confidence'])
                
                writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for file_entry in inventory.get('files', []):
                    row = file_entry.copy()
                    # Flatten hash and component data
                    if 'hashes' in file_entry:
                        row.update(file_entry['hashes'])
                    if 'components' in file_entry and file_entry['components']:
                        row['components_detected'] = len(file_entry['components'])
                        row['top_component'] = file_entry['components'][0]['name']
                        row['top_confidence'] = file_entry['components'][0]['confidence']
                    writer.writerow(row)
                
                console.print(csv_buffer.getvalue())
            elif format == 'tree':
                # Generate tree in memory and print
                from io import StringIO
                tree_output = StringIO()
                # We'll need to adapt the tree export function
                console.print("[yellow]Tree format to console not fully implemented yet[/yellow]")
        
        # Show summary stats
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"Total files: {inventory['summary']['total_files']}")
        console.print(f"Total size: {inventory['summary']['total_size']:,} bytes")
        
        if inventory['summary'].get('components_detected'):
            console.print(f"\n[bold]Components detected:[/bold]")
            for component in sorted(inventory['summary']['components_detected'])[:10]:
                console.print(f"  • {component}")
        
        if inventory['summary']['file_types']:
            console.print("\n[bold]Top file types:[/bold]")
            for ext, count in sorted(inventory['summary']['file_types'].items(), 
                                    key=lambda x: x[1], reverse=True)[:5]:
                console.print(f"  {ext}: {count} files")


@cli.command()
@click.option('--force', is_flag=True, help='Force full update instead of delta')
@click.pass_context
def update(ctx, force):
    """
    Update signature database.
    
    Downloads the latest signature updates from configured sources.
    
    This is a convenience alias for 'binarysniffer signatures update'.
    """
    from .signatures.manager import SignatureManager
    from .storage.database import SignatureDatabase
    
    config = ctx.obj['config']
    db = SignatureDatabase(config.db_path)
    manager = SignatureManager(config, db)
    
    console.print("Updating signatures from GitHub...")
    
    with console.status("Downloading from GitHub..."):
        downloaded = manager.download_from_github()
    
    if downloaded > 0:
        console.print(f"[green]Downloaded {downloaded} signature files[/green]")
        
        with console.status("Importing downloaded signatures..."):
            imported = manager.import_directory(
                config.data_dir / "downloaded_signatures", 
                force=force
            )
        
        console.print(f"[green]Imported {imported} signatures from GitHub[/green]")
    else:
        console.print("[yellow]No updates available or download failed[/yellow]")


@cli.command()
@click.pass_context
def stats(ctx):
    """Show signature database statistics."""
    from .storage.database import SignatureDatabase
    
    config = ctx.obj['config']
    db = SignatureDatabase(config.db_path)
    
    # Get statistics directly from database
    with db._get_connection() as conn:
        cursor = conn.execute("SELECT COUNT(DISTINCT id) FROM components")
        component_count = cursor.fetchone()[0]
        
        cursor = conn.execute("SELECT COUNT(*) FROM signatures")
        signature_count = cursor.fetchone()[0]
        
        # Get database file size
        import os
        db_size = os.path.getsize(config.db_path) if config.db_path.exists() else 0
        
        # Count by signature type
        cursor = conn.execute("SELECT sig_type, COUNT(*) FROM signatures GROUP BY sig_type")
        sig_types = dict(cursor.fetchall())
    
    console.print("\n[bold]Signature Database Statistics[/bold]\n")
    
    # Create table
    table = Table(show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Components", f"{component_count:,}")
    table.add_row("Signatures", f"{signature_count:,}")
    table.add_row("Database Size", f"{db_size / 1024 / 1024:.1f} MB")
    
    # Signature types
    if sig_types:
        type_names = {1: "String", 2: "Function", 3: "Constant", 4: "Pattern"}
        for sig_type, count in sig_types.items():
            table.add_row(f"  {type_names.get(sig_type, 'Unknown')}", f"{count:,}")
    
    console.print(table)


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('-o', '--output', type=click.Path(), 
              help='Save report to file (format auto-detected from extension)')
@click.option('-f', '--format', 
              type=click.Choice(['table', 'json', 'csv', 'markdown'], case_sensitive=False),
              default='table', show_default=True,
              help='Output format for license report')
@click.option('--check-compatibility', is_flag=True,
              help='Check license compatibility and show warnings')
@click.option('--include-dependencies/--no-dependencies', default=True,
              help='Include license detection in dependencies')
@click.option('--show-files', is_flag=True,
              help='Show which files contain each license')
@click.pass_context
def license(ctx, path, output, format, check_compatibility, include_dependencies, show_files):
    """Analyze licenses in files and directories.
    
    \b
    EXAMPLES:
        # Analyze licenses in a project
        binarysniffer license /path/to/project
        
        # Generate license report
        binarysniffer license app.apk -o licenses.json
        
        # Check license compatibility
        binarysniffer license project/ --check-compatibility
        
        # Show which files contain licenses
        binarysniffer license src/ --show-files
    """
    # Get or create sniffer instance
    sniffer = ctx.obj.get('sniffer')
    if not sniffer:
        from .core.analyzer_enhanced import EnhancedBinarySniffer
        sniffer = EnhancedBinarySniffer(ctx.obj['config'])
        ctx.obj['sniffer'] = sniffer
    
    path = Path(path)
    
    with console.status(f"Analyzing licenses in {path}..."):
        license_result = sniffer.analyze_licenses(path, include_dependencies)
    
    # Format output
    if format == 'json':
        output_license_json(license_result, output)
    elif format == 'csv':
        output_license_csv(license_result, output)
    elif format == 'markdown':
        output_license_markdown(license_result, output)
    else:  # table format
        output_license_table(license_result, check_compatibility, show_files)


@cli.command()
@click.pass_context
def config(ctx):
    """Show current configuration."""
    cfg = ctx.obj['config']
    
    console.print("\n[bold]BinarySniffer Configuration[/bold]\n")
    
    # Create table
    table = Table(show_header=False)
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")
    
    # Add configuration items
    for key, value in cfg.to_dict().items():
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        table.add_row(key.replace('_', ' ').title(), str(value))
    
    console.print(table)
    console.print(f"\nConfiguration file: {cfg.data_dir / 'config.json'}")


@cli.group(name='signatures')
@click.pass_context
def signatures(ctx):
    """Manage signature database."""
    pass


@signatures.command(name='status')
@click.pass_context
def signatures_status(ctx):
    """Show signature database status and verify import."""
    from .signatures.manager import SignatureManager
    from .storage.database import SignatureDatabase
    
    config = ctx.obj['config']
    db = SignatureDatabase(config.db_path)
    manager = SignatureManager(config, db)
    
    info = manager.get_signature_info()
    
    console.print("\n[bold]Signature Database Status[/bold]\n")
    
    table = Table(show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Database Version", info.get('database_version', 'N/A'))
    table.add_row("Packaged Version", info.get('packaged_version', 'N/A'))
    table.add_row("Sync Needed", "Yes" if info.get('sync_needed', False) else "No")
    table.add_row("Signature Count", f"{info.get('signature_count', 0):,}")
    table.add_row("Component Count", f"{info.get('component_count', 0):,}")
    
    if info.get('last_updated'):
        table.add_row("Last Updated", info['last_updated'])
    
    console.print(table)
    
    # Run verification
    console.print("\n[bold]Import Verification[/bold]\n")
    verification = manager.verify_import_status()
    summary = verification['summary']
    
    # Show summary
    verify_table = Table(show_header=False)
    verify_table.add_column("Check", style="cyan")
    verify_table.add_column("Status", style="green")
    
    verify_table.add_row("Signature Files", f"{summary['total_files']} files with {summary['total_file_signatures']} signatures")
    verify_table.add_row("Database Components", f"{summary['total_db_components']} components with {summary['total_db_signatures']} signatures")
    
    if summary['missing_in_db'] > 0:
        verify_table.add_row("Missing in DB", f"[red]{summary['missing_in_db']} components not imported[/red]")
    else:
        verify_table.add_row("Missing in DB", "[green]None - all imported[/green]")
    
    if summary['mismatches'] > 0:
        verify_table.add_row("Signature Mismatches", f"[yellow]{summary['mismatches']} components[/yellow]")
    else:
        verify_table.add_row("Signature Mismatches", "[green]None - all match[/green]")
    
    console.print(verify_table)
    
    # Show issues if any
    if verification['issues']:
        console.print("\n[bold yellow]Issues Found:[/bold yellow]")
        for issue in verification['issues'][:10]:  # Show first 10 issues
            if 'NOT IMPORTED' in issue:
                console.print(f"  [red]❌ {issue}[/red]")
            elif 'MISMATCH' in issue:
                console.print(f"  [yellow]⚠️  {issue}[/yellow]")
            elif 'PROBLEMATIC' in issue:
                console.print(f"  [red]❌ {issue}[/red]")
            else:
                console.print(f"  ⚠️  {issue}")
        
        if len(verification['issues']) > 10:
            console.print(f"  ... and {len(verification['issues']) - 10} more issues")
    
    # Recommendation
    if verification['rebuild_needed']:
        console.print("\n[bold red]Action Required:[/bold red]")
        console.print("  Database rebuild needed. Run: [cyan]binarysniffer signatures rebuild --no-github[/cyan]")
        if 'PROBLEMATIC' in ' '.join(verification['issues']):
            console.print("  Then remove problematic components from database")
    else:
        console.print("\n[bold green]✅ Database is in sync with signature files[/bold green]")


@signatures.command(name='import')
@click.option('--force', is_flag=True, help='Force reimport existing signatures')
@click.pass_context
def signatures_import(ctx, force):
    """Import packaged signatures into database."""
    from .signatures.manager import SignatureManager
    from .storage.database import SignatureDatabase
    
    config = ctx.obj['config']
    db = SignatureDatabase(config.db_path)
    manager = SignatureManager(config, db)
    
    console.print("Importing packaged signatures...")
    
    with console.status("Importing signatures..."):
        imported = manager.import_packaged_signatures(force=force)
    
    if imported > 0:
        console.print(f"[green]Imported {imported} signatures successfully![/green]")
    else:
        console.print("[yellow]No new signatures to import[/yellow]")


@signatures.command(name='rebuild')
@click.option('--github/--no-github', default=True, help='Include GitHub signatures')
@click.pass_context
def signatures_rebuild(ctx, github):
    """Rebuild signature database from scratch."""
    from .signatures.manager import SignatureManager
    from .storage.database import SignatureDatabase
    
    config = ctx.obj['config']
    db = SignatureDatabase(config.db_path)
    manager = SignatureManager(config, db)
    
    console.print("Rebuilding signature database from scratch...")
    
    with console.status("Rebuilding database..."):
        stats = manager.rebuild_database(include_github=github)
    
    console.print(f"[green]Database rebuilt successfully![/green]")
    console.print(f"  - Packaged signatures: {stats['packaged']}")
    if github:
        console.print(f"  - GitHub signatures: {stats['github']}")
    console.print(f"  - Total signatures: {stats['total']}")


@signatures.command(name='update')
@click.option('--force', is_flag=True, help='Force download even if up to date')
@click.pass_context  
def signatures_update(ctx, force):
    """Update signatures from GitHub repository."""
    from .signatures.manager import SignatureManager
    from .storage.database import SignatureDatabase
    
    config = ctx.obj['config']
    db = SignatureDatabase(config.db_path)
    manager = SignatureManager(config, db)
    
    console.print("Updating signatures from GitHub...")
    
    with console.status("Downloading from GitHub..."):
        downloaded = manager.download_from_github()
    
    if downloaded > 0:
        console.print(f"[green]Downloaded {downloaded} signature files[/green]")
        
        with console.status("Importing downloaded signatures..."):
            imported = manager.import_directory(
                config.data_dir / "downloaded_signatures", 
                force=force
            )
        
        console.print(f"[green]Imported {imported} signatures from GitHub[/green]")
    else:
        console.print("[yellow]No updates available or download failed[/yellow]")


@signatures.command(name='create')
@click.argument('path', type=click.Path(exists=True))
@click.option('--name', required=True, help='Component name (e.g., "FFmpeg", "OpenSSL")')
@click.option('--output', '-o', type=click.Path(), help='Output signature file path')
@click.option('--version', default='unknown', help='Component version')
@click.option('--license', default='', help='License (e.g., MIT, Apache-2.0, GPL-3.0)')
@click.option('--publisher', default='', help='Publisher/Author name')
@click.option('--description', default='', help='Component description')
@click.option('--type', 'input_type', type=click.Choice(['auto', 'binary', 'source']), default='auto',
              help='Input type: auto-detect, binary, or source code')
@click.option('--recursive/--no-recursive', default=True, help='Recursively analyze directories')
@click.option('--min-signatures', default=5, help='Minimum number of signatures required')
@click.option('--check-collisions/--no-check-collisions', default=False, 
              help='Check for collisions with existing signatures')
@click.option('--interactive/--no-interactive', default=False,
              help='Interactive review of colliding patterns')
@click.option('--collision-threshold', type=click.Choice(['low', 'medium', 'high', 'critical']),
              default='high', help='Auto-remove patterns at or above this collision severity')
@click.pass_context
def signatures_create(ctx, path, name, output, version, license, publisher, description, 
                     input_type, recursive, min_signatures, check_collisions, interactive,
                     collision_threshold):
    """Create signatures from a binary or source code.
    
    Examples:
    
        # Create signatures from a binary
        binarysniffer signatures create /usr/bin/ffmpeg --name FFmpeg
        
        # Create from source with full metadata
        binarysniffer signatures create /path/to/source --name MyLib \\
            --version 1.0.0 --license MIT --publisher "My Company"
    """
    from .signatures.symbol_extractor import SymbolExtractor
    from .signatures.validator import SignatureValidator
    from .signatures.collision_detector import SignatureCollisionDetector
    from datetime import datetime
    
    path = Path(path)
    
    # Auto-detect input type if needed
    if input_type == 'auto':
        if path.is_file():
            # Check if it's a binary
            try:
                with open(path, 'rb') as f:
                    header = f.read(4)
                    if header[:4] == b'\x7fELF' or header[:2] == b'MZ':
                        input_type = 'binary'
                    else:
                        input_type = 'source'
            except:
                input_type = 'source'
        else:
            input_type = 'source'
    
    console.print(f"Creating signatures for [bold]{name}[/bold] from {input_type}...")
    
    signatures = []
    
    if input_type == 'binary':
        # Extract symbols from binary
        with console.status("Extracting symbols from binary..."):
            symbols_data = SymbolExtractor.extract_symbols_from_binary(path)
            all_symbols = symbols_data.get('all', set())
            
        console.print(f"Found {len(all_symbols)} total symbols")
        
        # Generate signatures
        with console.status("Generating signatures..."):
            sig_patterns = SymbolExtractor.generate_signatures_from_binary(path, name)
            
            # Convert to signature format
            for comp_name, patterns in sig_patterns.items():
                for pattern in patterns[:50]:  # Limit to 50
                    confidence = 0.9
                    if 'version' in pattern.lower():
                        confidence = 0.95
                    elif pattern.endswith('_'):
                        confidence = 0.85
                    
                    if SignatureValidator.is_valid_signature(pattern, confidence):
                        sig_type = "prefix_pattern" if pattern.endswith('_') else "string_pattern"
                        signatures.append({
                            "id": f"{name.lower().replace(' ', '_')}_{len(signatures)}",
                            "type": sig_type,
                            "pattern": pattern,
                            "confidence": confidence,
                            "context": "binary_symbol",
                            "platforms": ["all"]
                        })
    else:
        # Use existing signature generator for source code
        generator = SignatureGenerator()
        with console.status("Analyzing source code..."):
            raw_sig = generator.generate_from_path(
                path=path,
                package_name=name,
                publisher=publisher,
                license_name=license,
                version=version,
                description=description,
                recursive=recursive,
                min_symbols=min_signatures
            )
        
        # Convert symbols to signatures
        for symbol in raw_sig.get("symbols", []):
            if SignatureValidator.is_valid_signature(symbol, 0.8):
                sig_type = "string_pattern"
                if symbol.endswith('_'):
                    sig_type = "prefix_pattern"
                elif '::' in symbol or '.' in symbol:
                    sig_type = "namespace_pattern"
                
                signatures.append({
                    "id": f"{name.lower().replace(' ', '_')}_{len(signatures)}",
                    "type": sig_type,
                    "pattern": symbol,
                    "confidence": 0.8,
                    "context": "source_code",
                    "platforms": ["all"]
                })
    
    # Collision detection if requested
    if check_collisions or interactive:
        console.print("\n[bold]Checking for signature collisions...[/bold]")
        detector = SignatureCollisionDetector()
        
        # Extract just the patterns
        patterns = [sig['pattern'] for sig in signatures]
        
        if interactive:
            # Interactive review mode
            console.print("Starting interactive collision review...")
            filtered_patterns = detector.interactive_review(patterns, name)
            
            # Rebuild signatures with filtered patterns
            original_count = len(signatures)
            signatures = [sig for sig in signatures if sig['pattern'] in filtered_patterns]
            removed_count = original_count - len(signatures)
            
            if removed_count > 0:
                console.print(f"\n[yellow]Removed {removed_count} colliding patterns[/yellow]")
        else:
            # Automatic filtering based on threshold
            report = detector.get_collision_report(patterns, name)
            
            if report['has_collisions']:
                console.print(f"\nFound {report['collision_count']} patterns with collisions:")
                
                # Show severity breakdown
                severity_counts = report['severity_counts']
                if severity_counts.get('critical', 0) > 0:
                    console.print(f"  [red]Critical: {severity_counts['critical']} patterns (5+ components)[/red]")
                if severity_counts.get('high', 0) > 0:
                    console.print(f"  [yellow]High: {severity_counts['high']} patterns (3-4 components)[/yellow]")
                if severity_counts.get('medium', 0) > 0:
                    console.print(f"  [cyan]Medium: {severity_counts['medium']} patterns (2 unrelated)[/cyan]")
                if severity_counts.get('low', 0) > 0:
                    console.print(f"  [green]Low: {severity_counts['low']} patterns (2 related)[/green]")
                
                # Show recommendations
                if report['recommendations']:
                    console.print("\n[bold]Recommendations:[/bold]")
                    for rec in report['recommendations']:
                        console.print(f"  • {rec}")
                
                # Auto-filter if not interactive
                if collision_threshold != 'none':
                    kept, removed = detector.filter_colliding_patterns(
                        patterns, collision_threshold, name
                    )
                    
                    if removed:
                        console.print(f"\n[yellow]Auto-removing {len(removed)} patterns at or above '{collision_threshold}' severity[/yellow]")
                        signatures = [sig for sig in signatures if sig['pattern'] in kept]
                        
                        # Show some examples of removed patterns
                        console.print("Removed patterns (first 5):")
                        for pattern in removed[:5]:
                            components = report['collisions'].get(pattern, [])
                            console.print(f"  - '{pattern}' (found in: {', '.join(components[:3])}...)")
            else:
                console.print("[green]✓ No collisions detected with existing signatures[/green]")
    
    # Check minimum signatures after filtering
    if len(signatures) < min_signatures:
        console.print(f"[red]Error: Only {len(signatures)} signatures remaining after filtering, " +
                     f"minimum {min_signatures} required[/red]")
        console.print("Try analyzing more files, lowering --min-signatures, or adjusting --collision-threshold")
        sys.exit(1)
    
    # Build signature file
    signature_file = {
        "component": {
            "name": name,
            "version": version,
            "category": "imported",
            "platforms": ["all"],
            "languages": ["native"] if input_type == 'binary' else ["unknown"],
            "description": description or f"Signatures for {name}",
            "license": license,
            "publisher": publisher
        },
        "signature_metadata": {
            "version": "1.0.0",
            "created": datetime.now().isoformat() + "Z",
            "updated": datetime.now().isoformat() + "Z",
            "signature_count": len(signatures),
            "confidence_threshold": 0.7,
            "source": f"{input_type}_analysis",
            "extraction_method": "symbol_extraction" if input_type == 'binary' else "ast_parsing"
        },
        "signatures": signatures
    }
    
    # Determine output path
    if not output:
        output = Path("signatures") / f"{name.lower().replace(' ', '-')}.json"
    else:
        output = Path(output)
    
    # Save signature file
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(signature_file, f, indent=2, ensure_ascii=False)
    
    console.print(f"\n[green]✓ Created {len(signatures)} signatures[/green]")
    console.print(f"Signature file saved to: [cyan]{output}[/cyan]")
    
    # Show summary
    console.print("\n[bold]Summary:[/bold]")
    table = Table(show_header=False)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Component", f"{name} v{version}")
    table.add_row("Signatures", str(len(signatures)))
    table.add_row("Input Type", input_type)
    table.add_row("License", license or "Not specified")
    table.add_row("Publisher", publisher or "Not specified")
    
    console.print(table)
    
    # Show example signatures
    console.print("\n[bold]Example signatures:[/bold]")
    for sig in signatures[:5]:
        console.print(f"  [{sig['type']}] {sig['pattern']} (confidence: {sig['confidence']})")


def save_extracted_features(batch_result: BatchAnalysisResult, output_path: str):
    """Save extracted features to a JSON file"""
    features_data = {}
    
    for file_path, result in batch_result.results.items():
        if result.extracted_features:
            features_data[file_path] = result.extracted_features.to_dict()
    
    if features_data:
        with open(output_path, 'w') as f:
            json.dump(features_data, f, indent=2)
        console.print(f"[green]Saved extracted features to {output_path}[/green]")
    else:
        console.print("[yellow]No features to save (use --show-features to enable feature collection)[/yellow]")


def output_table(batch_result: BatchAnalysisResult, min_patterns: int = 0, verbose_evidence: bool = False, show_features: bool = False, feature_limit: int = 20):
    """Output results as a table"""
    for file_path, result in batch_result.results.items():
        console.print(f"\n[bold]{file_path}[/bold]")
        console.print(f"  File size: {result.file_size:,} bytes")
        console.print(f"  File type: {result.file_type}")
        console.print(f"  Features extracted: {result.features_extracted}")
        console.print(f"  Analysis time: {result.analysis_time:.3f}s")
        
        # Show detected licenses if available
        if hasattr(result, 'detected_licenses') and result.detected_licenses:
            console.print(f"  [cyan]Detected licenses: {', '.join(result.detected_licenses)}[/cyan]")
        
        # Display extracted features if requested
        if show_features and result.extracted_features:
            console.print("\n[bold]Feature Extraction Summary:[/bold]")
            console.print(f"  Total features: {result.extracted_features.total_count}")
            
            for extractor_name, extractor_info in result.extracted_features.by_extractor.items():
                console.print(f"\n  [cyan]{extractor_name}:[/cyan]")
                console.print(f"    Features extracted: {extractor_info['count']}")
                
                if 'features_by_type' in extractor_info:
                    for feature_type, features in extractor_info['features_by_type'].items():
                        console.print(f"\n    [yellow]{feature_type.capitalize()}[/yellow] (showing first {min(len(features), feature_limit)}):")
                        for i, feature in enumerate(features[:feature_limit]):
                            # Truncate long features for display
                            display_feature = feature if len(feature) <= 80 else feature[:77] + "..."
                            console.print(f"      - {display_feature}")
        
        if result.error:
            console.print(f"[red]Error: {result.error}[/red]")
            continue
        
        if not result.matches:
            console.print("[yellow]No components detected[/yellow]")
            console.print(f"  Confidence threshold: {result.confidence_threshold}")
            continue
        
        # Filter matches based on min_patterns if specified
        filtered_matches = []
        for match in result.matches:
            pattern_count = 0
            if match.evidence:
                if 'signatures_matched' in match.evidence:
                    pattern_count = match.evidence['signatures_matched']
                elif 'signature_count' in match.evidence:
                    pattern_count = match.evidence['signature_count']
            
            if pattern_count >= min_patterns:
                filtered_matches.append(match)
        
        if not filtered_matches and min_patterns > 0:
            console.print(f"[yellow]No components with {min_patterns}+ patterns detected[/yellow]")
            console.print(f"  Confidence threshold: {result.confidence_threshold}")
            console.print(f"  Filtered out: {len(result.matches)} components")
            continue
        
        # Create matches table
        table = Table()
        table.add_column("Component", style="cyan")
        table.add_column("Confidence", style="green")
        table.add_column("License", style="yellow")
        table.add_column("Type", style="blue")
        table.add_column("Evidence", style="magenta")
        
        # Add column explanations
        if filtered_matches:
            console.print("\n[dim]Column explanations:[/dim]")
            console.print("[dim]  Type: Match type (string=exact match, library=known component)[/dim]")
            console.print("[dim]  Evidence: Number of signature patterns matched (higher=more certain)[/dim]\n")
        
        for match in sorted(filtered_matches, key=lambda m: m.confidence, reverse=True):
            evidence_str = ""
            if match.evidence:
                # Format evidence more clearly
                if 'signatures_matched' in match.evidence:
                    evidence_str = f"{match.evidence['signatures_matched']} patterns"
                elif 'signature_count' in match.evidence:
                    evidence_str = f"{match.evidence['signature_count']} patterns"
                
                if 'match_method' in match.evidence and match.evidence['match_method'] != 'direct':
                    method = match.evidence['match_method']
                    if method == 'direct string matching':
                        method = 'direct'
                    evidence_str += f" ({method})"
            
            table.add_row(
                match.component,
                f"{match.confidence:.1%}",
                match.license or "-",
                match.match_type,
                evidence_str or "-"
            )
        
        console.print(table)
        
        # Show archive contents if this was an archive and verbose mode is on
        # Note: For archives, we need extracted_features which requires --show-features or we enable it for -ve
        archive_types = ['android', 'ios', 'java', 'java_web', 'python', 'python_wheel', 
                        'nuget', 'chrome_extension', 'generic', 'zip', 'tar', 'archive']
        if verbose_evidence and (result.file_type in archive_types or 'archive' in result.file_type.lower()):
            # Check if we have processed files information
            # If show_features wasn't enabled, we don't have this info
            if hasattr(result, 'extracted_features') and result.extracted_features:
                for extractor_name, extractor_info in result.extracted_features.by_extractor.items():
                    if extractor_name == 'ArchiveExtractor' and 'metadata' in extractor_info:
                        metadata = extractor_info['metadata']
                        if 'processed_files' in metadata:
                            console.print("\n[dim]Archive Contents Analyzed:[/dim]")
                            processed = metadata['processed_files']
                            if len(processed) > 20:
                                # Show first 20 files if there are many
                                console.print(f"  [dim]Showing first 20 of {len(processed)} files:[/dim]")
                                for f in processed[:20]:
                                    console.print(f"    • {f}")
                                console.print(f"  [dim]... and {len(processed) - 20} more files[/dim]")
                            else:
                                for f in processed:
                                    console.print(f"    • {f}")
        
        # Show verbose evidence if requested
        if verbose_evidence and filtered_matches:
            console.print("\n[dim]Detailed Evidence:[/dim]")
            for match in filtered_matches:
                if match.evidence and 'matched_patterns' in match.evidence:
                    console.print(f"\n  [cyan]{match.component}[/cyan]:")
                    patterns = match.evidence['matched_patterns']
                    # Show first 10 patterns
                    for i, p in enumerate(patterns[:10]):
                        if p['pattern'] == p['matched_string']:
                            console.print(f"    • Pattern: '{p['pattern']}' (exact match, conf: {p['confidence']:.2f})")
                        else:
                            console.print(f"    • Pattern: '{p['pattern']}' matched '{p['matched_string']}' (conf: {p['confidence']:.2f})")
                    if len(patterns) > 10:
                        console.print(f"    ... and {len(patterns) - 10} more patterns")
        
        # Show summary
        console.print(f"\n  Total matches: {len(filtered_matches)}")
        if min_patterns > 0 and len(filtered_matches) < len(result.matches):
            console.print(f"  Filtered out: {len(result.matches) - len(filtered_matches)} components with <{min_patterns} patterns")
        console.print(f"  High confidence matches: {len([m for m in filtered_matches if m.confidence >= 0.8])}")
        console.print(f"  Unique components: {len(set(m.component for m in filtered_matches))}")
        if result.licenses:
            console.print(f"  Licenses detected: {', '.join(result.licenses)}")


def output_json(batch_result: BatchAnalysisResult, output_path: Optional[str], min_patterns: int = 0, verbose_evidence: bool = False):
    """Output results as JSON"""
    # Filter results if min_patterns specified
    if min_patterns > 0:
        for file_path, result in batch_result.results.items():
            filtered_matches = []
            for match in result.matches:
                pattern_count = 0
                if match.evidence:
                    if 'signatures_matched' in match.evidence:
                        pattern_count = match.evidence['signatures_matched']
                    elif 'signature_count' in match.evidence:
                        pattern_count = match.evidence['signature_count']
                if pattern_count >= min_patterns:
                    filtered_matches.append(match)
            result.matches = filtered_matches
    
    # JSON always includes full evidence data
    json_str = batch_result.to_json()
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(json_str)
        console.print(f"[green]Results saved to {output_path}[/green]")
    else:
        console.print(json_str)


def output_cyclonedx(batch_result: BatchAnalysisResult, output_path: Optional[str], include_features: bool = False):
    """Output results as CycloneDX SBOM"""
    from .output.cyclonedx_formatter import CycloneDxFormatter
    
    formatter = CycloneDxFormatter()
    sbom_json = formatter.format_results(
        batch_result,
        format_type='json',
        include_evidence=True,
        include_features=include_features
    )
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(sbom_json)
        console.print(f"[green]SBOM saved to {output_path}[/green]")
        
        # Show summary
        import json
        sbom_data = json.loads(sbom_json)
        console.print(f"[cyan]SBOM contains {len(sbom_data.get('components', []))} components[/cyan]")
    else:
        console.print(sbom_json)


def output_kissbom(batch_result: BatchAnalysisResult, output_path: Optional[str], format_type: str = 'json'):
    """Output results as KISS BOM"""
    from .output.kissbom_formatter import KissBomFormatter
    
    formatter = KissBomFormatter()
    
    # Convert BatchAnalysisResult to list of AnalysisResult
    if hasattr(batch_result, 'results'):
        # BatchAnalysisResult.results is a Dict[str, AnalysisResult]
        results = list(batch_result.results.values())
    else:
        # Single result
        results = [batch_result]
    
    kissbom_output = formatter.format_results(
        results,
        format_type=format_type,
        include_optional=False
    )
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(kissbom_output)
        console.print(f"[green]KISS BOM saved to {output_path}[/green]")
        
        # Show summary
        if format_type == 'json':
            import json
            kissbom_data = json.loads(kissbom_output)
            component_count = len(kissbom_data.get('components', kissbom_data.get('all_components', [])))
            console.print(f"[cyan]KISS BOM contains {component_count} components[/cyan]")
    else:
        console.print(kissbom_output)


def output_csv(batch_result: BatchAnalysisResult, output_path: Optional[str], min_patterns: int = 0):
    """Output results as CSV"""
    rows = []
    headers = ["File", "Component", "Confidence", "License", "Type", "Ecosystem", "Patterns"]
    
    for file_path, result in batch_result.results.items():
        if result.error:
            rows.append([file_path, "ERROR", "", "", "", "", result.error])
        elif not result.matches:
            rows.append([file_path, "NO_MATCHES", "", "", "", "", ""])
        else:
            for match in result.matches:
                pattern_count = 0
                if match.evidence:
                    if 'signatures_matched' in match.evidence:
                        pattern_count = match.evidence['signatures_matched']
                    elif 'signature_count' in match.evidence:
                        pattern_count = match.evidence['signature_count']
                
                # Filter by min_patterns
                if pattern_count >= min_patterns:
                    rows.append([
                        file_path,
                        match.component,
                        f"{match.confidence:.3f}",
                        match.license or "",
                        match.match_type,
                        match.ecosystem,
                        pattern_count
                    ])
    
    csv_content = tabulate(rows, headers=headers, tablefmt="csv")
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(csv_content)
        console.print(f"[green]Results saved to {output_path}[/green]")
    else:
        console.print(csv_content)


def output_license_table(license_result: Dict[str, Any], check_compatibility: bool, show_files: bool):
    """Output license analysis as a formatted table"""
    console.print("\n[bold]License Analysis Report[/bold]\n")
    
    # Basic info
    console.print(f"[cyan]Analysis Path:[/cyan] {license_result['analysis_path']}")
    console.print(f"[cyan]Total Components:[/cyan] {license_result['total_components']}")
    console.print(f"[cyan]Unique Licenses:[/cyan] {len(license_result['licenses_detected'])}\n")
    
    # License table
    table = Table(title="Detected Licenses")
    table.add_column("License", style="cyan")
    table.add_column("Count", style="green")
    table.add_column("Confidence", style="yellow")
    table.add_column("Components", style="magenta")
    
    license_details = license_result.get('license_details', {})
    for license_id in sorted(license_result['licenses_detected']):
        details = license_details.get(license_id, {})
        components = details.get('components', [])
        comp_str = ', '.join(components[:3])
        if len(components) > 3:
            comp_str += f" (+{len(components)-3} more)"
        
        table.add_row(
            license_id,
            str(details.get('count', 0)),
            f"{details.get('confidence', 0):.0%}",
            comp_str or "N/A"
        )
    
    console.print(table)
    
    # Show files if requested
    if show_files and license_result.get('license_files'):
        console.print("\n[bold]License Files Found:[/bold]")
        for file_path, matches in license_result['license_files'].items():
            licenses = ', '.join([m.license for m in matches])
            console.print(f"  • {file_path}: [green]{licenses}[/green]")
    
    # Compatibility check
    if check_compatibility:
        compatibility = license_result.get('compatibility', {})
        console.print("\n[bold]License Compatibility Check:[/bold]")
        
        if compatibility.get('compatible'):
            console.print("[green]✓ Licenses appear to be compatible[/green]")
        else:
            console.print("[red]✗ License compatibility issues detected[/red]")
        
        warnings = compatibility.get('warnings', [])
        if warnings:
            console.print("\n[yellow]Warnings:[/yellow]")
            for warning in warnings:
                console.print(f"  ⚠ {warning}")
        
        # Show license types
        license_types = compatibility.get('license_types', {})
        if any(license_types.values()):
            console.print("\n[bold]License Categories:[/bold]")
            if license_types.get('copyleft'):
                console.print(f"  Copyleft: {', '.join(license_types['copyleft'])}")
            if license_types.get('weak_copyleft'):
                console.print(f"  Weak Copyleft: {', '.join(license_types['weak_copyleft'])}")
            if license_types.get('permissive'):
                console.print(f"  Permissive: {', '.join(license_types['permissive'])}")
            if license_types.get('unknown'):
                console.print(f"  Unknown: {', '.join(license_types['unknown'])}")


def output_license_json(license_result: Dict[str, Any], output_path: Optional[str]):
    """Output license analysis as JSON"""
    import json
    from .core.results import ComponentMatch
    
    # Convert any sets to lists and ComponentMatch objects to dicts for JSON serialization
    def convert_for_json(obj):
        if isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, ComponentMatch):
            return obj.to_dict()
        elif isinstance(obj, dict):
            return {k: convert_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_for_json(item) for item in obj]
        return obj
    
    clean_result = convert_for_json(license_result)
    json_output = json.dumps(clean_result, indent=2)
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(json_output)
        console.print(f"[green]License report saved to {output_path}[/green]")
    else:
        console.print(json_output)


def output_license_csv(license_result: Dict[str, Any], output_path: Optional[str]):
    """Output license analysis as CSV"""
    import csv
    from io import StringIO
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    writer.writerow(['License', 'Count', 'Confidence', 'Components', 'Files'])
    
    # Data rows
    license_details = license_result.get('license_details', {})
    for license_id in sorted(license_result['licenses_detected']):
        details = license_details.get(license_id, {})
        components = ', '.join(details.get('components', []))
        files = ', '.join(details.get('files', []))
        
        writer.writerow([
            license_id,
            details.get('count', 0),
            f"{details.get('confidence', 0):.2f}",
            components,
            files
        ])
    
    csv_content = output.getvalue()
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(csv_content)
        console.print(f"[green]License report saved to {output_path}[/green]")
    else:
        console.print(csv_content)


def output_license_markdown(license_result: Dict[str, Any], output_path: Optional[str]):
    """Output license analysis as Markdown"""
    lines = []
    
    # Header
    lines.append("# License Analysis Report\n")
    lines.append(f"**Analysis Path:** `{license_result['analysis_path']}`  ")
    lines.append(f"**Total Components:** {license_result['total_components']}  ")
    lines.append(f"**Unique Licenses:** {len(license_result['licenses_detected'])}\n")
    
    # License table
    lines.append("## Detected Licenses\n")
    lines.append("| License | Count | Confidence | Components |")
    lines.append("|---------|-------|------------|------------|")
    
    license_details = license_result.get('license_details', {})
    for license_id in sorted(license_result['licenses_detected']):
        details = license_details.get(license_id, {})
        components = details.get('components', [])
        comp_str = ', '.join(components[:3])
        if len(components) > 3:
            comp_str += f" (+{len(components)-3} more)"
        
        lines.append(f"| {license_id} | {details.get('count', 0)} | "
                    f"{details.get('confidence', 0):.0%} | {comp_str or 'N/A'} |")
    
    # Compatibility
    compatibility = license_result.get('compatibility', {})
    if compatibility:
        lines.append("\n## License Compatibility\n")
        
        if compatibility.get('compatible'):
            lines.append("✅ **Licenses appear to be compatible**\n")
        else:
            lines.append("❌ **License compatibility issues detected**\n")
        
        warnings = compatibility.get('warnings', [])
        if warnings:
            lines.append("### Warnings\n")
            for warning in warnings:
                lines.append(f"- ⚠️ {warning}")
    
    # License files
    if license_result.get('license_files'):
        lines.append("\n## License Files\n")
        for file_path, matches in license_result['license_files'].items():
            licenses = ', '.join([m.license for m in matches])
            lines.append(f"- `{file_path}`: {licenses}")
    
    markdown_content = '\n'.join(lines)
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(markdown_content)
        console.print(f"[green]License report saved to {output_path}[/green]")
    else:
        console.print(markdown_content)


def main():
    """Main entry point"""
    # Check if --non-deterministic is in argv to decide on PYTHONHASHSEED
    if '--non-deterministic' not in sys.argv:
        # Default: deterministic mode
        if os.environ.get('PYTHONHASHSEED') != '0':
            # Re-execute with PYTHONHASHSEED=0 for deterministic results
            os.environ['PYTHONHASHSEED'] = '0'
            os.execv(sys.executable, [sys.executable] + sys.argv)
    
    cli(obj={})


if __name__ == "__main__":
    main()