"""
Command-line interface for BinarySniffer
"""

import os
import sys
import json
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskProgressColumn
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
@click.option('-v', '--debug', is_flag=True,
              help='Enable debug output (shows each file being processed)')
@click.option('--show-evidence', is_flag=True,
              help='Show detailed match evidence')
@click.option('--show-features', is_flag=True,
              help='Display extracted features (for debugging)')
@click.option('--save-features', type=click.Path(),
              help='Save features to JSON (for signature creation)')
@click.option('--full-export', type=click.Path(),
              help='Export ALL features without limits to JSON (includes file relationships)')
# Advanced options (hidden from basic help)
@click.option('--tlsh-threshold', type=int, default=70, hidden=True,
              help='TLSH distance threshold (0-300, lower=more similar)')
@click.option('--feature-limit', type=int, default=20, hidden=True,
              help='Number of features to display per category')
@click.option('-l', '--include-large', is_flag=True, default=False,
              help='Include large files (>50MB) in analysis')
@click.option('--skip-metadata', is_flag=True, default=False,
              help='Skip metadata files (plist, config, etc.) - speeds up analysis')
@click.option('--timeout', type=int, default=60, show_default=True,
              help='Timeout in seconds for analyzing each file')
@click.pass_context
def analyze(ctx, path, recursive, threshold, patterns, output, format, deep, fast, parallel,
            with_hashes, basic_hashes, min_matches, license_focus, license_only,
            debug, show_evidence, show_features, save_features, full_export,
            tlsh_threshold, feature_limit, include_large, skip_metadata, timeout):
    """
    Analyze files for open source components and security issues.
    
    The results show a 'Classification' column that contains either:
    - Software licenses (Apache-2.0, BSD-3-Clause, etc.) for OSS components  
    - Security severity levels (CRITICAL, HIGH, MEDIUM, LOW) for threats
    
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
    # Enable debug logging if requested
    if debug:
        import logging
        logging.basicConfig(level=logging.DEBUG,
                          format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                          force=True)
        console.print("[yellow]Debug mode enabled - showing detailed processing information[/yellow]")

    # Initialize sniffer (always use enhanced mode for better detection)
    if ctx.obj['sniffer'] is None:
        ctx.obj['sniffer'] = EnhancedBinarySniffer(ctx.obj['config'])

    sniffer = ctx.obj['sniffer']
    
    # Set defaults for new options
    threshold = threshold or ctx.obj['config'].min_confidence

    # Handle hash options properly
    include_hashes = basic_hashes or with_hashes
    include_fuzzy_hashes = with_hashes and not basic_hashes
    
    # Handle performance modes
    use_tlsh = not fast  # TLSH enabled by default, disabled in fast mode
    if fast:
        deep = False  # Fast mode disables deep analysis
    elif deep:
        use_tlsh = True  # Deep mode ensures TLSH is enabled
    
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
    
    # Set the include_large flag on the analyzer
    sniffer.include_large_files = include_large
    if not include_large:
        console.print("[dim]Note: Files >50MB will be skipped. Use --include-large to analyze them.[/dim]")

    # Set skip_metadata flag if requested
    if skip_metadata:
        sniffer.skip_metadata_files = True
        console.print("[dim]Note: Metadata files (plist, config, etc.) will be skipped.[/dim]")

    # Set the timeout value on the analyzer
    sniffer.file_timeout = timeout

    # Check for updates if auto-update is enabled
    if ctx.obj['config'].auto_update:
        if sniffer.check_updates():
            console.print("[yellow]Updates available. Run 'binarysniffer update' to get latest signatures.[/yellow]")

    start_time = time.time()
    
    try:
        if path.is_file():
            # Single file analysis
            # Enable show_features if show_evidence is set (to get archive contents)
            # Enable for full_export as well to collect all features
            effective_show_features = show_features or show_evidence or full_export
            # Set analyzer properties for single file analysis
            if hasattr(sniffer, 'tlsh_threshold'):
                sniffer.tlsh_threshold = tlsh_threshold
            if debug:
                console.print(f"[cyan]Starting analysis of: {path}[/cyan]")
                console.print(f"[dim]File size: {path.stat().st_size / (1024*1024):.1f} MB[/dim]")
            with console.status(f"Analyzing {path.name}..."):
                result = sniffer.analyze_file(
                    path, threshold, deep, effective_show_features,
                    use_tlsh=use_tlsh, tlsh_threshold=tlsh_threshold,
                    include_hashes=include_hashes,
                    include_fuzzy_hashes=include_fuzzy_hashes,
                    full_export=bool(full_export)  # Pass flag to enable full feature collection
                )
            if debug:
                if result.error:
                    console.print(f"[red]Failed: {result.error}[/red]")
                else:
                    console.print(f"[green]Completed: Found {len(result.matches)} components[/green]")
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
            # Enable show_features for full_export to collect all features
            effective_show_features = show_features or show_evidence or full_export
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                console=console
            ) as progress:
                # First, collect files to get the total count
                task = None
                current_file = None

                def update_progress(current, total, file_path=None):
                    nonlocal task, current_file
                    if file_path:
                        current_file = file_path
                        if debug:
                            console.print(f"[dim]Processing [{current}/{total}]: {file_path}[/dim]")
                    if task is None and total > 0:
                        if debug:
                            desc = f"Analyzing {total} files (current: {current_file or 'starting'})..."
                        else:
                            desc = f"Analyzing {total} files..."
                        task = progress.add_task(desc, total=total)
                    if task is not None:
                        if debug and current_file:
                            progress.update(task, completed=current, description=f"[{current}/{total}] {Path(current_file).name}")
                        else:
                            progress.update(task, completed=current)

                # For directory analysis, we need to set properties on the analyzer
                if effective_show_features:
                    sniffer.show_features = effective_show_features
                if full_export:
                    sniffer.full_export = True
                # Set TLSH threshold for directory analysis
                if hasattr(sniffer, 'tlsh_threshold'):
                    sniffer.tlsh_threshold = tlsh_threshold
                if hasattr(sniffer, 'use_tlsh'):
                    sniffer.use_tlsh = use_tlsh
                # Set hash options
                if hasattr(sniffer, 'include_hashes'):
                    sniffer.include_hashes = include_hashes
                    sniffer.include_fuzzy_hashes = include_fuzzy_hashes

                batch_result = sniffer.analyze_directory(
                    path,
                    recursive=recursive,
                    file_patterns=list(patterns) if patterns else None,
                    confidence_threshold=threshold,
                    parallel=parallel,
                    progress_callback=update_progress,
                    include_large=include_large
                )
                results = batch_result.results
        
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
        
        # Full export of all features if requested
        if full_export:
            export_all_features(batch_result, full_export)
        
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
def inventory(package_path, output, format, analyze, with_hashes, with_components, verbose):
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


@cli.command(name='ml-scan')
@click.argument('path', type=click.Path(exists=True))
@click.option('-r', '--recursive', is_flag=True, help='Scan directories recursively')
@click.option('--security-only', is_flag=True, help='Only show security findings')
@click.option('--risk-threshold', type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
              default='LOW', help='Minimum risk level to report')
@click.option('-f', '--format', type=click.Choice(['table', 'json', 'sarif', 'markdown', 'sbom']),
              default='table', help='Output format')
@click.option('-o', '--output', type=click.Path(), help='Save results to file')
@click.option('--deep', is_flag=True, help='Perform deep analysis including weight inspection')
@click.option('--sandbox', is_flag=True, help='Run analysis in isolated environment (not implemented)')
@click.option('--show-features', is_flag=True, help='Show extracted features')
@click.pass_context
def ml_scan(ctx, path, recursive, security_only, risk_threshold, format, output, deep, sandbox, show_features):
    """Perform security analysis on ML models.
    
    This command specializes in detecting malicious code, backdoors,
    and supply chain attacks in ML model files.
    
    Examples:
        binarysniffer ml-scan model.pkl
        binarysniffer ml-scan models/ --recursive --format sarif -o report.sarif
        binarysniffer ml-scan suspicious.pkl --security-only --risk-threshold HIGH
    """
    from pathlib import Path
    from binarysniffer.security.pickle_analyzer import PickleSecurityAnalyzer
    from binarysniffer.security.risk_scorer import RiskLevel
    from binarysniffer.security.obfuscation import ObfuscationDetector
    from binarysniffer.security.validators import ModelIntegrityValidator
    
    if sandbox:
        console.print("[yellow]Warning: Sandbox mode not yet implemented[/yellow]")
    
    path = Path(path)
    files_to_scan = []
    
    # Collect files to scan
    if path.is_file():
        files_to_scan = [path]
    elif path.is_dir():
        if recursive:
            # Find all ML model files
            ml_extensions = ['.pkl', '.pickle', '.p', '.onnx', '.safetensors', '.pt', '.pth', '.pb', '.h5']
            for ext in ml_extensions:
                files_to_scan.extend(path.rglob(f'*{ext}'))
        else:
            files_to_scan = [f for f in path.iterdir() if f.is_file()]
    
    if not files_to_scan:
        console.print("[yellow]No ML model files found to scan[/yellow]")
        return
    
    results = []
    risk_threshold_map = {
        'LOW': RiskLevel.LOW,
        'MEDIUM': RiskLevel.MEDIUM,
        'HIGH': RiskLevel.HIGH,
        'CRITICAL': RiskLevel.CRITICAL
    }
    min_risk = risk_threshold_map[risk_threshold]
    
    # Initialize analyzers
    pickle_analyzer = PickleSecurityAnalyzer()
    obfuscation_detector = ObfuscationDetector()
    integrity_validator = ModelIntegrityValidator()
    
    # Scan each file
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        scan_task = progress.add_task(f"Scanning {len(files_to_scan)} files...", total=len(files_to_scan))
        
        for file_path in files_to_scan:
            progress.update(scan_task, description=f"Scanning {file_path.name}...")
            
            # Determine file type
            file_type = 'unknown'
            if file_path.suffix.lower() in ['.pkl', '.pickle', '.p']:
                file_type = 'pickle'
            elif file_path.suffix.lower() == '.onnx':
                file_type = 'onnx'
            elif file_path.suffix.lower() == '.safetensors':
                file_type = 'safetensors'
            elif file_path.suffix.lower() in ['.pt', '.pth']:
                file_type = 'pytorch'
            elif file_path.suffix.lower() in ['.pb', '.h5']:
                file_type = 'tensorflow'
            
            # Perform security analysis based on file type
            if file_type == 'pickle':
                risk_assessment, features = pickle_analyzer.analyze_pickle(str(file_path))
                
                # Check obfuscation
                with open(file_path, 'rb') as f:
                    content = f.read()
                obfusc_results = obfuscation_detector.detect_obfuscation(content, features)
                
                # Validate integrity
                integrity_results = integrity_validator.validate_model(str(file_path), file_type)
                
                # Combine results
                result = {
                    'file': str(file_path),
                    'type': file_type,
                    'risk_assessment': risk_assessment,
                    'obfuscation': obfusc_results,
                    'integrity': integrity_results,
                    'features': list(features) if show_features else None
                }
                
                # Filter by risk threshold
                if risk_assessment.level.value >= min_risk.value:
                    results.append(result)
            else:
                # For other file types, use basic validation for now
                integrity_results = integrity_validator.validate_model(str(file_path), file_type)
                result = {
                    'file': str(file_path),
                    'type': file_type,
                    'integrity': integrity_results
                }
                results.append(result)
            
            progress.advance(scan_task)
    
    # Output results
    if format == 'table':
        _display_ml_security_table(results, security_only)
    elif format == 'json':
        _output_ml_security_json(results, output)
    elif format == 'sarif':
        _output_ml_security_sarif(results, output)
    elif format == 'markdown':
        _output_ml_security_markdown(results, output)
    elif format == 'sbom':
        _output_ml_security_sbom(results, output)
    
    # Summary
    if results:
        critical_count = sum(1 for r in results if 'risk_assessment' in r and r['risk_assessment'].level == RiskLevel.CRITICAL)
        high_count = sum(1 for r in results if 'risk_assessment' in r and r['risk_assessment'].level == RiskLevel.HIGH)
        
        if critical_count > 0:
            console.print(f"\n[red bold]⚠ {critical_count} CRITICAL risk files detected![/red bold]")
        if high_count > 0:
            console.print(f"[yellow]⚠ {high_count} HIGH risk files detected[/yellow]")
        
        console.print(f"\nTotal files with issues: {len(results)}/{len(files_to_scan)}")


def _display_ml_security_table(results, security_only):
    """Display ML security results in table format."""
    if not results:
        console.print("[green]✓ No security issues found[/green]")
        return
    
    table = Table(title="ML Model Security Analysis")
    table.add_column("File", style="cyan")
    table.add_column("Type", style="magenta")
    table.add_column("Risk Level", style="red")
    table.add_column("Issues", style="yellow")
    table.add_column("Recommendations", style="green")
    
    for result in results:
        file_name = Path(result['file']).name
        file_type = result['type']
        
        # Get risk level
        risk_level = "UNKNOWN"
        issues = []
        recommendations = []
        
        if 'risk_assessment' in result:
            risk = result['risk_assessment']
            risk_level = risk.level.value
            issues.extend([ind.detail for ind in risk.indicators[:3]])  # Top 3 issues
            recommendations.extend(risk.recommendations[:2])  # Top 2 recommendations
        
        if 'obfuscation' in result and result['obfuscation']['is_obfuscated']:
            issues.append("Obfuscation detected")
        
        if 'integrity' in result:
            integrity = result['integrity']
            if integrity.status.value != 'VALID':
                issues.append(f"Integrity: {integrity.status.value}")
        
        # Format for display
        issues_str = '\n'.join(issues) if issues else "None"
        recommendations_str = '\n'.join(recommendations) if recommendations else "Review model"
        
        # Color code risk level
        if risk_level == 'CRITICAL':
            risk_display = f"[red bold]{risk_level}[/red bold]"
        elif risk_level == 'HIGH':
            risk_display = f"[red]{risk_level}[/red]"
        elif risk_level == 'MEDIUM':
            risk_display = f"[yellow]{risk_level}[/yellow]"
        elif risk_level == 'LOW':
            risk_display = f"[blue]{risk_level}[/blue]"
        else:
            risk_display = f"[green]{risk_level}[/green]"
        
        table.add_row(file_name, file_type, risk_display, issues_str, recommendations_str)
    
    console.print(table)


def _output_ml_security_json(results, output_path):
    """Output ML security results in JSON format."""
    import json
    
    # Convert results to JSON-serializable format
    json_results = []
    for result in results:
        json_result = {
            'file': result['file'],
            'type': result['type']
        }
        
        if 'risk_assessment' in result:
            json_result['risk_assessment'] = result['risk_assessment'].to_dict()
        
        if 'obfuscation' in result:
            json_result['obfuscation'] = result['obfuscation']
        
        if 'integrity' in result:
            json_result['integrity'] = result['integrity'].to_dict()
        
        if 'features' in result and result['features']:
            json_result['features'] = result['features']
        
        json_results.append(json_result)
    
    output_data = {
        'scan_results': json_results,
        'summary': {
            'total_files': len(json_results),
            'critical': sum(1 for r in json_results if 'risk_assessment' in r and r['risk_assessment']['risk_assessment']['level'] == 'CRITICAL'),
            'high': sum(1 for r in json_results if 'risk_assessment' in r and r['risk_assessment']['risk_assessment']['level'] == 'HIGH'),
            'medium': sum(1 for r in json_results if 'risk_assessment' in r and r['risk_assessment']['risk_assessment']['level'] == 'MEDIUM'),
            'low': sum(1 for r in json_results if 'risk_assessment' in r and r['risk_assessment']['risk_assessment']['level'] == 'LOW'),
            'safe': sum(1 for r in json_results if 'risk_assessment' in r and r['risk_assessment']['risk_assessment']['level'] == 'SAFE')
        }
    }
    
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)
        console.print(f"[green]Results saved to {output_path}[/green]")
    else:
        console.print(json.dumps(output_data, indent=2))


def _output_ml_security_sarif(results, output_path):
    """Output ML security results in SARIF format."""
    import json
    from datetime import datetime
    
    # Create SARIF structure
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BinarySniffer-ML",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/oscarvalenzuelab/semantic-copycat-binarysniffer",
                    "rules": []
                }
            },
            "results": [],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.utcnow().isoformat() + "Z"
            }]
        }]
    }
    
    # Add rules and results
    rule_index = {}
    for result in results:
        if 'risk_assessment' not in result:
            continue
        
        risk = result['risk_assessment']
        for indicator in risk.indicators:
            # Create rule if not exists
            rule_id = f"ML-{indicator.type.upper()}"
            if rule_id not in rule_index:
                rule_index[rule_id] = len(sarif["runs"][0]["tool"]["driver"]["rules"])
                sarif["runs"][0]["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "shortDescription": {"text": indicator.type.replace('_', ' ').title()},
                    "fullDescription": {"text": indicator.detail},
                    "helpUri": f"https://attack.mitre.org/techniques/{indicator.mitre_technique}/" if indicator.mitre_technique else "",
                    "properties": {
                        "severity": indicator.severity.value
                    }
                })
            
            # Add result
            sarif["runs"][0]["results"].append({
                "ruleId": rule_id,
                "ruleIndex": rule_index[rule_id],
                "level": "error" if indicator.severity.value in ['CRITICAL', 'HIGH'] else "warning",
                "message": {"text": indicator.detail},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": result['file']
                        }
                    }
                }]
            })
    
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)
        console.print(f"[green]SARIF report saved to {output_path}[/green]")
    else:
        console.print(json.dumps(sarif, indent=2))


def _output_ml_security_markdown(results, output_path):
    """Output ML security results in Markdown format."""
    from datetime import datetime
    
    markdown = []
    markdown.append("# ML Model Security Report")
    markdown.append(f"\n**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    markdown.append(f"\n**Files Scanned**: {len(results)}")
    
    # Summary
    critical = sum(1 for r in results if 'risk_assessment' in r and r['risk_assessment'].level.value == 'CRITICAL')
    high = sum(1 for r in results if 'risk_assessment' in r and r['risk_assessment'].level.value == 'HIGH')
    
    markdown.append("\n## Summary")
    if critical > 0:
        markdown.append(f"- **🔴 CRITICAL**: {critical} files")
    if high > 0:
        markdown.append(f"- **🟠 HIGH**: {high} files")
    
    # Detailed findings
    markdown.append("\n## Detailed Findings")
    
    for result in results:
        file_name = Path(result['file']).name
        markdown.append(f"\n### {file_name}")
        markdown.append(f"- **Type**: {result['type']}")
        
        if 'risk_assessment' in result:
            risk = result['risk_assessment']
            markdown.append(f"- **Risk Level**: {risk.level.value}")
            markdown.append(f"- **Risk Score**: {risk.score}/100")
            markdown.append(f"- **Summary**: {risk.summary}")
            
            if risk.indicators:
                markdown.append("\n#### Security Indicators")
                for ind in risk.indicators[:5]:  # Top 5
                    markdown.append(f"- **{ind.severity.value}**: {ind.detail}")
            
            if risk.recommendations:
                markdown.append("\n#### Recommendations")
                for rec in risk.recommendations:
                    markdown.append(f"- {rec}")
        
        if 'obfuscation' in result and result['obfuscation']['is_obfuscated']:
            markdown.append("\n#### Obfuscation Analysis")
            markdown.append(f"- **Detected**: Yes")
            markdown.append(f"- **Confidence**: {result['obfuscation']['confidence']:.0%}")
            markdown.append(f"- **Techniques**: {', '.join(result['obfuscation']['techniques'])}")
    
    markdown_text = '\n'.join(markdown)
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(markdown_text)
        console.print(f"[green]Markdown report saved to {output_path}[/green]")
    else:
        console.print(markdown_text)


def _output_ml_security_sbom(results, output_path):
    """Output ML security results as enhanced SBOM."""
    import json
    import uuid
    from datetime import datetime
    
    # Create CycloneDX SBOM structure
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{
                "vendor": "BinarySniffer",
                "name": "ML Security Scanner",
                "version": "2.0.0"
            }]
        },
        "components": []
    }
    
    for result in results:
        component = {
            "type": "machine-learning-model",
            "bom-ref": f"model-{uuid.uuid4()}",
            "name": Path(result['file']).name,
            "properties": []
        }
        
        if 'risk_assessment' in result:
            risk = result['risk_assessment']
            component["properties"].extend([
                {"name": "security:risk-score", "value": str(risk.score)},
                {"name": "security:risk-level", "value": risk.level.value},
                {"name": "security:summary", "value": risk.summary}
            ])
            
            # Add vulnerabilities
            if "vulnerabilities" not in sbom:
                sbom["vulnerabilities"] = []
            
            for indicator in risk.indicators:
                if indicator.severity.value in ['CRITICAL', 'HIGH']:
                    sbom["vulnerabilities"].append({
                        "id": f"ML-{len(sbom['vulnerabilities'])+1:04d}",
                        "description": indicator.detail,
                        "ratings": [{
                            "severity": indicator.severity.value.lower(),
                            "method": "other"
                        }],
                        "affects": [{"ref": component["bom-ref"]}]
                    })
        
        sbom["components"].append(component)
    
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(sbom, f, indent=2)
        console.print(f"[green]SBOM saved to {output_path}[/green]")
    else:
        console.print(json.dumps(sbom, indent=2))


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
    table.add_row("License/Risk", license or "Not specified")
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


def export_all_features(batch_result: BatchAnalysisResult, output_path: str):
    """Export ALL features without limits to a comprehensive JSON file"""
    export_data = {
        "metadata": {
            "total_files": len(batch_result.results),
            "export_timestamp": datetime.now().isoformat(),
            "analysis_time": getattr(batch_result, 'total_time', 0)
        },
        "files": {}
    }
    
    total_features = 0
    for file_path, result in batch_result.results.items():
        if result.extracted_features:
            file_data = {
                "file_info": {
                    "path": file_path,
                    "size": result.file_size,
                    "type": result.file_type,
                    "analysis_time": result.analysis_time
                },
                "features": result.extracted_features.to_dict(),
                "components_detected": [
                    {
                        "name": match.component,
                        "confidence": match.confidence,
                        "version": match.version,
                        "license": match.license
                    } for match in result.matches
                ] if result.matches else []
            }
            
            # Count features
            if result.extracted_features and result.extracted_features.by_extractor:
                for extractor_data in result.extracted_features.by_extractor.values():
                    if 'features_by_type' in extractor_data:
                        for feature_list in extractor_data['features_by_type'].values():
                            total_features += len(feature_list)
            
            export_data["files"][file_path] = file_data
    
    export_data["metadata"]["total_features_extracted"] = total_features
    
    if export_data["files"]:
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2)
        console.print(f"[green]✓ Full feature export saved to {output_path}[/green]")
        console.print(f"  • Files analyzed: {len(export_data['files'])}")
        console.print(f"  • Total features extracted: {total_features:,}")
    else:
        console.print("[yellow]No features to export (use --full-export with file analysis)[/yellow]")


def output_table(batch_result: BatchAnalysisResult, min_patterns: int = 0, verbose_evidence: bool = False, show_features: bool = False, feature_limit: int = 20):
    """Output results as a table"""
    # Check if this is a multi-file analysis (directory scan)
    if len(batch_result.results) > 1:
        # Show consolidated summary for directory scans
        output_consolidated_summary(batch_result, min_patterns, verbose_evidence)
        return

    # Single file analysis - show detailed results
    for file_path, result in batch_result.results.items():
        console.print(f"\n[bold]{file_path}[/bold]")
        console.print(f"  File size: {result.file_size:,} bytes")
        console.print(f"  File type: {result.file_type}")
        console.print(f"  Features extracted: {result.features_extracted}")
        console.print(f"  Analysis time: {result.analysis_time:.3f}s")

        # Show file hashes if available
        if hasattr(result, 'file_hashes') and result.file_hashes:
            console.print("  [cyan]File Hashes:[/cyan]")
            if 'md5' in result.file_hashes:
                console.print(f"    MD5:    {result.file_hashes['md5']}")
            if 'sha1' in result.file_hashes:
                console.print(f"    SHA1:   {result.file_hashes['sha1']}")
            if 'sha256' in result.file_hashes:
                console.print(f"    SHA256: {result.file_hashes['sha256']}")
            if 'tlsh' in result.file_hashes and result.file_hashes['tlsh']:
                console.print(f"    TLSH:   {result.file_hashes['tlsh']}")
            if 'ssdeep' in result.file_hashes and result.file_hashes['ssdeep']:
                console.print(f"    ssdeep: {result.file_hashes['ssdeep']}")

        # Show package metadata if available
        if result.package_metadata:
            pkg = result.package_metadata
            meta = pkg['metadata']
            console.print(f"  [green]Package: {meta.get('name', 'Unknown')} ({pkg['package_type']})[/green]")

            # Show Maven coordinates if available
            if 'maven_groupId' in meta and 'maven_artifactId' in meta:
                console.print(f"  [green]Maven: {meta['maven_groupId']}:{meta['maven_artifactId']}")
                if 'maven_version' in meta:
                    console.print(f":{meta['maven_version']}[/green]")
                else:
                    console.print("[/green]")

            # Show homepage/URL if available
            if 'manifest_implementation_url' in meta:
                console.print(f"  [blue]Homepage: {meta['manifest_implementation_url']}[/blue]")
            elif 'manifest_bundle_homepage' in meta:
                console.print(f"  [blue]Homepage: {meta['manifest_bundle_homepage']}[/blue]")

            # Show license information
            license_info = []
            if 'extracted_license_info' in meta:
                license_info.extend(meta['extracted_license_info'])
            if 'manifest_bundle_license' in meta:
                license_info.append(f"Bundle License: {meta['manifest_bundle_license']}")

            if license_info:
                console.print(f"  [yellow]License Info:[/yellow]")
                for lic in license_info[:3]:  # Show first 3 license lines
                    console.print(f"    [yellow]{lic}[/yellow]")

            # Show structure info
            if 'class_count' in meta:
                console.print(f"  [green]Classes: {meta['class_count']:,}[/green]")
            if 'total_entries' in meta:
                console.print(f"  [green]Entries: {meta['total_entries']:,}[/green]")

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
        
        # Check for malformed or suspicious files
        if hasattr(result, 'metadata') and result.metadata:
            risk_level = result.metadata.get('risk_level', '')
            if risk_level == 'malformed':
                console.print("[red bold]⚠ WARNING: Malformed pickle file detected![/red bold]")
                console.print("  [yellow]This file appears to have an invalid structure and may be corrupted.[/yellow]")
                if result.metadata.get('suspicious_items'):
                    console.print(f"  Issues: {', '.join(result.metadata['suspicious_items'])}")
            elif risk_level == 'error':
                console.print("[orange1]⚠ File parsing error detected[/orange1]")
                console.print("  [yellow]This file could not be properly analyzed.[/yellow]")
        
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
        
        # Add warning header for malformed files
        if hasattr(result, 'metadata') and result.metadata:
            risk_level = result.metadata.get('risk_level', '')
            if risk_level == 'malformed' and any('Malformed' in m.component for m in filtered_matches):
                table.title = "[red bold]⚠ WARNING: Malformed/Corrupted File Detected[/red bold]"
                table.caption = "[yellow]This file has an invalid structure and may be corrupted or tampered with[/yellow]"
        
        table.add_column("Component", style="cyan")
        table.add_column("Confidence", style="green")
        table.add_column("Classification", style="yellow")
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
            # Check if any licenses are actually security classifications
            has_security_classifications = any(lic in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'] for lic in result.licenses)
            if has_security_classifications:
                console.print(f"  Classifications detected: {', '.join(result.licenses)}")
            else:
                console.print(f"  Licenses detected: {', '.join(result.licenses)}")


def output_consolidated_summary(batch_result: BatchAnalysisResult, min_patterns: int = 0, verbose_evidence: bool = False):
    """Output consolidated summary for directory scans"""
    from collections import defaultdict
    from rich.table import Table

    # Collect all components across all files
    component_files = defaultdict(list)  # component -> list of (file, confidence)
    component_licenses = defaultdict(set)  # component -> set of licenses
    component_max_confidence = defaultdict(float)  # component -> max confidence
    total_matches = 0
    files_with_matches = 0

    for file_path, result in batch_result.results.items():
        if result.error:
            continue

        if result.matches:
            files_with_matches += 1

        for match in result.matches:
            # Apply min_patterns filter
            pattern_count = 0
            if match.evidence:
                if 'signatures_matched' in match.evidence:
                    pattern_count = match.evidence['signatures_matched']
                elif 'signature_count' in match.evidence:
                    pattern_count = match.evidence['signature_count']

            if pattern_count >= min_patterns:
                total_matches += 1
                component_files[match.component].append((file_path, match.confidence))
                if match.license:
                    component_licenses[match.component].add(match.license)
                component_max_confidence[match.component] = max(
                    component_max_confidence[match.component],
                    match.confidence
                )

    if not component_files:
        console.print("\n[yellow]No components detected across all files[/yellow]")
        return

    # Create summary table
    console.print("\n[bold]Component Detection Summary[/bold]")
    console.print()

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", style="cyan")
    table.add_column("Max Confidence", justify="right")
    table.add_column("Files Found", justify="right")
    table.add_column("License(s)")

    # Sort by number of files found in (descending)
    sorted_components = sorted(
        component_files.items(),
        key=lambda x: (len(x[1]), component_max_confidence[x[0]]),
        reverse=True
    )

    for component, files_list in sorted_components[:50]:  # Show top 50 components
        licenses = component_licenses.get(component, set())
        license_str = ', '.join(sorted(licenses)) if licenses else "Unknown"

        # Color code confidence
        confidence = component_max_confidence[component]
        if confidence >= 0.8:
            conf_str = f"[green]{confidence:.0%}[/green]"
        elif confidence >= 0.6:
            conf_str = f"[yellow]{confidence:.0%}[/yellow]"
        else:
            conf_str = f"[red]{confidence:.0%}[/red]"

        table.add_row(
            component,
            conf_str,
            str(len(files_list)),
            license_str
        )

    console.print(table)

    if len(component_files) > 50:
        console.print(f"\n[dim]... and {len(component_files) - 50} more components[/dim]")

    # Show detailed evidence if requested
    if verbose_evidence:
        console.print("\n[bold]Evidence Details:[/bold]")

        # Show top components with evidence details
        for component, files_list in sorted_components[:10]:  # Show evidence for top 10
            console.print(f"\n  [cyan]{component}[/cyan]:")
            console.print(f"    Total files matched: {len(files_list)}")

            # Collect all evidence and files for this component
            component_evidence = {}
            file_matches = []
            match_types = set()

            for file_path, result in batch_result.results.items():
                if result.matches:
                    for match in result.matches:
                        if match.component == component:
                            # Store file and confidence
                            file_name = file_path.split('/')[-1] if '/' in file_path else file_path
                            file_matches.append((file_name, match.confidence, file_path))

                            # Collect evidence details and match types
                            if match.evidence:
                                # Collect match type
                                if 'match_method' in match.evidence:
                                    match_types.add(match.evidence['match_method'])
                                elif 'match_type' in match.evidence:
                                    match_types.add(match.evidence['match_type'])
                                else:
                                    match_types.add('direct string')

                                # Store best evidence values
                                for key, value in match.evidence.items():
                                    if key not in component_evidence or (isinstance(value, (int, float)) and value > component_evidence.get(key, 0)):
                                        component_evidence[key] = value

            # Display match types
            if match_types:
                console.print(f"    Match types: {', '.join(sorted(match_types))}")
            else:
                console.print(f"    Match types: direct string matching")

            # Display evidence details
            if component_evidence:
                if 'signature_count' in component_evidence:
                    console.print(f"    Patterns matched: {component_evidence['signature_count']}")
                elif 'signatures_matched' in component_evidence:
                    console.print(f"    Patterns matched: {component_evidence['signatures_matched']}")

                if 'bloom_probability' in component_evidence:
                    console.print(f"    Bloom filter probability: {component_evidence['bloom_probability']:.6f}")

                if 'minhash_similarity' in component_evidence:
                    console.print(f"    MinHash similarity: {component_evidence['minhash_similarity']:.2%}")

                if 'tlsh_score' in component_evidence:
                    console.print(f"    TLSH fuzzy match score: {component_evidence['tlsh_score']}")

            # Show top files where this component was found
            console.print(f"    Found in files:")
            for i, (file_name, confidence, full_path) in enumerate(sorted(file_matches, key=lambda x: x[1], reverse=True)[:5]):
                # Shorten long file names
                display_name = file_name if len(file_name) <= 50 else file_name[:47] + "..."
                console.print(f"      • {display_name} ({confidence:.0%})")
            if len(file_matches) > 5:
                console.print(f"      ... and {len(file_matches) - 5} more files")

        # Show file breakdown if not too many files
        if files_with_matches <= 50:
            console.print("\n[bold]Files with Components:[/bold]")
            file_count = 0
            for file_path, result in batch_result.results.items():
                if result.matches and not result.error:
                    components = set(m.component for m in result.matches)
                    console.print(f"  • {file_path}: {', '.join(sorted(components))}")
                    file_count += 1
                    if file_count >= 30:  # Limit to first 30 files
                        if files_with_matches > 30:
                            console.print(f"  [dim]... and {files_with_matches - 30} more files[/dim]")
                        break

    # Overall statistics
    console.print("\n[bold]Statistics:[/bold]")
    console.print(f"  Total files analyzed: {batch_result.total_files}")
    console.print(f"  Files with components: {files_with_matches}")
    console.print(f"  Unique components found: {len(component_files)}")
    console.print(f"  Total component instances: {total_matches}")

    # License summary
    all_licenses = set()
    for licenses in component_licenses.values():
        all_licenses.update(licenses)

    if all_licenses:
        console.print(f"\n[bold]Licenses Detected:[/bold]")
        for license in sorted(all_licenses):
            count = sum(1 for licenses in component_licenses.values() if license in licenses)
            console.print(f"  • {license}: {count} components")


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
    headers = ["File", "Component", "Confidence", "Classification", "Type", "Ecosystem", "Patterns"]
    
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