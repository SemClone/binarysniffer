"""
Command-line interface for BinarySniffer
"""

import sys
import json
import time
import logging
from pathlib import Path
from typing import Optional, List

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from tabulate import tabulate

from .core.analyzer import BinarySniffer
from .core.analyzer_enhanced import EnhancedBinarySniffer
from .core.config import Config
from .core.results import BatchAnalysisResult
from .signatures.generator import SignatureGenerator
from .__init__ import __version__


console = Console()
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version=__version__, prog_name="binarysniffer")
@click.option('--config', type=click.Path(exists=True), help='Path to configuration file')
@click.option('--data-dir', type=click.Path(), help='Override data directory')
@click.option('-v', '--verbose', count=True, help='Increase verbosity (-v, -vv, -vvv)')
@click.pass_context
def cli(ctx, config, data_dir, verbose):
    """
    Semantic Copycat BinarySniffer - Detect OSS components in binaries
    
    A high-performance CLI tool for detecting open source components
    through semantic signature matching.
    """
    # Setup logging
    log_levels = {0: "WARNING", 1: "INFO", 2: "DEBUG"}
    log_level = log_levels.get(verbose, "DEBUG")
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    # Load configuration
    if config:
        cfg = Config.load(Path(config))
    else:
        cfg = Config()
    
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
@click.option('--recursive', '-r', is_flag=True, help='Analyze directories recursively')
@click.option('--threshold', '-t', type=float, help='Confidence threshold (0.0-1.0)')
@click.option('--deep', is_flag=True, help='Enable deep analysis mode')
@click.option('--format', '-f', 
              type=click.Choice(['table', 'json', 'csv'], case_sensitive=False),
              default='table',
              help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
@click.option('--patterns', '-p', multiple=True, help='File patterns to match (e.g., *.exe, *.so)')
@click.option('--parallel/--no-parallel', default=True, help='Enable parallel processing')
@click.option('--enhanced', is_flag=True, help='Use enhanced detection (recommended)')
@click.pass_context
def analyze(ctx, path, recursive, threshold, deep, format, output, patterns, parallel, enhanced):
    """
    Analyze files for OSS components.
    
    Examples:
    
        # Analyze a single file
        binarysniffer analyze binary.exe
        
        # Analyze directory recursively
        binarysniffer analyze /path/to/project -r
        
        # Filter by file patterns
        binarysniffer analyze . -r -p "*.so" -p "*.dll"
        
        # Export results as JSON
        binarysniffer analyze project/ -f json -o results.json
    """
    # Initialize sniffer
    if ctx.obj['sniffer'] is None:
        if enhanced:
            ctx.obj['sniffer'] = EnhancedBinarySniffer(ctx.obj['config'])
        else:
            ctx.obj['sniffer'] = BinarySniffer(ctx.obj['config'])
    
    sniffer = ctx.obj['sniffer']
    path = Path(path)
    
    # Check for updates if auto-update is enabled
    if ctx.obj['config'].auto_update:
        if sniffer.check_updates():
            console.print("[yellow]Updates available. Run 'binarysniffer update' to get latest signatures.[/yellow]")
    
    start_time = time.time()
    
    try:
        if path.is_file():
            # Single file analysis
            with console.status(f"Analyzing {path.name}..."):
                result = sniffer.analyze_file(path, threshold, deep)
            results = {str(path): result}
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
                
                results = sniffer.analyze_directory(
                    path,
                    recursive=recursive,
                    file_patterns=list(patterns) if patterns else None,
                    confidence_threshold=threshold,
                    parallel=parallel
                )
                
                progress.update(task, completed=len(results))
        
        # Create batch result
        batch_result = BatchAnalysisResult.from_results(
            results,
            time.time() - start_time
        )
        
        # Output results
        if format == 'json':
            output_json(batch_result, output)
        elif format == 'csv':
            output_csv(batch_result, output)
        else:
            output_table(batch_result)
        
        # Summary
        console.print(f"\n[green]Analysis complete![/green]")
        console.print(f"Files analyzed: {batch_result.total_files}")
        console.print(f"Components found: {len(batch_result.all_components)}")
        console.print(f"Time elapsed: {batch_result.total_time:.2f}s")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        logger.exception("Analysis failed")
        sys.exit(1)


@cli.command()
@click.option('--force', is_flag=True, help='Force full update instead of delta')
@click.pass_context
def update(ctx, force):
    """
    Update signature database.
    
    Downloads the latest signature updates from configured sources.
    """
    # Initialize sniffer
    if ctx.obj['sniffer'] is None:
        ctx.obj['sniffer'] = BinarySniffer(ctx.obj['config'])
    
    sniffer = ctx.obj['sniffer']
    
    console.print("Checking for updates...")
    
    if not sniffer.check_updates() and not force:
        console.print("[green]Signatures are up to date![/green]")
        return
    
    console.print("Downloading updates...")
    
    with console.status("Updating signatures..."):
        success = sniffer.update_signatures(force=force)
    
    if success:
        console.print("[green]Signatures updated successfully![/green]")
        
        # Show statistics
        stats = sniffer.get_signature_stats()
        console.print(f"\nSignature Statistics:")
        console.print(f"  Components: {stats['component_count']:,}")
        console.print(f"  Signatures: {stats['signature_count']:,}")
        console.print(f"  Database size: {stats['database_size'] / 1024 / 1024:.1f} MB")
    else:
        console.print("[red]Failed to update signatures[/red]")
        sys.exit(1)


@cli.command()
@click.pass_context
def stats(ctx):
    """Show signature database statistics."""
    # Initialize sniffer
    if ctx.obj['sniffer'] is None:
        ctx.obj['sniffer'] = BinarySniffer(ctx.obj['config'])
    
    sniffer = ctx.obj['sniffer']
    stats = sniffer.get_signature_stats()
    
    console.print("\n[bold]Signature Database Statistics[/bold]\n")
    
    # Create table
    table = Table(show_header=False)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Components", f"{stats['component_count']:,}")
    table.add_row("Signatures", f"{stats['signature_count']:,}")
    table.add_row("Database Size", f"{stats['database_size'] / 1024 / 1024:.1f} MB")
    
    # Signature types
    if 'signature_types' in stats:
        type_names = {1: "String", 2: "Function", 3: "Constant", 4: "Pattern"}
        for sig_type, count in stats['signature_types'].items():
            table.add_row(f"  {type_names.get(sig_type, 'Unknown')}", f"{count:,}")
    
    # Metadata
    if 'metadata' in stats:
        table.add_row("Database Version", stats['metadata'].get('version', 'Unknown'))
    
    console.print(table)


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
    """Show signature database status."""
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


def output_table(batch_result: BatchAnalysisResult):
    """Output results as a table"""
    for file_path, result in batch_result.results.items():
        console.print(f"\n[bold]{file_path}[/bold]")
        console.print(f"  File size: {result.file_size:,} bytes")
        console.print(f"  File type: {result.file_type}")
        console.print(f"  Features extracted: {result.features_extracted}")
        console.print(f"  Analysis time: {result.analysis_time:.3f}s")
        
        if result.error:
            console.print(f"[red]Error: {result.error}[/red]")
            continue
        
        if not result.matches:
            console.print("[yellow]No components detected[/yellow]")
            console.print(f"  Confidence threshold: {result.confidence_threshold}")
            continue
        
        # Create matches table
        table = Table()
        table.add_column("Component", style="cyan")
        table.add_column("Confidence", style="green")
        table.add_column("License", style="yellow")
        table.add_column("Type", style="blue")
        table.add_column("Evidence", style="magenta")
        
        for match in sorted(result.matches, key=lambda m: m.confidence, reverse=True):
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
        
        # Show summary
        console.print(f"\n  Total matches: {len(result.matches)}")
        console.print(f"  High confidence matches: {len(result.high_confidence_matches)}")
        console.print(f"  Unique components: {len(result.unique_components)}")
        if result.licenses:
            console.print(f"  Licenses detected: {', '.join(result.licenses)}")


def output_json(batch_result: BatchAnalysisResult, output_path: Optional[str]):
    """Output results as JSON"""
    json_str = batch_result.to_json()
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(json_str)
        console.print(f"[green]Results saved to {output_path}[/green]")
    else:
        console.print(json_str)


def output_csv(batch_result: BatchAnalysisResult, output_path: Optional[str]):
    """Output results as CSV"""
    rows = []
    headers = ["File", "Component", "Confidence", "License", "Type", "Ecosystem"]
    
    for file_path, result in batch_result.results.items():
        if result.error:
            rows.append([file_path, "ERROR", "", "", "", result.error])
        elif not result.matches:
            rows.append([file_path, "NO_MATCHES", "", "", "", ""])
        else:
            for match in result.matches:
                rows.append([
                    file_path,
                    match.component,
                    f"{match.confidence:.3f}",
                    match.license or "",
                    match.match_type,
                    match.ecosystem
                ])
    
    csv_content = tabulate(rows, headers=headers, tablefmt="csv")
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(csv_content)
        console.print(f"[green]Results saved to {output_path}[/green]")
    else:
        console.print(csv_content)


def main():
    """Main entry point"""
    cli(obj={})


if __name__ == "__main__":
    main()