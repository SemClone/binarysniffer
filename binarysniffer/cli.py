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
@click.option('--threshold', '-t', type=float, help='Confidence threshold (0.0-1.0, default: 0.8)')
@click.option('--deep', is_flag=True, help='Enable deep analysis mode')
@click.option('--format', '-f', 
              type=click.Choice(['table', 'json', 'csv'], case_sensitive=False),
              default='table',
              help='Output format')
@click.option('--output', '-o', type=click.Path(), help='Save results to file')
@click.option('--patterns', '-p', multiple=True, help='File patterns to match (e.g., *.exe, *.so)')
@click.option('--parallel/--no-parallel', default=True, help='Enable parallel processing')
@click.option('--min-patterns', '-m', type=int, default=0, help='Minimum number of patterns to show component (filters results)')
@click.option('--verbose-evidence', '-v', is_flag=True, help='Show detailed evidence including matched patterns')
@click.pass_context
def analyze(ctx, path, recursive, threshold, deep, format, output, patterns, parallel, min_patterns, verbose_evidence):
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
    # Initialize sniffer (always use enhanced mode for better detection)
    if ctx.obj['sniffer'] is None:
        ctx.obj['sniffer'] = EnhancedBinarySniffer(ctx.obj['config'])
    
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
            output_json(batch_result, output, min_patterns, verbose_evidence)
        elif format == 'csv':
            output_csv(batch_result, output, min_patterns)
        else:
            output_table(batch_result, min_patterns, verbose_evidence)
        
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
    from .signatures.manager import SignatureManager
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
@click.pass_context
def signatures_create(ctx, path, name, output, version, license, publisher, description, 
                     input_type, recursive, min_signatures):
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
    
    # Check minimum signatures
    if len(signatures) < min_signatures:
        console.print(f"[red]Error: Only {len(signatures)} signatures generated, " +
                     f"minimum {min_signatures} required[/red]")
        console.print("Try analyzing more files or lowering --min-signatures")
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


def output_table(batch_result: BatchAnalysisResult, min_patterns: int = 0, verbose_evidence: bool = False):
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


def main():
    """Main entry point"""
    cli(obj={})


if __name__ == "__main__":
    main()