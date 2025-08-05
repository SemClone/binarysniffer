#!/usr/bin/env python3
"""
Basic usage examples for BinarySniffer library
"""

from pathlib import Path
from binarysniffer import BinarySniffer, Config


def example_single_file():
    """Example: Analyze a single file"""
    print("=== Single File Analysis ===")
    
    # Initialize analyzer with default config
    sniffer = BinarySniffer()
    
    # Analyze a file
    result = sniffer.analyze_file("/usr/bin/ls")
    
    # Display results
    print(f"File: {result.file_path}")
    print(f"Type: {result.file_type}")
    print(f"Matches found: {len(result.matches)}")
    
    for match in result.high_confidence_matches:
        print(f"  - {match.component}: {match.confidence:.1%} ({match.license})")


def example_directory_analysis():
    """Example: Analyze entire directory"""
    print("\n=== Directory Analysis ===")
    
    # Custom configuration
    config = Config(
        min_confidence=0.7,
        parallel_workers=8
    )
    
    sniffer = BinarySniffer(config)
    
    # Analyze directory
    results = sniffer.analyze_directory(
        "/usr/local/bin",
        recursive=True,
        file_patterns=["*.so", "*.dll", "*.exe"]
    )
    
    # Summary
    total_components = set()
    for path, result in results.items():
        if not result.error:
            total_components.update(result.unique_components)
    
    print(f"Files analyzed: {len(results)}")
    print(f"Unique components found: {len(total_components)}")


def example_batch_analysis():
    """Example: Analyze specific files"""
    print("\n=== Batch Analysis ===")
    
    sniffer = BinarySniffer()
    
    # List of files to analyze
    files = [
        "/usr/bin/python3",
        "/usr/bin/git",
        "/usr/lib/libssl.so"
    ]
    
    results = sniffer.analyze_batch(files, confidence_threshold=0.6)
    
    # Process results
    for file_path, result in results.items():
        if result.error:
            print(f"{file_path}: ERROR - {result.error}")
        elif result.matches:
            components = ", ".join(m.component for m in result.matches[:3])
            print(f"{file_path}: {components}")
        else:
            print(f"{file_path}: No matches")


def example_update_signatures():
    """Example: Update signature database"""
    print("\n=== Signature Update ===")
    
    sniffer = BinarySniffer()
    
    # Check for updates
    if sniffer.check_updates():
        print("Updates available!")
        
        # Perform update
        if sniffer.update_signatures():
            print("Signatures updated successfully")
            
            # Show new statistics
            stats = sniffer.get_signature_stats()
            print(f"Total signatures: {stats['signature_count']:,}")
    else:
        print("Signatures are up to date")


def example_custom_matching():
    """Example: Custom analysis with specific requirements"""
    print("\n=== Custom Analysis ===")
    
    # Configure for high-precision matching
    config = Config(
        min_confidence=0.9,
        min_string_length=8,
        max_strings_per_file=5000
    )
    
    sniffer = BinarySniffer(config)
    
    # Deep analysis of critical file
    result = sniffer.analyze_file(
        "/path/to/critical/binary",
        confidence_threshold=0.95,
        deep_analysis=True
    )
    
    # Filter results by license
    gpl_components = [
        m for m in result.matches 
        if m.license and 'GPL' in m.license
    ]
    
    if gpl_components:
        print("GPL-licensed components detected:")
        for match in gpl_components:
            print(f"  - {match.component}: {match.license}")


def example_programmatic_config():
    """Example: Programmatic configuration"""
    print("\n=== Programmatic Configuration ===")
    
    # Create custom config
    config = Config()
    config.data_dir = Path.home() / ".myapp" / "binarysniffer"
    config.signature_sources = [
        "https://my-signatures.example.com/custom.xmdb"
    ]
    config.auto_update = False
    config.cache_size_mb = 200
    
    # Save config for future use
    config.save()
    
    # Use with analyzer
    sniffer = BinarySniffer(config)
    print(f"Using data directory: {config.data_dir}")


if __name__ == "__main__":
    # Run examples (comment out those that won't work in your environment)
    
    # example_single_file()
    # example_directory_analysis()
    # example_batch_analysis()
    # example_update_signatures()
    # example_custom_matching()
    example_programmatic_config()
    
    print("\nExamples completed!")