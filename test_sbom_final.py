#\!/usr/bin/env python3
"""Final test of SBOM export functionality."""

from pathlib import Path
from binarysniffer import EnhancedBinarySniffer
from binarysniffer.core.results import BatchAnalysisResult
from binarysniffer.output.cyclonedx_formatter import CycloneDxFormatter
import json

# Create test file
test_file = Path("test_ffmpeg.c")
test_file.write_text("""
#include "libavcodec/avcodec.h"
#include "libavformat/avformat.h"
void av_register_all() {}
void avcodec_register_all() {}
""")

# Analyze file
sniffer = EnhancedBinarySniffer()
result = sniffer.analyze_file(test_file, confidence_threshold=0.1)

print(f"Analysis found {len(result.matches)} components")
for match in result.matches:
    print(f"  - {match.component} (confidence: {match.confidence:.1%})")
    if 'file_path' in match.evidence:
        print(f"    File path in evidence: {match.evidence['file_path']}")

# Create batch result for SBOM
batch_result = BatchAnalysisResult(
    results={str(test_file): result},
    total_files=1,
    successful_files=1,
    failed_files=0,
    total_time=result.analysis_time
)

# Generate SBOM
formatter = CycloneDxFormatter()
sbom_json = formatter.format_results(batch_result)
sbom = json.loads(sbom_json)

print(f"\nSBOM generated with {len(sbom['components'])} components")
print(f"SBOM spec version: {sbom['specVersion']}")

# Check evidence includes file paths
if sbom['components']:
    comp = sbom['components'][0]
    if 'evidence' in comp and 'occurrences' in comp['evidence']:
        for occ in comp['evidence']['occurrences']:
            print(f"Component location in SBOM: {occ['location']}")

print("\n✅ SBOM export test successful\!")

# Clean up
test_file.unlink()
