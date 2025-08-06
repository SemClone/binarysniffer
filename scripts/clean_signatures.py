#!/usr/bin/env python3
"""
Clean up existing signatures by removing generic patterns that cause false positives.
"""

import json
import shutil
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict


class SignatureCleaner:
    """Clean up problematic signatures from JSON files."""
    
    # Patterns that are too generic and should be removed
    PATTERNS_TO_REMOVE = {
        # Empty or very short
        "", "Hcl", "JSC", "OT:", "WTF", "awt", "fmt", "gwt", 
        "hah", "jms", "kd_", "kdu", "rx.", "sax",
        
        # Company/language names
        "android", "apache", "golang", "google", "kotlin", 
        "react", "React", "facebook", "squareup",
        
        # Generic HTTP patterns
        "HTTP", "HTTPS", "HTTP_REQUEST", "HTTP_RESPONSE", 
        "HTTP_0_9", "HTTP_1_0", "HTTP_1_1", "HTTP_2",
        "HttpHost", "HttpRequest", "HttpResponse", "HttpContext",
        "HttpProcessor", "HttpVersion", "HttpDateGenerator",
        
        # Generic programming terms
        "test", "Test", "debug", "Debug", "log", "Log",
        "error", "Error", "warning", "Warning", "info", "Info",
        "get", "set", "init", "create", "delete", "update",
        "read", "write", "open", "close", "start", "stop",
        "string", "String", "number", "Number", "array", "Array",
        "list", "List", "map", "Map", "object", "Object",
        
        # Single words that are too common
        "class", "function", "method", "interface", "struct",
        "public", "private", "static", "final", "const",
        "true", "false", "null", "void", "main", "app",
        
        # Common library terms
        "core", "util", "utils", "common", "base", "lib",
        "framework", "sdk", "api", "client", "server",
        
        # Generic patterns from analysis
        "codehaus", "jackson", "FasterXML", "dagger", 
        "inject", "sun.", "jdbc", "joda", "solr"
    }
    
    # Minimum pattern length
    MIN_PATTERN_LENGTH = 6
    
    # Prefixes that indicate valid library-specific patterns
    VALID_PREFIXES = {
        # Video/Audio codecs
        'av_', 'avcodec_', 'avformat_', 'avutil_', 'avfilter_', 
        'avdevice_', 'swscale_', 'swresample_', 'postproc_',
        'x264_', 'x265_', 'vpx_', 'vp8_', 'vp9_', 'theora_',
        'opus_', 'vorbis_', 'ogg_', 'mp3_', 'lame_', 'flac_',
        
        # Image libraries
        'png_', 'jpeg_', 'jpg_', 'gif_', 'webp_', 'tiff_',
        'PNG_', 'JPEG_', 'JPG_', 'GIF_', 'WEBP_', 'TIFF_',
        
        # Crypto/Security
        'SSL_', 'TLS_', 'RSA_', 'AES_', 'EVP_', 'BIO_', 
        'X509_', 'CRYPTO_', 'SHA_', 'MD5_',
        
        # Common libraries
        'curl_', 'CURL_', 'sqlite3_', 'sqlite_', 'z_', 'gz_',
        'xml_', 'XML_', 'json_', 'JSON_', 'yaml_', 'YAML_',
        
        # Programming language specific
        'java.', 'javax.', 'com.', 'org.', 'net.', 'io.',
        'android.', 'androidx.', 'kotlin.', 'scala.',
        
        # Apache specific (when properly namespaced)
        'org.apache.', 'apache.', 'httpcore.', 'httpclient.',
        
        # Other valid prefixes
        'fmt_', 'FMT_', 'spdlog_', 'boost_', 'poco_', 'qt_',
        'gtk_', 'wx_', 'opencv_', 'cv_', 'tensorflow_', 'tf_',
        'torch_', 'grpc_', 'protobuf_', 'pb_', 'kafka_',
        'redis_', 'mongo_', 'mysql_', 'postgres_', 'elastic_',
        
        # Mobile specific
        'firebase_', 'crashlytics_', 'fabric_', 'realm_',
        'retrofit_', 'okhttp_', 'picasso_', 'glide_',
        'butterknife_', 'eventbus_', 'leakcanary_',
        
        # Component specific prefixes
        'joda_', 'JODA_', 'solr_', 'SOLR_', 'lucene_', 'LUCENE_',
        'netty_', 'NETTY_', 'guava_', 'GUAVA_', 'gson_', 'GSON_',
        'jackson_', 'JACKSON_', 'dagger_', 'DAGGER_',
        'yoga_', 'YOGA_', 'folly_', 'FOLLY_', 'react_', 'REACT_'
    }
    
    def __init__(self):
        self.cleaned_count = 0
        self.total_signatures = 0
        self.component_stats = defaultdict(lambda: {'removed': 0, 'kept': 0})
    
    def should_keep_pattern(self, pattern: str, confidence: float = 0.5) -> bool:
        """Determine if a pattern should be kept."""
        # Remove if in removal list
        if pattern in self.PATTERNS_TO_REMOVE:
            return False
        
        # Remove if too short
        if len(pattern) < self.MIN_PATTERN_LENGTH:
            return False
        
        # Keep if it has a valid prefix
        pattern_lower = pattern.lower()
        for prefix in self.VALID_PREFIXES:
            if pattern_lower.startswith(prefix.lower()):
                return True
        
        # Keep if it's a proper namespace/package
        if '::' in pattern or pattern.count('.') >= 2:
            # But not if it ends with a dot
            if not pattern.endswith('.'):
                return True
        
        # Keep if high confidence and long enough
        if confidence >= 0.9 and len(pattern) >= 12:
            return True
        
        # Keep version patterns
        if any(v in pattern.lower() for v in ['version', '_v1', '_v2', '_v3', '_1_', '_2_']):
            return True
        
        # Keep patterns with special characters (often specific)
        if any(c in pattern for c in ['_', '->', '@', '(', ')', '[', ']']) and len(pattern) >= 8:
            # But not generic HTTP patterns
            if not any(http in pattern for http in ['HTTP', 'Http', 'http']):
                return True
        
        # Remove generic single words
        if pattern.isalpha() and len(pattern) < 10:
            return False
        
        # Remove test patterns
        if any(test in pattern.lower() for test in ['test', 'example', 'sample', 'demo']):
            return False
        
        # Default: keep if confidence is high enough
        return confidence >= 0.8 and len(pattern) >= 8
    
    def clean_signature_file(self, file_path: Path) -> Dict:
        """Clean a single signature file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            component_name = data.get('component', {}).get('name', 'Unknown')
            original_signatures = data.get('signatures', [])
            self.total_signatures += len(original_signatures)
            
            # Filter signatures
            cleaned_signatures = []
            for sig in original_signatures:
                pattern = sig.get('pattern', '')
                confidence = sig.get('confidence', 0.5)
                
                if self.should_keep_pattern(pattern, confidence):
                    cleaned_signatures.append(sig)
                    self.component_stats[component_name]['kept'] += 1
                else:
                    self.cleaned_count += 1
                    self.component_stats[component_name]['removed'] += 1
            
            # Update data
            data['signatures'] = cleaned_signatures
            data['signature_metadata']['signature_count'] = len(cleaned_signatures)
            data['signature_metadata']['updated'] = "2025-08-05T00:00:00Z"
            data['signature_metadata']['cleaned'] = True
            
            return {
                'component': component_name,
                'original_count': len(original_signatures),
                'cleaned_count': len(cleaned_signatures),
                'removed_count': len(original_signatures) - len(cleaned_signatures),
                'data': data
            }
            
        except Exception as e:
            print(f"Error cleaning {file_path}: {e}")
            return None
    
    def clean_all_signatures(self, signatures_dir: Path, output_dir: Path):
        """Clean all signature files in directory."""
        print("\n" + "="*80)
        print("SIGNATURE CLEANING PROCESS")
        print("="*80)
        
        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Create backup directory
        backup_dir = signatures_dir.parent / "signatures_backup"
        if not backup_dir.exists():
            print(f"\nCreating backup at: {backup_dir}")
            shutil.copytree(signatures_dir, backup_dir)
        
        # Process all signature files
        results = []
        for sig_file in sorted(signatures_dir.glob("*.json")):
            if sig_file.name in ["manifest.json", "template.json"]:
                # Copy these files as-is
                shutil.copy2(sig_file, output_dir / sig_file.name)
                continue
            
            print(f"\nProcessing: {sig_file.name}")
            result = self.clean_signature_file(sig_file)
            
            if result:
                results.append(result)
                
                # Save cleaned file
                output_file = output_dir / sig_file.name
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(result['data'], f, indent=2, ensure_ascii=False)
                
                print(f"  Original: {result['original_count']} signatures")
                print(f"  Cleaned: {result['cleaned_count']} signatures")
                print(f"  Removed: {result['removed_count']} signatures")
        
        # Print summary
        print("\n" + "="*80)
        print("CLEANING SUMMARY")
        print("="*80)
        print(f"\nTotal files processed: {len(results)}")
        print(f"Total signatures before: {self.total_signatures}")
        print(f"Total signatures after: {self.total_signatures - self.cleaned_count}")
        print(f"Total signatures removed: {self.cleaned_count}")
        print(f"Reduction: {self.cleaned_count / self.total_signatures * 100:.1f}%")
        
        # Show most affected components
        print("\n\nMOST AFFECTED COMPONENTS:")
        sorted_components = sorted(
            self.component_stats.items(), 
            key=lambda x: x[1]['removed'], 
            reverse=True
        )
        
        for component, stats in sorted_components[:10]:
            if stats['removed'] > 0:
                total = stats['removed'] + stats['kept']
                print(f"  {component}: {stats['removed']}/{total} removed ({stats['removed']/total*100:.1f}%)")
        
        # Special focus on Apache HTTP Core
        if 'Apache HTTP Core' in self.component_stats:
            stats = self.component_stats['Apache HTTP Core']
            print(f"\n\nAPACHE HTTP CORE CLEANUP:")
            print(f"  Signatures kept: {stats['kept']}")
            print(f"  Signatures removed: {stats['removed']}")
            
            # Show what patterns were kept
            httpcore_file = output_dir / "bsa-apache-httpcore.json"
            if httpcore_file.exists():
                with open(httpcore_file, 'r') as f:
                    httpcore_data = json.load(f)
                
                kept_patterns = [sig['pattern'] for sig in httpcore_data['signatures'][:10]]
                print(f"  Sample kept patterns: {', '.join(kept_patterns)}")


def main():
    """Main entry point."""
    project_root = Path(__file__).parent.parent
    signatures_dir = project_root / "signatures"
    output_dir = project_root / "signatures_cleaned"
    
    if not signatures_dir.exists():
        print(f"Error: Signatures directory not found at {signatures_dir}")
        return
    
    cleaner = SignatureCleaner()
    cleaner.clean_all_signatures(signatures_dir, output_dir)
    
    print(f"\n\nCleaned signatures saved to: {output_dir}")
    print("\nTo use the cleaned signatures:")
    print("1. Review the changes in signatures_cleaned/")
    print("2. If satisfied, replace signatures/ with signatures_cleaned/")
    print("3. Or selectively copy cleaned files back to signatures/")


if __name__ == "__main__":
    main()