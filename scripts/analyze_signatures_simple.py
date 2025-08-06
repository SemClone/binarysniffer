#!/usr/bin/env python3
"""
Analyze all signature files to identify generic patterns causing false positives.
Simplified version without module dependencies.
"""

import json
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple


class SimpleSignatureAnalyzer:
    """Analyze signature quality and identify problematic patterns."""
    
    # Generic words that are too common
    GENERIC_WORDS = {
        'a', 'about', 'above', 'after', 'again', 'all', 'also', 'am', 'an', 'and', 'any', 'are', 'as', 'at',
        'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by',
        'can', 'cannot', 'could', 'did', 'do', 'does', 'doing', 'down', 'during',
        'each', 'few', 'for', 'from', 'further',
        'had', 'has', 'have', 'having', 'he', 'her', 'here', 'hers', 'herself', 'him', 'himself', 'his', 'how',
        'i', 'if', 'in', 'into', 'is', 'it', 'its', 'itself',
        'me', 'more', 'most', 'my', 'myself',
        'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'our', 'ours', 'ourselves', 'out', 'over', 'own',
        'same', 'she', 'should', 'so', 'some', 'such',
        'than', 'that', 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there', 'these', 'they', 'this', 'those', 'through', 'to', 'too',
        'under', 'until', 'up', 'very',
        'was', 'we', 'were', 'what', 'when', 'where', 'which', 'while', 'who', 'whom', 'why', 'will', 'with', 'would',
        'you', 'your', 'yours', 'yourself', 'yourselves',
        'apache', 'google', 'facebook', 'microsoft', 'oracle', 'apple',
        'android', 'ios', 'linux', 'windows', 'macos', 'ubuntu',
        'java', 'python', 'javascript', 'cpp', 'golang', 'rust', 'kotlin', 'swift',
        'react', 'angular', 'vue', 'spring', 'django', 'flask', 'rails',
        'get', 'set', 'add', 'remove', 'delete', 'update', 'create', 'init', 'start', 'stop', 'run',
        'test', 'debug', 'log', 'error', 'warning', 'info', 'exception',
        'file', 'data', 'string', 'number', 'array', 'list', 'map', 'object', 'class', 'function',
        'public', 'private', 'static', 'final', 'const', 'var', 'let',
        'true', 'false', 'null', 'undefined', 'none', 'nil', 'void'
    }
    
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
                is_valid = self.is_valid_signature(pattern, confidence)
                
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
                    
                if pattern.lower() in self.GENERIC_WORDS:
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
    
    def is_valid_signature(self, pattern: str, confidence: float) -> bool:
        """Check if a signature is valid."""
        # Invalid if too short
        if len(pattern) < 6:
            return False
        
        # Invalid if it's a common word
        if pattern.lower() in self.GENERIC_WORDS:
            return False
        
        # Valid if it has library-specific prefixes
        valid_prefixes = {
            'av_', 'avcodec_', 'avformat_', 'avutil_', 'avfilter_', 'avdevice_', 'swscale_',  # FFmpeg
            'x264_', 'x265_', 'vpx_', 'vp8_', 'vp9_',  # Video codecs
            'png_', 'jpeg_', 'jpg_', 'gif_', 'webp_',  # Image libraries
            'SSL_', 'TLS_', 'RSA_', 'EVP_', 'BIO_', 'X509_',  # OpenSSL
            'curl_', 'CURL_',  # cURL
            'sqlite3_', 'sqlite_',  # SQLite
            'z_', 'gz_', 'inflate', 'deflate',  # zlib
            'BZ2_', 'bz_',  # bzip2
            'lzma_', 'LZMA_',  # LZMA
            'xml_', 'XML_', 'xmlParseDoc', 'xmlFree',  # libxml2
            'H5_', 'hdf5_', 'HDF5_',  # HDF5
            'cblas_', 'lapack_', 'blas_',  # Linear algebra
            'fftw_', 'FFTW_',  # FFTW
            'git_', 'GIT_',  # libgit2
            'ssh_', 'SSH_',  # libssh
            'uv_', 'UV_',  # libuv
            'opus_', 'OPUS_',  # Opus
            'vorbis_', 'ogg_',  # Vorbis/Ogg
            'FLAC_', 'flac_',  # FLAC
            'mp3_', 'lame_',  # MP3
            'fmt_', 'FMT_',  # fmt library
            'spdlog_', 'SPDLOG_',  # spdlog
            'boost_', 'BOOST_',  # Boost
            'poco_', 'Poco',  # POCO
            'qt_', 'Qt', 'QT_',  # Qt
            'gtk_', 'GTK_', 'gdk_',  # GTK
            'wx_', 'wxWidgets',  # wxWidgets
            'eigen_', 'Eigen',  # Eigen
            'opencv_', 'cv_', 'CV_',  # OpenCV
            'tensorflow_', 'tf_', 'TF_',  # TensorFlow
            'torch_', 'TORCH_', 'pytorch_',  # PyTorch
            'kafka_', 'KAFKA_',  # Kafka
            'redis_', 'REDIS_',  # Redis
            'mongo_', 'MONGO_', 'bson_',  # MongoDB
            'pq_', 'PQ_', 'postgres_',  # PostgreSQL
            'mysql_', 'MYSQL_',  # MySQL
            'grpc_', 'GRPC_',  # gRPC
            'protobuf_', 'pb_',  # Protocol Buffers
            'arrow_', 'ARROW_',  # Apache Arrow
            'parquet_', 'PARQUET_',  # Apache Parquet
            'thrift_', 'THRIFT_',  # Apache Thrift
            'kafka_', 'KAFKA_',  # Apache Kafka
            'hbase_', 'HBASE_',  # Apache HBase
            'hadoop_', 'HADOOP_',  # Apache Hadoop
            'spark_', 'SPARK_',  # Apache Spark
            'lucene_', 'LUCENE_',  # Apache Lucene
            'solr_', 'SOLR_',  # Apache Solr
            'elasticsearch_', 'ES_',  # Elasticsearch
            'joda_', 'JODA_',  # Joda-Time
            'guava_', 'GUAVA_',  # Google Guava
            'gson_', 'GSON_',  # Google Gson
            'jackson_', 'JACKSON_',  # Jackson
            'netty_', 'NETTY_',  # Netty
            'vertx_', 'VERTX_',  # Vert.x
            'akka_', 'AKKA_',  # Akka
            'rxjava_', 'RX_',  # RxJava
            'dagger_', 'DAGGER_',  # Dagger
            'retrofit_', 'RETROFIT_',  # Retrofit
            'okhttp_', 'OKHTTP_',  # OkHttp
            'picasso_', 'PICASSO_',  # Picasso
            'glide_', 'GLIDE_',  # Glide
            'butterknife_', 'BUTTERKNIFE_',  # Butterknife
            'eventbus_', 'EVENTBUS_',  # EventBus
            'leakcanary_', 'LEAKCANARY_',  # LeakCanary
            'fabric_', 'FABRIC_',  # Fabric
            'crashlytics_', 'CRASHLYTICS_',  # Crashlytics
            'firebase_', 'FIREBASE_',  # Firebase
            'realm_', 'REALM_',  # Realm
            'room_', 'ROOM_',  # Room
            'workmanager_', 'WORKMANAGER_',  # WorkManager
            'navigation_', 'NAVIGATION_',  # Navigation
            'paging_', 'PAGING_',  # Paging
            'compose_', 'COMPOSE_',  # Compose
            'hilt_', 'HILT_',  # Hilt
            'coroutines_', 'COROUTINES_',  # Kotlin Coroutines
            'ktor_', 'KTOR_',  # Ktor
            'koin_', 'KOIN_',  # Koin
            'arrow_', 'ARROW_',  # Arrow (Kotlin)
            'yoga_', 'YOGA_',  # Yoga layout
        }
        
        # Check if pattern starts with a valid prefix
        pattern_lower = pattern.lower()
        for prefix in valid_prefixes:
            if pattern_lower.startswith(prefix.lower()):
                return True
        
        # High confidence patterns are more likely to be valid
        if confidence >= 0.9 and len(pattern) >= 10:
            return True
        
        # Patterns with special characters or mixed case are often specific
        if any(c in pattern for c in ['_', '::', '.', '->', '@']) and len(pattern) >= 8:
            return True
        
        # Namespace patterns
        if '::' in pattern or (pattern.count('.') >= 2 and not pattern.endswith('.')):
            return True
        
        # Version patterns
        if any(v in pattern.lower() for v in ['version', 'v1', 'v2', 'v3', '_1_', '_2_', '_3_']):
            return True
        
        return False
    
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
        if pattern_lower.isalpha() and len(pattern) < 8 and pattern_lower in self.GENERIC_WORDS:
            return True
            
        return False
    
    def _get_invalidity_reason(self, pattern: str) -> str:
        """Get the reason why a pattern is invalid."""
        if len(pattern) < 6:
            return "too_short"
        elif pattern.lower() in self.GENERIC_WORDS:
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
            overlap_count = 0
            for pattern in httpcore_patterns:
                if pattern in self.pattern_components:
                    components = self.pattern_components[pattern]
                    if len(components) > 1:
                        other_comps = components - {'Apache HTTP Core'}
                        if other_comps:
                            if overlap_count < 10:  # Show first 10
                                print(f"  '{pattern}' also appears in: {', '.join(list(other_comps)[:3])}")
                            overlap_count += 1
            
            if overlap_count > 10:
                print(f"  ... and {overlap_count - 10} more patterns")
        
        # Check FFmpeg patterns
        print(f"\n\nFFMPEG SIGNATURE INVESTIGATION:")
        ffmpeg_file = signatures_dir / "bsa-ffmpeg.json"
        if ffmpeg_file.exists():
            with open(ffmpeg_file, 'r') as f:
                ffmpeg_data = json.load(f)
            
            ffmpeg_patterns = [sig['pattern'] for sig in ffmpeg_data.get('signatures', [])]
            print(f"  Total FFmpeg signatures: {len(ffmpeg_patterns)}")
            
            # Check how many are invalid
            invalid_count = 0
            for pattern in ffmpeg_patterns[:10]:  # Sample first 10
                if not self.is_valid_signature(pattern, 0.5):
                    invalid_count += 1
                    print(f"  Invalid pattern: '{pattern}'")
            
            print(f"  Invalid patterns in sample: {invalid_count}/10")
        
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
        return
    
    analyzer = SimpleSignatureAnalyzer()
    analyzer.generate_report(signatures_dir)


if __name__ == "__main__":
    main()