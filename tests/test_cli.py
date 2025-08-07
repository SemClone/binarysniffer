"""
Tests for CLI functionality
"""

import pytest
import tempfile
from pathlib import Path
from click.testing import CliRunner

from binarysniffer.cli import cli


class TestCLI:
    """Test command-line interface"""
    
    @pytest.fixture
    def runner(self):
        """Create CLI test runner"""
        return CliRunner()
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)
    
    def test_cli_help(self, runner):
        """Test help command"""
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'Semantic Copycat BinarySniffer' in result.output
        assert 'Commands:' in result.output
    
    def test_cli_version(self, runner):
        """Test version display"""
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert 'version' in result.output.lower()
        # Version should be in x.y.z format
        import re
        assert re.search(r'\d+\.\d+\.\d+', result.output)
    
    def test_analyze_help(self, runner):
        """Test analyze command help"""
        result = runner.invoke(cli, ['analyze', '--help'])
        assert result.exit_code == 0
        assert 'Analyze files for OSS components' in result.output
        assert '--threshold' in result.output
        assert '--format' in result.output
    
    def test_analyze_missing_file(self, runner):
        """Test analyzing non-existent file"""
        result = runner.invoke(cli, ['analyze', '/nonexistent/file'])
        assert result.exit_code == 2  # Click returns 2 for invalid arguments
        assert 'Error' in result.output or 'does not exist' in result.output
    
    def test_analyze_file_basic(self, runner, temp_dir):
        """Test basic file analysis"""
        # Create test file
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b'test data here')
        
        # Run analysis
        result = runner.invoke(cli, [
            '--data-dir', str(temp_dir / '.binarysniffer'),
            'analyze', 
            str(test_file)
        ])
        
        # Should complete successfully
        assert result.exit_code == 0
        assert 'Analysis complete!' in result.output
        assert 'Files analyzed: 1' in result.output
    
    def test_analyze_with_json_output(self, runner, temp_dir):
        """Test JSON output format"""
        # Create test file
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b'test data')
        
        # Run with JSON output
        result = runner.invoke(cli, [
            '--data-dir', str(temp_dir / '.binarysniffer'),
            'analyze',
            str(test_file),
            '--format', 'json'
        ])
        
        assert result.exit_code == 0
        # Output should be valid JSON
        assert '{' in result.output
        assert '"file_path"' in result.output
        assert '"matches"' in result.output
    
    def test_analyze_directory(self, runner, temp_dir):
        """Test directory analysis"""
        # Create a separate data directory to avoid analyzing it
        data_dir = temp_dir.parent / '.binarysniffer_test_data'
        data_dir.mkdir(exist_ok=True)
        
        # Create test files
        (temp_dir / "file1.bin").write_bytes(b'data1')
        (temp_dir / "file2.bin").write_bytes(b'data2')
        
        # Analyze directory
        result = runner.invoke(cli, [
            '--data-dir', str(data_dir),
            'analyze',
            str(temp_dir),
            '-r'
        ])
        
        # Clean up
        import shutil
        if data_dir.exists():
            shutil.rmtree(data_dir)
        
        assert result.exit_code == 0
        assert 'Files analyzed: 2' in result.output
    
    def test_stats_command(self, runner, temp_dir):
        """Test stats command"""
        result = runner.invoke(cli, [
            '--data-dir', str(temp_dir / '.binarysniffer'),
            'stats'
        ])
        
        assert result.exit_code == 0
        assert 'Signature Database Statistics' in result.output
        assert 'Components' in result.output
        assert 'Signatures' in result.output
    
    def test_config_command(self, runner, temp_dir):
        """Test config command"""
        result = runner.invoke(cli, [
            '--data-dir', str(temp_dir / '.binarysniffer'),
            'config'
        ])
        
        assert result.exit_code == 0
        assert 'BinarySniffer Configuration' in result.output
        assert 'Min Confidence' in result.output
    
    def test_update_command(self, runner, temp_dir):
        """Test update command"""
        result = runner.invoke(cli, [
            '--data-dir', str(temp_dir / '.binarysniffer'),
            'update'
        ])
        
        # Should complete (even if no updates available)
        assert result.exit_code == 0
    
    def test_verbose_flag(self, runner, temp_dir):
        """Test verbose output"""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b'test')
        
        # Run with verbose
        result = runner.invoke(cli, [
            '-v',
            '--data-dir', str(temp_dir / '.binarysniffer'),
            'analyze',
            str(test_file)
        ])
        
        assert result.exit_code == 0
        # Should show analysis in verbose mode - check for signature import messages or analysis details
        assert ('Importing' in result.output or 
                'File size:' in result.output or 
                'Analysis complete!' in result.output)
    
    def test_output_to_file(self, runner, temp_dir):
        """Test saving output to file"""
        test_file = temp_dir / "test.bin"
        test_file.write_bytes(b'test data')
        output_file = temp_dir / "results.json"
        
        # Run with output file
        result = runner.invoke(cli, [
            '--data-dir', str(temp_dir / '.binarysniffer'),
            'analyze',
            str(test_file),
            '--format', 'json',
            '--output', str(output_file)
        ])
        
        assert result.exit_code == 0
        assert output_file.exists()
        assert 'Results saved to' in result.output
        
        # Verify output file contains JSON
        content = output_file.read_text()
        assert '"file_path"' in content