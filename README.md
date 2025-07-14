# duss

Directory Usage Summary Script (DUSS)


A Python rewrite of the Perl duss.pl script that provides directory usage information.
Shows either directory sizes or file counts in a nicely formatted table, plus advanced
email analysis capabilities for spam detection.

## Commands

### Directory Analysis (Default)
The main command scans directories in the current directory and displays:
- Directory sizes (default) using du command
- File counts (with -f flag) by counting files recursively

### Email Analysis
Advanced email analysis mode for detecting spam patterns:
- Scans for .eml email files in subdirectories
- Extracts From, To, and Subject headers
- Identifies spam patterns (repeated sender+subject combinations)
- Shows frequency analysis of senders
- Uses parallel processing for fast analysis of large email archives

## Options

### Basic Options
- `-f, --files`: Count files instead of showing directory sizes
- `--help`: Show help information

### Email Analysis Options
- `-e, --emails`: Analyze .eml email files to detect potential spam patterns
- `-n, --top N`: Number of top results to show for email analysis (default: 20)
- `-w, --workers N`: Number of parallel workers for email processing (default: 8)

## Examples

```bash
# Directory usage (default)
python duss.py

# Count files instead of sizes
python duss.py -f

# Analyze emails for spam patterns
python duss.py -e

# Email analysis with custom options
python duss.py -e -n 10 -w 4
```
