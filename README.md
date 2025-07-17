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

### Time Report Analysis
Optimized time difference analysis for email sequences:
- Filters emails by subject pattern using regex
- Calculates time differences between consecutive matching emails
- Groups emails into execution blocks (resets when gap > 24 hours)
- Shows total runtime for each execution block
- Outputs as console table (default) or CSV for piping
- Uses efficient parsing (headers only) for better performance

**Time Report Output Format**:
- Block number (for filtering)
- Separate date and time columns (DD.MM.YYYY, HH:MM format)
- Subject line
- Minutes and hours since previous email
- Total runtime rows for each execution block
- Progress shown on stderr when using --csv (doesn't interfere with data)

## Options

### Basic Options
- `-f, --files`: Count files instead of showing directory sizes
- `--help`: Show help information

### Email Analysis Options
- `-e, --emails`: Analyze .eml email files to detect potential spam patterns
- `-n, --top N`: Number of top results to show for email analysis (default: 20)
- `-w, --workers N`: Number of parallel workers for email processing (default: 8)

### Time Report Options
- `--subject-pattern REGEX`: Filter emails by subject regex and calculate time differences
- `--csv`: Output results as CSV to stdout (for piping to other tools)

**Note**: `-e` and `--subject-pattern` are mutually exclusive options.

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

# Time report: Console table output (default)
python duss.py --subject-pattern "^DAG 11_calculations_phase_\\w succeeded"

# Time report: CSV output for piping/redirection
python duss.py --subject-pattern "^DAG 11_calculations_phase_\\w succeeded" --csv > report.csv

# Time report: Filter specific execution blocks
python duss.py --subject-pattern "^DAG.*succeeded" --csv | grep "^2," # Block 2 only

# Time report: Get only total runtime summaries
python duss.py --subject-pattern "^DAG.*succeeded" --csv | grep "Total Runtime"
```
