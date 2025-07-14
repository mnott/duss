# duss

Directory Usage Summary Script (DUSS)


A Python rewrite of the Perl duss.pl script that provides directory usage information.
Shows either directory sizes or file counts in a nicely formatted table.

## Commands

The main command scans directories in the current directory and displays:
- Directory sizes (default) using du command
- File counts (with -f flag) by counting files recursively

## Options

- `-f, --files`: Count files instead of showing directory sizes
- `--help`: Show help information
