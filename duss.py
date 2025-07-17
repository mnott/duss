#!/usr/bin/env python
# encoding: utf-8
r"""

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

"""

#
# Imports
#
import os
import subprocess
import time
import email
import email.policy
import sys
from pathlib import Path
from typing import Dict, Tuple, List, NamedTuple
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich import print
from rich import traceback
from rich import pretty
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.text import Text
import typer

import re
import csv
import datetime
import email.utils
from typing import Optional
pretty.install()
traceback.install()
console = Console()

class EmailInfo(NamedTuple):
    from_addr: str
    to_addr: str
    subject: str
    date: Optional[datetime.datetime]

app = typer.Typer(
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=False,
    help="Directory Usage Summary Script (DUSS)",
    epilog="A Python rewrite of duss.pl - shows directory sizes or file counts in a nice table.",
    invoke_without_command=True
)


def get_directory_size(directory: Path, show_progress: bool = False, progress_task=None, progress_obj=None) -> int:
    """Get directory size using du command."""
    try:
        if show_progress and progress_task is not None and progress_obj is not None:
            # Just show that we're calculating size without scanning subdirs first
            progress_obj.update(
                progress_task,
                description=f"[cyan]📁 Calculating size for [bold yellow]{directory.name}[/bold yellow]..."
            )

        result = subprocess.run(
            ["du", "-s", str(directory)],
            capture_output=True,
            text=True,
            check=True
        )
        # du output format: "size\tdirectory"
        size_str = result.stdout.split('\t')[0].strip()
        return int(size_str)
    except (subprocess.CalledProcessError, ValueError, IndexError):
        return 0


def count_files_in_directory(directory: Path, show_progress: bool = False, progress_task=None, progress_obj=None) -> int:
    """Count files in directory recursively."""
    try:
        if show_progress and progress_task is not None and progress_obj is not None:
            # Count files while showing progress - no initial directory scan
            file_count = 0
            shown_dirs = set()

            for item in directory.rglob("*"):
                if item.is_file():
                    file_count += 1
                    # Show progress for every 100 files or when entering a new directory
                    parent_rel = item.parent.relative_to(directory)
                    if file_count % 100 == 0 or parent_rel not in shown_dirs:
                        if parent_rel != Path("."):
                            progress_obj.update(
                                progress_task,
                                description=f"[cyan]📁 Scanning [bold yellow]{directory.name}[/bold yellow] → [dim]{parent_rel}[/dim] ({file_count:,} files)"
                            )
                            shown_dirs.add(parent_rel)

            return file_count

        # Default fast method using find
        result = subprocess.run(
            ["find", str(directory), "-type", "f"],
            capture_output=True,
            text=True,
            check=True
        )
        # Count non-empty lines
        lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
        return len(lines)
    except subprocess.CalledProcessError:
        return 0


def scan_directories(count_files: bool = False) -> Dict[str, int]:
    """Scan current directory for subdirectories and get their sizes or file counts."""
    current_dir = Path(".")
    results = {}

    # First, collect all directories to scan
    directories_to_scan = []
    for item in current_dir.iterdir():
        if item.is_dir() and not item.is_symlink():
            directories_to_scan.append(item)

    if not directories_to_scan:
        return results

    # Show what directories will be scanned
    dir_names = [d.name for d in directories_to_scan]

    # Create progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=False
    ) as progress:

        # Add progress task
        operation = "Counting files" if count_files else "Calculating sizes"
        task = progress.add_task(
            f"[cyan]Starting {operation.lower()}...",
            total=len(directories_to_scan)
        )

        for i, item in enumerate(directories_to_scan, 1):
            # Update progress description to show current directory
            progress.update(
                task,
                description=f"[cyan]📁 Scanning [bold yellow]{item.name}[/bold yellow] ({i}/{len(directories_to_scan)})"
            )

            # Add a small delay so users can see the progress
            time.sleep(0.1)

            # Calculate value for this directory
            if count_files:
                value = count_files_in_directory(item, show_progress=True, progress_task=task, progress_obj=progress)
            else:
                value = get_directory_size(item, show_progress=True, progress_task=task, progress_obj=progress)

            results[item.name] = value

            # Show what was found
            if count_files:
                progress.update(
                    task,
                    description=f"[green]✓ [bold]{item.name}[/bold]: {value:,} files"
                )
            else:
                size_human = format_size(value)
                progress.update(
                    task,
                    description=f"[green]✓ [bold]{item.name}[/bold]: {size_human}"
                )

            # Small delay to show the result
            time.sleep(0.2)

            # Update progress
            progress.update(task, advance=1)

        # Show completion
        progress.update(task, description=f"[green]✅ Scan completed! Processed {len(directories_to_scan)} directories")
        time.sleep(0.5)  # Brief pause to show completion

    return results


def format_size(size_kb: int) -> str:
    """Format size in KB to human readable format."""
    if size_kb < 1024:
        return f"{size_kb:,} KB"
    elif size_kb < 1024 * 1024:
        return f"{size_kb/1024:.1f} MB"
    else:
        return f"{size_kb/(1024*1024):.1f} GB"


def parse_eml_file(eml_path: Path) -> EmailInfo:
    """Parse an .eml file and extract From, To, and Subject headers."""
    try:
        with open(eml_path, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f, policy=email.policy.default)

        from_addr = msg.get('From', '').strip()
        to_addr = msg.get('To', '').strip()
        subject = msg.get('Subject', '').strip()
        received = msg.get_all('Received', [])
        date = None
        if received:
            last_received = received[-1]
            parts = last_received.split(';')
            if len(parts) > 1:
                date_str = parts[-1].strip()
                try:
                    date = email.utils.parsedate_to_datetime(date_str)
                except Exception:
                    pass
        if date is None:
            date_str = msg.get('Date', '').strip()
            if date_str:
                date = email.utils.parsedate_to_datetime(date_str)

        # Clean up addresses - extract just the email part if it's in "Name <email>" format
        if '<' in from_addr and '>' in from_addr:
            from_addr = from_addr.split('<')[1].split('>')[0].strip()
        if '<' in to_addr and '>' in to_addr:
            to_addr = to_addr.split('<')[1].split('>')[0].strip()

        return EmailInfo(from_addr, to_addr, subject, date)

    except Exception:
        return EmailInfo("", "", "", None)


def process_email_file_worker(eml_file: Path) -> Tuple[Path, EmailInfo]:
    """Worker function to process a single email file."""
    return eml_file, parse_eml_file(eml_file)


def scan_email_files(show_progress: bool = False, progress_task=None, progress_obj=None, max_workers: int = 8) -> List[EmailInfo]:
    """Scan current directory for .eml files and extract email headers using parallel processing."""
    current_dir = Path(".")
    emails = []

    # Find all .eml files
    eml_files = list(current_dir.rglob("*.eml"))

    if not eml_files:
        return emails

    if show_progress and progress_task is not None and progress_obj is not None:
        progress_obj.update(
            progress_task,
            description=f"[cyan]📧 Found {len(eml_files)} email files to analyze (using {max_workers} threads)",
            total=len(eml_files)
        )

    # Process files in parallel
    processed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {executor.submit(process_email_file_worker, eml_file): eml_file
                         for eml_file in eml_files}

        # Process results as they complete
        for future in as_completed(future_to_file):
            eml_file, email_info = future.result()

            if show_progress and progress_task is not None and progress_obj is not None:
                rel_path = eml_file.relative_to(current_dir)
                progress_obj.update(
                    progress_task,
                    description=f"[cyan]📧 Processing [bold yellow]{rel_path.parent}[/bold yellow] → [dim]{processed+1}/{len(eml_files)}[/dim]",
                    completed=processed
                )

            if email_info.from_addr:  # Only add if we successfully parsed something
                emails.append(email_info)

            processed += 1

    return emails


def abbreviate_subject(subject: str, max_length: int = 50) -> str:
    """Abbreviate subject line for console display."""
    if len(subject) <= max_length:
        return subject
    return subject[:max_length-3] + "..."


def parse_eml_file_minimal(eml_path: Path) -> Tuple[str, Optional[datetime.datetime]]:
    """Parse an .eml file and extract only Subject and Date headers for efficiency."""
    try:
        with open(eml_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Read only the headers section for efficiency
            headers = {}
            for line in f:
                line = line.strip()
                if not line:  # Empty line indicates end of headers
                    break
                if line.startswith(('Subject:', 'Date:', 'Received:')):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()
                elif line.startswith('\t') or line.startswith(' '):
                    # Continuation of previous header
                    if headers:
                        last_key = list(headers.keys())[-1]
                        headers[last_key] += ' ' + line.strip()

        subject = headers.get('subject', '').strip()
        date = None

        # Try to parse date from Received header first, then Date header
        if 'received' in headers:
            received = headers['received']
            if ';' in received:
                date_str = received.split(';')[-1].strip()
                try:
                    date = email.utils.parsedate_to_datetime(date_str)
                except Exception:
                    pass

        if date is None and 'date' in headers:
            date_str = headers['date']
            if date_str:
                try:
                    date = email.utils.parsedate_to_datetime(date_str)
                except Exception:
                    pass

        return subject, date

    except Exception:
        return "", None


def process_email_file_worker_minimal(eml_file: Path) -> Tuple[Path, Tuple[str, Optional[datetime.datetime]]]:
    """Worker function to process a single email file for subject pattern matching."""
    return eml_file, parse_eml_file_minimal(eml_file)


def scan_email_files_minimal(show_progress: bool = False, progress_task=None, progress_obj=None, max_workers: int = 8) -> List[Tuple[str, datetime.datetime]]:
    """Scan .eml files and extract only subject and date for efficiency."""
    current_dir = Path(".")
    emails = []

    # Find all .eml files
    eml_files = list(current_dir.rglob("*.eml"))

    if not eml_files:
        return emails

    if show_progress and progress_task is not None and progress_obj is not None:
        progress_obj.update(
            progress_task,
            description=f"[cyan]📧 Found {len(eml_files)} email files to analyze (using {max_workers} threads)",
            total=len(eml_files)
        )

    # Process files in parallel
    processed = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_file = {executor.submit(process_email_file_worker_minimal, eml_file): eml_file
                         for eml_file in eml_files}

        # Process results as they complete
        for future in as_completed(future_to_file):
            eml_file, (subject, date) = future.result()

            if show_progress and progress_task is not None and progress_obj is not None:
                rel_path = eml_file.relative_to(current_dir)
                progress_obj.update(
                    progress_task,
                    description=f"[cyan]📧 Processing [bold yellow]{rel_path.parent}[/bold yellow] → [dim]{processed+1}/{len(eml_files)}[/dim]",
                    completed=processed
                )

            if subject and date:  # Only add if we successfully parsed both
                emails.append((subject, date))

            processed += 1

    return emails


@app.callback()
def main(
    ctx: typer.Context,
    files: bool = typer.Option(
        False,
        "-f",
        "--files",
        help="Count files instead of showing directory sizes"
    ),
    emails: bool = typer.Option(
        False,
        "-e",
        "--emails",
        help="Analyze .eml email files to detect potential spam patterns"
    ),
    top: int = typer.Option(
        20,
        "-n",
        "--top",
        help="Number of top results to show for email analysis"
    ),
    workers: int = typer.Option(
        8,
        "-w",
        "--workers",
        help="Number of parallel workers for email processing"
    ),
    subject_pattern: str = typer.Option(
        None,
        "--subject-pattern",
        help="Regex pattern to filter emails and calculate time differences"
    ),
    csv_output: bool = typer.Option(
        False,
        "--csv",
        help="Output results as CSV (for piping to other tools)"
    )
) -> None:
    """
    Display directory usage summary in a formatted table.

    By default, shows directory sizes. Use -f to count files instead.
    Use -e to analyze email files for spam detection (with parallel processing).
    """

    # If a subcommand is being called, don't run the main functionality
    if ctx.invoked_subcommand is not None:
        return

    # Validate mutually exclusive options
    if emails and subject_pattern:
        console.print("[red]Error: Cannot use both --emails (-e) and --subject-pattern at the same time.[/red]")
        console.print("[yellow]Use --emails for spam analysis or --subject-pattern for time reports.[/yellow]")
        raise typer.Exit(1)

    # Email analysis mode
    if emails:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=False
        ) as progress:
            task = progress.add_task("[cyan]Scanning for email files...", total=1)

            email_data = scan_email_files(show_progress=True, progress_task=task, progress_obj=progress, max_workers=workers)

            if not email_data:
                console.print("[yellow]No .eml email files found in current directory or subdirectories.[/yellow]")
                return

            progress.update(task, description=f"[green]✅ Analyzed {len(email_data)} email files")
            time.sleep(0.5)

        # Analyze email patterns
        console.print(f"\n[blue]Analyzing {len(email_data):,} email messages for patterns...[/blue]")

        # Count patterns by From address
        from_counter = Counter(email.from_addr for email in email_data if email.from_addr)

        # Count patterns by From+Subject combination (to detect repeated spam)
        spam_patterns = Counter((email.from_addr, email.subject) for email in email_data
                               if email.from_addr and email.subject)

        # Display results
        console.print(f"\n[bold]Top {min(top, len(from_counter))} email senders by frequency:[/bold]")

        # Create table for sender analysis
        sender_table = Table(show_header=True, header_style="bold magenta")
        sender_table.add_column("From Address", style="cyan", no_wrap=True)
        sender_table.add_column("Count", justify="right", style="green")
        sender_table.add_column("Percentage", justify="right", style="yellow")

        total_emails = len(email_data)
        for from_addr, count in from_counter.most_common(top):
            percentage = (count / total_emails) * 100
            sender_table.add_row(from_addr, f"{count:,}", f"{percentage:.1f}%")

        console.print(sender_table)

        # Show potential spam patterns (same sender + subject)
        spam_candidates = [(pattern, count) for pattern, count in spam_patterns.most_common() if count > 1]

        if spam_candidates:
            console.print(f"\n[bold red]Potential spam patterns (same sender + subject, {len(spam_candidates)} patterns):[/bold red]")

            spam_table = Table(show_header=True, header_style="bold red")
            spam_table.add_column("From Address", style="cyan", no_wrap=True)
            spam_table.add_column("Subject", style="white")
            spam_table.add_column("Count", justify="right", style="red")

            for (from_addr, subject), count in spam_candidates[:top]:
                abbrev_subject = abbreviate_subject(subject, 60)
                spam_table.add_row(from_addr, abbrev_subject, f"{count:,}")

            console.print(spam_table)
        else:
            console.print(f"\n[green]✅ No obvious spam patterns detected (no repeated sender+subject combinations)[/green]")

        # Summary
        unique_senders = len(from_counter)
        unique_subjects = len(set(email.subject for email in email_data if email.subject))
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  Total emails: {total_emails:,}")
        console.print(f"  Unique senders: {unique_senders:,}")
        console.print(f"  Unique subjects: {unique_subjects:,}")
        if spam_candidates:
            console.print(f"  Potential spam patterns: [red]{len(spam_candidates):,}[/red]")

        return

    if subject_pattern:
        # Use stderr for progress when outputting CSV to stdout
        progress_console = Console(stderr=True) if csv_output else console

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=progress_console,
            transient=False
        ) as progress:
            task = progress.add_task("[cyan]Scanning for email files...", total=1)

            email_data = scan_email_files_minimal(show_progress=True, progress_task=task, progress_obj=progress, max_workers=workers)

            if not email_data:
                console.print("[yellow]No .eml email files found in current directory or subdirectories.[/yellow]")
                return

            progress.update(task, description=f"[green]✅ Analyzed {len(email_data)} email files")
            time.sleep(0.5)

        # Filter emails by subject pattern
        try:
            pattern = re.compile(subject_pattern)
        except re.error as e:
            progress_console.print(f"[red]Invalid regex pattern: {e}[/red]")
            return

        filtered_emails = []
        for subject, dt in email_data:
            if dt and pattern.search(subject):
                filtered_emails.append((subject, dt))

        if not filtered_emails:
            progress_console.print(f"[yellow]No emails found matching pattern: {subject_pattern}[/yellow]")
            return

        # Sort by date
        sorted_emails = sorted(filtered_emails, key=lambda x: x[1])

        if not csv_output:
            progress_console.print(f"\n[blue]Found {len(sorted_emails)} emails matching pattern[/blue]")

                # Calculate time differences
        table_rows = []
        prev_dt = None
        block_start = None
        block_count = 0

        for subject, dt in sorted_emails:
            if prev_dt is None:
                # First email - start of first block
                block_start = dt
                block_count += 1
                table_rows.append([
                    block_count,
                    dt.strftime('%d.%m.%Y'),
                    dt.strftime('%H:%M'),
                    subject,
                    "0.00",
                    "0.00"
                ])
            else:
                # Calculate time difference
                delta = dt - prev_dt
                delta_minutes = delta.total_seconds() / 60
                delta_hours = delta.total_seconds() / 3600

                # Check if gap is > 24 hours
                if delta_hours > 24:
                    # Add total runtime row for previous block using previous row's date/time
                    if block_start is not None:
                        total_delta = prev_dt - block_start
                        total_hours = total_delta.total_seconds() / 3600
                        table_rows.append([
                            block_count,
                            prev_dt.strftime('%d.%m.%Y'),
                            prev_dt.strftime('%H:%M'),
                            f"=== Block {block_count} Total Runtime ===",
                            "",
                            f"{total_hours:.2f}"
                        ])

                    # Start new block
                    block_count += 1
                    block_start = dt
                    table_rows.append([
                        block_count,
                        dt.strftime('%d.%m.%Y'),
                        dt.strftime('%H:%M'),
                        subject,
                        "0.00",
                        "0.00"
                    ])
                else:
                    # Normal entry within 24 hours
                    table_rows.append([
                        block_count,
                        dt.strftime('%d.%m.%Y'),
                        dt.strftime('%H:%M'),
                        subject,
                        f"{delta_minutes:.2f}",
                        f"{delta_hours:.2f}"
                    ])

            prev_dt = dt

        # Add final block total if we have data
        if block_start is not None and prev_dt is not None:
            total_delta = prev_dt - block_start
            total_hours = total_delta.total_seconds() / 3600
            table_rows.append([
                block_count,
                prev_dt.strftime('%d.%m.%Y'),
                prev_dt.strftime('%H:%M'),
                f"=== Block {block_count} Total Runtime ===",
                "",
                f"{total_hours:.2f}"
            ])

        # Output results
        if csv_output:
            # CSV output to stdout
            writer = csv.writer(sys.stdout)
            writer.writerow(['Block', 'Date', 'Time', 'Subject', 'Minutes Since Previous', 'Hours Since Previous'])
            writer.writerows(table_rows)
        else:
            # Console table output (default)
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Block", justify="right", style="blue", no_wrap=True)
            table.add_column("Date", style="cyan", no_wrap=True)
            table.add_column("Time", style="cyan", no_wrap=True)
            table.add_column("Subject", style="white")
            table.add_column("Minutes", justify="right", style="green")
            table.add_column("Hours", justify="right", style="yellow")

            for block, date, time_str, subject, minutes, hours in table_rows:
                # Special formatting for total runtime rows
                if "Total Runtime" in subject:
                    table.add_row(
                        str(block),
                        date,
                        time_str,
                        f"[bold blue]{subject}[/bold blue]",
                        minutes,
                        f"[bold]{hours}[/bold]"
                    )
                else:
                    table.add_row(str(block), date, time_str, subject, minutes, hours)

            console.print(table)

        if not csv_output:
            progress_console.print(f"\n[green]Total emails processed: {len([r for r in table_rows if not 'Total Runtime' in r[3]])}[/green]")
            progress_console.print(f"[green]Number of execution blocks: {block_count}[/green]")
        return
    # Directory scanning mode (default)
    results = scan_directories(count_files=files)

    if not results:
        console.print("[yellow]No directories found in current directory.[/yellow]")
        return

    # Sort by value (size or count)
    sorted_dirs = sorted(results.items(), key=lambda x: x[1])

    # Create rich table
    table = Table(show_header=True, header_style="bold magenta")

    if files:
        table.add_column("Directory", style="cyan", no_wrap=True)
        table.add_column("File Count", justify="right", style="green")

        for dir_name, count in sorted_dirs:
            table.add_row(dir_name, f"{count:,}")
    else:
        table.add_column("Directory", style="cyan", no_wrap=True)
        table.add_column("Size", justify="right", style="green")
        table.add_column("Size (Human)", justify="right", style="yellow")

        for dir_name, size_kb in sorted_dirs:
            table.add_row(
                dir_name,
                f"{size_kb:,} KB",
                format_size(size_kb)
            )

    # Display the table
    console.print(table)

    # Summary
    total_value = sum(results.values())
    if files:
        console.print(f"\n[bold]Total files across all directories: {total_value:,}[/bold]")
    else:
        console.print(f"\n[bold]Total size: {format_size(total_value)}[/bold]")


#
# Command: Doc
#
@app.command()
def doc(
    ctx:        typer.Context,
    title:      str  = typer.Option(None,   help="The title of the document"),
    toc:        bool = typer.Option(False,  help="Whether to create a table of contents"),
) -> None:
    """
    Re-create the documentation and write it to the output file.
    """
    import importlib
    import importlib.util
    import sys
    import os
    import doc2md

    def import_path(path):
        module_name = os.path.basename(path).replace("-", "_")
        spec = importlib.util.spec_from_loader(
            module_name,
            importlib.machinery.SourceFileLoader(module_name, path),
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules[module_name] = module
        return module

    mod_name = os.path.basename(__file__)
    if mod_name.endswith(".py"):
        mod_name = mod_name.rsplit(".py", 1)[0]
    atitle = title or mod_name.replace("_", "-")
    module = import_path(__file__)
    docstr = module.__doc__
    result = doc2md.doc2md(docstr, atitle, toc=toc, min_level=0)
    print(result)


#
# Main function
#
if __name__ == "__main__":
    try:
        app()
    except SystemExit as e:
        if e.code != 0:
            raise