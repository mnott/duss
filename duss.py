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

"""

#
# Imports
#
import os
import subprocess
import time
import email
import email.policy
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

pretty.install()
traceback.install()
console = Console()

class EmailInfo(NamedTuple):
    from_addr: str
    to_addr: str
    subject: str

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

        # Clean up addresses - extract just the email part if it's in "Name <email>" format
        if '<' in from_addr and '>' in from_addr:
            from_addr = from_addr.split('<')[1].split('>')[0].strip()
        if '<' in to_addr and '>' in to_addr:
            to_addr = to_addr.split('<')[1].split('>')[0].strip()

        return EmailInfo(from_addr, to_addr, subject)

    except Exception:
        return EmailInfo("", "", "")


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