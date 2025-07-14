#!/usr/bin/env python
# encoding: utf-8
r"""

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

"""

#
# Imports
#
import os
import subprocess
import time
from pathlib import Path
from typing import Dict, Tuple

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


@app.callback()
def main(
    ctx: typer.Context,
    files: bool = typer.Option(
        False,
        "-f",
        "--files",
        help="Count files instead of showing directory sizes"
    )
) -> None:
    """
    Display directory usage summary in a formatted table.

    By default, shows directory sizes. Use -f to count files instead.
    """

    # If a subcommand is being called, don't run the main functionality
    if ctx.invoked_subcommand is not None:
        return

    # Scan directories
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