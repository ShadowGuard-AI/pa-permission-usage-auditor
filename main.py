#!/usr/bin/env python3

import argparse
import logging
import os
import sys
import time
from datetime import datetime

try:
    import pathspec
    from rich.console import Console
    from rich.table import Column, Table
except ImportError as e:
    print(f"Error importing required libraries: {e}.  Please install them (e.g., pip install pathspec rich).")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_LOG_FILE = "pa_permission_usage_auditor.log"  # Default log file name

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Audits files under a root directory against a supplied access log. A file is reported as unused only when the access log does not list it. No process or user is monitored."
    )

    parser.add_argument(
        "--access-log",
        help="Path to an access log file listing used paths, one per line (absolute paths or paths relative to the root directory). Required: without usage data the audit is not performed and the run exits 1.",
        metavar="ACCESS_LOG_FILE"
    )

    parser.add_argument(
        "-w", "--whitelist",
        help="Path to a whitelist file containing paths to exclude from the audit (one path per line, supports globbing).",
        metavar="WHITELIST_FILE"
    )

    parser.add_argument(
        "-r", "--root_dir",
        help="Root directory to start the audit from (optional, defaults to current directory).",
        metavar="ROOT_DIR",
        default="."
    )

    parser.add_argument(
        "-l", "--log_file",
        help=f"Path to the log file (default: {DEFAULT_LOG_FILE}).",
        metavar="LOG_FILE",
        default=DEFAULT_LOG_FILE
    )

    parser.add_argument(
        "-o", "--output",
        help="Path to the output file for unused permissions.",
        metavar="OUTPUT_FILE"
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging."
    )
    
    return parser.parse_args()


def load_whitelist(whitelist_file):
    """
    Loads a whitelist of file paths from a file.
    Supports globbing using pathspec.

    Returns a PathSpec, or None when the named file is missing, empty, or
    unreadable. A named whitelist that cannot be loaded is an error, never a
    silent empty whitelist.
    """
    try:
        if not os.path.exists(whitelist_file):
            logging.error(f"Whitelist file not found: {whitelist_file}")
            return None

        with open(whitelist_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
            if not lines:
                logging.error("Whitelist file is empty.")
                return None
            return pathspec.PathSpec.from_lines("gitwildmatch", lines)

    except Exception as e:
        logging.error(f"Error loading whitelist file: {e}")
        return None


def load_access_log(access_log_file, root_dir):
    """
    Loads the set of used paths from an access log file, one path per line.
    Paths may be absolute or relative to the root directory.

    Returns a set of normalized path keys, or None when the file is missing
    or unreadable.
    """
    try:
        if not os.path.isfile(access_log_file):
            logging.error(f"Access log file not found: {access_log_file}")
            return None
        keys = set()
        with open(access_log_file, "r") as f:
            for line in f:
                entry = line.strip()
                if not entry:
                    continue
                keys.add(os.path.normpath(entry))
                if os.path.isabs(entry):
                    # Absolute log entries are stored twice, as written and relative to
                    # the root, but relative entries are stored only as written. The
                    # audit side checks both shapes, which mostly covers the asymmetry;
                    # an entry written with a leading ./ survives only because normpath
                    # strips it on both sides.
                    keys.add(os.path.normpath(os.path.relpath(entry, root_dir)))
        return keys
    except OSError as e:
        logging.error(f"Error loading access log file: {e}")
        return None


def is_whitelisted(path, whitelist):
    """
    Checks if a file path is whitelisted.

    Args:
        path (str): The file path to check.
        whitelist (pathspec.PathSpec): A PathSpec object containing the whitelist patterns.

    Returns:
        bool: True if the path is whitelisted, False otherwise.
    """
    if not whitelist:
        return False
    try:
        # Matching happens on the path relative to the root. A whitelist
        # pattern a user wrote with the root directory in front of it will
        # never match anything here, and the failure is silent.
        return whitelist.match_file(path)
    except Exception as e:
        logging.error(f"Error matching path against whitelist: {e}")
        return False  # Assume not whitelisted on error to be safe


def audit_permissions(root_dir, whitelist, used_paths, skip_paths=()):
    """
    Audits files under the root directory against real usage data.

    A file counts as used only when its path appears in the access log set
    loaded from the operator supplied access log. Files not listed there and
    not whitelisted are reported as unused. The walk is sorted, so the same
    inputs always produce the same findings in the same order.

    Returns a tuple of (unused file paths, total files audited).
    """
    unused_permissions = []
    total = 0
    skip_resolved = {os.path.realpath(p) for p in skip_paths}

    for root, dirs, files in os.walk(root_dir):
        dirs.sort()
        for file in sorted(files):
            filepath = os.path.join(root, file)
            if os.path.realpath(filepath) in skip_resolved:
                continue
            # The counter rises before the whitelist test, so the audited total
            # in the summary includes whitelisted files that were never compared
            # against the access log. The number is files walked past the skip
            # list, not files actually judged.
            total += 1
            normalized_filepath = os.path.relpath(filepath, root_dir)
            if is_whitelisted(normalized_filepath, whitelist):
                logging.debug(f"Skipping whitelisted file: {filepath}")
                continue

            if os.path.normpath(filepath) in used_paths or os.path.normpath(normalized_filepath) in used_paths:
                logging.debug(f"File '{filepath}' is listed in the access log.")
                continue

            logging.info(f"Found potential unused permission: {filepath}")
            unused_permissions.append(filepath)

    return sorted(unused_permissions), total


def output_results(unused_permissions, output_file=None, total=0):
    """
    Outputs the results to the console and, when an output file is named, to
    that file. A completed audit always writes the output file when one is
    named, even when the unused list is empty.

    Returns True on success, False when the output file could not be written.
    """
    console = Console()

    if not unused_permissions:
        console.print(f"[green]No unused permissions found in {total} files audited.[/green]")
    else:
        table = Table(title="Potentially Unused Permissions", show_header=True, header_style="bold magenta")
        table.add_column("File Path", style="cyan")
        for path in unused_permissions:
            table.add_row(path)
        console.print(table)

    if output_file:
        try:
            with open(output_file, "w") as f:
                for path in unused_permissions:
                    f.write(path + "\n")
            console.print(f"[green]Results written to {output_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error writing to output file: {e}[/red]")
            return False
    return True


def main():
    """
    Main function to execute the permission audit.
    """
    args = setup_argparse()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Wire the log file argument to an actual file handler.
    try:
        handler = logging.FileHandler(args.log_file)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(handler)
    except OSError as e:
        logging.error(f"Could not open log file {args.log_file}: {e}")
        sys.exit(1)

    if not os.path.isdir(args.root_dir):
        logging.error(f"Not checked: root directory does not exist: {args.root_dir}")
        sys.exit(1)

    if not args.access_log:
        logging.error("Not checked: no usage data supplied. Provide --access-log with a file listing used paths.")
        sys.exit(1)

    used_paths = load_access_log(args.access_log, args.root_dir)
    if used_paths is None:
        sys.exit(1)

    whitelist = None
    if args.whitelist:
        whitelist = load_whitelist(args.whitelist)
        if whitelist is None:
            sys.exit(1)

    if args.output:
        root_resolved = os.path.realpath(args.root_dir)
        output_resolved = os.path.realpath(args.output)
        input_paths = [args.access_log, args.log_file] + ([args.whitelist] if args.whitelist else [])
        if output_resolved == root_resolved or output_resolved.startswith(root_resolved + os.sep) or output_resolved in {os.path.realpath(p) for p in input_paths}:
            logging.error("Output file must not be inside the audited root directory or equal an input file.")
            sys.exit(1)

    logging.info(f"Starting permission audit from root directory: {args.root_dir}")
    if whitelist:
        logging.info(f"Using whitelist file: {args.whitelist}")
    start_time = time.time()

    # Only the log file is passed as a skip path. If the access log or
    # the whitelist file sits inside the audited root, those input files
    # are walked and can be reported as unused by the very run that is
    # reading them.
    unused_permissions, total = audit_permissions(args.root_dir, whitelist, used_paths, skip_paths=[args.log_file])

    end_time = time.time()
    logging.info(f"Permission audit completed in {end_time - start_time:.2f} seconds.")

    if total == 0:
        logging.error("Not checked: no files found under the root directory, so nothing was audited.")
        sys.exit(1)

    if not output_results(unused_permissions, args.output, total):
        sys.exit(1)


if __name__ == "__main__":
    main()