# pa-permission-usage-auditor
Audits files under a root directory against a supplied access log. A file is reported as unused only when its path does not appear in the access log; files listed in the access log count as used, and whitelisted files are skipped. It monitors no process and no user, and reads no system logs on its own: the access log the operator supplies is the only usage data. The same inputs always produce the same findings in the same order. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuard-AI/pa-permission-usage-auditor`
`pip install -r requirements.txt`

## Usage
`python3 main.py --access-log FILE [-w FILE] [-r DIR] [-l FILE] [-o FILE] [--debug]`

`--access-log` is required. All other options are optional.

The access log lists one used path per line, as an absolute path or as a path relative to the root directory. Without `--access-log` the audit is not performed: the run prints a not checked line and exits 1. A root directory that does not exist, or one that holds no files, also reports not checked at exit 1 with no clean line. A named whitelist file that is missing or empty is an error at exit 1, never a silent empty whitelist. The output file must not be inside the audited root directory or equal an input file; such a run refuses at exit 1. When an output file is named and the audit completes, the file is always written, even when the unused list is empty.

## Parameters
- `-h`: Show help message and exit
- `--access-log` (required): Path to an access log file listing used paths, one per line (absolute paths or paths relative to the root directory). Required: without usage data the audit is not performed and the run exits 1.
- `-w`, `--whitelist` (optional): Path to a whitelist file containing paths to exclude from the audit (one path per line, supports globbing).
- `-r`, `--root_dir` (optional): Root directory to start the audit from (optional, defaults to current directory).
- `-l`, `--log_file` (optional): Path to the log file (default: pa_permission_usage_auditor.log).
- `-o`, `--output` (optional): Path to the output file for unused permissions.
- `--debug` (optional): Enable debug logging.

## License
MIT License. See LICENSE.
