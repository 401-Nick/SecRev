# Secrev: Vibe-coded security auditing. (Don't be silly and use this for production plz.)

A command-line tool for AI-assisted security review of code using Google's Gemini models.

**Disclaimer:** This tool is an *aid* and not a substitute for human review or dedicated security tools. Findings require verification.

## Prerequisites

*   Python 3.8+
*   pipx
*   Google API Key (from Google AI Studio at https://aistudio.google.com/app/apikey)

## Installation

**1. Install pipx (if you haven't):**
   Follow official instructions available at https://pipx.pypa.io/stable/installation/

**2. Prepare for Local Installation:**
   If you have the secrev_cli.py script, verify file exists or create a file named pyproject.toml in the *same directory* with this content:

   ```
   [build-system]
   requires = ["setuptools>=61.0"]
   build-backend = "setuptools.build_meta"

   [project]
   name = "secrev"
   version = "0.1.0"
   description = "AI-Powered Code Security Reviewer using Google Gemini"
   requires-python = ">=3.8"
   dependencies = [
       "google-generativeai",
       "python-dotenv"
   ]

   [project.scripts]
   secrev = "secrev_cli:main"
   ```

**3. Install with pipx:**
   Navigate to the directory with secrev.py and pyproject.toml, then run:
   
   ```pipx install .```

   This makes secrev available as a command.

## Configuration: API Key

secrev needs your Google API Key. Provide it in one of these ways:

1.  **CLI Argument:**
    Run:
    secrev -d . --api-key YOUR_API_KEY

2.  **Environment Variable:**
    Set the GOOGLE_API_KEY environment variable:
    Example for bash/zsh: export GOOGLE_API_KEY="YOUR_API_KEY"
    Then run:
    secrev -d .

3.  **File named .env:**
    Create a file named .env in your current directory with the content:
    GOOGLE_API_KEY="YOUR_API_KEY"

## Usage Guide

**Command Structure:**
secrev -d <directory_to_scan> [options]

**Example:**
Scan the current directory:
secrev -d .

**Key Options:**

*   -d DIRECTORY or --directory DIRECTORY: (Required) Path to the directory to scan.
*   -m MODEL or --model MODEL: Gemini model (default is gemini-1.5-flash-latest).
*   -k API_KEY or --api-key API_KEY: Your Google API Key.
*   -o OUTPUT_FILE_BASE or --output-file-base OUTPUT_FILE_BASE: Base name for report files (e.g., scan_results).
*   --reports-dir DIR_NAME: Directory to save reports (default is ./secrev_reports).
*   --include-extensions .ext1,.ext2: Comma-separated extensions/names to *only* include (overrides defaults).
*   --exclude-extensions .ext1,.ext2: Comma-separated extensions to *add* to exclusion list.
*   --exclude-files name1,pattern2: Comma-separated names/patterns to *add* to exclusion list.
*   --chunk-size CHARS: Max characters per chunk sent to AI (default is 200000).
*   -y or --yes: Skip interactive file review.

## Interactive File Review

If you do not use the -y flag, secrev will list discovered files:
*   Enter numbers (e.g., 1 3) to toggle selection.
*   Type 'all' or 'none' to select/deselect all.
*   Type 'exclude .ext1 .ext2' to temporarily ignore files with those extensions.
*   Type 'list' to see current selections.
*   Type 'done' (or press Enter) to proceed.
*   Type 'cancel' (or Ctrl+C) to abort.

## Output

secrev generates two report files (a Markdown file ending in .md and a Text file ending in .txt) in the specified reports directory. These files contain potential vulnerabilities identified by the AI, including details like file path, location, description, impact, and suggested remediation.