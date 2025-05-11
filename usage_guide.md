================================
# SECREV - USAGE GUIDE & EXAMPLES

Copy and paste these commands to try out `secrev`.
Remember to replace placeholders like `YOUR_API_KEY` and `/path/to/your/code`.
This guide assumes you have `secrev` installed and available as a command.

---
## IMPORTANT: GOOGLE API KEY SETUP
---
`secrev` needs a Google API Key with Gemini API access.

**Option 1: `.env` file (recommended for regular use)**
Create a file named `.env` in the directory where you run `secrev`, with this content:
```
GOOGLE_API_KEY="YOUR_ACTUAL_API_KEY_HERE"
```

**Option 2: Environment Variable**
Set it in your terminal session before running `secrev`:

*(Linux/macOS)*
```bash
export GOOGLE_API_KEY="YOUR_ACTUAL_API_KEY_HERE"
```
*(Windows - Command Prompt)*
```batch
set GOOGLE_API_KEY="YOUR_ACTUAL_API_KEY_HERE"
```
*(Windows - PowerShell)*
```powershell
$env:GOOGLE_API_KEY="YOUR_ACTUAL_API_KEY_HERE"
```

**Option 3: Command-line (shown in examples below)**
Use the `-k` or `--api-key` flag. This overrides the `.env` file and environment variable.

---
## BASIC SCANS
---

Scan the current directory (assumes API key is in `.env` or environment variable)
```bash
secrev -d .
```

Scan a specific project folder (relative path)
```bash
secrev -d my_project
```

Scan a specific project folder (absolute path)
```bash
secrev -d /path/to/your/codebase
```

Scan a directory with spaces in its name
```bash
secrev -d "./my project folder with spaces"
```

---
## SPECIFYING THE MODEL
---
Use a specific Gemini model (e.g., `gemini-1.0-pro`)
(Make sure your API key has access to this model)
```bash
secrev -d . -m gemini-1.0-pro
```

Default model is `"gemini-1.5-flash-latest"`
```bash
secrev -d .
```

---
## PROVIDING API KEY VIA COMMAND
---
Override `.env` or environment variable with a key on the command line
```bash
secrev -d . -k "YOUR_API_KEY_DIRECTLY_HERE"
```

or long form:
```bash
secrev -d . --api-key "YOUR_API_KEY_DIRECTLY_HERE"
```

---
## CUSTOM REPORT FILE NAMES
---
Set a base name for your report files (e.g., `"my_app_scan"`)
This will create files like `"my_app_scan_TIMESTAMP.md"` and `".txt"`
```bash
secrev -d . -o my_app_scan
```

or long form with spaces (use quotes):
```bash
secrev -d . --output-file-base "WebApp Security Audit v1"
```

---
## CUSTOM REPORTS DIRECTORY
---
Save reports to a custom directory (e.g., `"security_audits"`)
The directory will be created if it doesn't exist.
```bash
secrev -d . --reports-dir security_audits
```

Use a path with spaces for the reports directory
```bash
secrev -d . --reports-dir "./My Scan Reports/ProjectX"
```

Combine with custom base name
```bash
secrev -d . --reports-dir "project_scans/iteration1" -o "backend_api_rev1"
```

---
## INCLUDING SPECIFIC FILE EXTENSIONS
---
Only scan Python and JavaScript files (overrides default relevant extensions)
```bash
secrev -d . --include-extensions .py,.js
```

Include Python files and files named exactly `"Dockerfile"` (no extension)
```bash
secrev -d . --include-extensions .py,Dockerfile
```

Include files ending with `.config` (case-insensitive for extensions)
```bash
secrev -d . --include-extensions .config
```

**Note:** This *replaces* the default list of what's considered relevant.
Files excluded by default (like binaries) will generally still be skipped.

---
## EXCLUDING SPECIFIC FILE EXTENSIONS
---
Scan normally, but explicitly exclude all `.xml` and `.md` files
This ADDS to the default list of excluded extensions.
```bash
secrev -d . --exclude-extensions .xml,.md
```

Exclude YAML files (both `.yml` and `.yaml` are typically handled as distinct if specified)
```bash
secrev -d . --exclude-extensions .yml,.yaml
```

Exclude temporary files
```bash
secrev -d . --exclude-extensions .tmp,.temp,.bak
```

---
## EXCLUDING SPECIFIC FILES OR DIRECTORIES
---
Exclude a specific configuration file by name (case-insensitive for filenames/patterns)
```bash
secrev -d . --exclude-files "config.backup.js"
```

Exclude all files within any directory named `"test_data"` or `"docs"`
Also exclude any file named exactly `"obsolete_code.py"`
```bash
secrev -d . --exclude-files test_data,docs,obsolete_code.py
```

Exclude a specific file in a specific path (provide the directory as part of the pattern)
This is more about excluding directories. For specific file paths, ensure the filename
itself or one of its parent directory names is in the exclude list.
To exclude `"my_project/src/legacy/old_util.js"`, you could use:
```bash
secrev -d my_project --exclude-files legacy,old_util.js
```
This would exclude any directory named `"legacy"` and any file named `"old_util.js"`.

**Note:** This ADDS to the default list of excluded names/patterns (like `"node_modules"`, `".git"`).
These patterns are matched against individual directory names in a path and the filename itself.
No wildcards like `*` or `?` are supported in these patterns; it's exact (case-insensitive) string matching.

---
## ADJUSTING CHUNK SIZE
---
Set the maximum characters per code chunk sent to the LLM (default is `200000`)
Smaller chunks might be better for very dense code or specific models, but means more API calls.
```bash
secrev -d . --chunk-size 100000
```

Larger chunks (be mindful of model context window limits for the chosen model)
```bash
secrev -d . --chunk-size 300000
```

---
## LIMITING TOTAL CHARACTERS PROCESSED
---
Set a safety limit on the total characters processed across all files (default is `5,000,000`)
Useful for very large codebases to control API costs/time.
```bash
secrev -d . --max-total-chars 1000000
```

Set to `0` for no limit (process everything, can be long/costly for huge projects)
```bash
secrev -d . --max-total-chars 0
```

---
## SKIPPING INTERACTIVE FILE REVIEW
---
Automatically scan all discovered files without prompting for review/selection
```bash
secrev -d . -y
```

or long form:
```bash
secrev -d . --yes
```

---
## COMBINING OPTIONS
---

Scan a Python project, skip interactive, custom report name/dir, specific model
```bash
secrev -d ./my_python_app \
    -m gemini-1.0-pro \
    -o "python_app_sec_v1" \
    --reports-dir "audits/python" \
    --include-extensions .py,.ini \
    --exclude-files "test_utils.py",migrations,venv \
    -y
```

Scan a large JavaScript project, limit total characters, custom chunk size
```bash
secrev -d ./large_js_frontend \
    --include-extensions .js,.jsx,.ts,.tsx,.json \
    --exclude-extensions .css,.scss,.svg \
    --exclude-files "mock_data",build,dist,"package-lock.json" \
    --chunk-size 150000 \
    --max-total-chars 2000000 \
    -o "frontend_scan_limited" \
    -y \
    -k "MY_SPECIAL_JS_PROJECT_API_KEY"
```

---
## INTERACTIVE MODE (DEFAULT)
---
If you DON'T use the `-y` or `--yes` flag, `secrev` will:
1. Discover files based on your criteria (or defaults).
2. List the discovered files with numbers.
3. Allow you to:
   - Enter number(s) to toggle selection (e.g., `'1 3 5'`).
   - Type `'all'` to select all, `'none'` to deselect all.
   - Type `'list'` to show current selections and excluded extensions.
   - Type `'exclude .ext1 .ext2 ...'` to exclude files with these extensions from the list for this scan.
   - Type `'done'` or press Enter (if no input) to proceed.
   - Type `'cancel'` or press Ctrl+C to abort the scan.

Example:
```bash
secrev -d .
```
(Then follow the on-screen prompts to refine which files get scanned)

---
## REPORT OUTPUT
---
After the scan, `secrev` will generate two report files in the reports directory
(default is `"secrev_reports"` or what you specify with `--reports-dir`):
1. A Markdown file: `YOUR_OUTPUT_BASE_NAME_YYYYMMDD_HHMMSS.md`
2. A Text file:    `YOUR_OUTPUT_BASE_NAME_YYYYMMDD_HHMMSS.txt`

(If `-o` is not used, default base name is `"secrev_scan"`)

These files contain the findings from the AI. Review them carefully!