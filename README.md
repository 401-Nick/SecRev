# SecRev: AI-Assisted Security Auditing

## **Important Notice**

This was vibe-coded and a proof-of-concept rather than a production-ready tool. It may not work as expected and could potentially cause issues. Use at your own risk.

This tool is intended for educational and research purposes only. Do not use it in production environments or for malicious activities.

A command-line utility for AI-assisted security code reviews using Google's Gemini models.

**Disclaimer:** SecRev is an *aid* and not a replacement for human expertise or dedicated security tools. All findings must be independently verified.

---

## Prerequisites

- Python 3.8+
- pipx
- Google API Key (available from [Google AI Studio](https://aistudio.google.com/app/apikey))

---

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/401-Nick/SecRev.git
    cd SecRev
    ```

2. **Install pipx (if not already installed):**
    Follow the [official pipx installation guide](https://pipx.pypa.io/stable/installation/).

3. **Install SecRev using pipx:**
    ```bash
    pipx install .
    ```

    This makes the `secrev` command globally available.

---

## Configuration: Setting Up Your API Key

SecRev requires a Google API Key. You can provide it in one of the following ways:

1. **CLI Argument:**
    ```bash
    secrev -d . --api-key YOUR_API_KEY
    ```

2. **Environment Variable:**
    ```bash
    export GOOGLE_API_KEY="YOUR_API_KEY"
    secrev -d .
    ```

3. **.env File:**
    Create a `.env` file in your working directory with the following content:
    ```plaintext
    GOOGLE_API_KEY="YOUR_API_KEY"
    ```

---

## Usage Guide

### **Basic Command Structure**
```bash
secrev -d <directory_to_scan> [options]
```

### **Example Usage**
Scan the current directory:
```bash
secrev -d .
```

### **Key Options**
- `-d, --directory DIRECTORY`: (Required) Directory to scan.
- `-m, --model MODEL`: Specify the Gemini model (default: `gemini-1.5-flash-latest`).
- `-k, --api-key API_KEY`: Provide your Google API Key.
- `-o, --output-file-base OUTPUT_FILE_BASE`: Base name for output files (e.g., `scan_results`).
- `--reports-dir DIR_NAME`: Directory for saving reports (default: `./secrev_reports`).
- `--include-extensions .ext1,.ext2`: Comma-separated extensions to include (overrides defaults).
- `--exclude-extensions .ext1,.ext2`: Comma-separated extensions to exclude.
- `--exclude-files name1,pattern2`: Comma-separated file names/patterns to exclude.
- `--chunk-size CHARS`: Maximum characters per chunk sent to AI (default: `200000`).
- `-y, --yes`: Skip interactive file review.

---

## Interactive File Review

If the `-y` flag is not used, SecRev will prompt you to review files interactively:

- Enter numbers (e.g., `1 3`) to toggle file selection.
- Type `all` or `none` to select/deselect all files.
- Type `exclude .ext1 .ext2` to temporarily exclude files with specific extensions.
- Type `list` to view current selections.
- Type `done` (or press Enter) to proceed.
- Type `cancel` (or press Ctrl+C) to abort.

---

## Output

SecRev generates two report files in the specified reports directory:

1. A Markdown file (`.md`)
2. A plain text file (`.txt`)

These reports include:
- File path and location of potential vulnerabilities.
- Description, impact, and suggested remediation.

---

For more details, refer to the [SecRev GitHub Repository](https://github.com/401-Nick/SecRev).