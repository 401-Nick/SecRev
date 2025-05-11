#!/usr/bin/env python3
import os
import argparse
import json # For potential future structured output
from datetime import datetime
from pathlib import Path
from typing import List, Set, Optional, Tuple, Dict, Any

from dotenv import load_dotenv
import google.generativeai as genai
import google.generativeai.types as genai_types # For GenerationConfig

# --- Configuration ---
DEFAULT_MODEL_NAME: str = "gemini-1.5-flash-latest"
DEFAULT_CHUNK_SIZE_CHARS: int = 200000
DEFAULT_MAX_TOTAL_CHARS_PROCESSED: int = 5000000
DEFAULT_REPORTS_DIR_NAME: str = "secrev_reports"
DEFAULT_REPORT_BASE_NAME: str = "secrev_scan"

DEFAULT_RELEVANT_EXTENSIONS: Set[str] = {
    '.py', '.js', '.ts', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.go', '.rb', '.php',
    '.html', '.htm', '.css', '.scss', '.less',
    '.json', '.yaml', '.yml', '.xml', '.ini', '.toml', '.env',
    '.sh', '.bash', '.ps1',
    '.sql', '.md', '.txt',
    '.dockerfile', 'dockerfile', '.tf', '.hcl'
}
DEFAULT_EXCLUDED_EXTENSIONS: Set[str] = {
    '.pyc', '.pyo', '.o', '.so', '.dll', '.exe',
    '.log', '.tmp', '.bak', '.swp',
    '.ds_store',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',
    '.mp3', '.wav', '.aac', '.flac', '.ogg',
    '.mp4', '.mov', '.avi', '.mkv', '.webm',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
}
DEFAULT_EXCLUDED_FILENAMES_PATTERNS: Set[str] = {
    '.gitignore', 'license', 'node_modules', 'venv', '.venv', 'dist', 'build',
    '__pycache__', '.git', '.svn', '.hg',
    'package-lock.json', 'yarn.lock', 'composer.lock', 'gemfile.lock', 'pipfile.lock',
}

# --- LLM Prompt Template ---
SECURITY_ANALYSIS_SYSTEM_PROMPT: str = """
You are an expert AI security code reviewer. Your task is to meticulously analyze the provided code snippet or configuration file for potential security vulnerabilities.
For each potential vulnerability you identify, please provide the following information in a structured format:

1.  **Vulnerability Type:** (e.g., SQL Injection, Cross-Site Scripting (XSS), Insecure Deserialization, Hardcoded Secrets, Weak Cryptography, Command Injection, Path Traversal, Insufficient Input Validation, Insecure Direct Object Reference (IDOR), Security Misconfiguration, Outdated Dependencies - if inferable from context like package files, etc.)
2.  **File Path:** (This will be provided alongside the code snippet)
3.  **Location/Snippet:** Provide the relevant line numbers or a small, specific code snippet where the vulnerability occurs. If line numbers are not available, describe the location (e.g., "within the 'authenticate_user' function").
4.  **Description:** Clearly explain the nature of the vulnerability and why it is a security risk.
5.  **Potential Impact:** Briefly describe what an attacker could achieve by exploiting this vulnerability.
6.  **Suggested Remediation:** Offer specific, actionable advice on how to fix or mitigate the vulnerability.
7.  **Severity (Estimate):** (e.g., Critical, High, Medium, Low, Informational) - Base this on potential impact and exploitability.

**Guidelines for your response:**
- Be precise and actionable.
- If multiple vulnerabilities are found in a single snippet, list each one separately.
- If you find NO specific, actionable security vulnerabilities in the provided snippet, clearly state: "No critical security vulnerabilities identified in this snippet."
- Focus on actual vulnerabilities, not just style suggestions, unless the style has direct security implications (e.g., overly complex code that might hide bugs).
- Do not invent file paths or line numbers if they are not evident from the input.
- Assume the code is part of a larger system but analyze the snippet in isolation unless broader context is explicitly given.
- When referring to the file path, use the one provided, prefixed with "File: ".

Let's begin the security review.
"""

# --- Helper Functions ---

def _normalize_extensions(extensions: Optional[List[str]]) -> Set[str]:
    if not extensions:
        return set()
    return {f".{e.strip('.').lower()}" if e.strip() else "" for e in extensions} - {""} # remove empty strings

def _normalize_patterns(patterns: Optional[List[str]]) -> Set[str]:
    if not patterns:
        return set()
    return {p.lower().strip('/') for p in patterns if p.strip()}

def load_api_key(args_api_key: Optional[str]) -> Optional[str]:
    if args_api_key:
        return args_api_key
    load_dotenv()
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        print("Error: GOOGLE_API_KEY not found. Set it in your .env file or pass via --api-key.")
        return None
    return api_key

def _should_prune_dir(dirname: str, excluded_patterns: Set[str]) -> bool:
    lname = dirname.lower()
    return lname in excluded_patterns

def is_excluded(
    file_path: Path,
    root_dir: Path,
    excluded_extensions: Set[str],
    excluded_filenames_patterns: Set[str]
) -> bool:
    filename_lower = file_path.name.lower()
    extension_lower = file_path.suffix.lower()

    if extension_lower in excluded_extensions:
        return True
    if filename_lower in excluded_filenames_patterns:
        return True
    try:
        relative_path_parts = file_path.relative_to(root_dir).parts
        for part in relative_path_parts[:-1]:
            if part.lower() in excluded_filenames_patterns:
                return True
    except ValueError:
        pass
    return False

def discover_code_files(
    directory_str: str,
    include_ext_cli: Optional[List[str]],
    exclude_ext_cli: Optional[List[str]],
    exclude_files_cli: Optional[List[str]]
) -> List[Path]:
    discovered_files: List[Path] = []
    abs_root_dir = Path(directory_str)
    if not abs_root_dir.is_absolute():
        abs_root_dir = abs_root_dir.resolve()

    cli_include_extensions = _normalize_extensions(include_ext_cli)
    current_include_extensions = cli_include_extensions if cli_include_extensions else DEFAULT_RELEVANT_EXTENSIONS.copy()

    current_excluded_extensions = DEFAULT_EXCLUDED_EXTENSIONS.copy()
    current_excluded_extensions.update(_normalize_extensions(exclude_ext_cli))

    current_excluded_filenames_patterns = DEFAULT_EXCLUDED_FILENAMES_PATTERNS.copy()
    current_excluded_filenames_patterns.update(_normalize_patterns(exclude_files_cli))

    print(f"[*] Starting file discovery in: {abs_root_dir}")
    print(f"    Including extensions/names: {current_include_extensions if current_include_extensions else 'All (based on internal defaults, except excluded)'}")
    print(f"    Excluding extensions: {current_excluded_extensions}")
    print(f"    Excluding names/patterns: {current_excluded_filenames_patterns}")

    for dirpath_str, dirnames, filenames in os.walk(abs_root_dir, topdown=True):
        dirpath = Path(dirpath_str)
        dirnames[:] = [d for d in dirnames if not _should_prune_dir(d, current_excluded_filenames_patterns)]

        for filename in filenames:
            file_path = dirpath / filename
            if is_excluded(file_path, abs_root_dir, current_excluded_extensions, current_excluded_filenames_patterns):
                continue

            ext_lower = file_path.suffix.lower()
            filename_lower = file_path.name.lower()

            is_relevant = False
            if cli_include_extensions:
                if ext_lower in current_include_extensions or filename_lower in current_include_extensions:
                    is_relevant = True
            elif current_include_extensions:
                 if ext_lower in current_include_extensions or filename_lower in current_include_extensions:
                    is_relevant = True
            else:
                is_relevant = True

            if is_relevant:
                discovered_files.append(file_path)

    print(f"[*] Discovered {len(discovered_files)} potentially relevant files initially.")
    return discovered_files

# --- Interactive File Review Enhancements ---

def _rebuild_selectable_list(
    all_discovered_files: List[Path],
    current_interactive_exclusions: Set[str],
    root_dir: Path
) -> Tuple[List[Dict[str, Any]], List[Path]]:
    """
    Filters the initially discovered files based on current interactive exclusions
    and rebuilds the list for display and selection.
    """
    filtered_for_display: List[Path] = []
    for abs_path in all_discovered_files:
        if abs_path.suffix.lower() not in current_interactive_exclusions:
            filtered_for_display.append(abs_path)

    selectable_files_rebuilt: List[Dict[str, Any]] = []
    print("\n--- Updated File List ---")
    if not filtered_for_display:
        print("No files remaining after applying exclusions.")
    else:
        print(f"Found {len(filtered_for_display)} files matching current criteria:")
        for i, abs_path in enumerate(filtered_for_display):
            relative_path = abs_path.relative_to(root_dir)
            # All files in the rebuilt list are initially selected
            selectable_files_rebuilt.append({"id": i + 1, "path_obj": abs_path, "rel_path_str": str(relative_path), "selected": True})
            print(f"  {i+1}. {str(relative_path)}")
    
    return selectable_files_rebuilt, filtered_for_display


def review_and_filter_files_interactive(
    initial_discovered_files: List[Path], # All files found by discover_code_files
    root_dir: Path
) -> Optional[List[Path]]:
    if not initial_discovered_files:
        return []

    print("\n--- File Review Stage ---")
    
    current_interactive_exclusions: Set[str] = set()
    # Build the initial list based on no interactive exclusions yet
    selectable_files, current_shown_files = _rebuild_selectable_list(initial_discovered_files, current_interactive_exclusions, root_dir)

    if not selectable_files: # No files even before interactive exclusions
        print("No files initially found to present for review.")
        return []


    while True:
        print("\nOptions:")
        print("  - Enter number(s) to toggle selection (e.g., '1 3 5').")
        print("  - Type 'all' to select all, 'none' to deselect all.")
        print("  - Type 'list' to show current selections and excluded extensions.")
        print("  - Type 'exclude .ext1 .ext2 ...' to exclude files with these extensions from the list.")
        print("  - Type 'done' or press Enter (if no input) to proceed.")
        print("  - Type 'cancel' or press Ctrl+C to abort the scan.")

        try:
            user_input = input("Your choice: ").strip().lower()
        except KeyboardInterrupt:
            print("\n[*] Scan aborted by user (Ctrl+C).")
            return None

        if not user_input or user_input == "done":
            break
        if user_input == "cancel":
            print("[*] Scan aborted by user.")
            return None
        
        if user_input.startswith("exclude "):
            parts = user_input.split()
            if len(parts) > 1:
                extensions_to_exclude = _normalize_extensions(parts[1:])
                newly_excluded_count = 0
                for ext in extensions_to_exclude:
                    if ext not in current_interactive_exclusions:
                        current_interactive_exclusions.add(ext)
                        newly_excluded_count +=1
                
                if newly_excluded_count > 0:
                    print(f"[*] Added {extensions_to_exclude} to interactive exclusion list.")
                    # Rebuild and re-display the list
                    selectable_files, current_shown_files = _rebuild_selectable_list(
                        initial_discovered_files, # Always filter from the original full list
                        current_interactive_exclusions,
                        root_dir
                    )
                    if not selectable_files:
                        print("All files have been excluded. Type 'done' to proceed with no files, or 'cancel'.")
                else:
                    print(f"[*] Extensions {extensions_to_exclude} were already excluded or invalid.")
            else:
                print("Usage: exclude .ext1 .ext2 ...")
            continue

        if user_input == "list":
            print("\nCurrent Selections (* indicates selected):")
            if not selectable_files:
                print("  No files currently in the list.")
            else:
                for f_info in selectable_files:
                    marker = "*" if f_info["selected"] else " "
                    print(f"  {marker} {f_info['id']}. {f_info['rel_path_str']}")
            print(f"Currently excluded extensions (interactive): {current_interactive_exclusions if current_interactive_exclusions else 'None'}")
            continue
        
        if user_input == "all":
            for f_info in selectable_files: f_info["selected"] = True
            if selectable_files: print("All currently listed files selected.")
            else: print("No files to select.")
            continue
        if user_input == "none":
            for f_info in selectable_files: f_info["selected"] = False
            if selectable_files: print("All currently listed files deselected.")
            else: print("No files to deselect.")
            continue

        try:
            ids_to_toggle = {int(x) for x in user_input.split()}
            valid_ids_toggled = set()
            for f_info in selectable_files:
                if f_info["id"] in ids_to_toggle:
                    f_info["selected"] = not f_info["selected"]
                    print(f"File '{f_info['rel_path_str']}' is now {'SELECTED' if f_info['selected'] else 'DESELECTED'}.")
                    valid_ids_toggled.add(f_info["id"])

            for invalid_id in ids_to_toggle - valid_ids_toggled:
                print(f"Warning: File number {invalid_id} not found in the list.")

        except ValueError:
            print("Invalid input. Please enter numbers, 'all', 'none', 'list', 'exclude ...', 'done', or 'cancel'.")

    final_selected_files = [f_info["path_obj"] for f_info in selectable_files if f_info["selected"]]

    if not final_selected_files:
        print("[*] No files selected for analysis.")
    else:
        print(f"\n[*] Proceeding with {len(final_selected_files)} selected file(s).")
    return final_selected_files

def chunk_content(content: str, chunk_size_chars: int) -> List[str]:
    if chunk_size_chars <= 0:
        return [content]
    return [content[i:i + chunk_size_chars] for i in range(0, len(content), chunk_size_chars)]

def analyze_code_with_llm(
    filepath_display: str,
    code_content_chunk: str,
    model_name: str,
    system_prompt: str
) -> str:
    try:
        model = genai.GenerativeModel(model_name)
        full_prompt = f"{system_prompt}\n\nFile: {filepath_display}\n\nCode Snippet to Analyze:\n```\n{code_content_chunk}\n```"
        response = model.generate_content(
            full_prompt,
            generation_config=genai_types.GenerationConfig(temperature=0.2)
        )
        if not response.parts:
            feedback = response.prompt_feedback
            if feedback and feedback.block_reason:
                return f"Error: Content generation blocked for {filepath_display}. Reason: {feedback.block_reason_message or feedback.block_reason}"
            return f"Error: Received an empty response from Gemini for {filepath_display}."
        return response.text
    except Exception as e:
        return f"Error during LLM API call for {filepath_display}: {e}"

def generate_report(
    findings: List[str],
    output_file_base_cli_arg: Optional[str],
    reports_dir_path: Path
) -> None:
    timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    reports_dir_path.mkdir(parents=True, exist_ok=True)
    base_name = Path(output_file_base_cli_arg).stem if output_file_base_cli_arg else DEFAULT_REPORT_BASE_NAME
    md_report_file = reports_dir_path / f"{base_name}_{timestamp_str}.md"
    txt_report_file = reports_dir_path / f"{base_name}_{timestamp_str}.txt"
    report_title = f"Secrev Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    disclaimer = (
        "This report was generated by an AI-assisted security review tool (Secrev). "
        "The findings are potential vulnerabilities and **require human verification and contextual understanding.** "
        "This tool is an aid and not a replacement for thorough manual code review, dedicated SAST/DAST tools, or professional security audits."
    )
    md_content_parts: List[str] = [f"# {report_title}\n\n", "## Disclaimer\n", f"{disclaimer}\n\n", "## Findings\n"]
    txt_content_parts: List[str] = [f"{report_title}\n\n", "Disclaimer:\n", f"{disclaimer}\n\n", "Findings:\n", "="*20 + "\n\n"]
    if not findings:
        no_findings_msg = "No potential vulnerabilities were reported by the LLM across the scanned files.\n"
        md_content_parts.append(no_findings_msg)
        txt_content_parts.append(no_findings_msg)
    else:
        actionable_findings_count = 0
        for finding_text in findings:
            is_error = "Error:" in finding_text
            is_no_vulns = "No critical security vulnerabilities identified" in finding_text
            if not is_error and not is_no_vulns:
                actionable_findings_count += 1
                md_content_parts.extend(["---\n", f"{finding_text}\n\n"])
                txt_content_parts.extend([f"------------------------\n{finding_text}\n\n"])
            elif is_error:
                md_content_parts.extend(["---\n", f"**Analysis Issue:**\n{finding_text}\n\n"])
                txt_content_parts.extend([f"--- ANALYSIS ISSUE ---\n{finding_text}\n\n"])
        if actionable_findings_count == 0 and any("Error:" not in f for f in findings if f):
            no_findings_msg = "The LLM reviewed the content but did not identify any critical security vulnerabilities.\n"
            md_content_parts.append(no_findings_msg)
            txt_content_parts.append(no_findings_msg)
    md_full_content = "".join(md_content_parts)
    txt_full_content = "".join(txt_content_parts)
    print("\n" + "="*20 + " Secrev Report Summary " + "="*20 + "\n")
    summary_for_console = md_full_content
    if len(summary_for_console) > 3000:
        summary_for_console = summary_for_console[:3000] + "\n... (Full report saved to file)"
    print(summary_for_console)
    try:
        md_report_file.write_text(md_full_content, encoding='utf-8')
        print(f"\n[*] Markdown report saved to: {md_report_file.resolve()}")
    except IOError as e:
        print(f"Error: Could not write Markdown report to file {md_report_file}: {e}")
    try:
        txt_report_file.write_text(txt_full_content, encoding='utf-8')
        print(f"[*] Text report saved to: {txt_report_file.resolve()}")
    except IOError as e:
        print(f"Error: Could not write Text report to file {txt_report_file}: {e}")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Secrev - AI-Powered Code Security Review Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-d", "--directory", required=True, type=str, help="Path to the codebase directory to scan.")
    parser.add_argument("-m", "--model", default=DEFAULT_MODEL_NAME, type=str, help=f"Gemini model name (default: {DEFAULT_MODEL_NAME}).")
    parser.add_argument("-k", "--api-key", type=str, help="Google API Key (overrides .env).")
    parser.add_argument(
        "-o", "--output-file-base", type=str,
        help=(
            "Base name for the report files (e.g., 'my_project_secrev').\n"
            "Timestamped .md and .txt files will be created in the reports directory.\n"
            f"If not specified, defaults to '{DEFAULT_REPORTS_DIR_NAME}/{DEFAULT_REPORT_BASE_NAME}_TIMESTAMP.ext'."
        )
    )
    parser.add_argument(
        "--reports-dir", default=DEFAULT_REPORTS_DIR_NAME, type=str,
        help=f"Directory to save report files (default: ./{DEFAULT_REPORTS_DIR_NAME})."
    )
    parser.add_argument("--include-extensions", type=lambda s: [item.strip() for item in s.split(',')],
                        help="Comma-separated list of file extensions/names to specifically include (e.g., .py,.js,Dockerfile).\nOverrides internal defaults.")
    parser.add_argument("--exclude-extensions", type=lambda s: [item.strip() for item in s.split(',')],
                        help="Comma-separated list of file extensions to explicitly exclude.\nAdds to internal defaults.")
    parser.add_argument("--exclude-files", type=lambda s: [item.strip() for item in s.split(',')],
                        help="Comma-separated list of specific filenames or directory patterns to exclude.\nAdds to internal defaults.")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE_CHARS,
                        help=f"Max characters per code chunk sent to LLM (default: {DEFAULT_CHUNK_SIZE_CHARS}).")
    parser.add_argument("--max-total-chars", type=int, default=DEFAULT_MAX_TOTAL_CHARS_PROCESSED,
                        help=f"Safety limit on total characters processed. Set to 0 for no limit (default: {DEFAULT_MAX_TOTAL_CHARS_PROCESSED}).")
    parser.add_argument("-y", "--yes", action="store_true", help="Automatically skip interactive file review.")

    args = parser.parse_args()

    try:
        raw_target_directory = Path(args.directory)
        if not raw_target_directory.is_dir():
            print(f"Error: Directory not found: {args.directory}")
            return 1
        target_directory_abs = raw_target_directory.resolve()
    except Exception as e:
        print(f"Error processing directory path '{args.directory}': {e}")
        return 1

    api_key = load_api_key(args.api_key)
    if not api_key:
        return 1
    
    try:
        genai.configure(api_key=api_key)
    except Exception as e:
        print(f"Error: Failed to configure Google Generative AI: {e}")
        return 1

    print(f"[*] Using LLM Model: {args.model}")

    initially_discovered_files = discover_code_files(
        str(target_directory_abs),
        args.include_extensions,
        args.exclude_extensions,
        args.exclude_files
    )

    if not initially_discovered_files:
        print("[*] No files initially found to scan based on the criteria. Exiting.")
        return 0

    files_to_scan: Optional[List[Path]]
    if args.yes:
        files_to_scan = initially_discovered_files
        print(f"[*] Skipping interactive review. Proceeding with all {len(files_to_scan)} initially discovered files.")
    else:
        files_to_scan = review_and_filter_files_interactive(initially_discovered_files, target_directory_abs)

    if files_to_scan is None:
        return 0
    if not files_to_scan:
        print("[*] No files selected for analysis after review. Exiting.")
        return 0

    all_llm_findings: List[str] = []
    total_chars_processed: int = 0
    reports_dir = Path(args.reports_dir)

    for i, file_path in enumerate(files_to_scan):
        relative_path_str = str(file_path.relative_to(target_directory_abs))
        print(f"\n[*] Processing file {i+1}/{len(files_to_scan)}: {relative_path_str}")

        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            error_msg = f"Error: Could not read file {relative_path_str}. Reason: {e}"
            print(f"    {error_msg}")
            all_llm_findings.append(error_msg)
            continue

        if not content.strip():
            print(f"    Skipping empty file: {relative_path_str}")
            continue

        content_len = len(content)
        if args.max_total_chars > 0 and (total_chars_processed + content_len > args.max_total_chars) and total_chars_processed < args.max_total_chars:
            print(f"    WARNING: Max total characters limit ({args.max_total_chars}) would be exceeded by this file's content ({content_len} chars). Skipping file.")
            continue

        code_chunks = chunk_content(content, args.chunk_size)

        for chunk_idx, chunk in enumerate(code_chunks):
            if not chunk.strip():
                continue
            chunk_len = len(chunk)
            if args.max_total_chars > 0 and (total_chars_processed + chunk_len > args.max_total_chars) and total_chars_processed < args.max_total_chars:
                print(f"    INFO: Max total characters limit ({args.max_total_chars}) would be exceeded by this chunk. Stopping analysis for this file.")
                break
            print(f"    Analyzing chunk {chunk_idx + 1}/{len(code_chunks)} (size: {chunk_len} chars)...")
            display_filepath = f"{relative_path_str} (Chunk {chunk_idx+1}/{len(code_chunks)})" if len(code_chunks) > 1 else relative_path_str
            llm_response = analyze_code_with_llm(
                display_filepath,
                chunk,
                args.model,
                SECURITY_ANALYSIS_SYSTEM_PROMPT
            )
            if llm_response:
                all_llm_findings.append(llm_response)
            total_chars_processed += chunk_len
            if args.max_total_chars > 0 and total_chars_processed >= args.max_total_chars:
                if i < len(files_to_scan) - 1 or chunk_idx < len(code_chunks) -1:
                    print(f"    INFO: Max total characters limit ({args.max_total_chars}) reached. Moving to report generation.")
                break
        if args.max_total_chars > 0 and total_chars_processed >= args.max_total_chars:
            break

    generate_report(all_llm_findings, args.output_file_base, reports_dir.resolve())
    print(f"\n[*] Secrev scan complete. Total characters processed: {total_chars_processed}")
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())