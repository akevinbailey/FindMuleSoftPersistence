#!/usr/bin/env python3
"""
Scan MuleSoft XML flow files (*.xml) and report file + line number for persistence/filesystem indicators.

Search is case-insensitive. Quotes in the rule descriptions are not part of the search.

RULES
1) Any line containing: file:config
2) An XML start-tag that begins with: <os:object-store ...>
   AND does NOT contain: persistent="false"
3) An XML start-tag that begins with: <vm:queue ...>
   AND contains: queueType="PERSISTENT"
4) Any line containing: java.io.File  OR  java.nio.file
5) DataWeave / Java-interop / Java module patterns that commonly indicate filesystem access, including:
   - DataWeave scripts embedded in XML: <dw:transform-message ...> ... </dw:transform-message>
     and <ee:transform ...> ... </ee:transform>
     We scan the DW body for patterns like:
       * new java.io.File( ... )
       * java.nio.file.Files.(write|newOutputStream|newBufferedWriter|createFile|createDirectories|copy|move|delete)
       * FileOutputStream, FileWriter, RandomAccessFile, Paths.get, Path.of, Files.writeString, etc.
   - Mule Java Module calls: <java:invoke ...>, <java:invoke-static ...>
     where method/class suggests filesystem access (Files.*, Paths.*, File*, etc.)

Notes:
- Handles multi-line start-tags for RULE 2 and RULE 3 (attributes spanning multiple lines).
- Best-effort skipping of XML comments <!-- ... --> so commented-out code is less likely to match.
- Reports the line number where the match occurs (or where the element start-tag begins).
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Tuple


# ---------------------------
# Comment stripping utilities
# ---------------------------

def strip_xml_comments(line: str, in_comment: bool) -> Tuple[str, bool]:
    """
    Remove XML comments from a single line while tracking multi-line <!-- --> comment blocks.
    Returns (cleaned_line, new_in_comment).
    """
    out: List[str] = []
    i = 0
    n = len(line)

    while i < n:
        if in_comment:
            end = line.find("-->", i)
            if end == -1:
                return "".join(out), True
            i = end + 3
            in_comment = False
            continue

        start = line.find("<!--", i)
        if start == -1:
            out.append(line[i:])
            break

        out.append(line[i:start])
        i = start + 4
        in_comment = True

    return "".join(out), in_comment


# ---------------------------
# Regex patterns (case-insensitive)
# ---------------------------

RE_FILE_CONFIG = re.compile(r"file:config", re.IGNORECASE)

RE_OS_OBJECT_STORE_START = re.compile(r"<\s*os:object-store\b", re.IGNORECASE)
RE_PERSISTENT_FALSE = re.compile(r"""\bpersistent\s*=\s*(['"])false\1""", re.IGNORECASE)

RE_VM_QUEUE_START = re.compile(r"<\s*vm:queue\b", re.IGNORECASE)
RE_QUEUETYPE_PERSISTENT = re.compile(r"""\bqueueType\s*=\s*(['"])PERSISTENT\1""", re.IGNORECASE)

RE_JAVA_IO_FILE = re.compile(r"java\.io\.file", re.IGNORECASE)
RE_JAVA_NIO_FILE = re.compile(r"java\.nio\.file", re.IGNORECASE)

# DataWeave transform containers (start/end tags)
RE_DW_TRANSFORM_START = re.compile(r"<\s*(dw:transform-message|ee:transform)\b", re.IGNORECASE)
RE_DW_TRANSFORM_END = re.compile(r"</\s*(dw:transform-message|ee:transform)\s*>", re.IGNORECASE)

# Mule Java module
RE_JAVA_INVOKE_START = re.compile(r"<\s*java:(invoke|invoke-static)\b", re.IGNORECASE)
RE_CLASS_ATTR = re.compile(r"""\bclass\s*=\s*(['"])(.*?)\1""", re.IGNORECASE)
RE_METHOD_ATTR = re.compile(r"""\bmethod\s*=\s*(['"])(.*?)\1""", re.IGNORECASE)

# Heuristics for filesystem access in DW or Java module calls
# (These are intentionally broad: it's a "find likely file access" scanner.)
DW_FS_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("DW:java.io.File", re.compile(r"\bjava\.io\.File\b", re.IGNORECASE)),
    ("DW:new File()", re.compile(r"\bnew\s+(?:java\.io\.)?File\s*\(", re.IGNORECASE)),
    ("DW:FileOutputStream", re.compile(r"\bFileOutputStream\b", re.IGNORECASE)),
    ("DW:FileInputStream", re.compile(r"\bFileInputStream\b", re.IGNORECASE)),
    ("DW:FileWriter", re.compile(r"\bFileWriter\b", re.IGNORECASE)),
    ("DW:FileReader", re.compile(r"\bFileReader\b", re.IGNORECASE)),
    ("DW:RandomAccessFile", re.compile(r"\bRandomAccessFile\b", re.IGNORECASE)),
    ("DW:java.nio.file", re.compile(r"\bjava\.nio\.file\b", re.IGNORECASE)),
    ("DW:Paths.get/Path.of", re.compile(r"\b(Paths\s*\.\s*get|Path\s*\.\s*of)\s*\(", re.IGNORECASE)),
    ("DW:Files.(write/stream/create/copy/move/delete)", re.compile(
        r"\bFiles\s*\.\s*(write|writeString|newOutputStream|newBufferedWriter|createFile|createDirectories|copy|move|delete|deleteIfExists)\s*\(",
        re.IGNORECASE
    )),
    # Sometimes people use fully qualified: java.nio.file.Files.write(...)
    ("DW:java.nio.file.Files.*", re.compile(
        r"\bjava\.nio\.file\.Files\s*\.\s*(write|writeString|newOutputStream|newBufferedWriter|createFile|createDirectories|copy|move|delete|deleteIfExists)\s*\(",
        re.IGNORECASE
    )),
]

JAVA_FS_CLASS_HINTS = re.compile(
    r"\b(java\.io\.File|java\.io\.FileOutputStream|java\.io\.FileWriter|java\.nio\.file\.Files|java\.nio\.file\.Paths|java\.nio\.file\.Path)\b",
    re.IGNORECASE,
)
JAVA_FS_METHOD_HINTS = re.compile(
    r"\b(write|writeString|newOutputStream|newBufferedWriter|createFile|createDirectories|copy|move|delete|deleteIfExists|readAllBytes|readString|newInputStream|newBufferedReader)\b",
    re.IGNORECASE,
)


# ---------------------------
# Core scanning helpers
# ---------------------------

def accumulate_until(lines: List[str], start_idx: int, in_comment: bool, end_re: re.Pattern) -> Tuple[str, int, bool]:
    """
    Accumulate from start_idx until a line matches end_re, inclusive.
    Best-effort removal of XML comments as we go.

    Returns (accumulated_text_without_comments, end_idx, new_in_comment)
    """
    parts: List[str] = []
    idx = start_idx

    while idx < len(lines):
        cleaned, in_comment = strip_xml_comments(lines[idx], in_comment)
        parts.append(cleaned)
        if end_re.search(cleaned):
            return "\n".join(parts), idx, in_comment
        idx += 1

    return "\n".join(parts), len(lines) - 1, in_comment


def accumulate_start_tag(lines: List[str], start_idx: int, in_comment: bool) -> Tuple[str, int, bool]:
    """
    Accumulate from the line where a start-tag begins until the first '>' is encountered
    (best-effort for multi-line start-tags).

    Returns (accumulated_text_without_comments, end_idx, new_in_comment)
    """
    parts: List[str] = []
    idx = start_idx

    while idx < len(lines):
        cleaned, in_comment = strip_xml_comments(lines[idx], in_comment)
        parts.append(cleaned)

        joined = "\n".join(parts)
        if ">" in joined:
            return joined, idx, in_comment

        idx += 1

    return "\n".join(parts), len(lines) - 1, in_comment


def first_start_tag_portion(accumulated: str) -> str:
    """
    Return only the start-tag portion up to and including the first '>'.
    """
    if ">" not in accumulated:
        return accumulated.strip()
    head = accumulated.split(">", 1)[0] + ">"
    return head.strip()


def extract_attr(start_tag: str, attr_re: re.Pattern) -> Optional[str]:
    m = attr_re.search(start_tag)
    if not m:
        return None
    return m.group(2)


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    snippet: str


def add_simple_line_findings(findings: List[Finding], path: Path, line_no: int, cleaned_line: str) -> None:
    # RULE 1
    if RE_FILE_CONFIG.search(cleaned_line):
        findings.append(Finding(str(path), line_no, "RULE_1:file:config", cleaned_line.strip()[:300]))

    # RULE 4
    if RE_JAVA_IO_FILE.search(cleaned_line):
        findings.append(Finding(str(path), line_no, "RULE_4:java.io.File", cleaned_line.strip()[:300]))
    if RE_JAVA_NIO_FILE.search(cleaned_line):
        findings.append(Finding(str(path), line_no, "RULE_4:java.nio.file", cleaned_line.strip()[:300]))

    # RULE 5 (line-level hints outside of DW blocks too)
    for label, pat in DW_FS_PATTERNS:
        if pat.search(cleaned_line):
            findings.append(Finding(str(path), line_no, f"RULE_5:{label}", cleaned_line.strip()[:300]))


def scan_dataweave_block(dw_text: str, path: Path, start_line_no: int) -> List[Finding]:
    """
    Scan the full text of a DW transform block for filesystem patterns.
    We report the transform block's start line (good enough for pinpointing),
    and include a short matching snippet from within the block.
    """
    res: List[Finding] = []
    # Create a single-line version for cleaner snippets
    flat = " ".join(x.strip() for x in dw_text.splitlines()).strip()

    for label, pat in DW_FS_PATTERNS:
        m = pat.search(dw_text)
        if m:
            # snippet centered around the match
            s = max(m.start() - 60, 0)
            e = min(m.end() + 120, len(flat))
            snippet = flat[s:e].strip()
            res.append(Finding(str(path), start_line_no, f"RULE_5:{label}", snippet[:300]))

    return res


def scan_java_module_start_tag(start_tag: str, path: Path, line_no: int) -> List[Finding]:
    """
    Look at <java:invoke ...> / <java:invoke-static ...> class/method hints.
    """
    findings: List[Finding] = []
    cls = extract_attr(start_tag, RE_CLASS_ATTR) or ""
    method = extract_attr(start_tag, RE_METHOD_ATTR) or ""

    # Quick heuristic: either class or method hints indicate file I/O
    if JAVA_FS_CLASS_HINTS.search(cls) or JAVA_FS_METHOD_HINTS.search(method):
        snippet = start_tag.replace("\n", " ").strip()
        rule = "RULE_5:java:invoke(filesystem)"
        details = f"{rule} class={cls!r} method={method!r}"
        findings.append(Finding(str(path), line_no, details[:120], snippet[:300]))

    return findings


def scan_file(path: Path) -> List[Finding]:
    findings: List[Finding] = []

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return [Finding(str(path), 1, "ERROR", f"Failed to read file: {e}")]

    lines = text.splitlines()
    in_comment = False
    i = 0

    while i < len(lines):
        raw = lines[i]
        cleaned, in_comment = strip_xml_comments(raw, in_comment)
        line_no = i + 1

        # Always apply simple line-based checks
        add_simple_line_findings(findings, path, line_no, cleaned)

        # RULE 2: os:object-store
        if RE_OS_OBJECT_STORE_START.search(cleaned):
            accumulated, end_idx, in_comment = accumulate_start_tag(lines, i, in_comment)
            start_tag = first_start_tag_portion(accumulated)
            if not RE_PERSISTENT_FALSE.search(start_tag):
                snippet = start_tag.replace("\n", " ")
                findings.append(
                    Finding(str(path), line_no, "RULE_2:os:object-store(not persistent=false)", snippet[:300])
                )
            i = end_idx + 1
            continue

        # RULE 3: vm:queue
        if RE_VM_QUEUE_START.search(cleaned):
            accumulated, end_idx, in_comment = accumulate_start_tag(lines, i, in_comment)
            start_tag = first_start_tag_portion(accumulated)
            if RE_QUEUETYPE_PERSISTENT.search(start_tag):
                snippet = start_tag.replace("\n", " ")
                findings.append(
                    Finding(str(path), line_no, "RULE_3:vm:queue(queueType=PERSISTENT)", snippet[:300])
                )
            i = end_idx + 1
            continue

        # RULE 5: DataWeave blocks (scan the whole transform body)
        if RE_DW_TRANSFORM_START.search(cleaned):
            dw_text, end_idx, in_comment = accumulate_until(lines, i, in_comment, RE_DW_TRANSFORM_END)
            findings.extend(scan_dataweave_block(dw_text, path, line_no))
            i = end_idx + 1
            continue

        # RULE 5: Mule Java module calls
        if RE_JAVA_INVOKE_START.search(cleaned):
            accumulated, end_idx, in_comment = accumulate_start_tag(lines, i, in_comment)
            start_tag = first_start_tag_portion(accumulated)
            findings.extend(scan_java_module_start_tag(start_tag, path, line_no))
            i = end_idx + 1
            continue

        i += 1

    return findings


def iter_xml_files(root: Path) -> List[Path]:
    """
    If root is a file: scan it if .xml
    Is root is a directory: recursively scan all *.xml
    EXCLUDING:
        - any directory starting with ".tooling"
        - any directory named "target"
        - everything beneath them
    """
    if root.is_file():
        return [root] if root.suffix.lower() == ".xml" else []

    xml_files: List[Path] = []

    for current_root, dirs, files in os.walk(root):
        # Modify dirs in-place to prevent os.walk from descending
        dirs[:] = [
            d for d in dirs
            if not d.startswith(".tooling") and d != "target"
        ]

        for file_name in files:
            if file_name.lower().endswith(".xml"):
                xml_files.append(Path(current_root) / file_name)

    return xml_files


# ---------------------------
# Output helpers
# ---------------------------

def write_csv(findings: List[Finding], out_path: Path) -> None:
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["file", "line", "rule", "snippet"])
        w.writeheader()
        for item in findings:
            w.writerow(asdict(item))


def write_json(findings: List[Finding], out_path: Path) -> None:
    with out_path.open("w", encoding="utf-8") as f:
        json.dump([asdict(x) for x in findings], f, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Scan MuleSoft XML flow files for persistence/filesystem indicators.",
                                 formatter_class=lambda prog: argparse.HelpFormatter(prog, width=120))
    ap.add_argument("path", help="Root folder (recursive) or single XML file to scan.")
    ap.add_argument("--format", choices=["text", "csv", "json"], default="text", help="Output format.")
    ap.add_argument("--out", help="Output file path for csv/json (required for csv/json).")
    args = ap.parse_args(argv)

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"ERROR: Path does not exist: {root}", file=sys.stderr)
        return 2

    files = iter_xml_files(root)
    findings: List[Finding] = []
    for f in files:
        findings.extend(scan_file(f))

    findings.sort(key=lambda x: (x.file, x.line, x.rule))

    if args.format == "text":
        if not findings:
            print("No matches found.")
            return 0
        for item in findings:
            print(f"{item.file}:{item.line}  {item.rule}")
            print(f"  {item.snippet}")
        print(f"\nTotal findings: {len(findings)}")
        return 0

    if not args.out:
        print("ERROR: --out is required for csv/json output", file=sys.stderr)
        return 2

    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "csv":
        write_csv(findings, out_path)
    else:
        write_json(findings, out_path)

    print(f"Wrote {len(findings)} findings to {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())