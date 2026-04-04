#!/usr/bin/env python3
"""Dead-Code-Forensic: Find dead code, trace its origin, assess deletion safety.

Not just "unused code finder" — a forensic investigation:
- WHO wrote it (git blame)
- WHY they wrote it (commit message)
- WHEN it was last touched
- WHAT breaks if you delete it (dependency analysis)
- SHOULD you delete it (safety verdict)
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Language detection & patterns
# ---------------------------------------------------------------------------

LANG_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".vue": "vue",
    ".svelte": "svelte",
}

# Patterns for detecting function/class/variable definitions
DEFINITION_PATTERNS = {
    "python": {
        "function": r'^\s*def\s+(\w+)\s*\(',
        "class": r'^\s*class\s+(\w+)\s*[\(:]',
        "variable": r'^(\w+)\s*=\s*',
        "export": None,  # Python uses __all__
    },
    "javascript": {
        "function": r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>|\w+\s*=>))',
        "class": r'class\s+(\w+)',
        "variable": r'(?:const|let|var)\s+(\w+)\s*=',
        "export": r'export\s+(?:default\s+)?(?:function|class|const|let|var|async)\s+(\w+)',
        "export_named": r'export\s*\{\s*([^}]+)\s*\}',
    },
    "typescript": {
        "function": r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*(?::\s*\S+\s*)?=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))',
        "class": r'class\s+(\w+)',
        "variable": r'(?:const|let|var)\s+(\w+)\s*(?::\s*\S+\s*)?=',
        "export": r'export\s+(?:default\s+)?(?:function|class|const|let|var|async|interface|type|enum)\s+(\w+)',
        "export_named": r'export\s*\{\s*([^}]+)\s*\}',
        "interface": r'(?:export\s+)?interface\s+(\w+)',
        "type_alias": r'(?:export\s+)?type\s+(\w+)\s*=',
    },
    "go": {
        "function": r'^func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(',
        "type": r'^type\s+(\w+)\s+(?:struct|interface)',
        "variable": r'^(?:var|const)\s+(\w+)',
    },
    "java": {
        "function": r'(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\(',
        "class": r'(?:public|private|protected)?\s*class\s+(\w+)',
        "variable": r'(?:private|protected|public)\s+\w+\s+(\w+)\s*[;=]',
    },
    "rust": {
        "function": r'(?:pub\s+)?fn\s+(\w+)',
        "struct": r'(?:pub\s+)?struct\s+(\w+)',
        "enum": r'(?:pub\s+)?enum\s+(\w+)',
        "trait": r'(?:pub\s+)?trait\s+(\w+)',
    },
}

# Patterns for commented-out code
COMMENT_CODE_PATTERNS = [
    # Single-line comments that look like code
    r'^\s*(?://|#)\s*(?:def |function |class |const |let |var |import |from |return |if |for |while )',
    r'^\s*(?://|#)\s*\w+\s*\(.*\)\s*;?\s*$',
    r'^\s*(?://|#)\s*\w+\s*=\s*',
    # Block comments with code
    r'^\s*/\*[\s\S]*?(?:function|class|const|return|import)',
]

# Built-in names to skip
SKIP_NAMES = {
    "python": {"__init__", "__str__", "__repr__", "__len__", "__eq__", "__hash__",
               "__enter__", "__exit__", "__iter__", "__next__", "__call__",
               "main", "setUp", "tearDown", "test_"},
    "javascript": {"constructor", "render", "componentDidMount", "componentWillUnmount",
                   "getInitialState", "default", "module"},
    "typescript": {"constructor", "render", "default", "module"},
    "go": {"main", "init", "New", "String", "Error"},
    "java": {"main", "toString", "equals", "hashCode"},
    "rust": {"main", "new", "default", "from", "into", "drop"},
}


# ---------------------------------------------------------------------------
# Git integration
# ---------------------------------------------------------------------------

def run_git(args, cwd=None):
    result = subprocess.run(
        ["git"] + args, capture_output=True, text=True, cwd=cwd,
    )
    return result.stdout if result.returncode == 0 else ""


def git_blame_line(file_path, line_num, cwd=None):
    """Get blame info for a specific line."""
    result = run_git(
        ["blame", "-L", f"{line_num},{line_num}", "--porcelain", file_path],
        cwd=cwd,
    )
    if not result:
        return None

    info = {}
    for line in result.split("\n"):
        if line.startswith("author "):
            info["author"] = line[7:]
        elif line.startswith("author-time "):
            ts = int(line[12:])
            info["date"] = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
            info["age_days"] = (datetime.now(timezone.utc) - datetime.fromtimestamp(ts, tz=timezone.utc)).days
        elif line.startswith("summary "):
            info["commit_message"] = line[8:]

    # Get commit hash from first line
    first_line = result.split("\n")[0]
    if first_line:
        info["commit"] = first_line.split()[0][:8]

    return info if info else None


def git_log_file(file_path, cwd=None):
    """Get the last modification info for a file."""
    result = run_git(
        ["log", "-1", "--format=%H|||%an|||%aI|||%s", "--", file_path],
        cwd=cwd,
    )
    if not result.strip():
        return None
    parts = result.strip().split("|||")
    if len(parts) >= 4:
        return {
            "commit": parts[0][:8],
            "author": parts[1],
            "date": parts[2][:10],
            "message": parts[3],
        }
    return None


# ---------------------------------------------------------------------------
# Dead code detector
# ---------------------------------------------------------------------------

class DeadCodeDetector:
    def __init__(self, project_dir, extensions=None, exclude_dirs=None):
        self.project_dir = Path(project_dir).resolve()
        self.extensions = extensions or list(LANG_MAP.keys())
        self.exclude_dirs = exclude_dirs or {
            "node_modules", ".git", "__pycache__", "venv", ".venv", "env",
            "dist", "build", ".next", ".nuxt", "vendor", "target",
            ".tox", ".pytest_cache", ".mypy_cache", "coverage",
        }
        self.files = []
        self.definitions = []     # All function/class/var definitions found
        self.references = defaultdict(set)  # name -> set of files that reference it
        self.dead_code = []       # Confirmed dead code
        self.commented_code = []  # Commented-out code blocks

    def scan(self):
        """Run the full dead code scan."""
        print(f"[*] Scanning {self.project_dir}...")
        self._collect_files()
        print(f"[*] Found {len(self.files)} source files")

        self._extract_definitions()
        print(f"[*] Found {len(self.definitions)} definitions")

        self._build_reference_map()
        self._find_dead_code()
        self._find_commented_code()

        print(f"[+] Found {len(self.dead_code)} dead code items")
        print(f"[+] Found {len(self.commented_code)} commented code blocks")

        return self._build_report()

    def _collect_files(self):
        """Collect all source files."""
        for ext in self.extensions:
            for file_path in self.project_dir.rglob(f"*{ext}"):
                # Skip excluded dirs
                parts = file_path.relative_to(self.project_dir).parts
                if any(d in self.exclude_dirs for d in parts):
                    continue
                # Skip test files for some checks
                self.files.append(file_path)

    def _extract_definitions(self):
        """Extract all function/class/variable definitions from all files."""
        for file_path in self.files:
            lang = LANG_MAP.get(file_path.suffix, None)
            if not lang or lang not in DEFINITION_PATTERNS:
                continue

            patterns = DEFINITION_PATTERNS[lang]
            skip = SKIP_NAMES.get(lang, set())
            rel_path = str(file_path.relative_to(self.project_dir))
            is_test = any(t in rel_path.lower() for t in ["test", "spec", "__test__", "_test."])

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.split("\n")
            except:
                continue

            for line_num, line in enumerate(lines, 1):
                for def_type, pattern in patterns.items():
                    if pattern is None:
                        continue
                    m = re.search(pattern, line)
                    if m:
                        # Get the first non-None group
                        name = next((g for g in m.groups() if g), None)
                        if not name:
                            continue

                        # Skip builtins and test methods
                        if name in skip or name.startswith("_"):
                            continue
                        if any(name.startswith(s) for s in skip if s.endswith("_")):
                            continue

                        self.definitions.append({
                            "name": name,
                            "type": def_type,
                            "file": rel_path,
                            "line": line_num,
                            "line_content": line.strip()[:120],
                            "lang": lang,
                            "is_test": is_test,
                            "is_exported": "export" in def_type or
                                           (lang == "go" and name[0].isupper()),
                        })

    def _build_reference_map(self):
        """Build a map of where each name is referenced across the project."""
        # Collect all definition names
        all_names = {d["name"] for d in self.definitions}

        for file_path in self.files:
            rel_path = str(file_path.relative_to(self.project_dir))
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except:
                continue

            for name in all_names:
                # Simple reference check: word boundary match
                # Skip if name is too short (likely false positives)
                if len(name) < 3:
                    continue
                if re.search(r'\b' + re.escape(name) + r'\b', content):
                    self.references[name].add(rel_path)

    def _find_dead_code(self):
        """Identify definitions that are never referenced outside their own file."""
        for defn in self.definitions:
            if defn["is_test"]:
                continue  # Don't flag test code

            name = defn["name"]
            refs = self.references.get(name, set())

            # Remove the definition's own file from references
            other_refs = refs - {defn["file"]}

            # A definition is "dead" if:
            # 1. Only referenced in its own file (possibly just the definition line)
            # 2. Or not referenced anywhere at all
            is_dead = False
            reason = ""

            if not refs:
                is_dead = True
                reason = "Never referenced anywhere"
            elif refs == {defn["file"]}:
                # Only in own file — might be used internally
                # Check if referenced more than once in own file
                try:
                    content = (self.project_dir / defn["file"]).read_text(
                        encoding="utf-8", errors="ignore"
                    )
                    count = len(re.findall(r'\b' + re.escape(name) + r'\b', content))
                    if count <= 1:
                        is_dead = True
                        reason = "Defined but never called (only 1 occurrence in file)"
                    elif defn["is_exported"] and not other_refs:
                        is_dead = True
                        reason = "Exported but never imported by other files"
                except:
                    pass

            if is_dead:
                # Git blame for forensics
                blame = git_blame_line(
                    defn["file"], defn["line"],
                    cwd=str(self.project_dir),
                )

                self.dead_code.append({
                    **defn,
                    "reason": reason,
                    "references": sorted(refs),
                    "blame": blame,
                    "safety": self._assess_safety(defn, refs),
                })

    def _find_commented_code(self):
        """Find commented-out code blocks."""
        for file_path in self.files:
            rel_path = str(file_path.relative_to(self.project_dir))
            try:
                lines = file_path.read_text(encoding="utf-8", errors="ignore").split("\n")
            except:
                continue

            consecutive_comments = []
            for line_num, line in enumerate(lines, 1):
                is_commented_code = False
                for pattern in COMMENT_CODE_PATTERNS:
                    if re.search(pattern, line):
                        is_commented_code = True
                        break

                if is_commented_code:
                    consecutive_comments.append((line_num, line.strip()))
                else:
                    if len(consecutive_comments) >= 2:
                        # Found a block of commented code
                        blame = git_blame_line(
                            rel_path, consecutive_comments[0][0],
                            cwd=str(self.project_dir),
                        )
                        self.commented_code.append({
                            "file": rel_path,
                            "start_line": consecutive_comments[0][0],
                            "end_line": consecutive_comments[-1][0],
                            "line_count": len(consecutive_comments),
                            "preview": consecutive_comments[0][1][:100],
                            "blame": blame,
                        })
                    consecutive_comments = []

    def _assess_safety(self, defn, refs):
        """Assess how safe it is to delete this code."""
        # Safe to delete
        if not refs or (refs == {defn["file"]} and not defn["is_exported"]):
            if defn["type"] in ("variable", "type_alias", "interface"):
                return {"verdict": "SAFE", "reason": "Unused local variable/type"}
            if defn.get("is_test"):
                return {"verdict": "SAFE", "reason": "Unused test helper"}
            return {"verdict": "SAFE", "reason": "No references found"}

        # Exported but unused — might be used by external consumers
        if defn["is_exported"]:
            return {
                "verdict": "CAUTION",
                "reason": "Exported — might be used by external packages or dynamic imports",
            }

        # Referenced in own file but possibly dead
        return {
            "verdict": "INVESTIGATE",
            "reason": "Only referenced in same file — check if it's truly called",
        }

    def _build_report(self):
        """Build the full forensic report."""
        # Summary stats
        lang_counts = defaultdict(int)
        for f in self.files:
            lang = LANG_MAP.get(f.suffix, "other")
            lang_counts[lang] += 1

        # Group dead code by file
        by_file = defaultdict(list)
        for dc in self.dead_code:
            by_file[dc["file"]].append(dc)

        # Safety breakdown
        safe = [dc for dc in self.dead_code if dc["safety"]["verdict"] == "SAFE"]
        caution = [dc for dc in self.dead_code if dc["safety"]["verdict"] == "CAUTION"]
        investigate = [dc for dc in self.dead_code if dc["safety"]["verdict"] == "INVESTIGATE"]

        # Top offenders (files with most dead code)
        offenders = sorted(by_file.items(), key=lambda x: -len(x[1]))[:10]

        # Author responsibility
        author_dead = defaultdict(int)
        for dc in self.dead_code:
            if dc.get("blame") and dc["blame"].get("author"):
                author_dead[dc["blame"]["author"]] += 1

        return {
            "summary": {
                "project": str(self.project_dir),
                "files_scanned": len(self.files),
                "definitions_found": len(self.definitions),
                "dead_code_items": len(self.dead_code),
                "commented_code_blocks": len(self.commented_code),
                "languages": dict(lang_counts),
                "safety_breakdown": {
                    "safe_to_delete": len(safe),
                    "caution": len(caution),
                    "investigate": len(investigate),
                },
            },
            "dead_code": self.dead_code,
            "commented_code": self.commented_code,
            "top_offenders": [(f, len(items)) for f, items in offenders],
            "author_responsibility": dict(sorted(author_dead.items(), key=lambda x: -x[1])),
        }


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

def generate_markdown(report):
    """Generate Markdown forensic report."""
    s = report["summary"]
    lines = []

    lines.append("# Dead Code Forensic Report\n")
    lines.append(f"> Project: `{s['project']}`")
    lines.append(f"> Files scanned: {s['files_scanned']}")
    lines.append(f"> Definitions found: {s['definitions_found']}")
    lines.append(f"> Dead code items: **{s['dead_code_items']}**")
    lines.append(f"> Commented code blocks: **{s['commented_code_blocks']}**")

    # Languages
    langs = ", ".join(f"{l}: {c}" for l, c in s["languages"].items())
    lines.append(f"> Languages: {langs}\n")

    # Safety summary
    sb = s["safety_breakdown"]
    lines.append("## Safety Summary\n")
    lines.append("```")
    lines.append(f"  SAFE to delete:     {sb['safe_to_delete']:>4}  ← just delete these")
    lines.append(f"  CAUTION (exported):  {sb['caution']:>4}  ← check external usage first")
    lines.append(f"  INVESTIGATE:         {sb['investigate']:>4}  ← manual review needed")
    lines.append("```\n")

    # Top offender files
    if report["top_offenders"]:
        lines.append("## Top Offender Files\n")
        lines.append("| File | Dead Items |")
        lines.append("|------|-----------|")
        for f, count in report["top_offenders"]:
            lines.append(f"| `{f}` | {count} |")
        lines.append("")

    # Author responsibility
    if report["author_responsibility"]:
        lines.append("## Who Wrote the Dead Code?\n")
        lines.append("| Author | Dead Items |")
        lines.append("|--------|-----------|")
        for author, count in report["author_responsibility"].items():
            lines.append(f"| {author} | {count} |")
        lines.append("")

    # Dead code details
    if report["dead_code"]:
        lines.append("---\n")
        lines.append("## Dead Code Details\n")

        # Group by safety
        for verdict in ["SAFE", "CAUTION", "INVESTIGATE"]:
            items = [dc for dc in report["dead_code"] if dc["safety"]["verdict"] == verdict]
            if not items:
                continue

            emoji = {"SAFE": "SAFE", "CAUTION": "CAUTION", "INVESTIGATE": "INVESTIGATE"}[verdict]
            lines.append(f"### [{emoji}] — {len(items)} items\n")

            for dc in items:
                blame = dc.get("blame", {})
                author = blame.get("author", "unknown")
                date = blame.get("date", "unknown")
                commit_msg = blame.get("commit_message", "")
                commit = blame.get("commit", "")
                age = blame.get("age_days", 0)

                lines.append(f"#### `{dc['name']}` ({dc['type']}) in `{dc['file']}:{dc['line']}`\n")
                lines.append(f"```\n{dc['line_content']}\n```\n")
                lines.append(f"- **Reason:** {dc['reason']}")
                lines.append(f"- **Safety:** {dc['safety']['verdict']} — {dc['safety']['reason']}")
                lines.append(f"- **Author:** {author} ({date}, {age} days ago)")
                if commit_msg:
                    lines.append(f"- **Commit:** `{commit}` — {commit_msg}")
                lines.append(f"- **Verdict:** {'Delete it.' if verdict == 'SAFE' else 'Check before deleting.' if verdict == 'CAUTION' else 'Manual review needed.'}")
                lines.append("")

    # Commented code
    if report["commented_code"]:
        lines.append("---\n")
        lines.append("## Commented-Out Code Blocks\n")
        lines.append("These are blocks of 2+ lines that look like commented-out code (not comments):\n")

        for cc in report["commented_code"][:20]:
            blame = cc.get("blame", {})
            author = blame.get("author", "unknown")
            date = blame.get("date", "unknown")
            lines.append(f"- **`{cc['file']}:{cc['start_line']}-{cc['end_line']}`** ({cc['line_count']} lines)")
            lines.append(f"  - Preview: `{cc['preview'][:80]}`")
            lines.append(f"  - Author: {author} ({date})")
            lines.append(f"  - Verdict: Delete — version control has the history")

        lines.append("")

    # Cleanup script suggestion
    safe_items = [dc for dc in report["dead_code"] if dc["safety"]["verdict"] == "SAFE"]
    if safe_items:
        lines.append("---\n")
        lines.append("## Suggested Cleanup\n")
        lines.append(f"**{len(safe_items)} items** can be safely deleted. Files to review:\n")
        safe_files = sorted(set(dc["file"] for dc in safe_items))
        for f in safe_files:
            file_items = [dc for dc in safe_items if dc["file"] == f]
            names = ", ".join(dc["name"] for dc in file_items)
            lines.append(f"- `{f}`: remove `{names}`")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Dead-Code-Forensic: Find dead code with git archaeology")
    parser.add_argument("--dir", "-d", default=".", help="Project directory to scan")
    parser.add_argument("--ext", nargs="*", help="File extensions to scan (e.g., .py .js .ts)")
    parser.add_argument("--exclude", nargs="*", help="Additional directories to exclude")
    parser.add_argument("--json", dest="json_output", help="Output raw JSON report")
    parser.add_argument("--output", "-o", help="Output Markdown report")
    args = parser.parse_args()

    extensions = args.ext or list(LANG_MAP.keys())
    exclude = None
    if args.exclude:
        exclude = {
            "node_modules", ".git", "__pycache__", "venv", ".venv",
            "dist", "build", ".next", "vendor", "target",
        } | set(args.exclude)

    detector = DeadCodeDetector(args.dir, extensions, exclude)
    report = detector.scan()

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        print(f"[+] JSON report: {args.json_output}")

    md = generate_markdown(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"[+] Report: {args.output}")
    else:
        print(md)


if __name__ == "__main__":
    main()
