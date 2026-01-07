#!/usr/bin/env python3
"""
Veracode Pipeline Scan JSON -> SARIF 2.1.0 (GitHub Code Scanning).

Goals:
- Show ALL findings in GitHub Code Scanning
- Use real repo file+line whenever possible
- Otherwise anchor to a placeholder file with stable line numbers
- Works with results.json or filtered_results.json

Expected Pipeline JSON shape:
{ ..., "findings": [ { ... } ] }
Each finding usually has:
  - severity (0-5)
  - cwe_id
  - issue_type / title
  - issue_id
  - files.source_file.file
  - files.source_file.line
"""

import argparse
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple

SEV_MAP = {
    "5": ("error",   "VERY_HIGH", "9.5"),
    "4": ("error",   "HIGH",      "8.0"),
    "3": ("warning", "MEDIUM",    "5.5"),
    "2": ("note",    "LOW",       "3.0"),
    "1": ("note",    "VERY_LOW",  "1.0"),
    "0": ("note",    "INFO",      "0.1"),
}

# Try common Java/web roots (safe even if they don't exist)
SOURCE_ROOTS = [
    "",
    "src/main/java/",
    "src/main/webapp/",
    "src/main/resources/",
    "src/",
]

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def as_str(x: Any) -> str:
    return "" if x is None else str(x)

def normalize_path(p: str) -> str:
    p = p.replace("\\", "/").strip()
    if p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")

def safe_int(x: Any, default: int = 1) -> int:
    try:
        v = int(str(x))
        return v if v >= 1 else default
    except Exception:
        return default

def stable_placeholder_line(rule_id: str, msg: str) -> int:
    h = sha256_text(f"{rule_id}|{msg}")
    return (int(h[:8], 16) % 20000) + 1

def strip_build_prefix(p: str) -> str:
    """
    Strip common build output prefixes seen in pipeline scan results.
    Examples:
      target/verademo/WEB-INF/views/profile.jsp -> WEB-INF/views/profile.jsp
      target/classes/com/x/Foo.class -> com/x/Foo.class
    """
    p = normalize_path(p)
    if p.startswith("target/"):
        rest = p[len("target/"):]
        if "/" in rest:
            rest = rest.split("/", 1)[1]
        return rest
    return p

def resolve_repo_uri(repo_root: str, raw_path: str) -> Optional[str]:
    raw_path = strip_build_prefix(raw_path)

    # Try under known source roots
    for root in SOURCE_ROOTS:
        candidate = normalize_path((root + raw_path) if root else raw_path)
        full = os.path.join(repo_root, candidate)
        if os.path.isfile(full):
            return candidate

    # Try raw as-is
    raw_norm = normalize_path(raw_path)
    if os.path.isfile(os.path.join(repo_root, raw_norm)):
        return raw_norm

    return None

def extract_file_and_line(finding: Dict[str, Any]) -> Tuple[Optional[str], Optional[int]]:
    files = finding.get("files") or {}
    src = files.get("source_file") or {}

    path = src.get("file") or src.get("upload_file") or ""
    line = src.get("line")

    path_s = as_str(path).strip()
    if not path_s:
        return None, None

    line_i = safe_int(line, default=1) if line is not None else None
    return path_s, line_i

def rule_id_from_finding(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    cwe_id = as_str(finding.get("cwe_id")).strip()
    issue_type = as_str(finding.get("issue_type")).strip()
    title = as_str(finding.get("title")).strip()

    if cwe_id:
        rid = f"CWE-{cwe_id}" if not cwe_id.upper().startswith("CWE-") else cwe_id.upper()
    else:
        rid = "VERACODE-ISSUE"

    name = issue_type or title or rid
    desc = issue_type or title or name
    return rid, name, desc

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--placeholder-uri", required=True)
    ap.add_argument("--output-stats", required=True)
    ap.add_argument("--tool-name", default="Veracode Pipeline Scan")
    ap.add_argument("--tool-version", default="")
    args = ap.parse_args()

    repo_root = os.getenv("GITHUB_WORKSPACE", os.getcwd())
    placeholder_uri = normalize_path(args.placeholder_uri)

    with open(args.input, "r", encoding="utf-8") as f:
        payload = json.load(f)

    findings = payload.get("findings") if isinstance(payload, dict) else None
    if not isinstance(findings, list):
        raise SystemExit("Expected an object with a 'findings' array (pipeline results JSON).")

    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    total = 0
    with_file = 0
    with_placeholder = 0
    unresolved_paths = 0

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        total += 1

        sev_raw = as_str(finding.get("severity")).strip()
        sarif_level, sev_label, gh_sec_score = SEV_MAP.get(sev_raw, ("warning", "UNKNOWN", "0.0"))

        rid, rname, rdesc = rule_id_from_finding(finding)

        issue_id = as_str(finding.get("issue_id")).strip()
        msg = f"[{sev_label}] {rdesc}" + (f" (issue_id={issue_id})" if issue_id else "")

        raw_path, raw_line = extract_file_and_line(finding)

        if raw_path and raw_line:
            resolved = resolve_repo_uri(repo_root, raw_path)
            if resolved:
                uri = resolved
                start_line = int(raw_line)
                with_file += 1
            else:
                uri = placeholder_uri
                start_line = stable_placeholder_line(rid, msg)
                with_placeholder += 1
                unresolved_paths += 1
        else:
            uri = placeholder_uri
            start_line = stable_placeholder_line(rid, msg)
            with_placeholder += 1

        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rname,
                "shortDescription": {"text": rname},
                "fullDescription": {"text": rdesc},
                "help": {"text": f"{rname}\nSeverity: {sev_label}\nRule: {rid}"},
                "properties": {
                    "tags": ["security", "veracode", "pipeline-scan"],
                    "security-severity": gh_sec_score,
                    "veracode-severity": sev_label,
                    "cwe": as_str(finding.get("cwe_id")).strip(),
                },
            }

        results.append({
            "ruleId": rid,
            "level": sarif_level,
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": start_line},
                }
            }],
            "properties": {
                "issue_id": issue_id,
                "veracode_severity": sev_label,
                "isPlaceholderLocation": (uri == placeholder_uri),
                "raw_path": as_str(raw_path),
                "raw_line": as_str(raw_line),
            },
        })

    sarif: Dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": args.tool_name,
                **({"version": args.tool_version} if args.tool_version else {}),
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    stats = {
        "findings_total_in_json": total,
        "sarif_results_written": len(results),
        "sarif_rules_written": len(rules),
        "results_with_file_location": with_file,
        "results_with_placeholder_location": with_placeholder,
        "unresolved_paths_count": unresolved_paths,
        "placeholder_uri": placeholder_uri,
        "repo_root": repo_root,
        "source_roots_tried": SOURCE_ROOTS,
    }
    with open(args.output_stats, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print("SARIF written:", args.output)
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
