#!/usr/bin/env python3
import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

NOISY_KEYS = {
    "last_update_time", "last_seen_date", "last_seen", "last_updated",
    "last_updated_date", "data_refresh_date", "generation_date"
}

SEV_MAP = {"5": "VERY_HIGH", "4": "HIGH", "3": "MEDIUM", "2": "LOW", "1": "VERY_LOW", "0": "INFO"}

def load_json(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        # sometimes wrapped; try a few common keys
        for k in ("findings", "items", "results"):
            if isinstance(data.get(k), list):
                return [x for x in data[k] if isinstance(x, dict)]
        return []
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    return []

def norm_sev(v: Any) -> str:
    if v is None:
        return "UNKNOWN"
    s = str(v).strip()
    return SEV_MAP.get(s, s.upper())

def best_id(f: Dict[str, Any]) -> str:
    # Prefer stable IDs; fall back to a composite signature
    for k in ("issue_id", "flaw_id", "id", "finding_id", "guid"):
        v = f.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    # composite signature (best effort)
    parts = [
        str(f.get("cwe") or ""),
        str(f.get("category") or f.get("categoryname") or ""),
        str(f.get("file_path") or f.get("file") or ""),
        str(f.get("line") or ""),
        str(f.get("scan_type") or ""),
    ]
    return "SIG:" + "|".join(parts)

def get_file(f: Dict[str, Any]) -> str:
    return str(f.get("file_path") or f.get("file") or f.get("filename") or "").strip() or "UNKNOWN_FILE"

def get_cwe_cat(f: Dict[str, Any]) -> str:
    cwe = f.get("cwe") or f.get("cwe_id")
    cat = f.get("category") or f.get("categoryname") or f.get("category_name")
    if cwe and cat:
        return f"{cwe} - {cat}"
    if cwe:
        return str(cwe)
    if cat:
        return str(cat)
    return "UNKNOWN_CWE_OR_CATEGORY"

def affects_policy(f: Dict[str, Any]) -> Optional[bool]:
    # Try common shapes; if absent, return None
    candidates = [
        f.get("affects_policy_compliance"),
        f.get("vulnerability_affects_policy_compliance"),
        f.get("component_affects_policy_compliance"),
    ]
    for c in candidates:
        if isinstance(c, bool):
            return c
        if isinstance(c, str):
            if c.lower() in ("true", "yes", "y"):
                return True
            if c.lower() in ("false", "no", "n"):
                return False
    return None

def strip_noisy(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if k not in NOISY_KEYS}

def diff_fields(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    o = strip_noisy(old)
    n = strip_noisy(new)
    keys = set(o.keys()) | set(n.keys())
    changed = {}
    for k in keys:
        if o.get(k) != n.get(k):
            changed[k] = {"from": o.get(k), "to": n.get(k)}
    return changed

def write_md(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def write_csv(path: str, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow(r)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app-name", required=True)
    ap.add_argument("--current", required=True)
    ap.add_argument("--previous")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    cur = load_json(args.current)
    prev = load_json(args.previous) if args.previous else []

    cur_by_id = {best_id(f): f for f in cur}
    prev_by_id = {best_id(f): f for f in prev}

    cur_ids = set(cur_by_id.keys())
    prev_ids = set(prev_by_id.keys())

    added = sorted(cur_ids - prev_ids)
    removed = sorted(prev_ids - cur_ids)
    common = sorted(cur_ids & prev_ids)

    # D) Raw changes
    changed = []
    for fid in common:
        ch = diff_fields(prev_by_id[fid], cur_by_id[fid])
        if ch:
            changed.append({"id": fid, "changed_fields": ch})

    raw_out = {
        "app_name": args.app_name,
        "counts": {"current": len(cur_ids), "previous": len(prev_ids), "added": len(added), "removed": len(removed), "changed": len(changed)},
        "added_ids": added,
        "removed_ids": removed,
        "changed": changed[:2000],  # guardrail; still “raw enough”
        "notes": "Changed list truncated to 2000 items if very large."
    }
    with open(os.path.join(args.out_dir, "raw_changes.json"), "w", encoding="utf-8") as f:
        json.dump(raw_out, f, indent=2)

    # Severity deltas
    def sev_counter(items: List[Dict[str, Any]]) -> Counter:
        c = Counter()
        for f in items:
            c[norm_sev(f.get("severity") or f.get("severity_level"))] += 1
        return c

    cur_sev = sev_counter(cur)
    prev_sev = sev_counter(prev)
    all_sevs = ["VERY_HIGH", "HIGH", "MEDIUM", "LOW", "VERY_LOW", "INFO", "UNKNOWN"]

    # A) Executive summary
    exec_lines = []
    exec_lines.append(f"# Veracode Findings Delta — {args.app_name}\n")
    exec_lines.append(f"- Current findings: **{len(cur_ids)}**")
    exec_lines.append(f"- Previous findings: **{len(prev_ids)}**")
    exec_lines.append(f"- New (IDs not seen before): **{len(added)}**")
    exec_lines.append(f"- Removed (IDs no longer present): **{len(removed)}**")
    exec_lines.append(f"- Changed (same ID, fields changed): **{len(changed)}**\n")

    exec_lines.append("## Severity delta\n")
    exec_lines.append("| Severity | Previous | Current | Δ |")
    exec_lines.append("|---|---:|---:|---:|")
    for s in all_sevs:
        p = prev_sev.get(s, 0)
        c = cur_sev.get(s, 0)
        exec_lines.append(f"| {s} | {p} | {c} | {c-p:+d} |")

    write_md(os.path.join(args.out_dir, "executive_summary.md"), "\n".join(exec_lines) + "\n")

    # B) Developer breakdown (by file and by CWE/category)
    def group_delta(key_fn):
        cur_g = Counter()
        prev_g = Counter()
        for f in cur:
            cur_g[key_fn(f)] += 1
        for f in prev:
            prev_g[key_fn(f)] += 1
        keys = set(cur_g.keys()) | set(prev_g.keys())
        rows = []
        for k in keys:
            rows.append({
                "group": k,
                "previous": prev_g.get(k, 0),
                "current": cur_g.get(k, 0),
                "delta": cur_g.get(k, 0) - prev_g.get(k, 0),
            })
        rows.sort(key=lambda r: (abs(r["delta"]), r["current"]), reverse=True)
        return rows

    by_file = group_delta(get_file)
    by_cwe = group_delta(get_cwe_cat)

    write_csv(os.path.join(args.out_dir, "developer_by_file.csv"), by_file, ["group", "previous", "current", "delta"])
    write_csv(os.path.join(args.out_dir, "developer_by_cwe_category.csv"), by_cwe, ["group", "previous", "current", "delta"])

    # C) Compliance summary (best-effort)
    # If policy-impact flag exists, report it. Otherwise fall back to severities (VERY_HIGH/HIGH).
    cur_policy_flags = [affects_policy(f) for f in cur]
    prev_policy_flags = [affects_policy(f) for f in prev]
    has_policy_flag = any(v is not None for v in cur_policy_flags + prev_policy_flags)

    comp_lines = []
    comp_lines.append(f"# Compliance delta — {args.app_name}\n")
    if has_policy_flag:
        def count_affects(items):
            t = 0
            f_count = 0
            u = 0
            for x in items:
                v = affects_policy(x)
                if v is True:
                    t += 1
                elif v is False:
                    f_count += 1
                else:
                    u += 1
            return t, f_count, u
        ct, cf, cu = count_affects(cur)
        pt, pf, pu = count_affects(prev)
        comp_lines.append(f"- Affects policy compliance (True): prev **{pt}** → curr **{ct}** (Δ {ct-pt:+d})")
        comp_lines.append(f"- Does not affect policy (False): prev **{pf}** → curr **{cf}** (Δ {cf-pf:+d})")
        comp_lines.append(f"- Unknown/Not provided: prev **{pu}** → curr **{cu}** (Δ {cu-pu:+d})\n")
    else:
        comp_lines.append("- No explicit `*_affects_policy_*` flag present in findings JSON for this tenant/export.\n")
        comp_lines.append("## Policy-relevant proxy (severity)\n")
        for s in ("VERY_HIGH", "HIGH"):
            p = prev_sev.get(s, 0)
            c = cur_sev.get(s, 0)
            comp_lines.append(f"- {s}: prev **{p}** → curr **{c}** (Δ {c-p:+d})")
        comp_lines.append("\n")

    write_md(os.path.join(args.out_dir, "compliance_summary.md"), "\n".join(comp_lines) + "\n")

    # Helpful index
    write_md(
        os.path.join(args.out_dir, "README.md"),
        "\n".join([
            f"# Diff outputs — {args.app_name}",
            "",
            "- `executive_summary.md` — A) executive delta",
            "- `developer_by_file.csv` and `developer_by_cwe_category.csv` — B) developer delta",
            "- `compliance_summary.md` — C) compliance delta",
            "- `raw_changes.json` — D) raw change listing (added/removed/changed)",
            "",
        ])
    )

    print("Diff outputs written to:", args.out_dir)

if __name__ == "__main__":
    main()
