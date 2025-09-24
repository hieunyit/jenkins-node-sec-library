#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Unified Vulnerability Report Aggregator with Interactive Filtering

Usage:
  python vuln_report.py <file1> [<file2> ...] [OPTIONS]

Options:
  --output-html=FILE       Export interactive HTML report with filters
  --output-json=FILE       Export JSON report
  --quiet, -q              Suppress console output
  --ref-mode=MODE          Reference mode: auto|fileline|package
  --ref-path=MODE          Path format: full|base|tailN (e.g., tail2)
  --ref-width=N            Max width for reference column in console output
  --only-tools=LIST        Filter by tools (comma-separated)
  --include=PATTERN        Include pattern (regex, applies to title/ref)
  --exclude=PATTERN        Exclude pattern (regex, applies to title/ref)
  --no-color               Disable colored console output
  --no-skip-empty          Do NOT skip files with 0 findings
  --no-dedupe              Disable deduplication (keep duplicates)
  --no-dedupe-cve          Do NOT dedupe by CVE/component (still dedupe exact)
  --interactive            Enable interactive console filtering
  --min-severity=LEVEL     Minimum severity level (critical|high|medium|low|info)

Supported formats (auto-detected): SARIF, SonarQube JSON, Dependency-Check JSON,
RetireJS, npm audit JSON, Gitleaks JSON, Semgrep JSON, Trivy JSON, Snyk JSON (OSS/Container)
"""

import json, sys, re, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import argparse

# ANSI colors (auto-disabled if not TTY or --no-color)
RESET=""; BOLD=""; DIM=""; RED=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; GREEN=""

def _enable_color(enable: bool):
    global RESET,BOLD,DIM,RED,YELLOW,BLUE,MAGENTA,CYAN,GREEN
    if enable and sys.stdout.isatty():
        RESET="\033[0m"; BOLD="\033[1m"; DIM="\033[2m"
        RED="\033[31m"; YELLOW="\033[33m"; BLUE="\033[34m"; MAGENTA="\033[35m"; CYAN="\033[36m"; GREEN="\033[32m"
    else:
        RESET=BOLD=DIM=RED=YELLOW=BLUE=MAGENTA=CYAN=GREEN=""

SEV_ORDER = {"critical":4,"high":3,"medium":2,"moderate":2,"low":1,"info":0,"unknown":0,"":0,None:0}
SEV_ALIAS = {"moderate":"medium","informational":"info","error":"high","warning":"medium","note":"low"}

def norm_sev(s: Optional[str]) -> str:
    if not s: return "unknown"
    s = str(s).strip().lower()
    s = SEV_ALIAS.get(s, s)
    return s if s in SEV_ORDER else "unknown"

def cut(s: Optional[str], n: Optional[int]) -> str:
    if s is None: return ""
    s = str(s).replace("\n"," ").replace("\r"," ")
    if not n: return s
    return (s[:n-1]+"…") if len(s)>n else s

def load_json(path: Path) -> Any:
    txt = path.read_text(encoding="utf-8", errors="ignore")
    try:
        return json.loads(txt)
    except Exception:
        txt = txt.lstrip("\ufeff")
        return json.loads(txt)

def detect_format(obj: Any, path: Path) -> str:
    # SARIF
    if isinstance(obj, dict) and obj.get("version") == "2.1.0" and "runs" in obj: return "sarif"
    if isinstance(obj, dict) and str(obj.get("$schema","")).endswith("sarif-2.1.0.json"): return "sarif"
    if path.suffix.lower() == ".sarif": return "sarif"
    # SonarQube
    if isinstance(obj, dict) and "hotspots" in obj and "paging" in obj: return "sonarqube"
    if isinstance(obj, dict) and "issues" in obj and isinstance(obj.get("issues"), list): return "sonarqube"
    # Dependency-Check
    if isinstance(obj, dict) and isinstance(obj.get("dependencies"), list): return "dependency_check"
    # RetireJS
    if isinstance(obj, dict) and "data" in obj and "start" in obj and "version" in obj: return "retirejs"
    # npm audit
    if isinstance(obj, dict) and "auditReportVersion" in obj and "vulnerabilities" in obj: return "npm_audit"
    # Gitleaks
    if (isinstance(obj, list) and (len(obj)==0 or (isinstance(obj[0], dict) and any(k in obj[0] for k in ("RuleID","Description","File"))))) \
       or (isinstance(obj, dict) and any(k in obj for k in ("results","leaks"))): return "gitleaks"
    # Semgrep
    if isinstance(obj, dict) and "results" in obj and any(isinstance(x, dict) and ("check_id" in x or "path" in x) for x in obj.get("results", [])): return "semgrep"
    # Trivy
    if isinstance(obj, dict) and ("Results" in obj or "ArtifactType" in obj or "ArtifactName" in obj): return "trivy"
    # Snyk JSON (OSS/Container)
    if isinstance(obj, dict) and isinstance(obj.get("vulnerabilities"), list):
        arr = obj.get("vulnerabilities") or []
        if (not arr) or (isinstance(arr[0], dict) and any(k in arr[0] for k in ("id","packageName","name","severity","identifiers"))):
            return "snyk"
    return "unknown"

# ---------------- Helpers ----------------

def path_tail(s: str, depth: int) -> str:
    if not s: return ""
    s = s.replace("\\", "/")
    parts = s.split("/")
    if depth <= 0 or depth >= len(parts): return s
    return "/".join(parts[-depth:])

def format_path(s: str, ref_path_mode: str, tail_depth: int) -> str:
    if not s: return ""
    if ref_path_mode == "full":
        return s.replace("\\","/")
    if ref_path_mode == "base":
        s = s.replace("\\", "/")
        return s.rsplit("/", 1)[-1]
    # tailN
    return path_tail(s, tail_depth)

def build_ref(f: Dict[str, Any], ref_mode: str, ref_path_mode: str, tail_depth: int) -> str:
    """
    ref_mode:
      - auto: package@version cho dependency; file[:line] cho code
      - fileline: luôn file[:line] (nếu có)
      - package: luôn component (nếu có)
    ref_path_mode: full | base | tailN (tail_depth = N)
    """
    comp = (f.get("component") or "").strip()
    file = (f.get("file") or "").strip()
    line = f.get("line")

    def fileline(path_mode: str = None):
        pmode = path_mode or ref_path_mode
        fp = format_path(file, pmode, tail_depth) if file else "unknown"
        return f"{fp}:{line}" if line else fp

    # === SPECIAL CASE: SonarQube => luôn 'TênFile:Line' ===
    if (f.get("tool") or "").lower() == "sonarqube":
        return fileline(path_mode="base")
    # ======================================================

    if ref_mode == "package":
        return comp or fileline()
    if ref_mode == "fileline":
        return fileline()

    # auto
    if comp:
        return comp
    return fileline()

# ---------------- Parsers (with SonarQube) ----------------

def parse_sonarqube(obj: Dict[str, Any], source: str) -> Iterable[Dict[str, Any]]:
    """
    Parse SonarQube hotspots/issues JSON

    Mapping:
      Tool       -> 'sonarqube'
      ID         -> ruleKey (docker:S6504, typescript:S2068, ...)
      Title      -> message (prefix [SEC_CATEGORY] nếu có)
      File       -> component 'project:path/file' -> 'path/file'
      Line       -> line
      CVE/CWE    -> auto-detect từ ruleKey/message
      Component  -> project
      Severity   -> dựa vào vulnerabilityProbability/sonar severity/type
    """
    items = obj.get("hotspots", []) or obj.get("issues", [])
    for item in items:
        key = item.get("key", "")
        component = item.get("component", "")
        project = item.get("project", "") or (component.split(":")[0] if ":" in component else "")
        message = item.get("message", "") or ""
        rule_key = item.get("ruleKey", item.get("rule", "")) or key
        line = item.get("line")

        # Severity heuristic
        severity = "unknown"
        vuln_prob = (item.get("vulnerabilityProbability") or "").strip().upper()
        sonar_sev = (item.get("severity") or "").strip().upper()
        issue_type = (item.get("type") or "").strip().upper()
        sec_category = (item.get("securityCategory") or "").strip()

        if vuln_prob == "HIGH":
            severity = "high"
        elif vuln_prob == "MEDIUM":
            severity = "medium"
        elif vuln_prob == "LOW":
            severity = "low"
        elif sonar_sev in ("BLOCKER", "CRITICAL"):
            severity = "critical"
        elif sonar_sev == "MAJOR":
            severity = "high"
        elif sonar_sev == "MINOR":
            severity = "medium"
        elif sonar_sev == "INFO":
            severity = "info"
        else:
            if issue_type in ("SECURITY_HOTSPOT", "VULNERABILITY") or sec_category:
                severity = "medium"
            else:
                severity = "low"

        # File path
        if component and ":" in component:
            file_path = component.split(":", 1)[1]
        else:
            file_path = component

        # Title
        title = f"[{sec_category.upper()}] {message}" if sec_category else message

        # Detect CVE/CWE
        text_for_scan = f"{message} {rule_key}"
        cve_list = re.findall(r"CVE-\d{4}-\d{4,}", text_for_scan, flags=re.I)
        cwe_list = re.findall(r"CWE-\d+", text_for_scan, flags=re.I)
        cve = ",".join(sorted({x.upper() for x in cve_list})) if cve_list else ""
        cwe = ",".join(sorted({x.upper() for x in cwe_list})) if cwe_list else ""

        yield {
            "tool": "sonarqube",
            "source": source,
            "id": rule_key,
            "title": title or f"SonarQube {rule_key}",
            "severity": severity,
            "component": project or "",
            "file": file_path or "",
            "line": line,
            "url": "",
            "cve": cve,
            "cwe": cwe,
        }

def parse_sarif(obj: Dict[str,Any], source: str) -> Iterable[Dict[str,Any]]:
    rules_index: Dict[str, Dict[str,Any]] = {}
    for run in obj.get("runs", []):
        tool = (run.get("tool", {}).get("driver", {}) or {}).get("name", "SARIF")
        for rule in (run.get("tool", {}).get("driver", {}).get("rules") or []):
            rid = rule.get("id");  rules_index[rid] = rule
        for res in run.get("results", []):
            rid = res.get("ruleId") or ""
            sev = norm_sev(res.get("level"))
            msg = (res.get("message") or {}).get("text") or rid or tool
            locs = res.get("locations") or []; fpath=None; line=None
            if locs:
                loc = locs[0].get("physicalLocation", {}) if isinstance(locs[0], dict) else {}
                art = (loc.get("artifactLocation") or {})
                fpath = art.get("uri") or art.get("uriBaseId")
                region = loc.get("region", {})
                if isinstance(region, dict): line = region.get("startLine")
            if not line:
                m = re.search(r"\bline\s+(\d+)\b", msg, flags=re.I)
                if m:
                    try: line = int(m.group(1))
                    except: line = None
            rule = rules_index.get(rid, {})
            rule_name = rule.get("shortDescription",{}).get("text") or rule.get("fullDescription",{}).get("text") or rid
            title = f"{rule_name}"
            yield {"tool":tool,"source":source,"id":rid,"title":title,"severity":sev,"component":"",
                   "file":fpath or "","line":line,"url":"","cve":"","cwe":""}

def parse_retirejs(obj: Dict[str,Any], source: str) -> Iterable[Dict[str,Any]]:
    for item in obj.get("data", []):
        for res in item.get("results", []):
            comp = res.get("component") or res.get("npmname") or ""
            version = res.get("version") or ""
            for v in (res.get("vulnerabilities") or []):
                sev = norm_sev(v.get("severity"))
                cve = ",".join(v.get("identifiers",{}).get("CVE") or [])
                title = v.get("identifiers",{}).get("summary") or (v.get("info") or [""])[0] or "retire.js finding"
                below = v.get("below")
                yield {
                    "tool":"npm/retirejs","source":source,"id":cve or title,"title": (f"{title} (affected < {below})" if below else title),
                    "severity":sev,"component": f"{comp}@{version}" if version else comp,
                    "file": item.get("file") or "", "line": None, "url":"", "cve":cve, "cwe":""
                }

def parse_npm_audit(obj: Dict[str,Any], source: str) -> Iterable[Dict[str,Any]]:
    for pkg, meta in (obj.get("vulnerabilities") or {}).items():
        sev = norm_sev(meta.get("severity"))
        for v in (meta.get("via") or []):
            if isinstance(v, dict):
                title = v.get("title") or v.get("name") or "npm advisory"
                rng = v.get("range") or meta.get("range") or ""
                yield {"tool":"npm audit","source":source,"id":v.get("source") or "","title": (f"{title} (affected {rng})" if rng else title),
                       "severity":sev,"component":pkg,"file":"","line":None,"url":v.get("url") or "","cve":"", "cwe":""}
            elif isinstance(v,str):
                yield {"tool":"npm audit","source":source,"id":v,"title":v,"severity":sev,"component":pkg,"file":"","line":None,"url":"","cve":"","cwe":""}

def parse_gitleaks(obj: Any, source: str) -> Iterable[Dict[str,Any]]:
    items = obj if isinstance(obj,list) else (obj.get("results") or obj.get("leaks") or [])
    for it in items:
        rule=it.get("RuleID") or "gitleaks"
        desc=it.get("Description") or rule
        sev="critical" if str(rule).lower() in ("private-key","private_key","rsa_private_key") else "high"
        yield {"tool":"gitleaks","source":source,"id":rule,"title":desc,"severity":sev,"component":"",
               "file":it.get("File") or "","line":it.get("StartLine") or None,"url":"","cve":"","cwe":""}

def parse_semgrep(obj: Dict[str,Any], source: str) -> Iterable[Dict[str,Any]]:
    for r in obj.get("results", []):
        yield {"tool":"semgrep","source":source,"id":r.get("check_id") or "","title":(r.get("extra") or {}).get("message") or "semgrep finding",
               "severity":norm_sev((r.get("extra") or {}).get("severity")),"component":"",
               "file":r.get("path") or "","line":(r.get("start") or {}).get("line"),"url":"","cve":"","cwe":""}

def parse_trivy(obj: Dict[str,Any], source: str) -> Iterable[Dict[str,Any]]:
    for result in obj.get("Results", []) or []:
        target=result.get("Target") or ""
        for v in result.get("Vulnerabilities") or []:
            sev=norm_sev(v.get("Severity")); vid=v.get("VulnerabilityID") or ""
            pkg = v.get("PkgName") or v.get("PkgID") or ""
            inst = v.get("InstalledVersion") or v.get("PkgVersion") or ""
            comp = f"{pkg}@{inst}" if pkg else inst
            yield {"tool":"trivy","source":source,"id":vid,"title":v.get("Title") or vid,"severity":sev,"component":comp,
                   "file":target,"line":None,"url":v.get("PrimaryURL") or "","cve": vid if str(vid).upper().startswith(("CVE-","GHSA-")) else "","cwe":""}
        for m in result.get("Misconfigurations") or []:
            sev=norm_sev(m.get("Severity"))
            msg=m.get("Message") or m.get("Description") or m.get("Title") or m.get("ID") or "trivy misconfiguration"
            yield {"tool":"trivy","source":source,"id":m.get("ID") or "","title":msg,"severity":sev,"component":"",
                   "file":f"{target}:{m.get('Namespace','')}","line":None,"url":m.get("PrimaryURL") or "","cve":"","cwe":""}
        for s in result.get("Secrets") or []:
            sev=norm_sev(s.get("Severity") or "high")
            title=s.get("Title") or s.get("RuleID") or "Secret detected"
            yield {"tool":"trivy","source":source,"id":s.get("RuleID") or "","title":title,"severity":sev,"component":"",
                   "file":s.get("Target") or target,"line":s.get("StartLine") or None,"url":s.get("RuleURL") or "","cve":"","cwe":""}

def parse_dependency_check(obj: Dict[str,Any], source: str) -> Iterable[Dict[str,Any]]:
    for d in obj.get("dependencies") or []:
        for v in (d.get("vulnerabilities") or []):
            name=v.get("name") or ""
            sev=norm_sev(v.get("severity"))
            desc=v.get("description") or name or "dependency-check finding"
            cve = name if str(name).upper().startswith(("CVE-","GHSA-")) else ""
            yield {"tool":"dependency-check","source":source,"id":name,"title":desc,"severity":sev,"component":"",
                   "file":d.get("filePath") or "","line":None,"url":v.get("url") or "","cve":cve,"cwe":""}

def parse_snyk(obj: Dict[str, Any], source: str) -> Iterable[Dict[str, Any]]:
    for v in obj.get("vulnerabilities") or []:
        sev = norm_sev(v.get("severity"))
        title = v.get("title") or v.get("id") or "snyk vulnerability"
        pkg = v.get("packageName") or v.get("name") or ""
        ver = v.get("version") or ""
        comp = f"{pkg}@{ver}" if pkg and ver else (pkg or ver)
        idf = v.get("identifiers") or {}
        cve_list, cwe_list = [], []
        if isinstance(idf, dict):
            if isinstance(idf.get("CVE"), list): cve_list = [str(x) for x in idf.get("CVE") if x]
            if isinstance(idf.get("CWE"), list): cwe_list = [str(x) for x in idf.get("CWE") if x]
        cve = ",".join(sorted(set(cve_list)))
        cwe = ",".join(sorted(set(cwe_list)))
        target = ""
        frm = v.get("from") or []
        if isinstance(frm, list) and frm:
            target = ",".join(str(x) for x in frm if x)

        yield {
            "tool": "snyk",
            "source": source,
            "id": v.get("id") or "",
            "title": title,
            "severity": sev,
            "component": comp or pkg,
            "file": target,
            "line": None,
            "url": v.get("url") or "",
            "cve": cve,
            "cwe": cwe,
        }

PARSERS = {
    "sarif": parse_sarif,
    "sonarqube": parse_sonarqube,
    "retirejs": parse_retirejs,
    "npm_audit": parse_npm_audit,
    "gitleaks": parse_gitleaks,
    "semgrep": parse_semgrep,
    "trivy": parse_trivy,
    "dependency_check": parse_dependency_check,
    "snyk": parse_snyk,
}

def human_now() -> str: 
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def print_header(t: str, w: int):
    print(f"{BOLD}{t}{RESET}")
    print(f"{DIM}{'-'*min(w,120)}{RESET}")

def colfit(t: str, w: int) -> str:
    t=t or ""
    return t+" "*(w-len(t)) if (w and len(t)<=w) else (t if not w else t[:w-1]+"…")

def table(rows: List[Tuple[str,str,str,str,str]], hdrs: List[str], w: int):
    tool_w, sev_w, cve_w, title_w = 12, 8, 16, 68
    if w and (tool_w+sev_w+cve_w+title_w+8) > w:
        title_w = max(32, w - (tool_w+sev_w+cve_w+8))
    print(BOLD + " ".join([
        colfit(hdrs[0], tool_w),
        colfit(hdrs[1], sev_w),
        colfit(hdrs[2], cve_w),
        colfit(hdrs[3], title_w),
        "Ref"
    ]) + RESET)
    print(DIM + " ".join([
        "-"*tool_w, "-"*sev_w, "-"*cve_w, "-"*title_w, "-"*8
    ]) + RESET)
    for r in rows:
        print(" ".join([
            colfit(str(r[0]), tool_w),
            colfit(str(r[1]), sev_w),
            colfit(str(r[2]), cve_w),
            colfit(str(r[3]), title_w),
            str(r[4])
        ]))

def _match_filters(text: str, include_patterns: List[str], exclude_patterns: List[str]) -> bool:
    s = text or ''
    for pat in exclude_patterns:
        if re.search(pat, s, flags=re.I): return False
    if include_patterns:
        return any(re.search(p, s, flags=re.I) for p in include_patterns)
    return True

# ---------------- Filtering helpers ----------------

def filter_by_severity(findings: List[Dict[str, Any]], min_severity: str) -> List[Dict[str, Any]]:
    min_level = SEV_ORDER.get(min_severity.lower(), 0)
    return [f for f in findings if SEV_ORDER.get(f.get("severity"), 0) >= min_level]

def filter_by_search(findings: List[Dict[str, Any]], search_term: str) -> List[Dict[str, Any]]:
    if not search_term:
        return findings
    pattern = re.compile(re.escape(search_term), re.I)
    result = []
    for f in findings:
        searchable_text = " ".join([
            str(f.get("title", "")),
            str(f.get("tool", "")),
            str(f.get("component", "")),
            str(f.get("file", "")),
            str(f.get("cve", "")),
            str(f.get("id", ""))
        ])
        if pattern.search(searchable_text):
            result.append(f)
    return result

def interactive_filter_menu(findings: List[Dict[str, Any]], 
                          ref_mode: str, ref_path_mode: str, ref_tail_depth: int, 
                          max_width: int) -> List[Dict[str, Any]]:
    current_findings = findings[:]
    while True:
        print(f"\n{BOLD}=== Interactive Filter Menu ==={RESET}")
        print(f"Current findings: {len(current_findings)}")
        summary = _summarize(current_findings)
        sev_line = f"CRITICAL:{summary['critical']} HIGH:{summary['high']} MEDIUM:{summary['medium']} LOW:{summary['low']} INFO:{summary['info']}"
        print(sev_line)
        print(f"\n{BOLD}Options:{RESET}")
        print("1. Search by keyword")
        print("2. Filter by severity")
        print("3. Filter by tool")
        print("4. Show current results")
        print("5. Reset filters")
        print("6. Export current results")
        print("0. Exit interactive mode")
        try:
            choice = input(f"\n{CYAN}Enter choice (0-6): {RESET}").strip()
            if choice == "0":
                break
            elif choice == "1":
                search_term = input(f"{CYAN}Enter search term: {RESET}").strip()
                current_findings = filter_by_search(current_findings, search_term)
                print(f"{GREEN}Filtered to {len(current_findings)} findings{RESET}")
            elif choice == "2":
                print(f"{CYAN}Severity levels: critical, high, medium, low, info{RESET}")
                min_sev = input(f"{CYAN}Enter minimum severity: {RESET}").strip().lower()
                if min_sev in SEV_ORDER:
                    current_findings = filter_by_severity(current_findings, min_sev)
                    print(f"{GREEN}Filtered to {len(current_findings)} findings{RESET}")
                else:
                    print(f"{RED}Invalid severity level{RESET}")
            elif choice == "3":
                tools = sorted(set(f.get("tool", "") for f in current_findings if f.get("tool")))
                print(f"{CYAN}Available tools: {', '.join(tools)}{RESET}")
                tool_filter = input(f"{CYAN}Enter tool name: {RESET}").strip()
                if tool_filter:
                    current_findings = [f for f in current_findings if tool_filter.lower() in f.get("tool", "").lower()]
                    print(f"{GREEN}Filtered to {len(current_findings)} findings{RESET}")
            elif choice == "4":
                if current_findings:
                    show_findings_table(current_findings, ref_mode, ref_path_mode, ref_tail_depth, max_width)
                else:
                    print(f"{YELLOW}No findings to display{RESET}")
            elif choice == "5":
                current_findings = findings[:]
                print(f"{GREEN}Filters reset. Back to {len(current_findings)} findings{RESET}")
            elif choice == "6":
                filename = input(f"{CYAN}Enter filename (without extension): {RESET}").strip()
                if filename:
                    export_filtered_results(current_findings, filename, ref_mode, ref_path_mode, ref_tail_depth)
        except KeyboardInterrupt:
            print(f"\n{YELLOW}Exiting interactive mode...{RESET}")
            break
        except Exception as e:
            print(f"{RED}Error: {e}{RESET}")
    return current_findings

def show_findings_table(findings: List[Dict[str, Any]], ref_mode: str, ref_path_mode: str, 
                       ref_tail_depth: int, max_width: int):
    if not findings:
        print(f"{YELLOW}No findings to display{RESET}")
        return
    findings_sorted = sorted(findings, key=lambda x: (-SEV_ORDER.get(x.get("severity"), 0), 
                                                     x.get("cve", ""), 
                                                     x.get("tool", ""), 
                                                     x.get("title", "")))
    rows = []
    for f in findings_sorted:
        ref_val = build_ref(f, ref_mode, ref_path_mode, ref_tail_depth)
        rows.append((
            f.get("tool", ""),
            (f.get("severity") or "").upper(),
            f.get("cve", ""),
            f.get("title", ""),
            ref_val
        ))
    table(rows, ["Tool", "Severity", "CVE", "Title", "Reference"], max_width)

def export_filtered_results(findings: List[Dict[str, Any]], filename: str, 
                          ref_mode: str, ref_path_mode: str, ref_tail_depth: int):
    try:
        json_filename = f"{filename}.json"
        summary = _summarize(findings)
        metadata = {
            "generated_at": datetime.datetime.now().isoformat(),
            "generator": "vuln_report.py (filtered)",
            "total_findings": len(findings),
            "ref_mode": ref_mode,
            "ref_path_mode": ref_path_mode,
            "ref_tail_depth": ref_tail_depth
        }
        json_data = {
            "metadata": metadata,
            "summary": {
                "total_findings": len(findings),
                "by_severity": summary,
                "tools_used": sorted(list(set(f.get("tool", "") for f in findings if f.get("tool")))),
                "sources_scanned": sorted(list(set(f.get("source", "") for f in findings if f.get("source"))))
            },
            "findings": findings
        }
        Path(json_filename).write_text(json.dumps(json_data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"{GREEN}JSON exported to: {json_filename}{RESET}")

        html_filename = f"{filename}.html"
        html_content = generate_html_report(findings, summary, ref_mode, ref_path_mode, ref_tail_depth)
        Path(html_filename).write_text(html_content, encoding="utf-8")
        print(f"{GREEN}HTML exported to: {html_filename}{RESET}")
    except Exception as e:
        print(f"{RED}Export failed: {e}{RESET}")

# ---------------- HTML report (NO f-string to avoid brace clashes) ----------------

def generate_html_report(findings: List[Dict[str, Any]], summary: Dict[str, int], 
                         ref_mode: str, ref_path_mode: str, ref_tail_depth: int) -> str:
    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c", 
        "medium": "#d97706",
        "low": "#65a30d",
        "info": "#0891b2",
        "unknown": "#6b7280"
    }
    findings_json = json.dumps(findings, ensure_ascii=False)
    severity_colors_json = json.dumps(severity_colors)
    sev_order_json = json.dumps(SEV_ORDER)
    now = human_now()

    html = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Interactive Vulnerability Report - """ + now + """</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8fafc; line-height: 1.5; }
  .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
  .header h1 { margin: 0; font-size: 28px; font-weight: 600; }
  .header .meta { margin-top: 8px; opacity: 0.9; }
  .controls { padding: 20px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; display: flex; flex-wrap: wrap; gap: 15px; align-items: center; }
  .control-group { display: flex; flex-direction: column; gap: 5px; }
  .control-group label { font-size: 12px; font-weight: 600; color: #475569; text-transform: uppercase; }
  .control-group input, .control-group select { padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px; font-size: 14px; background: white; transition: border-color 0.2s; }
  .control-group input:focus, .control-group select:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); }
  .search-box { min-width: 250px; }
  .btn { padding: 8px 16px; background: #3b82f6; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; transition: background-color 0.2s; }
  .btn:hover { background: #2563eb; }
  .btn-secondary { background: #6b7280; }
  .btn-secondary:hover { background: #4b5563; }
  .summary { padding: 20px 30px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 15px; }
  .summary-card { background: white; padding: 15px; border-radius: 6px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .summary-card .count { font-size: 20px; font-weight: 700; margin-bottom: 5px; }
  .summary-card .label { font-size: 11px; text-transform: uppercase; font-weight: 600; color: #64748b; }
  .content { padding: 0; }
  .table-container { overflow-x: auto; max-height: 70vh; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
  th { background: #f1f5f9; font-weight: 600; color: #475569; font-size: 14px; position: sticky; top: 0; z-index: 10; }
  tbody tr:hover { background: #f8fafc; }
  .severity-badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; color: white; min-width: 60px; text-align: center; }
  .tool-badge { background: #e2e8f0; color: #475569; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; display: inline-block; }
  .cve-link { color: #3b82f6; text-decoration: none; font-weight: 500; }
  .cve-link:hover { text-decoration: underline; }
  .ref-text { font-family: 'Monaco', 'Menlo', 'Consolas', monospace; font-size: 12px; color: #64748b; background: #f8fafc; padding: 4px 8px; border-radius: 4px; display: inline-block; }
  .title-cell { max-width: 400px; word-wrap: break-word; }
  .no-results { text-align: center; padding: 60px 20px; color: #64748b; background: #f8fafc; margin: 20px; }
  .stats { padding: 10px 30px; background: #f1f5f9; font-size: 14px; color: #64748b; display: flex; justify-content: space-between; align-items: center; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Interactive Vulnerability Report</h1>
    <div class="meta">Generated on """ + now + """</div>
  </div>

  <div class="controls">
    <div class="control-group">
      <label>Search</label>
      <input type="text" id="searchInput" class="search-box" placeholder="Search title, tool, CVE, component...">
    </div>
    <div class="control-group">
      <label>Severity</label>
      <select id="severityFilter">
        <option value="">All Severities</option>
        <option value="critical">Critical+</option>
        <option value="high">High+</option>
        <option value="medium">Medium+</option>
        <option value="low">Low+</option>
      </select>
    </div>
    <div class="control-group">
      <label>Tool</label>
      <select id="toolFilter">
        <option value="">All Tools</option>
      </select>
    </div>
    <div class="control-group">
      <label>Actions</label>
      <div style="display: flex; gap: 8px;">
        <button class="btn" onclick="resetFilters()">Reset</button>
        <button class="btn btn-secondary" onclick="exportResults()">Export</button>
      </div>
    </div>
  </div>

  <div class="summary" id="summarySection">
    <div class="summary-grid" id="summaryGrid"></div>
  </div>

  <div class="stats" id="statsSection">
    <span id="resultCount">Loading...</span>
    <span id="filterStatus"></span>
  </div>

  <div class="content">
    <div class="table-container">
      <table id="resultsTable">
        <thead>
          <tr>
            <th style="width: 100px;">Tool</th>
            <th style="width: 80px;">Severity</th>
            <th style="width: 120px;">CVE</th>
            <th style="min-width: 300px;">Title</th>
            <th style="width: 200px;">Reference</th>
          </tr>
        </thead>
        <tbody id="tableBody"></tbody>
      </table>
    </div>
    <div class="no-results" id="noResults" style="display: none;">
      <div style="font-size: 48px; margin-bottom: 16px;">🔍</div>
      <h3>No vulnerabilities found</h3>
      <p>Try adjusting your filters or search terms.</p>
    </div>
  </div>
</div>

<script>
// Injected data/config from Python
const allFindings = """ + findings_json + """;
const severityColors = """ + severity_colors_json + """;
const severityOrder = """ + sev_order_json + """;
const refMode = '""" + ref_mode + """';
const refPathMode = '""" + ref_path_mode + """';
const refTailDepth = """ + str(ref_tail_depth) + """;

let filteredFindings = [...allFindings];

document.addEventListener('DOMContentLoaded', function() {
  populateToolFilter();
  updateDisplay();
  setupEventListeners();
});

function setupEventListeners() {
  document.getElementById('searchInput').addEventListener('input', debounce(applyFilters, 300));
  document.getElementById('severityFilter').addEventListener('change', applyFilters);
  document.getElementById('toolFilter').addEventListener('change', applyFilters);
}

function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => { clearTimeout(timeout); func(...args); };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

function populateToolFilter() {
  const tools = [...new Set(allFindings.map(f => f.tool).filter(t => t))].sort();
  const toolSelect = document.getElementById('toolFilter');
  tools.forEach(tool => {
    const option = document.createElement('option');
    option.value = tool;
    option.textContent = tool;
    toolSelect.appendChild(option);
  });
}

function applyFilters() {
  const searchTerm = document.getElementById('searchInput').value.toLowerCase();
  const severityFilter = document.getElementById('severityFilter').value;
  const toolFilter = document.getElementById('toolFilter').value;

  filteredFindings = allFindings.filter(finding => {
    if (searchTerm) {
      const searchableText = [
        finding.title || '', finding.tool || '', finding.component || '',
        finding.file || '', finding.cve || '', finding.id || ''
      ].join(' ').toLowerCase();
      if (!searchableText.includes(searchTerm)) return false;
    }
    if (severityFilter) {
      const findingSeverity = finding.severity || 'unknown';
      const minLevel = severityOrder[severityFilter] || 0;
      const currentLevel = severityOrder[findingSeverity] || 0;
      if (currentLevel < minLevel) return false;
    }
    if (toolFilter && finding.tool !== toolFilter) return false;
    return true;
  });
  updateDisplay();
  updateFilterStatus();
}

function updateDisplay() { updateSummary(); updateTable(); updateStats(); }

function updateSummary() {
  const summary = { critical:0, high:0, medium:0, low:0, info:0, unknown:0 };
  filteredFindings.forEach(f => { const sev = f.severity || 'unknown'; summary[sev] = (summary[sev] || 0) + 1; });
  const summaryGrid = document.getElementById('summaryGrid');
  summaryGrid.innerHTML = '';
  ['critical','high','medium','low','info','unknown'].forEach(severity => {
    const count = summary[severity] || 0;
    if (count > 0 || ['critical','high','medium'].includes(severity)) {
      const card = document.createElement('div');
      card.className = 'summary-card';
      const color = severityColors[severity] || '#6b7280';
      card.innerHTML = '<div class="count" style="color:'+color+';">'+count+'</div>'
                     + '<div class="label">'+severity.toUpperCase()+'</div>';
      summaryGrid.appendChild(card);
    }
  });
  const totalCard = document.createElement('div');
  totalCard.className = 'summary-card';
  totalCard.innerHTML = '<div class="count" style="color:#1f2937;">'+filteredFindings.length+'</div><div class="label">TOTAL</div>';
  summaryGrid.appendChild(totalCard);
}

function updateTable() {
  const tableBody = document.getElementById('tableBody');
  const noResults = document.getElementById('noResults');
  if (filteredFindings.length === 0) {
    tableBody.innerHTML = '';
    noResults.style.display = 'block';
    return;
  }
  noResults.style.display = 'none';
  const sortedFindings = [...filteredFindings].sort((a,b) => {
    const aSev = severityOrder[a.severity] || 0;
    const bSev = severityOrder[b.severity] || 0;
    if (aSev !== bSev) return bSev - aSev;
    const aCve = a.cve || '', bCve = b.cve || '';
    if (aCve !== bCve) return aCve.localeCompare(bCve);
    const aTool = a.tool || '', bTool = b.tool || '';
    if (aTool !== bTool) return aTool.localeCompare(bTool);
    const aTitle = a.title || '', bTitle = b.title || '';
    return aTitle.localeCompare(bTitle);
  });
  tableBody.innerHTML = sortedFindings.map(finding => {
    const severity = finding.severity || 'unknown';
    const severityColor = severityColors[severity] || '#6b7280';
    const ref = buildReference(finding);
    let cveDisplay = '';
    if (finding.cve) {
      if (finding.cve.includes(',')) cveDisplay = finding.cve;
      else if (finding.cve.toUpperCase().startsWith('CVE-'))
        cveDisplay = '<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name='+finding.cve+'" class="cve-link" target="_blank" rel="noopener">'+finding.cve+'</a>';
      else cveDisplay = finding.cve;
    }
    return '<tr>'
      + '<td><span class="tool-badge">'+escapeHtml(finding.tool || '')+'</span></td>'
      + '<td><span class="severity-badge" style="background-color:'+severityColor+';">'+severity.toUpperCase()+'</span></td>'
      + '<td>'+cveDisplay+'</td>'
      + '<td class="title-cell">'+escapeHtml(finding.title || '')+'</td>'
      + '<td><span class="ref-text">'+escapeHtml(ref)+'</span></td>'
      + '</tr>';
  }).join('');
}

function buildReference(finding) {
  const file = (finding.file || '').trim();
  const line = finding.line;

  function formatPath(path, mode) {
    if (!path) return '';
    if (mode === 'full') return path.replace(/\\\\/g, '/');
    if (mode === 'base') return path.replace(/\\\\/g, '/').split('/').pop();
    const parts = path.replace(/\\\\/g, '/').split('/');
    return parts.slice(-Math.min(refTailDepth, parts.length)).join('/');
  }
  function fileLineRef(mode) {
    const fp = file ? formatPath(file, mode) : 'unknown';
    return (line || line === 0) ? (fp + ':' + line) : fp;
  }
  // SonarQube: always filename:line
  if ((finding.tool || '').toLowerCase() === 'sonarqube') {
    return fileLineRef('base');
  }
  if (refMode === 'package') return (finding.component || '').trim() || fileLineRef(refPathMode);
  if (refMode === 'fileline') return fileLineRef(refPathMode);
  return (finding.component || '').trim() || fileLineRef(refPathMode);
}

function updateStats() {
  const resultCount = document.getElementById('resultCount');
  resultCount.textContent = 'Showing ' + filteredFindings.length + ' of ' + allFindings.length + ' findings';
}

function updateFilterStatus() {
  const searchTerm = document.getElementById('searchInput').value;
  const severityFilter = document.getElementById('severityFilter').value;
  const toolFilter = document.getElementById('toolFilter').value;
  const filters = [];
  if (searchTerm) filters.push('search: "'+searchTerm+'"');
  if (severityFilter) filters.push('severity: '+severityFilter+'+');
  if (toolFilter) filters.push('tool: '+toolFilter);
  const filterStatus = document.getElementById('filterStatus');
  filterStatus.textContent = filters.length ? ('Filtered by: ' + filters.join(', ')) : '';
}

function resetFilters() {
  document.getElementById('searchInput').value = '';
  document.getElementById('severityFilter').value = '';
  document.getElementById('toolFilter').value = '';
  applyFilters();
}

function exportResults() {
  const data = {
    metadata: { generated_at: new Date().toISOString(), generator: 'vuln_report.py (interactive)', total_findings: filteredFindings.length, exported_from_browser: true },
    summary: calculateSummary(filteredFindings),
    findings: filteredFindings
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url;
  a.download = 'vuln-report-filtered-' + new Date().toISOString().split('T')[0] + '.json';
  document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
}

function calculateSummary(findings) {
  const summary = { critical:0, high:0, medium:0, low:0, info:0, unknown:0 };
  findings.forEach(f => { const sev = f.severity || 'unknown'; summary[sev] = (summary[sev] || 0) + 1; });
  return {
    total_findings: findings.length,
    by_severity: summary,
    tools_used: [...new Set(findings.map(f => f.tool).filter(t => t))].sort(),
    sources_scanned: [...new Set(findings.map(f => f.source).filter(s => s))].sort()
  };
}
function escapeHtml(text) { const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }
</script>
</body>
</html>
"""
    return html

# ---------------- Dedupe & summary ----------------

def _dedupe(findings: List[Dict[str, Any]], dedupe_cve: bool) -> List[Dict[str, Any]]:
    """Dedupe:
    - Bước 1: exact-key (tool,id,title,component,file,line,cve)
    - Bước 2: (tuỳ chọn) chỉ gộp theo (CVE, component) nếu có CVE
    """
    def sev_rank(f): return SEV_ORDER.get(f.get("severity"), 0)
    best: Dict[Tuple[Any,...], Dict[str,Any]] = {}
    for f in findings:
        key = (f.get("tool"), f.get("id"), f.get("title"), f.get("component"), f.get("file"), f.get("line"), f.get("cve"))
        if key not in best or sev_rank(f) > sev_rank(best[key]):
            best[key] = f
    deduped = list(best.values())
    if not dedupe_cve:
        return deduped
    groups: Dict[Tuple[str,str], Dict[str,Any]] = {}
    for f in deduped:
        cve = str(f.get("cve") or "").strip()
        if not cve: continue
        comp = str(f.get("component") or "").strip()
        key = (cve, comp)
        g = groups.get(key)
        if (g is None) or (sev_rank(f) > sev_rank(g)):
            groups[key] = f
    no_cve_items = [f for f in deduped if not str(f.get("cve") or "").strip()]
    return list(groups.values()) + no_cve_items

def _summarize(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    summary: Dict[str, int] = {"critical":0, "high":0, "medium":0, "low":0, "info":0, "unknown":0}
    for f in findings:
        s = norm_sev(f.get("severity"))
        summary[s] = summary.get(s, 0) + 1
    return summary

# ---------------- Main ----------------

def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description='Enhanced Vulnerability Report Aggregator with Interactive Filtering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python vuln_report.py scan1.json scan2.json
  python vuln_report.py *.json --output-html=report.html
  python vuln_report.py results/ --interactive --min-severity=high
  python vuln_report.py scan.json --only-tools=trivy,semgrep --include="SQL"
        '''
    )
    parser.add_argument('files', nargs='+', help='Input files to process')
    parser.add_argument('--output-html', help='Export interactive HTML report')
    parser.add_argument('--output-json', help='Export JSON report')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress console output')
    parser.add_argument('--interactive', action='store_true', help='Enable interactive console filtering')
    parser.add_argument('--ref-mode', choices=['auto', 'fileline', 'package'], default='auto', help='Reference mode (default: auto)')
    parser.add_argument('--ref-path', default='tail2', help='Path format: full|base|tailN (default: tail2)')
    parser.add_argument('--ref-width', type=int, help='Max width for reference column')
    parser.add_argument('--only-tools', help='Filter by tools (comma-separated)')
    parser.add_argument('--include', action='append', default=[], help='Include pattern (regex)')
    parser.add_argument('--exclude', action='append', default=[], help='Exclude pattern (regex)')
    parser.add_argument('--min-severity', choices=['critical','high','medium','low','info'], help='Minimum severity level')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--no-skip-empty', action='store_true', help="Don't skip empty findings")
    parser.add_argument('--no-dedupe', action='store_true', help='Disable deduplication')
    parser.add_argument('--no-dedupe-cve', action='store_true', help='Disable CVE/component deduplication')
    parser.add_argument('--max-width', type=int, default=120, help='Max console width')

    args = parser.parse_args(argv[1:])

    # Process path mode
    ref_path_mode = "tail"
    ref_tail_depth = 2
    if args.ref_path == "full":
        ref_path_mode = "full"
    elif args.ref_path == "base":
        ref_path_mode = "base"
    elif args.ref_path.startswith("tail"):
        ref_path_mode = "tail"
        try:
            ref_tail_depth = int(args.ref_path[4:]) if len(args.ref_path) > 4 else 2
        except:
            ref_tail_depth = 2

    only_tools = set()
    if args.only_tools:
        only_tools = set(t.strip().lower() for t in args.only_tools.split(",") if t.strip())

    _enable_color(not args.no_color)

    if not args.files:
        parser.print_help()
        return 1

    # Expand file patterns if needed
    files = []
    for pattern in args.files:
        path = Path(pattern)
        if path.is_file():
            files.append(str(path))
        elif path.is_dir():
            json_files = list(path.glob("*.json")) + list(path.glob("*.sarif"))
            files.extend(str(f) for f in json_files)
        elif "*" in pattern:
            from glob import glob
            files.extend(glob(pattern))
        else:
            files.append(pattern)

    all_findings: List[Dict[str, Any]] = []

    # Process files
    for fpath in files:
        p = Path(fpath)
        if not p.exists():
            if not args.quiet:
                print(f"{YELLOW}Warning: file not found: {p}{RESET}")
            continue
        try:
            obj = load_json(p)
        except Exception as e:
            if not args.quiet:
                print(f"{RED}Error: cannot parse JSON from {p}: {e}{RESET}")
            continue
        fmt = detect_format(obj, p)
        parser_func = PARSERS.get(fmt)
        if not parser_func:
            if not args.no_skip_empty and not args.quiet:
                print_header(f"{p} — format: unknown (no findings)", args.max_width)
            continue
        findings = list(parser_func(obj, str(p)))
        if not findings and not args.no_skip_empty:
            continue
        for it in findings:
            it["source"] = str(p)
            it["severity"] = norm_sev(it.get("severity"))
        all_findings.extend(findings)

    if only_tools:
        all_findings = [f for f in all_findings if (f.get("tool","")).lower() in only_tools]
    if args.min_severity:
        all_findings = filter_by_severity(all_findings, args.min_severity)

    if args.include or args.exclude:
        filtered: List[Dict[str,Any]] = []
        for f in all_findings:
            ref = build_ref(f, args.ref_mode, ref_path_mode, ref_tail_depth)
            hay = f"{f.get('title','')} | {ref}"
            if _match_filters(hay, args.include, args.exclude):
                filtered.append(f)
        all_findings = filtered

    if not args.no_dedupe:
        all_findings = _dedupe(all_findings, dedupe_cve=not args.no_dedupe_cve)

    if args.interactive and not args.quiet:
        all_findings = interactive_filter_menu(all_findings, args.ref_mode, ref_path_mode, ref_tail_depth, args.max_width)

    all_findings.sort(key=lambda x: (-SEV_ORDER.get(x.get("severity"),0), x.get("cve",""), x.get("tool",""), x.get("title","")))

    summary = _summarize(all_findings)

    if not args.quiet:
        header = f"Enhanced Vulnerability Report • {human_now()}"
        print_header(header, args.max_width)
        sev_line = f"CRITICAL:{summary['critical']} HIGH:{summary['high']} MEDIUM:{summary['medium']} LOW:{summary['low']} INFO:{summary['info']}"
        print(sev_line); print()
        if all_findings:
            show_findings_table(all_findings, args.ref_mode, ref_path_mode, ref_tail_depth, args.max_width)
        else:
            print(f"{GREEN}No findings after filters.{RESET}")

    if args.output_html:
        html = generate_html_report(all_findings, summary, args.ref_mode, ref_path_mode, ref_tail_depth)
        Path(args.output_html).write_text(html, encoding="utf-8")
        if not args.quiet:
            print(f"\n{GREEN}Interactive HTML report saved to: {args.output_html}{RESET}")

    if args.output_json:
        meta = {
            "arguments": argv[1:],
            "ref_mode": args.ref_mode,
            "ref_path_mode": ref_path_mode,
            "ref_tail_depth": ref_tail_depth,
            "filters_applied": {
                "min_severity": args.min_severity,
                "only_tools": list(only_tools),
                "include_patterns": args.include,
                "exclude_patterns": args.exclude
            }
        }
        json_data = {
            "metadata": {
                "generated_at": datetime.datetime.now().isoformat(),
                "generator": "vuln_report.py",
                "version": "2.1",
                **meta
            },
            "summary": {
                "total_findings": len(all_findings),
                "by_severity": summary,
                "tools_used": sorted(list(set(f.get("tool", "") for f in all_findings if f.get("tool")))),
                "sources_scanned": sorted(list(set(f.get("source", "") for f in all_findings if f.get("source"))))
            },
            "findings": all_findings
        }
        Path(args.output_json).write_text(json.dumps(json_data, ensure_ascii=False, indent=2), encoding="utf-8")
        if not args.quiet:
            print(f"{GREEN}JSON report saved to: {args.output_json}{RESET}")

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
