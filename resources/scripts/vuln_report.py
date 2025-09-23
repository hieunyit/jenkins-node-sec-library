#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Vulnerability Report Aggregator

Usage:
  python vuln_report.py <file1> [<file2> ...] [OPTIONS]

Options:
  --output-html=FILE       Export HTML report
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

Supported formats (auto-detected): SARIF, Dependency-Check JSON, RetireJS, npm audit JSON,
Gitleaks JSON, Semgrep JSON, Trivy JSON, Snyk JSON (OSS/Container)
"""

import json, sys, re, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
      - auto: package@version for dependency; file[:line] for code
      - fileline: always file[:line] (if available)
      - package: always component (if available)
    ref_path_mode: full | base | tailN (tail_depth = N)
    """
    comp = (f.get("component") or "").strip()
    file = (f.get("file") or "").strip()
    line = f.get("line")

    def fileline():
        fp = format_path(file, ref_path_mode, tail_depth) if file else "unknown"
        return f"{fp}:{line}" if line else fp

    if ref_mode == "package":
        return comp or fileline()
    if ref_mode == "fileline":
        return fileline()

    # auto
    if comp:
        return comp
    return fileline()

# ---------------- Parsers ----------------

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
        # Vulnerabilities (package-level)
        for v in result.get("Vulnerabilities") or []:
            sev=norm_sev(v.get("Severity")); vid=v.get("VulnerabilityID") or ""
            pkg = v.get("PkgName") or v.get("PkgID") or ""
            inst = v.get("InstalledVersion") or v.get("PkgVersion") or ""
            comp = f"{pkg}@{inst}" if pkg else inst
            yield {"tool":"trivy","source":source,"id":vid,"title":v.get("Title") or vid,"severity":sev,"component":comp,
                   "file":target,"line":None,"url":v.get("PrimaryURL") or "","cve": vid if str(vid).upper().startswith(("CVE-","GHSA-")) else "","cwe":""}
        # Misconfigurations / Secrets
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
    """
    Snyk JSON: vulnerabilities[]
    """
    for v in obj.get("vulnerabilities") or []:
        sev = norm_sev(v.get("severity"))
        title = v.get("title") or v.get("id") or "snyk vulnerability"
        # component / package
        pkg = v.get("packageName") or v.get("name") or ""
        ver = v.get("version") or ""
        comp = f"{pkg}@{ver}" if pkg and ver else (pkg or ver)
        # identifiers
        cve_list = []; cwe_list = []
        idf = v.get("identifiers") or {}
        if isinstance(idf, dict):
            if isinstance(idf.get("CVE"), list): cve_list = [str(x) for x in idf.get("CVE") if x]
            if isinstance(idf.get("CWE"), list): cwe_list = [str(x) for x in idf.get("CWE") if x]
        cve = ",".join(sorted(set(cve_list)))
        cwe = ",".join(sorted(set(cwe_list)))
        # from -> target/image/layer trail (store in file field)
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
    # Use ASCII dashes to avoid mojibake on some consoles
    print(f"{DIM}{'-'*min(w,120)}{RESET}")

def colfit(t: str, w: int) -> str:
    t=t or ""
    return t+" "*(w-len(t)) if (w and len(t)<=w) else (t if not w else t[:w-1]+"…")

def table(rows: List[Tuple[str,str,str,str,str]], hdrs: List[str], w: int):
    # Columns: Tool | Severity | CVE | Title | Ref (Ref optionally cut by --ref-width)
    tool_w, sev_w, cve_w, title_w = 12, 8, 16, 68
    # If total > width: reduce title_w, keep Ref full
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
            str(r[4])  # Ref printed after optional external cut
        ]))

def _match_filters(text: str, include_patterns: List[str], exclude_patterns: List[str]) -> bool:
    s = text or ''
    for pat in exclude_patterns:
        if re.search(pat, s, flags=re.I): return False
    if include_patterns:
        return any(re.search(p, s, flags=re.I) for p in include_patterns)
    return True

# ---------------- Report generators ----------------

def generate_html_report(findings: List[Dict[str, Any]], summary: Dict[str, int], 
                         ref_mode: str, ref_path_mode: str, ref_tail_depth: int) -> str:
    """Generate HTML vulnerability report"""
    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c", 
        "medium": "#d97706",
        "low": "#65a30d",
        "info": "#0891b2",
        "unknown": "#6b7280"
    }
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Report - {human_now()}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f8fafc; }}
  .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
  .header h1 {{ margin: 0; font-size: 28px; font-weight: 600; }}
  .header .meta {{ margin-top: 8px; opacity: 0.9; }}
  .summary {{ padding: 30px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; }}
  .summary-card {{ background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  .summary-card .count {{ font-size: 24px; font-weight: 700; margin-bottom: 5px; }}
  .summary-card .label {{ font-size: 12px; text-transform: uppercase; font-weight: 600; color: #64748b; }}
  .content {{ padding: 30px; }}
  .table-container {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
  th {{ background: #f1f5f9; font-weight: 600; color: #475569; font-size: 14px; }}
  .severity-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; color: white; }}
  .tool-badge {{ background: #e2e8f0; color: #475569; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 500; }}
  .cve-link {{ color: #3b82f6; text-decoration: none; }}
  .cve-link:hover {{ text-decoration: underline; }}
  .ref-text {{ font-family: 'Monaco', 'Menlo', monospace; font-size: 12px; color: #64748b; }}
  tr:hover {{ background: #f8fafc; }}
  .empty-state {{ text-align: center; padding: 60px 20px; color: #64748b; }}
  .empty-state .icon {{ font-size: 48px; margin-bottom: 16px; }}
</style>
</head>
<body>
  <div class="container"> 
    <div class="header"> 
      <h1>Vulnerability Report</h1>
      <div class="meta">Generated on {human_now()}</div>
    </div>
    <div class="summary">
      <div class="summary-grid">
"""
    # Add summary cards
    total_findings = len(findings)
    for severity in ["critical", "high", "medium", "low", "info", "unknown"]:
        count = summary.get(severity, 0)
        if count > 0 or severity in ["critical", "high", "medium"]:
            color = severity_colors.get(severity, "#6b7280")
            html_content += f"""
        <div class="summary-card">
          <div class="count" style="color: {color};">{count}</div>
          <div class="label">{severity.upper()}</div>
        </div>
"""
    html_content += f"""
        <div class="summary-card">
          <div class="count" style="color: #1f2937;">{total_findings}</div>
          <div class="label">TOTAL</div>
        </div>
      </div>
    </div>
    <div class="content">
"""
    if findings:
        html_content += """
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Tool</th>
              <th>Severity</th>
              <th>CVE</th>
              <th>Title</th>
              <th>Reference</th>
            </tr>
          </thead>
          <tbody>
"""
        findings_sorted = sorted(findings, key=lambda x: (-SEV_ORDER.get(x.get("severity"), 0), x.get("cve", ""), x.get("tool", ""), x.get("title", "")))
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c", 
            "medium": "#d97706",
            "low": "#65a30d",
            "info": "#0891b2",
            "unknown": "#6b7280"
        }
        for f in findings_sorted:
            severity = f.get("severity", "unknown")
            color = severity_colors.get(severity, "#6b7280")
            ref_val = build_ref(f, ref_mode, ref_path_mode, ref_tail_depth)
            cve_text = f.get("cve", "")
            cve_display = ""
            if cve_text:
                if "," not in cve_text and cve_text.upper().startswith("CVE-"):
                    cve_display = f'<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_text}" class="cve-link" target="_blank" rel="noopener">{cve_text}</a>'
                else:
                    cve_display = cve_text
            title = (f.get('title', '') or '').replace('<','&lt;').replace('>','&gt;')
            ref_safe = (ref_val or '').replace('<','&lt;').replace('>','&gt;')
            html_content += f"""
            <tr>
              <td><span class="tool-badge">{f.get('tool', '')}</span></td>
              <td><span class="severity-badge" style="background-color: {color};">{severity.upper()}</span></td>
              <td>{cve_display}</td>
              <td>{title}</td>
              <td><span class="ref-text">{ref_safe}</span></td>
            </tr>
"""
        html_content += """
          </tbody>
        </table>
      </div>
"""
    else:
        html_content += """
      <div class="empty-state"> 
        <div class="icon">✅</div>
        <h3>No vulnerabilities found</h3>
        <p>All scanned files appear to be clean.</p>
      </div>
"""
    html_content += """
    </div>
  </div>
</body>
</html>
"""
    return html_content

def generate_json_report(findings: List[Dict[str, Any]], summary: Dict[str, int], metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Generate JSON vulnerability report"""
    return {
        "metadata": {
            "generated_at": datetime.datetime.now().isoformat(),
            "generator": "vuln_report.py",
            "version": "2.0",
            **metadata
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": summary,
            "tools_used": sorted(list(set(f.get("tool", "") for f in findings if f.get("tool")))),
            "sources_scanned": sorted(list(set(f.get("source", "") for f in findings if f.get("source"))))
        },
        "findings": findings
    }

# ---------------- Core helpers ----------------

def _dedupe(findings: List[Dict[str, Any]], dedupe_cve: bool) -> List[Dict[str, Any]]:
    """Dedupe findings, keeping the one with the highest severity rank.
    - Always dedupe by full key (tool,id,title,component,file,line,cve)
    - If dedupe_cve=True, also dedupe records that share (cve, component or id) to reduce noise
    """
    def sev_rank(f): return SEV_ORDER.get(f.get("severity"), 0)

    # exact key dedupe first
    best: Dict[Tuple[Any,...], Dict[str,Any]] = {}
    for f in findings:
        key = (
            f.get("tool"), f.get("id"), f.get("title"), f.get("component"),
            f.get("file"), f.get("line"), f.get("cve"),
        )
        if key not in best or sev_rank(f) > sev_rank(best[key]):
            best[key] = f

    deduped = list(best.values())

    if not dedupe_cve:
        return deduped

    # secondary dedupe: by (CVE, component) if CVE exists; else by (id, component)
    groups: Dict[Tuple[str,str], Dict[str,Any]] = {}
    for f in deduped:
        cve = str(f.get("cve") or "").strip()
        comp = str(f.get("component") or "").strip()
        if not cve and not comp:
            continue
        if cve:
            key = (f"CVE:{cve}", comp)
        else:
            id_str = str(f.get("id") or "").strip()
            key = (f"ID:{id_str}", comp)
        g = groups.get(key)
        if (g is None) or (sev_rank(f) > sev_rank(g)):
            groups[key] = f

    # keep one per group + keep entries with neither CVE nor component
    selected = list(groups.values())
    no_key_items = [
        f for f in deduped
        if (str(f.get("cve") or "").strip() == "" and str(f.get("component") or "").strip() == "")
    ]
    return selected + no_key_items

def _summarize(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    summary: Dict[str, int] = {"critical":0, "high":0, "medium":0, "low":0, "info":0, "unknown":0}
    for f in findings:
        s = norm_sev(f.get("severity"))
        summary[s] = summary.get(s, 0) + 1
    return summary

# ---------------- Main ----------------

def main(argv: List[str]) -> int:
    files: List[str] = []
    max_width = 120
    color = True
    include: List[str] = []
    exclude: List[str] = []
    only: set = set()
    skip_empty = True
    dedupe = True
    dedupe_cve = True
    ref_mode = "auto"
    ref_path_mode = "tail"
    ref_tail_depth = 2
    ref_width: Optional[int] = None  # None => do not cut Ref
    output_html: Optional[str] = None
    output_json: Optional[str] = None
    quiet = False

    # --- parse args ---
    for a in argv[1:]:
        if a == "--no-color": color = False
        elif a in ("--quiet", "-q"): quiet = True
        elif a.startswith("--max-width="): max_width = int(a.split("=",1)[1])
        elif a.startswith("--include="): include.append(a.split("=",1)[1])
        elif a.startswith("--exclude="): exclude.append(a.split("=",1)[1])
        elif a.startswith("--only-tools="): only = set(t.strip().lower() for t in a.split("=",1)[1].split(",") if t.strip())
        elif a == "--no-skip-empty": skip_empty = False
        elif a == "--no-dedupe": dedupe = False
        elif a == "--no-dedupe-cve": dedupe_cve = False
        elif a.startswith("--ref-mode="): ref_mode = a.split("=",1)[1].strip().lower()
        elif a.startswith("--ref-path="):
            val = a.split("=",1)[1].strip().lower()
            if val == "full": ref_path_mode = "full"
            elif val == "base": ref_path_mode = "base"
            elif val.startswith("tail"):
                ref_path_mode = "tail"
                try:
                    ref_tail_depth = int(val[4:]) if len(val) > 4 else 2
                except: ref_tail_depth = 2
        elif a.startswith("--ref-width="):
            try: ref_width = int(a.split("=",1)[1])
            except: ref_width = None
        elif a.startswith("--output-html="): output_html = a.split("=",1)[1]
        elif a.startswith("--output-json="): output_json = a.split("=",1)[1]
        else:
            files.append(a)

    _enable_color(color)

    if not files:
        print("Usage: python vuln_report.py <file1> [<file2> ...] [OPTIONS]")
        print("\nOptions:")
        print("  --output-html=FILE       Export HTML report")
        print("  --output-json=FILE       Export JSON report")
        print("  --quiet, -q              Suppress console output")
        print("  --ref-mode=MODE          Reference mode: auto|fileline|package")
        print("  --ref-path=MODE          Path format: full|base|tailN (e.g., tail2)")
        print("  --ref-width=N            Max width for reference column")
        print("  --only-tools=LIST        Filter by tools (comma-separated)")
        print("  --include=PATTERN        Include pattern (regex)")
        print("  --exclude=PATTERN        Exclude pattern (regex)")
        print("  --no-color               Disable colored output")
        print("  --no-skip-empty          Don't skip empty findings")
        print("  --no-dedupe              Disable deduplication")
        print("  --no-dedupe-cve          Disable CVE/component deduplication")
        return 1

    all_findings: List[Dict[str, Any]] = []

    for fpath in files:
        p = Path(fpath)
        if not p.exists():
            print(f"{YELLOW}Warning: file not found: {p}{RESET}")
            continue
        try:
            obj = load_json(p)
        except Exception as e:
            print(f"{RED}Error: cannot parse JSON from {p}: {e}{RESET}")
            continue
        fmt = detect_format(obj, p)
        parser = PARSERS.get(fmt)
        if not parser:
            if not skip_empty and not quiet:
                print_header(f"{p} — format: unknown (no findings)", max_width)
            continue
        findings = list(parser(obj, str(p)))
        if not findings and skip_empty:
            continue
        # annotate the raw source file path
        for it in findings:
            it["source"] = str(p)
            it["severity"] = norm_sev(it.get("severity"))
        all_findings.extend(findings)

    # filter by tool
    if only:
        all_findings = [f for f in all_findings if (f.get("tool","")).lower() in only]

    # apply include/exclude based on title or reference
    if include or exclude:
        filtered: List[Dict[str,Any]] = []
        for f in all_findings:
            ref = build_ref(f, ref_mode, ref_path_mode, ref_tail_depth)
            hay = f"{f.get('title','')} | {ref}"
            if _match_filters(hay, include, exclude):
                filtered.append(f)
        all_findings = filtered

    # deduplication
    if dedupe:
        all_findings = _dedupe(all_findings, dedupe_cve=dedupe_cve)

    # sort for output
    all_findings.sort(key=lambda x: (-SEV_ORDER.get(x.get("severity"),0), x.get("cve",""), x.get("tool",""), x.get("title","")))

    # summary
    summary = _summarize(all_findings)

    # console output
    if not quiet:
        header = f"Aggregated Vulnerability Report • {human_now()}"
        print_header(header, max_width)
        sev_line = f"CRITICAL:{summary['critical']} HIGH:{summary['high']} MEDIUM:{summary['medium']} LOW:{summary['low']} INFO:{summary['info']}"
        print(sev_line)
        print()
        rows: List[Tuple[str,str,str,str,str]] = []
        for f in all_findings:
            ref_val = build_ref(f, ref_mode, ref_path_mode, ref_tail_depth)
            if ref_width:
                ref_val = cut(ref_val, ref_width)
            rows.append((
                f.get("tool",""),
                (f.get("severity") or "").upper(),
                f.get("cve",""),
                f.get("title",""),
                ref_val
            ))
        if rows:
            table(rows, ["Tool","Severity","CVE","Title"], max_width)
        else:
            print(f"{GREEN}No findings after filters.{RESET}")

    # outputs
    if output_html:
        html = generate_html_report(all_findings, summary, ref_mode, ref_path_mode, ref_tail_depth)
        Path(output_html).write_text(html, encoding="utf-8")
        if not quiet:
            print(f"\n{GREEN}HTML report saved to: {output_html}{RESET}")

    if output_json:
        meta = {
            "arguments": [a for a in argv[1:]],
            "ref_mode": ref_mode,
            "ref_path_mode": ref_path_mode,
            "ref_tail_depth": ref_tail_depth,
        }
        j = generate_json_report(all_findings, summary, meta)
        Path(output_json).write_text(json.dumps(j, ensure_ascii=False, indent=2), encoding="utf-8")
        if not quiet:
            print(f"{GREEN}JSON report saved to: {output_json}{RESET}")

    return 0

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
