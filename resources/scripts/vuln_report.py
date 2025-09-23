#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, sys, re, datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

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

def cut(s: str, n: Optional[int]) -> str:
    if s is None: return ""
    s = str(s).replace("\n"," ").replace("\r"," ")
    if not n: return s
    return (s[:n-1]+"…") if len(s)>n else s

def load_json(path: Path) -> Any:
    txt = path.read_text(encoding="utf-8", errors="ignore")
    try: return json.loads(txt)
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
      - auto: package@version cho dependency; file[:line] cho code
      - fileline: luôn file[:line] (nếu có)
      - package: luôn component (nếu có)
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
    rules_index = {}
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
                   "file":target,"line":None,"url":v.get("PrimaryURL") or "","cve": vid if vid.startswith(("CVE-","GHSA-")) else "","cwe":""}
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
    Ref = package@version (dependency style). CVE lấy từ identifiers.CVE[].
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
        # từ "from" giữ vào file để tra nguồn (image/layer), Ref vẫn là comp
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

def human_now(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def print_header(t,w): print(f"{BOLD}{t}{RESET}"); print(f"{DIM}{'─'*min(w,120)}{RESET}")
def colfit(t,w): t=t or ""; return t+" "*(w-len(t)) if (w and len(t)<=w) else (t if not w else t[:w-1]+"…")

def table(rows,hdrs,w):
    # Cột: Tool | Severity | CVE | Title | Ref (Ref mặc định KHÔNG cắt)
    tool_w, sev_w, cve_w, title_w = 12, 8, 16, 68
    # Nếu tổng > width: giảm title_w, Ref vẫn in full
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
        "─"*tool_w, "─"*sev_w, "─"*cve_w, "─"*title_w, "─"*8
    ]) + RESET)
    for r in rows:
        print(" ".join([
            colfit(str(r[0]), tool_w),
            colfit(str(r[1]), sev_w),
            colfit(str(r[2]), cve_w),
            colfit(str(r[3]), title_w),
            str(r[4])  # Ref in full
        ]))

def _match_filters(text, include_patterns, exclude_patterns):
    s = text or ''
    for pat in exclude_patterns:
        if re.search(pat, s): return False
    if include_patterns: return any(re.search(p, s) for p in include_patterns)
    return True

def main(argv: List[str]) -> int:
    files=[]; max_width=120; color=True
    include=[]; exclude=[]; only=set()
    skip_empty=True; dedupe=True; dedupe_cve=True
    ref_mode="auto"; ref_path_mode="tail"; ref_tail_depth=2
    ref_width=None  # None => không cắt Ref
    for a in argv[1:]:
        if a=="--no-color": color=False
        elif a.startswith("--max-width="): max_width=int(a.split("=",1)[1])
        elif a.startswith("--include="): include.append(a.split("=",1)[1])
        elif a.startswith("--exclude="): exclude.append(a.split("=",1)[1])
        elif a.startswith("--only-tools="): only=set(t.strip().lower() for t in a.split("=",1)[1].split(",") if t.strip())
        elif a=="--no-skip-empty": skip_empty=False
        elif a=="--no-dedupe": dedupe=False
        elif a=="--no-dedupe-cve": dedupe_cve=False
        elif a.startswith("--ref-mode="): ref_mode=a.split("=",1)[1].strip().lower()
        elif a.startswith("--ref-path="):
            val=a.split("=",1)[1].strip().lower()
            if val=="full": ref_path_mode="full"
            elif val=="base": ref_path_mode="base"
            elif val.startswith("tail"):
                ref_path_mode="tail"
                try:
                    ref_tail_depth=int(val[4:]) if len(val)>4 else 2
                except: ref_tail_depth=2
        elif a.startswith("--ref-width="):
            try: ref_width=int(a.split("=",1)[1])
            except: ref_width=None
        else: files.append(a)
    _enable_color(color)
    if not files:
        print("Usage: python vuln_report.py <file1> [<file2> ...] "
              "[--ref-mode=auto|fileline|package] [--ref-path=full|base|tailN] [--ref-width=N]")
        return 1

    findings=[]; seen=set(); errors=[]
    for path in files:
        p=Path(path)
        if not p.exists(): errors.append(f"Missing: {path}"); continue
        try:
            obj=load_json(p); fmt=detect_format(obj,p)
            if fmt=="unknown": errors.append(f"Skip (unknown format): {path}"); continue
            for f in PARSERS[fmt](obj, source=p.name):
                f["severity"]=norm_sev(f.get("severity"))
                if only and f.get("tool","").lower() not in only: continue
                if skip_empty and (not f.get("title") or f["title"].strip().lower() in ("na","unknown","gitleaks","semgrep finding","trivy vulnerability","dependency-check finding","snyk vulnerability")):
                    continue
                blob=" ".join([str(f.get("title","")), str(f.get("cve","")), str(f.get("component","")), str(f.get("file",""))])
                if not _match_filters(blob, include, exclude): continue
                # Dedupe (ưu tiên theo CVE)
                if dedupe and dedupe_cve and f.get("cve"):
                    key=("CVE", f["cve"])
                else:
                    key=(f.get("tool",""), f.get("title",""), f.get("component",""), f.get("file",""), f.get("line"))
                if dedupe and key in seen: continue
                seen.add(key); findings.append(f)
        except Exception as e:
            errors.append(f"Error: {path} -> {e}")

    width=max_width
    print_header(f"Aggregated Vulnerability Report • {human_now()}", width)
    by_sev={}
    for f in findings: by_sev[f["severity"]]=by_sev.get(f["severity"],0)+1
    sev_line=[]
    for s in ("critical","high","medium","low","info","unknown"):
        if by_sev.get(s): sev_line.append(f"{s.upper()}:{by_sev[s]}")
    print(" ".join(sev_line) if sev_line else "No issues")

    if findings:
        print("\n")
        headers=["Tool","Severity","CVE","Title","Ref"]
        rows=[]
        findings_sorted = sorted(findings, key=lambda x:(-SEV_ORDER.get(x["severity"],0), x.get("cve",""), x.get("tool",""), x.get("title","")))
        for f in findings_sorted:
            ref_val = build_ref(f, ref_mode, ref_path_mode, ref_tail_depth)
            rows.append([
                f.get("tool",""),
                (f.get("severity","") or "").upper(),
                cut(f.get("cve",""), 16),
                cut(f.get("title",""), 90),
                (cut(ref_val, ref_width) if ref_width else ref_val),  # mặc định: KHÔNG cắt Ref
            ])
        table(rows, headers, width)

    if errors:
        print("\nNotes:")
        for e in errors: print(" - " + e)

    return 2 if (by_sev.get("critical",0) or by_sev.get("high",0)) else 0

if __name__=="__main__":
    sys.exit(main(sys.argv))
