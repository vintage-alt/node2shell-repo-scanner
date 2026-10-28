import os
import re
import yaml
import json

# UPDATE THIS PATH to where your repos are cloned
BASE_DIR = r"C:\RepoRoot" 

SAFE_NODE_VERSIONS = {22: (23, 4), 24: (22, 1), 26: (12, 1)}
EOL_NODE_MAX = 21

TARGET_EXACT_FILES = {
    '.nvmrc', '.node-version', 'package.json',
    'requirements.txt', 'pyproject.toml', 'pipfile', 'pipfile.lock', 'poetry.lock', 'uv.lock',
    'gemfile.lock', 'pom.xml', 'build.gradle', 'build.gradle.kts',
    'serverless.yml', 'serverless.yaml',
    'go.mod', 'cargo.lock', 'composer.lock', 'packages.lock.json',
    'dockerfile'
}

def is_node_vulnerable(version_str):
    clean_v = version_str.strip().lstrip('v').split('-')[0]
    parts = clean_v.split('.')
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except (ValueError, IndexError):
        return True

    if major <= EOL_NODE_MAX or major in (21, 23, 25):
        return True

    if major in SAFE_NODE_VERSIONS:
        s_minor, s_patch = SAFE_NODE_VERSIONS[major]
        if (minor, patch) < (s_minor, s_patch):
            return True
        return False
    return False

def parse_semver(v_str):
    clean_v = re.sub(r'[^0-9.]', '', v_str.strip())
    parts = [p for p in clean_v.split('.') if p != '']
    if not parts:
        return None
    try:
        padded = (parts + ['0', '0', '0'])[:3]
        return tuple(int(p) for p in padded)
    except (ValueError, IndexError):
        return None

def parse_semver_full(v_str):
    clean_v = re.sub(r'[^0-9.]', '', v_str.strip())
    parts = [p for p in clean_v.split('.') if p != '']
    try:
        return tuple(int(p) for p in parts)
    except (ValueError, IndexError):
        return None

def is_brotli_c_vulnerable(v_tuple, is_brotlicffi=False):
    if not v_tuple or len(v_tuple) < 3:
        return False

    if is_brotlicffi:
        if v_tuple[:3] == (1, 2, 0):
            return True
        if v_tuple[:3] == (1, 2, 1):
            return False
        major, minor, patch = v_tuple[:3]
    else:
        major, minor, patch = v_tuple[:3]

    if (major, minor) > (1, 2):
        return False
    if (major, minor) == (1, 0) and patch >= 10:
        return False
    if (major, minor) == (1, 1) and patch >= 1:
        return False
    if (major, minor) == (1, 2) and patch >= 1:
        return False

    if (1, 0, 3) <= (major, minor, patch) <= (1, 2, 0):
        return True
    return False

def check_node_version_string(ver_str, source_label):
    clean = ver_str.strip().lstrip('v').split('-')[0]
    parts = [p for p in clean.split('.') if p and p not in ('x', '*')]
    if not parts:
        return ("unpinned", f"{source_label}: `{ver_str}` (dynamic version)")
    try:
        major = int(parts[0])
    except ValueError:
        return ("unpinned", f"{source_label}: `{ver_str}` (non-standard)")

    if major <= EOL_NODE_MAX or major in (21, 23, 25):
        return ("vulnerable", f"{source_label}: `{ver_str}` (EOL/unpatched <= 21)")

    if len(parts) == 1:
        min_m, min_p = SAFE_NODE_VERSIONS.get(major, (0, 0))
        return ("unpinned", f"{source_label}: `{ver_str}` (floating major, verify >= {major}.{min_m}.{min_p})")

    if is_node_vulnerable(clean):
        return ("vulnerable", f"{source_label}: `{ver_str}` (pinned vulnerable)")
    return ("safe", f"{source_label}: `{ver_str}`")

def is_target_file(path):
    filename = os.path.basename(path).lower()
    if filename in TARGET_EXACT_FILES:
        return True
    if filename.startswith('dockerfile') or filename.endswith('.dockerfile'):
        return True
    if filename.startswith('requirements') and filename.endswith('.txt'):
        return True
    if filename.endswith('.csproj'):
        return True
    if '.github/workflows/' in path.replace('\\', '/') and filename.endswith(('.yml', '.yaml')):
        return True
    return False

def analyze_file(repo_name, path, content):
    findings = []
    filename = os.path.basename(path).lower()
    rel_path = os.path.relpath(path, BASE_DIR)

    if filename in ('.nvmrc', '.node-version'):
        lines = content.strip().splitlines()
        if lines:
            findings.append(check_node_version_string(lines[0], f"`{rel_path}`"))

    elif filename == 'package.json':
        try:
            pkg = json.loads(content)
            engines = pkg.get("engines", {}).get("node")
            if engines:
                findings.append(("context", f"`{rel_path}` engines.node: `{engines}`"))
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            for d in ('brotli', 'iltorb', 'wasm-brotli'):
                if d in deps:
                    findings.append(("unpinned", f"`{rel_path}` declares `{d}: {deps[d]}`"))
        except Exception:
            pass

    elif (filename.startswith('requirements') and filename.endswith('.txt')) or filename == 'pyproject.toml':
        for line in content.splitlines():
            line_clean = line.strip().lower()
            if not line_clean or line_clean.startswith('#'):
                continue
            if re.search(r'^(brotli|brotlicffi)\b', line_clean) or re.search(r'["\'](brotli|brotlicffi)\b', line_clean):
                is_cffi = 'brotlicffi' in line_clean
                pin = re.search(r'==\s*([0-9.]+(?:\.[0-9]+)*)', line_clean)
                if pin:
                    vt = parse_semver_full(pin.group(1))
                    status = "vulnerable" if is_brotli_c_vulnerable(vt, is_cffi) else "safe"
                    findings.append((status, f"`{rel_path}`: `{line.strip()}`"))
                else:
                    lower = re.search(r'(?:>=|~=|>\s*)\s*([0-9.]+(?:\.[0-9]+)*)', line_clean)
                    if lower:
                        vt = parse_semver_full(lower.group(1))
                        if is_brotli_c_vulnerable(vt, is_cffi):
                            findings.append(("unpinned", f"`{rel_path}`: `{line.strip()}` (range vulnerable)"))
                        else:
                            findings.append(("safe", f"`{rel_path}`: `{line.strip()}` (lower bound safe)"))
                    else:
                        findings.append(("unpinned", f"`{rel_path}`: `{line.strip()}` (unpinned)"))

    elif filename == 'pipfile.lock':
        try:
            data = json.loads(content)
            for section in ('default', 'develop'):
                for pkg_name, meta in data.get(section, {}).items():
                    if pkg_name.lower() in ('brotli', 'brotlicffi'):
                        ver = meta.get('version', '').lstrip('=')
                        is_cffi = pkg_name.lower() == 'brotlicffi'
                        vt = parse_semver_full(ver)
                        status = "vulnerable" if is_brotli_c_vulnerable(vt, is_cffi) else "safe"
                        findings.append((status, f"`{rel_path}`: `{pkg_name}=={ver}`"))
        except Exception:
            pass

    elif filename in ('poetry.lock', 'uv.lock'):
        for block in content.split('[[package]]'):
            m_name = re.search(r'name\s*=\s*"(brotli|brotlicffi)"', block, re.I)
            if m_name:
                vm = re.search(r'version\s*=\s*"([0-9.]+(?:\.[0-9]+)*)"', block)
                if vm:
                    pkg_name = m_name.group(1)
                    is_cffi = pkg_name.lower() == 'brotlicffi'
                    vt = parse_semver_full(vm.group(1))
                    status = "vulnerable" if is_brotli_c_vulnerable(vt, is_cffi) else "safe"
                    findings.append((status, f"`{rel_path}`: `{pkg_name}=={vm.group(1)}`"))

    elif filename == 'gemfile.lock':
        for line in content.splitlines():
            m = re.search(r'^\s*brotli\s+\(([0-9.]+)\)', line, re.I)
            if m:
                findings.append(("unpinned", f"`{rel_path}`: `brotli ({m.group(1)})` — verify host `libbrotli1`"))

    elif filename == 'pom.xml' and 'brotli4j' in content.lower():
        m = re.search(r'<artifactId>brotli4j</artifactId>[\s\S]*?<version>([0-9.]+)</version>', content, re.I)
        if m:
            vt = parse_semver(m.group(1))
            status = "vulnerable" if is_brotli_c_vulnerable(vt) else "safe"
            findings.append((status, f"`{rel_path}` brotli4j: `{m.group(1)}`"))
        else:
            findings.append(("unpinned", f"`{rel_path}` references `brotli4j`"))

    elif filename in ('build.gradle', 'build.gradle.kts') and 'brotli4j' in content.lower():
        findings.append(("unpinned", f"`{rel_path}` references `brotli4j`"))

    elif filename == 'go.mod' and 'brotli' in content.lower():
        for line in content.splitlines():
            low = line.lower()
            if 'andybalholm/brotli' in low:
                findings.append(("context", f"`{rel_path}` Go port `{line.strip()}` (no RCE risk)"))
            elif 'google/brotli' in low:
                findings.append(("unpinned", f"`{rel_path}` Go C-binding `{line.strip()}`"))

    elif filename == 'cargo.lock' and 'brotli-decompressor' in content.lower():
        findings.append(("context", f"`{rel_path}` Rust `brotli-decompressor` (no RCE risk)"))

    elif filename == 'composer.lock' and 'brotli' in content.lower():
        findings.append(("unpinned", f"`{rel_path}` PHP `brotli` extension"))

    elif filename.endswith('.csproj'):
        clower = content.lower()
        if 'brotli' in clower:
            findings.append(("unpinned", f"`{rel_path}` (.NET) Brotli reference"))
        elif 'system.net.http' in clower or 'system.io.compression' in clower:
            findings.append(("context", f"`{rel_path}` (.NET) HTTP/Compression stack (Brotli opt-in)"))

    elif filename in ('serverless.yml', 'serverless.yaml'):
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                runtime = str(data.get('provider', {}).get('runtime', ''))
                if runtime.startswith('nodejs'):
                    findings.append(check_node_version_string(runtime.replace('nodejs', ''), f"`{rel_path}` runtime"))
                elif runtime:
                    findings.append(("context", f"`{rel_path}` runtime: `{runtime}`"))
        except Exception:
            pass

    elif filename.startswith('dockerfile') or filename.endswith('.dockerfile'):
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.upper().startswith('FROM '):
                image = stripped[5:].split()[0]
                node_match = re.match(r'^(?:[\w.\-/]+/)?node:([0-9.]+)', image, re.I)
                if node_match:
                    findings.append(check_node_version_string(node_match.group(1), f"`{rel_path}` FROM `{image}`"))
                else:
                    findings.append(("context", f"`{rel_path}` FROM `{image}` (rebuild if `libbrotli1` installed)"))

    elif '.github/workflows/' in path.replace('\\', '/') and filename.endswith(('.yml', '.yaml')):
        try:
            wf = yaml.safe_load(content)
            def extract(d):
                out = []
                if isinstance(d, dict):
                    for k, v in d.items():
                        if k == 'node-version':
                            out.extend(v if isinstance(v, list) else [v])
                        else:
                            out.extend(extract(v))
                elif isinstance(d, list):
                    for item in d:
                        out.extend(extract(item))
                return out
            for ver in extract(wf):
                findings.append(check_node_version_string(str(ver), f"Workflow `{rel_path}`"))
        except Exception:
            pass

    return findings

def check_local_reachability(repo_dir):
    inbound_terms = [
        "import brotli", "import brotlicffi", "from brotli", "from brotlicffi",
        "require('brotli')", 'require("brotli")',
        "Brotli.inflate", "BRS::String", "BRS::File",
        "brotli4j", "BrotliInputStream", "Decoder.decompress",
        "BrotliDecoder", "BrotliStream", "brotli.NewReader",
        "brotliDecompress", "brotliDecompressSync", "createBrotliDecompress",
        "brotli.decompress", "brotlicffi.decompress", "Decompressor(",
        "express.json", "bodyParser"
    ]
    outbound_terms = [
        "requests.get", "httpx.get", "urllib3",
        "fetch(", "axios.get", "axios.post", "DecompressionMethods.Brotli"
    ]

    inbound_hits = set()
    outbound_hits = set()

    for root, dirs, files in os.walk(repo_dir):
        # Skip .git, node_modules, venv to speed up scanning
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '.venv', 'dist', 'build')]
        
        for file in files:
            filepath = os.path.join(root, file)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for term in inbound_terms:
                        if term in content:
                            inbound_hits.add(f"Found `{term}` in code")
                            
                    for term in outbound_terms:
                        if term in content:
                            outbound_hits.add(f"Found `{term}` in code")
            except Exception:
                pass

    return list(inbound_hits), list(outbound_hits)

def audit_local_repo(repo_name, repo_dir):
    findings = []
    
    # Walk directory to find target files
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '.venv', 'dist', 'build')]
        for file in files:
            filepath = os.path.join(root, file)
            if is_target_file(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        findings.extend(analyze_file(repo_name, filepath, content))
                except Exception:
                    pass

    has_vulnerable_version = any(status == "vulnerable" for status, _ in findings)
    has_unpinned_exposure = any(status == "unpinned" for status, _ in findings)

    print(f"    -> Running Local Code Search on {repo_name}...")
    inbound_hits, outbound_hits = check_local_reachability(repo_dir)

    has_inbound = len(inbound_hits) > 0
    has_outbound = len(outbound_hits) > 0

    if has_inbound:
        tier = "CRITICAL"
    elif has_outbound:
        tier = "HIGH"
    elif has_vulnerable_version:
        tier = "HIGH"
    elif has_unpinned_exposure:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    return findings, inbound_hits, outbound_hits, tier

def generate_html_report(total_repos, audit_data, target, filename="brotli_local_triage.html"):
    tiers = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for d in audit_data.values():
        tiers[d['tier']] += 1

    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>CVE-2026-111497 Local Triage Report</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;background:#0b0f19;color:#e2e8f0;margin:0;padding:24px}}
.container{{max-width:1200px;margin:auto;background:#131c2e;padding:32px;border-radius:10px;border:1px solid #1e293b}}
h1{{color:#f8fafc;margin-top:0}} .summary{{display:flex;gap:16px;margin:24px 0}}
.card{{background:#0b0f19;padding:18px;border-radius:8px;flex:1;text-align:center;border:1px solid #1e293b}}
.card.crit{{border-left:4px solid #ef4444}} .card.crit h3{{color:#ef4444}}
.card.high{{border-left:4px solid #f97316}} .card.high h3{{color:#f97316}}
.card.med{{border-left:4px solid #0284c7}} .card.med h3{{color:#38bdf8}}
.filters{{display:flex;gap:10px;margin-bottom:20px}}
.filter-btn{{background:#1e293b;border:1px solid #334155;color:#cbd5e1;padding:8px 16px;border-radius:6px;cursor:pointer;font-weight:600}}
.filter-btn.active{{background:#2563eb;color:#fff;border-color:#2563eb}}
.badge{{padding:3px 8px;border-radius:4px;font-size:.75em;font-weight:700}}
.badge-CRITICAL{{background:#7f1d1d;color:#fecaca}}
.badge-HIGH{{background:#7c2d12;color:#fed7aa}}
.badge-MEDIUM{{background:#0c4a6e;color:#bae6fd}}
.badge-LOW{{background:#064e3b;color:#a7f3d0}}
.repo-box{{border:1px solid #1e293b;border-radius:8px;margin-bottom:16px;background:#0b0f19}}
.repo-header{{background:#182234;padding:12px 18px;display:flex;justify-content:space-between;align-items:center}}
.repo-body{{padding:16px}} .inbound{{border-left:4px solid #ef4444;padding:8px 14px;background:rgba(239,68,68,.08);margin-bottom:10px;border-radius:4px}}
.outbound{{border-left:4px solid #f97316;padding:8px 14px;background:rgba(249,115,22,.08);margin-bottom:10px;border-radius:4px}}
code{{background:#1e293b;color:#38bdf8;padding:1px 5px;border-radius:3px}}
.commands{{background:#0b0f19;border:1px solid #334155;padding:16px;border-radius:8px;margin:24px 0}}
.commands pre{{margin:0;font-size:.9em;line-height:1.6;overflow-x:auto}}
.caveats{{background:#0f172a;border:1px solid #334155;padding:16px 20px;border-radius:8px;margin-top:24px;color:#94a3b8;font-size:.88em;line-height:1.6}}
</style></head><body><div class="container">
<h1>CVE-2026-111497 Local Triage Report</h1>
<p style="color:#94a3b8">Scope: <strong>{target}</strong> | Local Filesystem Scan</p>

<div class="summary">
<div class="card"><h3>{total_repos}</h3><p>Local Repos Scanned</p></div>
<div class="card crit"><h3>{tiers['CRITICAL']}</h3><p>Critical (Inbound calls)</p></div>
<div class="card high"><h3>{tiers['HIGH']}</h3><p>High (Outbound calls / Vuln Pins)</p></div>
<div class="card med"><h3>{tiers['MEDIUM']}</h3><p>Medium (Unpinned / Floating)</p></div>
</div>

<div class="filters">
<button class="filter-btn active" onclick="filterRepos('ALL', this)">All Actionable ({tiers['CRITICAL']+tiers['HIGH']+tiers['MEDIUM']})</button>
<button class="filter-btn" onclick="filterRepos('CRITICAL', this)">Critical ({tiers['CRITICAL']})</button>
<button class="filter-btn" onclick="filterRepos('HIGH', this)">High ({tiers['HIGH']})</button>
<button class="filter-btn" onclick="filterRepos('MEDIUM', this)">Medium ({tiers['MEDIUM']})</button>
</div>
<div id="repo-container">
"""

    for repo, d in audit_data.items():
        if d['tier'] == 'LOW' and not d['findings']:
            continue
            
        html += f'<div class="repo-box" data-tier="{d["tier"]}"><div class="repo-header"><strong>{repo}</strong>'
        html += f'<span class="badge badge-{d["tier"]}">{d["tier"]}</span></div><div class="repo-body">'
        if d['inbound']:
            html += '<div class="inbound"><strong>Inbound decode signals:</strong><ul>'
            for h in d['inbound'][:5]: # Limit display to 5 to keep UI clean
                html += f'<li>{h}</li>'
            if len(d['inbound']) > 5:
                html += f'<li>...and {len(d["inbound"])-5} more</li>'
            html += '</ul></div>'
        if d['outbound']:
            html += '<div class="outbound"><strong>Outbound fetch signals:</strong><ul>'
            for h in d['outbound'][:5]:
                html += f'<li>{h}</li>'
            if len(d['outbound']) > 5:
                html += f'<li>...and {len(d["outbound"])-5} more</li>'
            html += '</ul></div>'
        html += '<ul>'
        for status, text in d['findings']:
            parts = text.split('`')
            fmt = ''.join(f'<code>{p}</code>' if i % 2 else p for i, p in enumerate(parts))
            html += f'<li>[{status.upper()}] {fmt}</li>'
        html += '</ul></div></div>'

    html += '''</div>
</div>
<script>
function filterRepos(tier, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.repo-box').forEach(box => {
        box.style.display = (tier === 'ALL' || box.getAttribute('data-tier') === tier) ? 'block' : 'none';
    });
}
</script></body></html>'''
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"\n[+] Report saved to: {filename}")

def main():
    if not os.path.exists(BASE_DIR):
        print(f"[!] Error: Local directory {BASE_DIR} does not exist.")
        return

    # Find all directories inside BASE_DIR (assuming each is a repo)
    repo_dirs = [d for d in os.listdir(BASE_DIR) if os.path.isdir(os.path.join(BASE_DIR, d))]
    
    print(f"[*] Found {len(repo_dirs)} local repositories in {BASE_DIR}.\n")

    audit_data = {}
    for i, repo_name in enumerate(repo_dirs):
        repo_path = os.path.join(BASE_DIR, repo_name)
        print(f"[{i+1}/{len(repo_dirs)}] Scanning {repo_name}...")
        
        findings, inbound, outbound, tier = audit_local_repo(repo_name, repo_path)
        
        if findings or inbound or outbound:
            audit_data[repo_name] = {
                "findings": findings,
                "inbound": inbound,
                "outbound": outbound,
                "tier": tier
            }

    generate_html_report(len(repo_dirs), audit_data, BASE_DIR)

if __name__ == "__main__":
    main()
