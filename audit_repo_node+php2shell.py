import os
import re
import sys
import html
from pathlib import Path
from datetime import datetime

# Directories to skip for fast scanning on Windows
SKIP_DIRS = {
    '.git', 'node_modules', 'vendor', 'venv', '.venv', 'env',
    '__pycache__', 'dist', 'build', '.next', '.nuxt', 'coverage', '.idea', '.vscode'
}

TARGET_FILES = {
    'dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml',
    '.nvmrc', '.node-version', '.php-version', '.tool-versions', 'mise.toml',
    'package.json', 'composer.json', 'serverless.yml', 'serverless.yaml',
    'vercel.json', 'netlify.toml', 'wrangler.toml', 'fly.toml', 'app.yaml',
    'project.toml', 'procfile', 'jenkinsfile', '.gitlab-ci.yml', 'bitbucket-pipelines.yml'
}

def is_node_vulnerable(ver_str):
    """Checks if a Node.js version string falls into vulnerable Node2Shell ranges."""
    clean = re.sub(r'^[^\d]*', '', ver_str.strip())
    match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?', clean)
    if not match:
        return False, False, None
    
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else 0
    patch = int(match.group(3)) if match.group(3) is not None else 0

    # Floating version tag (e.g. "node:22", "22.x")
    if match.group(2) is None or 'x' in ver_str.lower() or '*' in ver_str:
        if major <= 20:
            return True, False, f"Node {major}.x is EOL & vulnerable (CVE-2026-111497)"
        if major in (22, 24, 26):
            return True, True, f"Floating tag '{ver_str}' does not enforce patched build (22.23.4 / 24.22.1 / 26.12.1)"
        return False, False, None

    v = (major, minor, patch)
    if major <= 20:
        return True, False, f"Node {major}.{minor}.{patch} is EOL & vulnerable (CVE-2026-111497)"
    if major == 22 and v < (22, 23, 4):
        return True, False, f"Node {major}.{minor}.{patch} < 22.23.4 (Vulnerable to Node2Shell)"
    if major == 24 and v < (24, 22, 1):
        return True, False, f"Node {major}.{minor}.{patch} < 24.22.1 (Vulnerable to Node2Shell)"
    if major == 26 and v < (26, 12, 1):
        return True, False, f"Node {major}.{minor}.{patch} < 26.12.1 (Vulnerable to Node2Shell)"
    if major in (21, 23, 25):
        return True, False, f"Node {major}.{minor}.{patch} is an unmaintained odd release"

    return False, False, None

def is_php_vulnerable(ver_str):
    """Checks if a PHP version string falls into vulnerable PHP2Shell ranges."""
    clean = re.sub(r'^[^\d]*', '', ver_str.strip())
    match = re.match(r'^(\d+)(?:\.(\d+))?(?:\.(\d+))?', clean)
    if not match:
        return False, False, None
    
    major = int(match.group(1))
    minor = int(match.group(2)) if match.group(2) is not None else 0
    patch = int(match.group(3)) if match.group(3) is not None else 0

    if match.group(3) is None or 'x' in ver_str.lower() or '*' in ver_str:
        if major < 8 or (major == 8 and minor <= 1):
            return True, False, f"PHP {major}.{minor} is EOL & vulnerable (CVE-2026-109618/109619)"
        if major == 8 and minor in (2, 3, 4, 5):
            return True, True, f"Floating tag '{ver_str}' risks cached unpatched layer (needs 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)"
        return False, False, None

    v = (major, minor, patch)
    if major < 8 or (major == 8 and minor <= 1):
        return True, False, f"PHP {major}.{minor}.{patch} is EOL & vulnerable (PHP2Shell)"
    if major == 8 and minor == 2 and v < (8, 2, 35):
        return True, False, f"PHP {major}.{minor}.{patch} < 8.2.35 (Vulnerable to PHP2Shell)"
    if major == 8 and minor == 3 and v < (8, 3, 36):
        return True, False, f"PHP {major}.{minor}.{patch} < 8.3.36 (Vulnerable to PHP2Shell)"
    if major == 8 and minor == 4 and v < (8, 4, 27):
        return True, False, f"PHP {major}.{minor}.{patch} < 8.4.27 (Vulnerable to PHP2Shell)"
    if major == 8 and minor == 5 and v < (8, 5, 12):
        return True, False, f"PHP {major}.{minor}.{patch} < 8.5.12 (Vulnerable to PHP2Shell)"

    return False, False, None

def classify_context(file_path: Path, lines: list, line_idx: int, is_floating: bool):
    """Determines Priority (P0-P3) and adds a human-readable build-time vs runtime quote."""
    name_lower = file_path.name.lower()
    parts_lower = [p.lower() for p in file_path.parts]

    # 1. Dockerfile (Check if single-stage vs multi-stage builder)
    if name_lower == 'dockerfile' or name_lower.startswith('dockerfile') or name_lower.endswith('.dockerfile'):
        from_indices = [i for i, l in enumerate(lines, 1) if re.match(r'^\s*FROM\s+', l, re.I)]
        last_from_idx = from_indices[-1] if from_indices else line_idx

        if line_idx < last_from_idx:
            final_from_line = lines[last_from_idx - 1].strip()
            return (
                "P2 - Build-Time Only",
                f"Used in build-time stage only (Multi-stage Dockerfile; final production stage is '{final_from_line}'). Does not ship vulnerable runtime to production, only exposes CI build runner."
            )
        else:
            if is_floating:
                return (
                    "P1 - High (Floating Prod Tag)",
                    "Used to build production runtime container, but uses a floating tag. Creates a vulnerable runtime upfront unless rebuilt with '--pull --no-cache'."
                )
            return (
                "P0 - Critical (Prod Runtime)",
                "Directly builds vulnerable production container runtime upfront (Final Dockerfile stage). Live instance will run this exact unpatched binary."
            )

    # 2. Container Orchestration & Serverless/PaaS Deployment Manifests
    if name_lower in ('docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml',
                      'serverless.yml', 'serverless.yaml', 'vercel.json', 'netlify.toml',
                      'wrangler.toml', 'fly.toml', 'app.yaml', 'project.toml', 'procfile') or name_lower.endswith(('.tf', '.tfvars')):
        if is_floating:
            return (
                "P1 - High (Floating Deploy Config)",
                "Used to provision live runtime/serverless environment with a floating version. Verify active deployment pulls patched binary."
            )
        return (
            "P0 - Critical (Prod Runtime)",
            "Directly provisions or deploys a vulnerable live runtime instance upfront in cloud/container orchestration."
        )

    # 3. CI/CD Workflows (GitHub Actions, GitLab CI, Jenkins, Bitbucket)
    if ('.github' in parts_lower and 'workflows' in parts_lower) or name_lower in ('jenkinsfile', '.gitlab-ci.yml', 'bitbucket-pipelines.yml'):
        return (
            "P2 - Build-Time / CI Runner",
            "File used at build/test time in CI/CD pipeline. Spins up vulnerable runtime in ephemeral build runner (risk of outbound Brotli exploit during build), not live production server."
        )

    # 4. Version Manager Pins (.nvmrc, .node-version, .php-version, .tool-versions, mise.toml)
    if name_lower in ('.nvmrc', '.node-version', '.php-version', '.tool-versions', 'mise.toml'):
        return (
            "P1 - High (PaaS / Local Pin)",
            "Version manager lockfile. Builds vulnerable production runtime upfront IF deployed via PaaS/Buildpacks (Vercel, Render, Heroku); ignored if deployed via Dockerfile."
        )

    # 5. Package Manifests (package.json, composer.json)
    if name_lower in ('package.json', 'composer.json'):
        return (
            "P3 - Low (Advisory / Package Config)",
            "Advisory engine/platform constraint used during package install. Does NOT install or change the production runtime binary on Docker/VMs (only read by PaaS auto-buildpacks)."
        )

    return ("P2 - Medium", "Configuration references vulnerable runtime version; verify if consumed by production deployment or build-time only.")

PATTERNS = [
    (re.compile(r'(?:FROM|image:)\s+[\'"]?(?:[\w.\-]+/)?node:([0-9]+(?:\.[0-9]+){0,2}[a-zA-Z0-9.\-_]*)', re.I), 'Node.js'),
    (re.compile(r'(?:FROM|image:)\s+[\'"]?(?:[\w.\-]+/)?php:([0-9]+(?:\.[0-9]+){0,2}[a-zA-Z0-9.\-_]*)', re.I), 'PHP'),
    (re.compile(r'(?:node-version|NODE_VERSION|nodejs)\s*[:=]\s*[\'"]?([vV]?[0-9]+(?:\.[0-9xX*]+){0,2})', re.I), 'Node.js'),
    (re.compile(r'(?:php-version|PHP_VERSION)\s*[:=]\s*[\'"]?([0-9]+(?:\.[0-9xX*]+){0,2})', re.I), 'PHP'),
    (re.compile(r'"node"\s*:\s*"([^"]+)"', re.I), 'Node.js'),
    (re.compile(r'"php"\s*:\s*"([^"]+)"', re.I), 'PHP'),
    (re.compile(r'^(?:nodejs|node)\s+([0-9]+(?:\.[0-9]+){0,2})', re.I), 'Node.js'),
    (re.compile(r'^php\s+([0-9]+(?:\.[0-9]+){0,2})', re.I), 'PHP'),
]

def should_scan_file(file_path: Path) -> bool:
    name_lower = file_path.name.lower()
    if name_lower in TARGET_FILES or name_lower.startswith('dockerfile') or name_lower.endswith('.dockerfile'):
        return True
    parts = [p.lower() for p in file_path.parts]
    if '.github' in parts and 'workflows' in parts and name_lower.endswith(('.yml', '.yaml')):
        return True
    if name_lower.endswith(('.tf', '.tfvars')):
        return True
    return False

def scan_file(file_path: Path, repo_name: str, rel_path: str):
    findings = []
    name_lower = file_path.name.lower()
    try:
        lines = file_path.read_text(encoding='utf-8', errors='ignore').splitlines()
    except Exception:
        return findings

    for idx, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith('#') or line.startswith('//'):
            continue

        if name_lower in ('.nvmrc', '.node-version') and idx == 1:
            vuln, is_float, reason = is_node_vulnerable(line)
            if vuln:
                prio, ctx_quote = classify_context(file_path, lines, idx, is_float)
                findings.append((prio, repo_name, rel_path, idx, 'Node.js', line, reason, ctx_quote, line))
            continue

        if name_lower == '.php-version' and idx == 1:
            vuln, is_float, reason = is_php_vulnerable(line)
            if vuln:
                prio, ctx_quote = classify_context(file_path, lines, idx, is_float)
                findings.append((prio, repo_name, rel_path, idx, 'PHP', line, reason, ctx_quote, line))
            continue

        for regex, runtime in PATTERNS:
            m = regex.search(line)
            if m:
                ver_extracted = m.group(1)
                if runtime == 'Node.js':
                    vuln, is_float, reason = is_node_vulnerable(ver_extracted)
                else:
                    vuln, is_float, reason = is_php_vulnerable(ver_extracted)

                if vuln:
                    prio, ctx_quote = classify_context(file_path, lines, idx, is_float)
                    findings.append((prio, repo_name, rel_path, idx, runtime, ver_extracted, reason, ctx_quote, line))
                    break
    return findings

def generate_html_report(findings, output_file, root_dir):
    # Sort findings so P0 Critical shows up at the very top
    findings.sort(key=lambda x: x[0])

    prio_styles = {
        "P0": "#dc2626",  # Red - Critical Prod Runtime
        "P1": "#ea580c",  # Orange - Floating / PaaS Lock
        "P2": "#ca8a04",  # Amber - Build-Time Only / CI Runner
        "P3": "#475569",  # Slate - Advisory Only
    }

    rows_html = ""
    for prio, repo, fpath, lineno, runtime, ver, reason, ctx_quote, snippet in findings:
        p_key = prio[:2]
        p_color = prio_styles.get(p_key, "#475569")
        rows_html += f"""
        <tr>
            <td><span class="prio-badge" style="background:{p_color}">{html.escape(prio)}</span></td>
            <td><strong>{html.escape(repo)}</strong></td>
            <td><code>{html.escape(fpath)}</code></td>
            <td style="text-align:center;"><span class="line-badge">L{lineno}</span></td>
            <td><strong>{html.escape(runtime)}</strong> (<code>{html.escape(ver)}</code>)<br><small style="color:#fca5a5;">{html.escape(reason)}</small></td>
            <td class="quote-cell">"{html.escape(ctx_quote)}"</td>
            <td><pre>{html.escape(snippet)}</pre></td>
        </tr>"""

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Vulnerable Runtime Audit Report</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; margin: 2rem; }}
    h1 {{ color: #f8fafc; margin-bottom: 0.2rem; }}
    .meta {{ color: #94a3b8; margin-bottom: 1.5rem; font-size: 0.9rem; }}
    table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid #334155; font-size: 0.88rem; vertical-align: top; }}
    th {{ background: #334155; color: #f1f5f9; text-transform: uppercase; font-size: 0.76rem; letter-spacing: 0.05em; }}
    tr:hover {{ background: #263349; }}
    code {{ color: #38bdf8; font-family: Consolas, monospace; }}
    pre {{ margin: 0; font-family: Consolas, monospace; font-size: 0.8rem; color: #cbd5e1; background: #0f172a; padding: 6px 8px; border-radius: 4px; max-width: 340px; overflow-x: auto; }}
    .line-badge {{ background: #475569; color: #fff; padding: 2px 8px; border-radius: 4px; font-family: monospace; }}
    .prio-badge {{ color: #fff; padding: 4px 8px; border-radius: 4px; font-weight: 700; font-size: 0.76rem; display: inline-block; white-space: nowrap; }}
    .quote-cell {{ color: #fde047; font-style: italic; max-width: 340px; line-height: 1.4; }}
</style>
</head>
<body>
    <h1>Vulnerable Runtime Audit (Node2Shell & PHP2Shell)</h1>
    <div class="meta">Scanned Root: <code>{html.escape(str(root_dir))}</code> | Total Findings: <strong>{len(findings)}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
    <table>
        <thead>
            <tr>
                <th>Priority</th>
                <th>Repo Name</th>
                <th>File Path</th>
                <th>Line No</th>
                <th>Vulnerable Version</th>
                <th>Execution Context (Build-Time vs. Prod Runtime)</th>
                <th>Config Line</th>
            </tr>
        </thead>
        <tbody>
            {rows_html if rows_html else '<tr><td colspan="7" style="text-align:center;color:#4ade80;">No vulnerable runtime versions found!</td></tr>'}
        </tbody>
    </table>
</body>
</html>"""
    Path(output_file).write_text(html_content, encoding='utf-8')

def main():
    if len(sys.argv) > 1:
        root_input = sys.argv[1]
    else:
        root_input = input("Enter Windows root folder path containing your repos (e.g. C:\\Projects): ").strip('" ')

    root_path = Path(root_input).resolve()
    if not root_path.exists():
        print(f"[!] Error: Path '{root_path}' does not exist.")
        sys.exit(1)

    all_findings = []
    sub_dirs = [d for d in root_path.iterdir() if d.is_dir() and d.name not in SKIP_DIRS]
    repos = sub_dirs if sub_dirs else [root_path]

    print(f"\nScanning {len(repos)} repositories in '{root_path}'...\n")
    print(f"{'REPO NAME':<24} | {'FILE PATH':<36} | {'LINE':<5} | {'CONTEXT NOTE'}")
    print("-" * 115)

    for repo_dir in repos:
        repo_name = repo_dir.name
        for dirpath, dirnames, filenames in os.walk(repo_dir):
            dirnames[:] = [d for d in dirnames if d.lower() not in SKIP_DIRS]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if should_scan_file(fpath):
                    rel_path = str(fpath.relative_to(repo_dir))
                    results = scan_file(fpath, repo_name, rel_path)
                    for r in results:
                        all_findings.append(r)
                        # r = (prio, repo_name, rel_path, idx, runtime, ver_extracted, reason, ctx_quote, line)
                        short_note = f"[{r[0]}] {r[7][:48]}..."
                        print(f"{r[1]:<24} | {r[2]:<36} | {r[3]:<5} | {short_note}")

    report_path = Path.cwd() / "vuln_runtime_report.html"
    generate_html_report(all_findings, report_path, root_path)
    print("-" * 115)
    print(f"[+] Total vulnerable instances found: {len(all_findings)}")
    print(f"[+] HTML Report saved to: {report_path}")

if __name__ == "__main__":
    main()
