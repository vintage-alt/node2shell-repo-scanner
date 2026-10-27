import os
import requests
import base64
import yaml
import json

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_ORG = os.getenv("GITHUB_ORG") # Optional: Leave blank for personal account, or set to your organization name
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

# Vulnerability thresholds for Node2Shell (CVE-2026-111497)
# Versions below these are vulnerable: 22.23.4, 24.22.1, 26.12.1
SAFE_VERSIONS = {
    22: (23, 4),
    24: (22, 1),
    26: (12, 1)
}

def is_version_vulnerable(version_str):
    """Parses a version string and checks if it falls below the patch threshold."""
    clean_v = version_str.strip().lstrip('v').split('-')[0]
    parts = clean_v.split('.')
    try:
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        return True # Unknown format, flag for safety

    if major < 20:
        return True # Node 20 and older received no fix
    if major in SAFE_VERSIONS:
        s_minor, s_patch = SAFE_VERSIONS[major]
        if minor < s_minor:
            return True
        if minor == s_minor and patch < s_patch:
            return True
        return False
    return False

def get_file_content(repo_full_name, path):
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
    res = requests.get(url, headers=HEADERS)
    if res.status_code == 200:
        content_b64 = res.json().get("content", "")
        try:
            return base64.b64decode(content_b64).decode('utf-8')
        except Exception:
            return None
    return None

def extract_node_versions_from_workflow(data):
    versions = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k == 'node-version':
                if isinstance(v, list):
                    versions.extend(v)
                else:
                    versions.append(v)
            else:
                versions.extend(extract_node_versions_from_workflow(v))
    elif isinstance(data, list):
        for item in data:
            versions.extend(extract_node_versions_from_workflow(item))
    return versions

def scan_github_actions(repo):
    findings = []
    url = f"https://api.github.com/repos/{repo}/contents/.github/workflows"
    res = requests.get(url, headers=HEADERS)
    if res.status_code == 200:
        files = res.json()
        if isinstance(files, list):
            for file in files:
                if file['name'].endswith(('.yml', '.yaml')):
                    content = get_file_content(repo, file['path'])
                    if content:
                        try:
                            workflow = yaml.safe_load(content)
                            versions = extract_node_versions_from_workflow(workflow)
                            for v in versions:
                                v_str = str(v)
                                if is_version_vulnerable(v_str):
                                    findings.append(("vulnerable", f"Vulnerable node-version in GitHub Action `{file['name']}`: `{v_str}`"))
                                else:
                                    findings.append(("safe", f"Safe node-version in GitHub Action `{file['name']}`: `{v_str}`"))
                        except Exception:
                            pass
    return findings

def scan_repository(repo):
    findings = []
    
    # 1. Check .nvmrc or .node-version
    for vfile in ['.nvmrc', '.node-version']:
        content = get_file_content(repo, vfile)
        if content:
            ver = content.strip()
            if is_version_vulnerable(ver):
                findings.append(("vulnerable", f"Vulnerable version found in `{vfile}`: `{ver}`"))
            else:
                findings.append(("safe", f"Safe version in `{vfile}`: `{ver}`"))

    # 2. Check package.json engines
    pkg_content = get_file_content(repo, 'package.json')
    if pkg_content:
        try:
            pkg_data = json.loads(pkg_content)
            node_engine = pkg_data.get("engines", {}).get("node")
            if node_engine:
                findings.append(("info", f"Package engine constraint: `node: {node_engine}` (Verify manually)"))
        except:
            pass

    # 3. Check Dockerfiles
    dockerfile = get_file_content(repo, 'Dockerfile')
    if dockerfile:
        for line in dockerfile.splitlines():
            if line.strip().upper().startswith('FROM NODE'):
                findings.append(("info", f"Dockerfile base image: `{line.strip()}`"))

    # 4. Check GitHub Actions Workflows
    findings.extend(scan_github_actions(repo))

    return findings

def main():
    repos = []
    page = 1
    
    if GITHUB_ORG:
        print(f"Fetching repositories for organization: {GITHUB_ORG}...")
        base_url = f"https://api.github.com/orgs/{GITHUB_ORG}/repos"
    else:
        print("Fetching repositories for authenticated user...")
        base_url = "https://api.github.com/user/repos"

    while True:
        url = f"{base_url}?per_page=100&page={page}&type=all"
        res = requests.get(url, headers=HEADERS)
        if res.status_code != 200:
            print(f"Failed to fetch repositories: {res.status_code} - {res.text}")
            break
        data = res.json()
        if not data or not isinstance(data, list):
            break
        
        repos.extend([r['full_name'] for r in data])
        print(f"Fetched page {page} ({len(data)} repositories)...")
        
        if len(data) < 100:
            break
        page += 1

    print(f"\nTotal repositories loaded: {len(repos)}. Starting vulnerability scan...\n")
    
    repo_results = {}
    vulnerable_repo_count = 0
    for repo in repos:
        findings = scan_repository(repo)
        if findings:
            has_vuln = any(status == "vulnerable" for status, _ in findings)
            if has_vuln:
                vulnerable_repo_count += 1
            repo_results[repo] = (has_vuln, findings)

    target_name = GITHUB_ORG if GITHUB_ORG else "Personal User Account"
    
    # Build HTML Report with filtering controls
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Node2Shell (CVE-2026-111497) Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 900px; margin: auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
        h1 {{ color: #1f2937; border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; margin-top: 0; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ background: #f8fafc; border: 1px solid #e2e8f0; padding: 15px 20px; border-radius: 6px; flex: 1; text-align: center; }}
        .card h3 {{ margin: 0; font-size: 1.5em; color: #0f172a; }}
        .card p {{ margin: 5px 0 0; color: #64748b; font-size: 0.9em; }}
        .filters {{ margin: 20px 0; display: flex; gap: 10px; }}
        .filter-btn {{ background: #e2e8f0; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; color: #475569; transition: background 0.2s; }}
        .filter-btn.active {{ background: #2563eb; color: #fff; }}
        .repo-box {{ margin-bottom: 20px; border: 1px solid #e5e7eb; border-radius: 6px; overflow: hidden; }}
        .repo-header {{ background: #f1f5f9; padding: 12px 15px; font-weight: bold; font-size: 1.05em; border-bottom: 1px solid #e5e7eb; color: #334155; }}
        .repo-body {{ padding: 15px; background: #fff; }}
        ul {{ margin: 0; padding-left: 20px; }}
        li {{ margin-bottom: 8px; font-size: 0.95em; }}
        .badge-vulnerable {{ background: #fee2e2; color: #991b1b; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .badge-safe {{ background: #d1fae5; color: #065f46; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .badge-info {{ background: #e0f2fe; color: #0369a1; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        code {{ background: #f1f5f9; padding: 2px 4px; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Node2Shell (CVE-2026-111497) Audit Report</h1>
        <p>Target Scope: <strong>{target_name}</strong> | Automated vulnerability scan results across repositories for runtime Node.js exposure.</p>
        
        <div class="summary">
            <div class="card">
                <h3>{len(repos)}</h3>
                <p>Repositories Scanned</p>
            </div>
            <div class="card">
                <h3>{len(repo_results)}</h3>
                <p>Repositories with Configs</p>
            </div>
            <div class="card" style="border-left: 4px solid #dc2626;">
                <h3 style="color: #dc2626;">{vulnerable_repo_count}</h3>
                <p>Vulnerable Repositories</p>
            </div>
        </div>

        <div class="filters">
            <button class="filter-btn active" onclick="filterReport('all', this)">All Repositories ({len(repo_results)})</button>
            <button class="filter-btn" onclick="filterReport('vulnerable', this)">Vulnerable Only ({vulnerable_repo_count})</button>
        </div>
        
        <div id="repo-list-container">
"""

    if repo_results:
        for repo, (has_vuln, findings) in repo_results.items():
            vuln_attr = "true" if has_vuln else "false"
            html_content += f"""
        <div class="repo-box" data-vulnerable="{vuln_attr}">
            <div class="repo-header">Repo: {repo}</div>
            <div class="repo-body">
                <ul>
"""
            for status, text in findings:
                badge = f'<span class="badge-{status}">{status.upper()}</span>'
                parts = text.split('`')
                formatted_li = ""
                for i, part in enumerate(parts):
                    if i % 2 == 1:
                        formatted_li += f"<code>{part}</code>"
                    else:
                        formatted_li += part
                
                html_content += f"                    <li>{badge} {formatted_li}</li>\n"
            html_content += """                </ul>
            </div>
        </div>
"""
    else:
        html_content += "<p>No matching configuration files or workflows were found across the scanned repositories.</p>"

    html_content += """
        </div>
    </div>

    <script>
        function filterReport(type, btn) {
            // Update active button state
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Toggle repository visibility
            const boxes = document.querySelectorAll('.repo-box');
            boxes.forEach(box => {
                if (type === 'all') {
                    box.style.display = 'block';
                } else if (type === 'vulnerable') {
                    if (box.getAttribute('data-vulnerable') === 'true') {
                        box.style.display = 'block';
                    } else {
                        box.style.display = 'none';
                    }
                }
            });
        }
    </script>
</body>
</html>
"""

    with open("node2shell_report.html", "w") as f:
        f.write(html_content)
    print("Audit complete! HTML report with filter options saved to node2shell_report.html")

if __name__ == "__main__":
    main()
