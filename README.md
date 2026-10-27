# node2shell-repo-scanner
uses github api to scan authorized code base for vulnerable version of node+brotli in use

```
pip install requests pyyaml
export GITHUB_TOKEN="your_personal_access_token"
export GITHUB_ORG="your-organization-name"
python audit_node2shell.py
```
