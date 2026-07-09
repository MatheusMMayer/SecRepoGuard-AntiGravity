import json
import re
from typing import List, Dict, Any

# Local database of known risky packages (mock rules for academic demo/basic static checks)
LOCAL_RISK_DATABASE = {
    "pypi": {
        "requests": {
            "max_safe_version": "2.25.0",
            "reason": "Vulnerabilidades conhecidas de vazamento de credenciais (CVE-2018-18074) e SSRF em versões anteriores a 2.25.0.",
        },
        "urllib3": {
            "max_safe_version": "1.26.5",
            "reason": "Vulnerabilidade de bypass de SSL/TLS (CVE-2021-33503) em versões anteriores a 1.26.5.",
        },
        "django": {
            "max_safe_version": "3.2.19",
            "reason": "Múltiplas vulnerabilidades críticas incluindo XSS e injeção de SQL em versões anteriores a 3.2.19.",
        },
        "flask": {
            "max_safe_version": "2.2.5",
            "reason": "Problemas de negação de serviço e segurança de sessão em versões anteriores a 2.2.5.",
        }
    },
    "npm": {
        "lodash": {
            "max_safe_version": "4.17.21",
            "reason": "Vulnerabilidade crítica de Prototype Pollution (CVE-2020-8203) em versões anteriores a 4.17.21.",
        },
        "express": {
            "max_safe_version": "4.16.0",
            "reason": "Vulnerabilidade de Open Redirect e problemas de segurança de roteamento em versões anteriores a 4.16.0.",
        },
        "minimist": {
            "max_safe_version": "1.2.6",
            "reason": "Prototype Pollution em versões anteriores a 1.2.6 (CVE-2021-44906).",
        }
    }
}

def parse_version_tuple(version_str: str) -> tuple:
    """
    Parses a version string (e.g., '^1.2.3-beta', '>=2.20.0') into a tuple of integers (major, minor, patch).
    Non-numeric suffix parts are stripped.
    """
    if not version_str:
        return (0, 0, 0)
    # Remove common prefix symbols like ^, ~, >=, <=
    clean_version = re.sub(r'^[~^>=<]+', '', version_str).strip()
    parts = []
    # Split by dot
    for part in clean_version.split('.'):
        match = re.match(r'^(\d+)', part)
        if match:
            parts.append(int(match.group(1)))
        else:
            parts.append(0)
    # Pad to 3 elements
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

def parse_requirements_txt(content: str, filepath: str) -> List[Dict[str, Any]]:
    """
    Parses a requirements.txt file content.
    Returns a list of dictionaries with name, version, ecosystem, and filepath.
    """
    dependencies = []
    lines = content.splitlines()
    for idx, line in enumerate(lines, 1):
        line = line.strip()
        # Ignore comments and empty lines
        if not line or line.startswith('#') or line.startswith('-r'):
            continue
        
        # Split on separators: ==, >=, <=, >, <, ~=
        # Match name and version
        match = re.match(r'^([a-zA-Z0-9_\-\[\]]+)\s*([~=><]+)\s*([a-zA-Z0-9_\-\.\+]+)', line)
        if match:
            name = match.group(1).strip()
            version = match.group(3).strip()
        else:
            # Maybe just dependency name without specified version
            name = re.split(r'[\s;]', line)[0].strip()
            version = ""
            
        if name:
            dependencies.append({
                "name": name,
                "version": version,
                "ecosystem": "PyPI",
                "filepath": filepath,
                "line": idx
            })
    return dependencies

def parse_package_json(content: str, filepath: str) -> List[Dict[str, Any]]:
    """
    Parses a package.json file content.
    Returns a list of dictionaries with name, version, ecosystem, and filepath.
    """
    dependencies = []
    try:
        data = json.loads(content)
        # Parse both dependencies and devDependencies
        for dep_type in ("dependencies", "devDependencies"):
            deps = data.get(dep_type, {})
            if isinstance(deps, dict):
                for name, version in deps.items():
                    dependencies.append({
                        "name": name,
                        "version": str(version),
                        "ecosystem": "npm",
                        "filepath": filepath,
                        "line": 0 # JSON-wide metadata
                    })
    except Exception:
        # Ignore JSON parse issues; they will be captured/logged as empty findings or handled
        pass
    return dependencies

def check_local_dependency_risks(dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Checks list of dependencies against local risk database.
    Returns findings.
    """
    findings = []
    for dep in dependencies:
        eco = dep["ecosystem"].lower()
        name = dep["name"].lower()
        version = dep["version"]
        
        db = LOCAL_RISK_DATABASE.get(eco, {})
        if name in db:
            risk_info = db[name]
            max_safe = risk_info["max_safe_version"]
            
            # If version is empty, we flag it as high risk since we can't verify it
            if not version:
                findings.append({
                    "filepath": dep["filepath"],
                    "line": dep["line"],
                    "package": dep["name"],
                    "version": "indefinida",
                    "ecosystem": dep["ecosystem"],
                    "severity": "Médio",
                    "description": f"Dependência sem versão fixada. {risk_info['reason']}"
                })
                continue
                
            v_tuple = parse_version_tuple(version)
            safe_tuple = parse_version_tuple(max_safe)
            
            if v_tuple < safe_tuple:
                findings.append({
                    "filepath": dep["filepath"],
                    "line": dep["line"],
                    "package": dep["name"],
                    "version": version,
                    "ecosystem": dep["ecosystem"],
                    "severity": "Alto",
                    "description": f"Versão instalada ({version}) é inferior à recomendada ({max_safe}). {risk_info['reason']}"
                })
    return findings
