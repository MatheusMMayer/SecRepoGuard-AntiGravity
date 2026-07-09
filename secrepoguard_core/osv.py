import json
import urllib.request
import urllib.error
import re
from typing import List, Dict, Any

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

def clean_version_for_query(version_str: str) -> str:
    """
    Cleans prefixes (e.g., ^, ~, >=) from version strings for OSV.dev querying.
    """
    if not version_str:
        return ""
    # Strip spaces first so regex anchor works properly
    clean = version_str.strip()
    # Remove symbols like ^, ~, >=, <=, etc.
    clean = re.sub(r'^[~^>=<]+', '', clean).strip()
    # Remove any extra range details or spaces
    clean = re.split(r'[\s,;]', clean)[0]
    return clean

def query_osv_package(name: str, version: str, ecosystem: str) -> List[Dict[str, Any]]:
    """
    Queries OSV.dev API for vulnerabilities related to a single dependency version.
    Only sends package name, version, and ecosystem.
    """
    cleaned_version = clean_version_for_query(version)
    if not name or not cleaned_version:
        return []
        
    payload = {
        "version": cleaned_version,
        "package": {
            "name": name,
            "ecosystem": ecosystem
        }
    }
    
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            OSV_QUERY_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            res_body = response.read().decode("utf-8")
            res_json = json.loads(res_body)
            
            vulns = res_json.get("vulns", [])
            results = []
            for vuln in vulns:
                vuln_id = vuln.get("id", "Unknown ID")
                summary = vuln.get("summary", "Sem descrição disponível.")
                aliases = vuln.get("aliases", [])
                aliases_str = f" ({', '.join(aliases)})" if aliases else ""
                
                results.append({
                    "vuln_id": vuln_id,
                    "summary": f"{summary}{aliases_str}",
                    "details": vuln.get("details", "")
                })
            return results
            
    except urllib.error.HTTPError as e:
        # 404 or other errors mean no vuln found, or invalid package ecosystem combo
        return []
    except urllib.error.URLError:
        # OSV.dev might be unreachable, handle gracefully
        # Return a warning indicator or log silently
        return [{"vuln_id": "CONNECTION_ERROR", "summary": "Não foi possível conectar ao OSV.dev para buscar vulnerabilidades."}]
    except Exception:
        # Fallback for unexpected errors
        return []

def query_dependencies_vulnerabilities(dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Queries OSV.dev API for all dependencies in the list.
    """
    vulnerability_findings = []
    
    # Track connection errors to avoid printing them multiple times
    connection_failed = False
    
    for dep in dependencies:
        if connection_failed:
            continue
            
        vulns = query_osv_package(dep["name"], dep["version"], dep["ecosystem"])
        
        for vuln in vulns:
            if vuln["vuln_id"] == "CONNECTION_ERROR":
                connection_failed = True
                vulnerability_findings.append({
                    "filepath": dep["filepath"],
                    "line": dep["line"],
                    "package": dep["name"],
                    "version": dep["version"],
                    "ecosystem": dep["ecosystem"],
                    "vuln_id": "AVISO",
                    "description": "Erro de conexão ao OSV.dev. A verificação online foi interrompida."
                })
                break
                
            vulnerability_findings.append({
                "filepath": dep["filepath"],
                "line": dep["line"],
                "package": dep["name"],
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "vuln_id": vuln["vuln_id"],
                "description": vuln["summary"]
            })
            
    return vulnerability_findings
