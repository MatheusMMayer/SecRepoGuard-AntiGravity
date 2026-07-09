import json
import os
from typing import List, Dict, Any

def build_summary(
    secrets: List[Dict[str, Any]],
    local_risks: List[Dict[str, Any]],
    online_risks: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Builds a summary dictionary of all findings.
    """
    return {
        "total_secrets_found": len(secrets),
        "total_local_risks_found": len(local_risks),
        "total_osv_vulnerabilities_found": len(online_risks),
        "total_issues": len(secrets) + len(local_risks) + len(online_risks)
    }

def format_text_report(
    target_name: str,
    secrets: List[Dict[str, Any]],
    local_risks: List[Dict[str, Any]],
    online_risks: List[Dict[str, Any]]
) -> str:
    """
    Formats the analysis findings into a structured plain text report.
    """
    summary = build_summary(secrets, local_risks, online_risks)
    
    report = []
    report.append("================================================================================")
    report.append("                    SECREPOGUARD - RELATÓRIO DE SEGURANÇA                       ")
    report.append("================================================================================")
    report.append(f"Alvo Analisado: {target_name}")
    report.append(f"Total de Segredos Expostos Encontrados: {summary['total_secrets_found']}")
    report.append(f"Total de Riscos em Dependências (Local): {summary['total_local_risks_found']}")
    report.append(f"Total de Vulnerabilidades em Dependências (OSV.dev): {summary['total_osv_vulnerabilities_found']}")
    report.append(f"Total de Alertas Gerados: {summary['total_issues']}")
    report.append("================================================================================\n")

    # 1. Secrets Section
    report.append("1. SEGREDOS E CREDENCIAIS EXPOSTAS")
    report.append("--------------------------------------------------------------------------------")
    if not secrets:
        report.append("Nenhum segredo ou credencial em formato de texto plano foi detectado.")
    else:
        for idx, sec in enumerate(secrets, 1):
            rel_path = os.path.basename(sec["filepath"])
            report.append(f"[{idx}] Regra: {sec['rule']}")
            report.append(f"    Arquivo: {sec['filepath']} (Linha {sec['line']})")
            report.append(f"    Valor Mascarado: {sec['masked_value']}")
            report.append("")
    report.append("--------------------------------------------------------------------------------\n")

    # 2. Local Dependency Risks Section
    report.append("2. RISCOS DE DEPENDÊNCIAS (VERIFICAÇÃO LOCAL)")
    report.append("--------------------------------------------------------------------------------")
    if not local_risks:
        report.append("Nenhum risco de dependência conhecido foi detectado localmente.")
    else:
        for idx, risk in enumerate(local_risks, 1):
            report.append(f"[{idx}] Pacote: {risk['package']} ({risk['ecosystem']})")
            report.append(f"    Versão Declarada: {risk['version']}")
            report.append(f"    Severidade: {risk['severity']}")
            report.append(f"    Arquivo: {risk['filepath']} (Linha {risk['line']})")
            report.append(f"    Descrição: {risk['description']}")
            report.append("")
    report.append("--------------------------------------------------------------------------------\n")

    # 3. Online Vulnerability Risks Section (OSV.dev)
    report.append("3. VULNERABILIDADES DE DEPENDÊNCIAS (CONSULTA OSV.DEV)")
    report.append("--------------------------------------------------------------------------------")
    if not online_risks:
        report.append("Nenhuma vulnerabilidade adicional foi identificada no OSV.dev.")
    else:
        for idx, vuln in enumerate(online_risks, 1):
            report.append(f"[{idx}] Pacote: {vuln['package']} ({vuln['ecosystem']}) - ID: {vuln['vuln_id']}")
            report.append(f"    Versão Declarada: {vuln['version']}")
            report.append(f"    Arquivo: {vuln['filepath']} (Linha {vuln['line']})")
            report.append(f"    Vulnerabilidade: {vuln['description']}")
            report.append("")
    report.append("--------------------------------------------------------------------------------\n")

    # Warning Footer
    report.append("================================================================================")
    report.append("AVISO IMPORTANTE:")
    report.append("Os achados listados neste relatório são potenciais e baseados em análise estática.")
    report.append("Recomenda-se triagem e validação humana para eliminação de falsos positivos antes")
    report.append("de qualquer ação corretiva.")
    report.append("================================================================================")
    
    return "\n".join(report)

def format_json_report(
    target_name: str,
    secrets: List[Dict[str, Any]],
    local_risks: List[Dict[str, Any]],
    online_risks: List[Dict[str, Any]]
) -> str:
    """
    Formats the analysis findings into a structured JSON string.
    """
    summary = build_summary(secrets, local_risks, online_risks)
    report_dict = {
        "target": target_name,
        "summary": summary,
        "secrets_findings": secrets,
        "local_dependency_findings": local_risks,
        "osv_vulnerability_findings": online_risks,
        "disclaimer": "Os achados deste relatório são potenciais e requerem validação humana."
    }
    return json.dumps(report_dict, indent=4, ensure_ascii=False)

def save_report_to_file(filepath: str, content: str) -> None:
    """
    Helper function to save report content to a file.
    Creates parent directories if necessary.
    """
    dir_name = os.path.dirname(filepath)
    if dir_name:
        os.makedirs(dir_name, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
