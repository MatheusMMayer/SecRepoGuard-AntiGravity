import json
import pytest
from secrepoguard_core.report import (
    build_summary,
    format_text_report,
    format_json_report
)

def test_build_summary():
    secrets = [{"rule": "API Key", "filepath": "app.py", "line": 2, "masked_value": "AIz..."}]
    local_risks = [{"package": "requests", "version": "2.20.0", "ecosystem": "PyPI", "severity": "Alto", "description": "vulnerable", "filepath": "req.txt", "line": 1}]
    online_risks = []
    
    summary = build_summary(secrets, local_risks, online_risks)
    assert summary["total_secrets_found"] == 1
    assert summary["total_local_risks_found"] == 1
    assert summary["total_osv_vulnerabilities_found"] == 0
    assert summary["total_issues"] == 2

def test_format_text_report():
    secrets = [{"rule": "API Key", "filepath": "app.py", "line": 2, "masked_value": "AIz..."}]
    local_risks = []
    online_risks = []
    
    report = format_text_report("Test Target", secrets, local_risks, online_risks)
    assert "SECREPOGUARD - RELATÓRIO DE SEGURANÇA" in report
    assert "Alvo Analisado: Test Target" in report
    assert "1. SEGREDOS E CREDENCIAIS EXPOSTAS" in report
    assert "AIz..." in report

def test_format_json_report():
    secrets = [{"rule": "API Key", "filepath": "app.py", "line": 2, "masked_value": "AIz..."}]
    local_risks = []
    online_risks = []
    
    report_json_str = format_json_report("Test Target", secrets, local_risks, online_risks)
    report_dict = json.loads(report_json_str)
    
    assert report_dict["target"] == "Test Target"
    assert report_dict["summary"]["total_secrets_found"] == 1
    assert len(report_dict["secrets_findings"]) == 1
    assert report_dict["secrets_findings"][0]["rule"] == "API Key"
