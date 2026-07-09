import json
from unittest.mock import patch, MagicMock
from secrepoguard_core.osv import (
    clean_version_for_query,
    query_osv_package,
    query_dependencies_vulnerabilities
)

def test_clean_version_for_query():
    assert clean_version_for_query("^1.2.3") == "1.2.3"
    assert clean_version_for_query(">=2.0.0, <3.0.0") == "2.0.0"
    assert clean_version_for_query("  ~1.0  ") == "1.0"
    assert clean_version_for_query("") == ""

@patch("urllib.request.urlopen")
def test_query_osv_package_success(mock_urlopen):
    # Set up mock response
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "vulns": [
            {
                "id": "GHSA-p5z5-c6xp-83v9",
                "summary": "Use of Out-of-range Pointer Index in requests",
                "aliases": ["CVE-2018-18074"]
            }
        ]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    vulns = query_osv_package("requests", "2.20.0", "PyPI")
    assert len(vulns) == 1
    assert vulns[0]["vuln_id"] == "GHSA-p5z5-c6xp-83v9"
    assert "CVE-2018-18074" in vulns[0]["summary"]

@patch("urllib.request.urlopen")
def test_query_osv_package_no_vulns(mock_urlopen):
    # Empty response meaning no vulnerabilities found
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({}).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    vulns = query_osv_package("requests", "2.26.0", "PyPI")
    assert len(vulns) == 0

@patch("urllib.request.urlopen")
def test_query_dependencies_vulnerabilities(mock_urlopen):
    # Mock OSV response for a vulnerable package
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "vulns": [
            {
                "id": "CVE-TEST",
                "summary": "Vulnerability test description"
            }
        ]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response
    mock_urlopen.return_value = mock_response
    
    dependencies = [
        {"name": "requests", "version": "2.20.0", "ecosystem": "PyPI", "filepath": "reqs.txt", "line": 1}
    ]
    
    findings = query_dependencies_vulnerabilities(dependencies)
    assert len(findings) == 1
    assert findings[0]["package"] == "requests"
    assert findings[0]["vuln_id"] == "CVE-TEST"
