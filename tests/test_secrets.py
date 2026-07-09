import pytest
from secrepoguard_core.secrets import (
    mask_secret,
    mask_db_url,
    scan_text_for_secrets
)

def test_mask_secret():
    assert mask_secret("") == ""
    assert mask_secret("short") == "*****"
    assert mask_secret("AIzaSyD-TEST-KEY") == "AIz...KEY"
    assert mask_secret("super_long_secret_value_12345") == "sup...345"

def test_mask_db_url():
    db_url = "postgres://admin:password123@localhost:5432/db"
    masked = mask_db_url(db_url, "password123")
    assert "pas...123" in masked
    assert "password123" not in masked

def test_scan_text_for_secrets():
    content = """
    # Configuration
    API_KEY = "AIzaSyD-TEST-KEY-123"
    SECRET_KEY = "short"
    JWT_SECRET = "jwt_signing_key_456"
    database_url = "mysql://user:pass123@localhost:3306/db"
    # Normal comment
    other_var = 123
    """
    
    findings = scan_text_for_secrets(content, "test_file.py")
    rules_found = [f["rule"] for f in findings]
    
    assert "API Key" in rules_found
    assert "JWT Secret" in rules_found
    assert "Database URL" in rules_found
    # Check that the secrets are masked
    for f in findings:
        if f["rule"] == "API Key":
            assert f["masked_value"] == "AIz...123"
        elif f["rule"] == "Database URL":
            assert "pas...123" in f["masked_value"]
