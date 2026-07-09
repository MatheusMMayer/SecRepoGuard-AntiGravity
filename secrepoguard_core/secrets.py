import re
from typing import List, Dict, Any

# Define regex patterns for secrets scanning.
# Using capture groups to isolate the actual secret value.
PATTERNS = {
    "API Key": re.compile(r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"),
    "Secret Key": re.compile(r"(?i)(?:secret[_-]?key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.\/]{16,})['\"]"),
    "JWT Secret": re.compile(r"(?i)(?:jwt[_-]?secret)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"),
    "Access Token": re.compile(r"(?i)(?:access[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.\/]{16,})['\"]"),
    "GitHub Token": re.compile(r"\b(gh[pousr]_[a-zA-Z0-9]{36,})\b"),
    "GitHub Token (Variable)": re.compile(r"(?i)(?:github[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]"),
    "Database URL": re.compile(r"\b((?:postgres|mysql|mongodb|sqlite|oracle|mssql|redis):\/\/[a-zA-Z0-9_\-]+:([^@\s]+)@[a-zA-Z0-9_\-\.]+:[0-9]+\/[a-zA-Z0-9_\-]+)\b"),
    "DB Password": re.compile(r"(?i)(?:db[_-]?password|database[_-]?password|db_pass|dbpass)\s*[:=]\s*['\"]([^'\"\s]{4,})['\"]"),
    "Private Key": re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"),
    "JWT Token": re.compile(r"\b(eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_+/=]*)\b")
}

def mask_secret(secret: str) -> str:
    """
    Masks a sensitive string, leaving only the first and last 3 characters if length > 6.
    Otherwise, returns all asterisks.
    """
    if not secret:
        return ""
    length = len(secret)
    if length > 6:
        return f"{secret[:3]}...{secret[-3:]}"
    return "*" * length

def mask_db_url(db_url: str, password_part: str) -> str:
    """
    Masks the password part of a database URL.
    """
    if not db_url or not password_part:
        return db_url
    masked_pw = mask_secret(password_part)
    return db_url.replace(f":{password_part}@", f":{masked_pw}@")

def scan_line_for_secrets(line: str, line_num: int, filepath: str) -> List[Dict[str, Any]]:
    """
    Scans a single line of text for potential secrets and returns findings.
    """
    findings = []
    
    for rule_name, pattern in PATTERNS.items():
        matches = pattern.finditer(line)
        for m in matches:
            # Depending on the rule, we extract the captured secret
            if rule_name == "Database URL":
                full_url = m.group(1)
                password = m.group(2)
                masked_val = mask_db_url(full_url, password)
                findings.append({
                    "filepath": filepath,
                    "line": line_num,
                    "rule": rule_name,
                    "masked_value": masked_val
                })
            elif rule_name in ("GitHub Token", "Private Key", "JWT Token"):
                # Matches without separate config variable format (matched directly)
                secret_val = m.group(1)
                findings.append({
                    "filepath": filepath,
                    "line": line_num,
                    "rule": rule_name,
                    "masked_value": mask_secret(secret_val)
                })
            else:
                # Matches with variable name config assignment (group 1 is the value)
                secret_val = m.group(1)
                findings.append({
                    "filepath": filepath,
                    "line": line_num,
                    "rule": rule_name,
                    "masked_value": mask_secret(secret_val)
                })
                
    return findings

def scan_text_for_secrets(text: str, filepath: str) -> List[Dict[str, Any]]:
    """
    Scans full file text line-by-line for potential secrets.
    """
    all_findings = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        findings = scan_line_for_secrets(line, idx, filepath)
        all_findings.extend(findings)
    return all_findings
