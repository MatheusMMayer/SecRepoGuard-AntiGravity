import pytest
from secrepoguard_core.dependencies import (
    parse_version_tuple,
    parse_requirements_txt,
    parse_package_json,
    check_local_dependency_risks
)

def test_parse_version_tuple():
    assert parse_version_tuple("1.2.3") == (1, 2, 3)
    assert parse_version_tuple("^4.17.15") == (4, 17, 15)
    assert parse_version_tuple(">=2.20.0-beta") == (2, 20, 0)
    assert parse_version_tuple("invalid") == (0, 0, 0)
    assert parse_version_tuple("") == (0, 0, 0)

def test_parse_requirements_txt():
    content = """
    # Comments
    requests==2.28.1
    numpy>=1.20
    flask~=2.2.0
    other-package
    """
    deps = parse_requirements_txt(content, "requirements.txt")
    assert len(deps) == 4
    
    # Assert specific matches
    requests_dep = next(d for d in deps if d["name"] == "requests")
    assert requests_dep["version"] == "2.28.1"
    assert requests_dep["ecosystem"] == "PyPI"
    
    other_dep = next(d for d in deps if d["name"] == "other-package")
    assert other_dep["version"] == ""

def test_parse_package_json():
    content = """
    {
      "dependencies": {
        "lodash": "^4.17.15",
        "express": "4.15.2"
      },
      "devDependencies": {
        "minimist": "1.2.0"
      }
    }
    """
    deps = parse_package_json(content, "package.json")
    assert len(deps) == 3
    
    lodash_dep = next(d for d in deps if d["name"] == "lodash")
    assert lodash_dep["version"] == "^4.17.15"
    assert lodash_dep["ecosystem"] == "npm"

def test_check_local_dependency_risks():
    deps = [
        {"name": "requests", "version": "2.20.0", "ecosystem": "PyPI", "filepath": "reqs.txt", "line": 2},
        {"name": "requests", "version": "2.26.0", "ecosystem": "PyPI", "filepath": "reqs.txt", "line": 3},
        {"name": "lodash", "version": "^4.17.15", "ecosystem": "npm", "filepath": "pkg.json", "line": 4},
        {"name": "other", "version": "1.0.0", "ecosystem": "PyPI", "filepath": "reqs.txt", "line": 5}
    ]
    risks = check_local_dependency_risks(deps)
    # requests 2.20.0 is vulnerable (< 2.25.0), lodash 4.17.15 is vulnerable (< 4.17.21)
    # requests 2.26.0 is safe. other is not in DB.
    assert len(risks) == 2
    packages_with_risks = [r["package"] for r in risks]
    assert "requests" in packages_with_risks
    assert "lodash" in packages_with_risks
