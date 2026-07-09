import os
from typing import List, Dict, Any, Tuple
from secrepoguard_core.utils import read_text_file
from secrepoguard_core.secrets import scan_text_for_secrets
from secrepoguard_core.dependencies import (
    parse_requirements_txt,
    parse_package_json
)

# Directories that should be skipped during search traversal
IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", "target", ".next", "coverage"
}

def should_skip_directory(dir_name: str) -> bool:
    """
    Checks if a directory name should be ignored.
    """
    return dir_name in IGNORED_DIRS

def scan_repository(
    base_path: str,
    enable_secrets: bool = True,
    enable_dependencies: bool = True
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Traverses the directory structure and scans matching files.
    Returns a tuple of (secrets_findings, parsed_dependencies).
    """
    secrets_findings = []
    parsed_dependencies = []

    # If the path points directly to a file
    if os.path.isfile(base_path):
        normalized_path = os.path.abspath(base_path)
        content = read_text_file(normalized_path)
        if content:
            if enable_secrets:
                secrets_findings.extend(scan_text_for_secrets(content, normalized_path))
            if enable_dependencies:
                filename = os.path.basename(normalized_path)
                if filename == "requirements.txt":
                    parsed_dependencies.extend(parse_requirements_txt(content, normalized_path))
                elif filename == "package.json":
                    parsed_dependencies.extend(parse_package_json(content, normalized_path))
        return secrets_findings, parsed_dependencies

    # If it is a directory, traverse recursively
    for root, dirs, files in os.walk(base_path):
        # Modify dirs in-place to skip ignored directories
        dirs[:] = [d for d in dirs if not should_skip_directory(d)]
        
        for file in files:
            filepath = os.path.join(root, file)
            normalized_path = os.path.abspath(filepath)
            
            # 1. Run Secrets scanner if enabled
            if enable_secrets:
                content = read_text_file(normalized_path)
                if content:
                    secrets_findings.extend(scan_text_for_secrets(content, normalized_path))
            
            # 2. Run Dependency manifest scanner if enabled
            if enable_dependencies:
                if file == "requirements.txt":
                    # Read only if not already read
                    content = read_text_file(normalized_path)
                    if content:
                        parsed_dependencies.extend(parse_requirements_txt(content, normalized_path))
                elif file == "package.json":
                    content = read_text_file(normalized_path)
                    if content:
                        parsed_dependencies.extend(parse_package_json(content, normalized_path))

    return secrets_findings, parsed_dependencies
