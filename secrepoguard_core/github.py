import os
import subprocess
import tempfile
import shutil
import urllib.parse

class GitCloneError(Exception):
    """Exception raised when cloning a git repository fails."""
    pass

def is_valid_git_url(url: str) -> bool:
    """
    Checks if a given string has a valid git URL scheme.
    """
    if not url:
        return False
    parsed = urllib.parse.urlparse(url)
    # Simple check for https, http, ssh/git urls
    if parsed.scheme in ('git', 'http', 'https') or url.startswith('git@'):
        return True
    return False

def clone_github_repo(repo_url: str) -> str:
    """
    Clones a public GitHub repository into a temporary directory.
    Returns the path to the cloned repository.
    Raises GitCloneError if git is not installed or the clone fails.
    """
    if not is_valid_git_url(repo_url):
        raise GitCloneError(f"URL de repositório inválida: {repo_url}")
        
    temp_dir = tempfile.mkdtemp(prefix="secrepoguard_")
    
    try:
        # Run git clone with a depth of 1 to keep it fast
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, temp_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return temp_dir
    except FileNotFoundError:
        # git command not found
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise GitCloneError("O executável 'git' não foi encontrado no sistema. Por favor, certifique-se de que o Git está instalado e no PATH.")
    except subprocess.CalledProcessError as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        error_msg = e.stderr or e.stdout or "Erro desconhecido durante git clone"
        raise GitCloneError(f"Falha ao clonar o repositório. Detalhes: {error_msg.strip()}")
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise GitCloneError(f"Ocorreu um erro inesperado ao clonar: {str(e)}")
