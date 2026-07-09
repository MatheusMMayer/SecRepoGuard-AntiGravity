import argparse
import sys
from typing import List

def get_parser() -> argparse.ArgumentParser:
    """
    Creates and configures the argparse command-line parser.
    """
    parser = argparse.ArgumentParser(
        description="SecRepoGuard-AntiGravity - Ferramenta CLI de Auditoria Básica de Segurança em Repositórios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  # Analisar uma pasta local completa (todos os escaneamentos)
  python secrepoguard.py --path /caminho/do/projeto --all
  
  # Analisar um repositório do GitHub apenas para segredos
  python secrepoguard.py --repo https://github.com/usuario/repo --scan-secrets
  
  # Analisar dependências locais e verificar vulnerabilidades no OSV.dev, salvando relatórios
  python secrepoguard.py --path . --scan-dependencies --scan-vulnerabilities --output reports/auditoria.txt --json reports/auditoria.json
"""
    )

    # Repository targets (mutually exclusive group)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--repo",
        type=str,
        help="URL de um repositório Git público no GitHub para clonar e analisar."
    )
    group.add_argument(
        "--path",
        type=str,
        help="Caminho local para uma pasta ou arquivo de projeto a ser analisado."
    )

    # Reporting outputs
    parser.add_argument(
        "--output",
        type=str,
        help="Caminho do arquivo TXT para salvar o relatório formatado de segurança."
    )
    parser.add_argument(
        "--json",
        type=str,
        help="Caminho do arquivo JSON para salvar o relatório estruturado de segurança."
    )

    # Scan control flags
    parser.add_argument(
        "--scan-secrets",
        action="store_true",
        help="Habilita a busca estática por segredos e chaves expostas em arquivos de texto."
    )
    parser.add_argument(
        "--scan-dependencies",
        action="store_true",
        help="Habilita a análise de dependências declaradas em requirements.txt e package.json."
    )
    parser.add_argument(
        "--scan-vulnerabilities",
        action="store_true",
        help="Habilita a consulta online ao OSV.dev para buscar vulnerabilidades conhecidas das dependências."
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Habilita todos os escaneamentos disponíveis (segredos, dependências e vulnerabilidades no OSV.dev)."
    )

    # Option to keep temporary cloned repositories
    parser.add_argument(
        "--keep",
        action="store_true",
        help="Retém o repositório Git clonado na pasta temporária. Por padrão, ele é excluído após a execução."
    )

    return parser

def parse_args(args: List[str] = None) -> argparse.Namespace:
    """
    Parses CLI arguments. Resolves flags dependencies.
    """
    parser = get_parser()
    parsed = parser.parse_args(args)

    # Resolve scan flags.
    # If --all is requested, enable everything.
    if parsed.all:
        parsed.scan_secrets = True
        parsed.scan_dependencies = True
        parsed.scan_vulnerabilities = True
    # If no scanning flag is specified, we default to running everything (user-friendly behavior)
    elif not (parsed.scan_secrets or parsed.scan_dependencies or parsed.scan_vulnerabilities):
        parsed.scan_secrets = True
        parsed.scan_dependencies = True
        parsed.scan_vulnerabilities = True
        
    return parsed
