import os
import sys
import shutil
from secrepoguard_core.cli import parse_args
from secrepoguard_core.github import clone_github_repo, GitCloneError
from secrepoguard_core.scanner import scan_repository
from secrepoguard_core.dependencies import check_local_dependency_risks
from secrepoguard_core.osv import query_dependencies_vulnerabilities
from secrepoguard_core.report import (
    format_text_report,
    format_json_report,
    save_report_to_file
)

def main():
    try:
        args = parse_args()
    except SystemExit:
        return

    cloned_path = None
    target_name = ""
    
    # 1. Resolve Target Path
    if args.repo:
        print(f"[*] Acessando repositório remoto: {args.repo}")
        try:
            cloned_path = clone_github_repo(args.repo)
            scan_path = cloned_path
            target_name = f"Repo Clonado ({args.repo})"
            print(f"[+] Repositório clonado com sucesso em pasta temporária: {cloned_path}")
        except GitCloneError as e:
            print(f"[!] Erro ao clonar: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        scan_path = os.path.abspath(args.path)
        target_name = f"Pasta Local ({args.path})"
        if not os.path.exists(scan_path):
            print(f"[!] Erro: O caminho especificado '{args.path}' não existe.", file=sys.stderr)
            sys.exit(1)

    print(f"[*] Iniciando análise estática de segurança em: {scan_path}")
    if args.scan_secrets:
        print("    -> Escaneamento de segredos: HABILITADO")
    if args.scan_dependencies:
        print("    -> Análise de dependências: HABILITADO")
    if args.scan_vulnerabilities:
        print("    -> Consulta ao OSV.dev: HABILITADO")

    # 2. Run Scan
    secrets_findings = []
    dependencies = []
    
    try:
        secrets_findings, dependencies = scan_repository(
            scan_path,
            enable_secrets=args.scan_secrets,
            enable_dependencies=args.scan_dependencies
        )
    except Exception as e:
        print(f"[!] Erro durante a varredura estática: {e}", file=sys.stderr)
        # Ensure cleanup before exit
        if cloned_path and not args.keep:
            shutil.rmtree(cloned_path, ignore_errors=True)
        sys.exit(1)

    # 3. Analyze Dependencies (Local database)
    local_risks = []
    if args.scan_dependencies and dependencies:
        print(f"[*] Analisando {len(dependencies)} dependências locais...")
        local_risks = check_local_dependency_risks(dependencies)

    # 4. Analyze Dependencies (OSV.dev Online)
    online_risks = []
    if args.scan_dependencies and args.scan_vulnerabilities and dependencies:
        print("[*] Consultando vulnerabilidades conhecidas no OSV.dev...")
        online_risks = query_dependencies_vulnerabilities(dependencies)

    # 5. Format Reports
    txt_report = format_text_report(target_name, secrets_findings, local_risks, online_risks)
    json_report = format_json_report(target_name, secrets_findings, local_risks, online_risks)

    # 6. Display to Console
    print("\n" + txt_report + "\n")

    # 7. Write to Files if requested
    if args.output:
        try:
            out_path = os.path.abspath(args.output)
            save_report_to_file(out_path, txt_report)
            print(f"[+] Relatório de texto salvo com sucesso em: {out_path}")
        except Exception as e:
            print(f"[!] Erro ao salvar o relatório TXT: {e}", file=sys.stderr)

    if args.json:
        try:
            json_path = os.path.abspath(args.json)
            save_report_to_file(json_path, json_report)
            print(f"[+] Relatório JSON salvo com sucesso em: {json_path}")
        except Exception as e:
            print(f"[!] Erro ao salvar o relatório JSON: {e}", file=sys.stderr)

    # 8. Cleanup Temporary Directory
    if cloned_path:
        if args.keep:
            print(f"[*] Nota: A pasta temporária do repositório clonado foi mantida em: {cloned_path}")
        else:
            print("[*] Limpando arquivos temporários do repositório...")
            shutil.rmtree(cloned_path, ignore_errors=True)
            print("[+] Limpeza concluída.")

if __name__ == "__main__":
    main()
