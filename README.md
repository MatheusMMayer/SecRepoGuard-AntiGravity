# SecRepoGuard - Ferramenta de Auditoria Estática de Segurança para Repositórios

SecRepoGuard é uma ferramenta de linha de comando (CLI) em Python projetada para a auditoria básica e estática de segurança em repositórios de software locais ou remotos (GitHub). Seu foco central está na identificação precoce de **segredos expostos** (credenciais, chaves de API, senhas, chaves privadas) e **dependências desatualizadas ou vulneráveis** (`requirements.txt` e `package.json`).

---

## 1. Problema Abordado

Durante o ciclo de desenvolvimento de software, é comum que desenvolvedores cometam erros de configuração ao deixar chaves privadas, senhas de banco de dados, tokens de autenticação ou chaves de API expostas em arquivos de texto sob controle de versão. Além disso, a utilização de dependências de terceiros com vulnerabilidades conhecidas aumenta significativamente a superfície de ataque da aplicação. 

O SecRepoGuard mitiga esses riscos fornecendo uma varredura rápida, estática e sem execução de código que pode ser facilmente integrada a pipelines de integração contínua (CI/CD) ou utilizada para revisões de segurança pontuais.

---

## 2. Requisitos de Segurança & Premissas

Para assegurar a integridade do ambiente do usuário auditando repositórios desconhecidos, o SecRepoGuard adota os seguintes pilares de segurança:
1. **Sem Execução de Código**: A ferramenta funciona exclusivamente como analisador estático (parsing textual). Ela **não executa** código do repositório auditado.
2. **Sem Instalação de Dependências**: O SecRepoGuard analisa manifests (`requirements.txt`, `package.json`) apenas como arquivos de texto e não instala nenhum pacote do repositório alvo.
3. **Privacidade Total de Segredos**: Segredos potenciais são mascarados em todas as saídas geradas e **nunca** são transmitidos para serviços externos.
4. **Consulta Segura ao OSV.dev**: A integração online com o banco de dados do OSV (Open Source Vulnerabilities) envia estritamente o **nome do pacote, sua versão e seu ecossistema** (p. ex., PyPI ou npm). Nenhum outro dado do código é compartilhado.
5. **Validação Humana**: Todos os achados identificados pela ferramenta devem ser tratados como **potenciais alertas** e necessitam de triagem analítica por um especialista de segurança.

---

## 3. Estrutura do Projeto

O repositório está estruturado de maneira modular para facilitar a manutenção e legibilidade do código:

```
secrepoguard/
├── README.md                 # Instruções de execução e detalhes acadêmicos
├── LICENSE                   # Licença MIT do projeto
├── requirements.txt           # Dependências para execução dos testes (pytest)
├── secrepoguard.py           # Ponto de entrada CLI principal
├── secrepoguard_core/        # Módulos de lógica principal
│   ├── __init__.py           # Inicialização do pacote
│   ├── cli.py                # Definição e parser de argumentos CLI
│   ├── github.py             # Lógica para clonagem segura de repositórios do GitHub
│   ├── scanner.py            # Varredor de sistema de arquivos e orquestrador
│   ├── secrets.py            # Expressões regulares e mascaramento de segredos
│   ├── dependencies.py       # Leitores de manifestos e banco local de riscos
│   ├── osv.py                # Integração de requisições HTTP com a API OSV.dev
│   ├── report.py             # Gerador de relatórios (Console, TXT, JSON)
│   └── utils.py              # Funções utilitárias (detecção de binários, leitura segura)
├── examples/                 # Pasta de exemplos para testes manuais
│   └── vulnerable_project/   # Projeto mock contendo falhas intencionais
│       ├── app.py            # Código-fonte expondo chaves e tokens
│       ├── .env.example      # Variáveis de ambiente com credenciais
│       ├── requirements.txt   # Dependências python antigas
│       └── package.json      # Dependências JS antigas
├── reports/                  # Relatórios de exemplo gerados
│   └── example_report.txt    # Relatório de teste em texto plano
└── tests/                    # Testes de unidade
    ├── test_secrets.py       # Testes da lógica de segredos e mascaramento
    ├── test_dependencies.py  # Testes dos parsers de dependências e regras locais
    ├── test_report.py        # Testes de formatação de saída
    └── test_osv.py           # Testes simulados da chamada à API OSV
```

---

## 4. Avaliação Acadêmica (SBSeg 2026)

Em conformidade com os critérios de avaliação de artefatos científicos do SBSeg 2026, o SecRepoGuard demonstra excelente desempenho nos seguintes pilares:

### A. Disponibilidade (Availability)
O código-fonte completo está disponível de forma aberta sob a Licença MIT. A ferramenta depende exclusivamente da biblioteca padrão do Python 3 (com exceção do `pytest` para testes unitários), garantindo que possa ser instalada e executada em qualquer plataforma que suporte Python 3.x, sem restrições ou custos.

### B. Funcionalidade (Functionality)
O SecRepoGuard resolve efetivamente o problema proposto executando:
- **Varredura de Segredos**: Expressões regulares robustas que encontram strings críticas como `API_KEY`, `SECRET_KEY`, `JWT_SECRET`, `ACCESS_TOKEN`, `GITHUB_TOKEN`, `DATABASE_URL`, `DB_PASSWORD`, `PRIVATE_KEY` e assinaturas JWT estruturadas.
- **Auditoria de Dependências (Local)**: Consulta imediata a regras de risco estáticas contidas localmente (sem necessidade de rede).
- **Auditoria de Dependências (Remoto)**: Integração via requisições assíncronas/síncronas com o OSV.dev para buscar vulnerabilidades reais cadastradas em CVEs globais.
- **Interface CLI Completa**: Entrada de parâmetros de forma estruturada.

### C. Sustentabilidade (Sustainability)
A sustentabilidade do projeto é assegurada por sua arquitetura limpa e modular. Cada módulo tem responsabilidade única (SRP - Single Responsibility Principle). A ferramenta foi construída sem dependências pesadas, o que reduz custos de manutenção de bibliotecas de terceiros a zero e mitiga problemas de incompatibilidade com atualizações futuras do Python.

### D. Reprodutibilidade (Reproducibility)
O SecRepoGuard inclui um projeto vulnerável fictício completo (`examples/vulnerable_project`) para reprodução imediata de cenários de teste, além de uma suíte abrangente de testes unitários que utiliza mocks de rede para assegurar que os testes funcionem perfeitamente em ambientes offline (sem rede), gerando resultados consistentes em qualquer máquina.

---

## 5. Como Executar

### Pré-requisitos
- Python 3.8 ou superior instalado.
- Git instalado (necessário apenas para a clonagem automática via `--repo`).

### Passo 1: Preparar o ambiente
1. Clone este repositório ou navegue até a pasta do projeto.
2. (Opcional) Crie e ative um ambiente virtual:
   ```bash
   python -m venv venv
   # No Windows:
   venv\Scripts\activate
   # No Linux/macOS:
   source venv/bin/activate
   ```
3. Instale as dependências de testes:
   ```bash
   pip install -r requirements.txt
   ```

### Passo 2: Execução básica da CLI

O SecRepoGuard aceita os seguintes parâmetros de linha de comando:

| Argumento | Tipo | Descrição |
| :--- | :--- | :--- |
| `--repo URL` | Entrada | URL do repositório Git público no GitHub para clonagem temporária e análise. |
| `--path CAMINHO` | Entrada | Caminho local para diretório ou arquivo específico a ser auditado. |
| `--output ARQUIVO` | Saída | Caminho do arquivo para salvar o relatório formatado em TXT. |
| `--json ARQUIVO` | Saída | Caminho do arquivo para salvar o relatório estruturado em JSON. |
| `--scan-secrets` | Flag | Executa apenas análise estática de segredos expostos. |
| `--scan-dependencies`| Flag | Executa apenas parsing de arquivos de dependência. |
| `--scan-vulnerabilities`| Flag | Habilita a consulta online ao OSV.dev para verificar vulnerabilidades das dependências. |
| `--all` | Flag | Habilita simultaneamente todas as varreduras disponíveis. |
| `--keep` | Flag | Retém a pasta temporária criada ao clonar um repositório remoto. |

> [!NOTE]
> Se nenhuma flag de varredura (`--scan-secrets`, `--scan-dependencies`, `--scan-vulnerabilities`, `--all`) for explicitamente passada, o sistema adotará o comportamento seguro padrão de executar todas as análises (`--all`).

---

## 6. Exemplos de Uso

### Exemplo 1: Analisar projeto local vulnerável simulando saída no terminal
```bash
python secrepoguard.py --path examples/vulnerable_project
```

### Exemplo 2: Executar todas as varreduras e exportar resultados em TXT e JSON
```bash
python secrepoguard.py --path examples/vulnerable_project --all --output reports/auditoria.txt --json reports/auditoria.json
```

### Exemplo 3: Analisar um repositório remoto público do GitHub
```bash
python secrepoguard.py --repo https://github.com/octocat/Spoon-Knife --scan-secrets
```

---

## 7. Executando os Testes Unitários

A suíte de testes unitários garante a estabilidade de cada componente. Os testes utilizam mocks para evitar conexões com a API externa do OSV.dev durante a execução.

Para rodar os testes, execute o seguinte comando na raiz do projeto:
```bash
pytest tests/ -v
```
