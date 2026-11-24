---
titulo: SAST, DAST, IAST e SCA
resumo: As quatro famílias de testes automatizados de segurança de aplicações e quando usar cada uma.
nivel: intermediario
categorias: [appsec, devsecops]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://owasp.org/www-community/Source_Code_Analysis_Tools, https://owasp.org/www-project-devsecops-guideline/, https://google.github.io/osv.dev/]
---
# SAST, DAST, IAST e SCA

## Em uma frase
Formas complementares de achar falhas: **olhando o código** (SAST), **atacando a aplicação rodando** (DAST), **instrumentando a execução** (IAST) e **checando dependências** (SCA).

## Explicação técnica
| Técnica | Analisa | Quando | Pontos fortes | Limites |
|---|---|---|---|---|
| **SAST** | Código-fonte/bytecode | No PR/CI | Cedo e barato; aponta a linha | Falsos positivos; não vê configuração em execução |
| **DAST** | App em execução (caixa-preta) | Homologação | Encontra problemas reais de runtime | Tarde no ciclo; cobertura depende do crawl |
| **IAST** | Agente dentro da app durante testes | Testes funcionais | Precisão maior, com contexto | Depende de linguagem/agente; custo |
| **SCA** | Bibliotecas de terceiros e versões | CI e contínuo | Aponta CVEs conhecidas em dependências | Não acha falhas no seu próprio código |

Exemplos open source: Semgrep CE e CodeQL (SAST), OWASP ZAP (DAST), OSV-Scanner e Dependabot (SCA).

## Exemplo prático
Pipeline: PR → SAST + SCA (bloqueiam itens críticos) → deploy em homologação → DAST noturno → relatório para o time.

## Onde aparece no mercado
DevSecOps, requisitos de clientes corporativos, normas (PCI DSS) e programas de SBOM para cadeia de suprimentos.

## Riscos e impactos
Excesso de alertas leva o time a ignorar tudo; ferramenta sem dono vira "teatro de segurança".

## Como aplicar bem
- Começar com poucas regras de alta confiança e quebrar o build só para itens críticos.
- Triagem com responsável definido.
- SCA com prioridade por KEV/EPSS e se a função vulnerável é alcançável.

## Exercícios
1. Qual técnica encontra uma biblioteca com CVE conhecida?
2. Por que o DAST acha problemas que o SAST não vê?
3. Cite uma ferramenta open source de SAST.
