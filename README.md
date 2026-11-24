# CyberRadar BR

Radar de vulnerabilidades e ameaças **em português**, com priorização explicável (KEV + EPSS + CVSS), resumos por IA
fundamentados em dados oficiais e um módulo de aprendizado com repetição espaçada. **Custo zero:** GitHub Actions + GitHub Pages.

> **Para colocar no ar, siga [`CONFIGURACAO.md`](CONFIGURACAO.md).** Sem nenhuma chave já funciona; cada token só melhora o resultado.

## O que já está pronto
| Módulo | O que faz |
|---|---|
| Coleta | CISA KEV, NVD 2.0 (incremental), FIRST EPSS (diário), GitHub Advisory Database e feeds RSS configuráveis |
| Normalização | Registro único por CVE; CVSS do CNA preferido ao do NVD; produtos via CPE; pacotes via GHSA |
| Priorização | Score 0–100 transparente (`config/settings.toml → [scoring]`), exibido decomposto em cada página |
| Notícias | Só título, trecho curto e link; agrupamento de histórias duplicadas (CVE em comum ou título semelhante) |
| IA | Cadeia de provedores compatíveis com a API da OpenAI (Groq → OpenRouter → Gemini → Cloudflare → Mistral → Ollama), orçamento diário, saída em JSON **validada contra os dados** (rejeita CVE, link ou CVSS inventados) e fallback por template |
| Site estático | Painel, lista filtrável, página por CVE priorizada, notícias, boletins, enciclopédia, aprender (FSRS), fontes/licenças, busca (Pagefind), RSS/JSON Feed e sitemap |
| Sinais de exploit | Índices públicos do Nuclei (MIT) e Metasploit (BSD-3), baixados 1×/dia: indicam se já há template de detecção ou módulo público para a CVE (entra no score) |
| Caso da semana | IA gera estudo de caso + questões a partir da CVE da semana e o workflow `learning-draft` abre um PR para revisão humana |
| Tradução no navegador | Notícias ainda não traduzidas ganham botão que usa a Translator API do Chrome (no dispositivo do visitante, custo zero) |
| Alertas | Telegram (canal), Discord (webhook) e Bluesky, com anti-enxurrada na primeira execução |
| Boletim semanal | Markdown gerado às segundas, publicado e anunciado nos canais |
| Segurança | CSP sem scripts inline, escape de todo conteúdo externo, Actions fixadas por SHA, permissões mínimas por job, segredos só em Secrets, prompts com aviso anti-injeção |

## Estrutura
```
cyberradar/            código Python (collectors/, pipeline/, ai/, notify/, site/)
config/settings.toml   fontes, pesos, provedores de IA e limites — edite aqui
content/               enciclopédia (Markdown), baralhos (JSON) e boletins gerados
data/                  base versionada (gerada pelo pipeline; não edite à mão)
schemas/               JSON Schema dos registros e dos itens de aprendizado
tests/                 testes offline com fixtures (pytest)
.github/workflows/     pipeline.yml (cron + deploy), learning-draft.yml (PR semanal), ci.yml (testes)
```

## Comandos
```bash
pip install -r requirements.txt
python -m cyberradar status            # o que está configurado (sem mostrar segredos)
python -m cyberradar update            # coleta + IA + poda
python -m cyberradar notify --dry-run  # mostra os alertas sem enviar
python -m cyberradar report            # boletim semanal
python -m cyberradar learning-draft    # rascunho do caso da semana (precisa de IA)
python -m cyberradar validate          # valida os baralhos
python -m cyberradar build             # gera _site/ (+ índice de busca)
python -m cyberradar serve             # http://localhost:8000
python -m pytest -q
```

## Como os dados fluem
1. `update`: o KEV e o NVD (desde o último cursor) entram em `data/vulns/<ano>/<CVE>.json`. O GHSA complementa e o EPSS fica em `data/epss.json`.
   Campos voláteis (EPSS, KEV, prioridade) são **recalculados em memória** para não reescrever milhares de arquivos por dia.
2. As notícias vão para `data/news/AAAA-MM.json`, agrupadas e (com IA) traduzidas e resumidas em lote.
3. As CVEs com prioridade ≥ `ai.min_priority` recebem análise por IA (até `max_cve_per_run` por hora). As demais exibem texto automático.
4. A poda remove CVEs antigas de baixa prioridade fora do KEV (`[retention]`).
5. `build` gera páginas só para as CVEs priorizadas ou do KEV. As outras aparecem na lista com link para o NVD (limite de arquivos do Pages).

## Licenças
Código MIT · conteúdo editorial CC BY 4.0 · dados conforme as fontes (página `/fontes/`) · ts-fsrs (MIT) embutido.
Não afiliado ao NIST, MITRE, CISA, FIRST, GitHub, CompTIA, ISC2, Microsoft ou Cisco.
