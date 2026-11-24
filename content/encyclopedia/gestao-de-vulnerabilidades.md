---
titulo: Gestão de vulnerabilidades (CVE, CVSS, EPSS, KEV e SSVC)
resumo: Como descobrir, priorizar e corrigir falhas — e por que o CVSS sozinho não basta.
nivel: iniciante
categorias: [gestao, priorizacao]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://www.first.org/cvss/, https://www.first.org/epss/, https://www.cisa.gov/known-exploited-vulnerabilities-catalog, https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc]
---
# Gestão de vulnerabilidades

## Em uma frase
É o processo contínuo de **encontrar, priorizar, corrigir e verificar** falhas de segurança nos ativos da organização.

## Explicação técnica
- **CVE** é o identificador único de uma vulnerabilidade publicada (ex.: `CVE-2021-44228`). Quem atribui é um *CNA* (fabricante, pesquisador, órgão).
- **CVSS** mede a **gravidade técnica** se a falha for explorada (0–10). Não diz se alguém está explorando.
- **EPSS** estima a **probabilidade de tentativa de exploração nos próximos 30 dias** (0–1), com base em dados observados.
- **KEV** (CISA) é a lista de falhas com **exploração ativa confirmada**.
- **SSVC** é um modelo de decisão (agir, acompanhar…) baseado em exploração, automação e impacto.

Priorizar só por CVSS gera filas enormes de "críticas" que talvez nunca sejam exploradas. Combinar **KEV → EPSS → CVSS → contexto do ativo** (exposto à internet? dados sensíveis?) reduz o esforço e o risco.

## Exemplo prático
Duas falhas no mesmo servidor: A tem CVSS 9.1 e EPSS 0,2%; B tem CVSS 7.5, está no KEV e tem EPSS 94%. **Corrija B primeiro**: ela já está sendo usada por atacantes.

## Onde aparece no mercado
Scanners (Nessus, OpenVAS, Qualys), plataformas de *Risk-Based Vulnerability Management*, SLAs de correção em políticas internas e exigências regulatórias.

## Riscos e impactos
Backlog sem priorização, janelas de exposição longas, correções que quebram sistemas sem teste e falsa sensação de segurança por "zerar" só os itens de CVSS alto.

## Como se proteger
1. Inventário de ativos atualizado (você não corrige o que não conhece).
2. Política com prazos por prioridade (ex.: itens do KEV em até 7 dias em ativos expostos).
3. Janela de manutenção e testes de patch.
4. Mitigações temporárias (bloquear porta, desativar recurso) quando o patch atrasa.
5. Verificação pós-correção (novo scan).

## Exercícios
1. Por que uma CVE com CVSS 10 pode ter prioridade menor que uma com CVSS 7?
2. O que significa um EPSS de 0,85?
3. Qual a diferença entre "severidade" e "risco"?
