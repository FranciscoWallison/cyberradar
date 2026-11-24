---
titulo: DevSecOps
resumo: Segurança integrada ao ciclo de desenvolvimento e entrega contínua.
nivel: intermediario
categorias: [appsec, devsecops]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://owasp.org/www-project-devsecops-guideline/, https://slsa.dev/, https://csrc.nist.gov/pubs/sp/800/218/final]
---
# DevSecOps
## Em uma frase
Levar a segurança para **dentro** do fluxo de desenvolvimento (planejar, codar, testar, entregar, operar), em vez de deixá-la para o fim.

## Explicação técnica
Práticas típicas: modelagem de ameaças no design; SAST, SCA e varredura de segredos no PR; IaC scanning; assinatura e proveniência de artefatos (SLSA, Sigstore); DAST em homologação; monitoramento em produção. O **NIST SSDF (SP 800-218)** organiza essas práticas em um framework.

## Exemplo prático
Um PR que adiciona uma chave de API no código é bloqueado pela varredura de segredos; outro que inclui biblioteca com CVE crítica recebe comentário automático com a versão corrigida.

## Onde aparece no mercado
Plataformas de CI/CD (GitHub Actions, GitLab CI), exigências de SBOM e segurança da cadeia de suprimentos em contratos públicos e corporativos.

## Riscos e impactos
Pipeline comprometido vira porta de entrada (ataques de supply chain); ferramentas barulhentas fazem o time ignorar alertas.

## Como aplicar bem
- Começar pequeno: segredos + SCA + SAST com poucas regras de alta confiança.
- Permissões mínimas nos pipelines e *actions* fixadas por versão/commit.
- SBOM e assinatura de artefatos.
- Métricas: tempo para corrigir, não quantidade de alertas.

## Exercícios
1. Cite três controles que podem rodar em um PR.
2. O que é o NIST SSDF?
3. Por que fixar dependências do pipeline por commit é importante?
