---
titulo: Segurança de APIs
resumo: Os riscos específicos de APIs e o OWASP API Security Top 10.
nivel: intermediario
categorias: [web, appsec, api]
cwe: [CWE-639, CWE-285]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://owasp.org/API-Security/editions/2023/en/0x11-t10/, https://cwe.mitre.org/data/definitions/639.html]
---
# Segurança de APIs
## Em uma frase
APIs expõem dados e funções diretamente; o erro mais comum é **não checar se o usuário pode acessar aquele objeto ou ação**.

## Explicação técnica
O **OWASP API Security Top 10 (2023)**: API1 Autorização quebrada em nível de objeto (BOLA) · API2 Autenticação quebrada · API3 Autorização quebrada em nível de propriedade · API4 Consumo irrestrito de recursos · API5 Autorização quebrada em nível de função · API6 Acesso irrestrito a fluxos de negócio sensíveis · API7 SSRF · API8 Configuração incorreta · API9 Gestão inadequada de inventário · API10 Consumo inseguro de APIs de terceiros.

## Exemplo prático
`GET /api/contas/1001` funciona para o dono, mas também quando outro usuário troca para `1002` — BOLA (CWE-639). A correção é verificar a posse do recurso no servidor em **toda** requisição.

## Onde aparece no mercado
Apps móveis, Open Finance, integrações B2B e microsserviços; é foco de bug bounty e de gateways de API.

## Riscos e impactos
Vazamento de dados de milhares de clientes com um script simples, fraudes e abuso de recursos (custos).

## Como se proteger
- Autorização por objeto e por função no servidor, negada por padrão.
- Autenticação padronizada (OAuth 2.0/OIDC), tokens de vida curta.
- Rate limiting e limites de tamanho.
- Inventário de APIs (inclusive versões antigas) e testes automatizados de autorização.

## Exercícios
1. O que é BOLA?
2. Por que APIs "esquecidas" são um risco (API9)?
3. Como o rate limiting ajuda?
