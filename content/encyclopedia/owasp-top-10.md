---
titulo: OWASP Top 10
resumo: A lista de referência dos riscos mais críticos em aplicações web.
nivel: iniciante
categorias: [web, appsec, owasp-top10]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://owasp.org/Top10/, https://owasp.org/www-project-application-security-verification-standard/]
---
# OWASP Top 10
## Em uma frase
Documento de conscientização da OWASP que reúne as **categorias de risco mais importantes** em aplicações web, atualizado periodicamente com dados da comunidade.

## Explicação técnica
Na edição **2021** as categorias eram: A01 Quebra de controle de acesso · A02 Falhas criptográficas · A03 Injeção · A04 Design inseguro · A05 Configuração incorreta de segurança · A06 Componentes vulneráveis e desatualizados · A07 Falhas de identificação e autenticação · A08 Falhas de integridade de software e dados · A09 Falhas de log e monitoramento · A10 SSRF.
A OWASP publica novas edições ao longo do tempo (a de 2025 reorganizou categorias e deu mais peso à cadeia de suprimentos de software) — **confira sempre a lista vigente em owasp.org/Top10**.

## Exemplo prático
Um endpoint `/pedidos/123` que devolve o pedido de qualquer cliente quando se troca o número é **quebra de controle de acesso** — a categoria mais frequente nos dados da OWASP.

## Onde aparece no mercado
Requisitos de contratos e auditorias, treinamentos de desenvolvedores, relatórios de pentest e regras de ferramentas SAST/DAST.

## Riscos e impactos
Vazamento de dados, fraude e tomada de contas. O Top 10 **não é** uma norma completa: para requisitos verificáveis use o **OWASP ASVS**.

## Como se proteger
- Treinar o time nas categorias e usar as *Cheat Sheets* da OWASP.
- Controle de acesso no servidor, negado por padrão.
- SCA para componentes, SAST/DAST no pipeline.
- Logs de segurança e alertas.

## Exercícios
1. Por que o Top 10 não substitui um padrão como o ASVS?
2. Em qual categoria cai usar uma biblioteca com CVE conhecida?
3. Dê um exemplo de quebra de controle de acesso.
