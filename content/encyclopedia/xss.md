---
titulo: Cross-Site Scripting (XSS)
resumo: Quando um site exibe conteúdo de terceiros que o navegador executa como script.
nivel: iniciante
categorias: [web, appsec, owasp-top10]
cwe: [CWE-79]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://cwe.mitre.org/data/definitions/79.html, https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html, https://developer.mozilla.org/docs/Web/HTTP/CSP]
---
# Cross-Site Scripting (XSS)

## Em uma frase
O site coloca na página um dado não confiável **sem codificá-lo**, e o navegador da vítima o executa como JavaScript.

## Explicação técnica
- **Refletido:** o dado vem na própria requisição (ex.: parâmetro da URL).
- **Armazenado:** o dado fica salvo (comentário, perfil) e atinge todos que abrem a página.
- **Baseado em DOM:** o JavaScript do próprio site insere o dado com APIs perigosas (`innerHTML`, `document.write`).

O script roda com os privilégios do site: lê dados da página, faz ações em nome do usuário e pode roubar tokens acessíveis por JavaScript.

## Exemplo prático (defensivo)
Use `textContent` em vez de `innerHTML` para texto vindo de fora, e templates com **escape automático** (Jinja2, React). Este portal faz isso com títulos de notícias coletadas.

## Onde aparece no mercado
Comentários, buscas, painéis internos, e-mails renderizados em webmail e plugins de CMS — é uma das classes mais comuns em programas de bug bounty.

## Riscos e impactos
Sequestro de sessão, phishing dentro do domínio legítimo, alteração de conteúdo e ações não autorizadas.

## Como se proteger
- Codificação de saída de acordo com o contexto (HTML, atributo, URL, JS).
- Escape automático no template; evitar `innerHTML`/`v-html`/`dangerouslySetInnerHTML`.
- **Content Security Policy** sem `unsafe-inline` para scripts.
- Cookies de sessão `HttpOnly` e `SameSite`.
- Sanitização com biblioteca madura quando HTML do usuário for inevitável.

## Exercícios
1. Qual a diferença entre XSS armazenado e refletido?
2. Por que a CSP reduz o impacto de um XSS?
3. Qual CWE descreve XSS?
