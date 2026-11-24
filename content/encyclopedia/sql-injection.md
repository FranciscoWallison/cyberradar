---
titulo: SQL Injection
resumo: Quando dados enviados pelo usuário viram parte de um comando SQL.
nivel: iniciante
categorias: [web, appsec, owasp-top10]
cwe: [CWE-89]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://cwe.mitre.org/data/definitions/89.html, https://owasp.org/Top10/, https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html]
---
# SQL Injection (SQLi)

## Em uma frase
A aplicação monta uma consulta ao banco **concatenando texto do usuário**, e esse texto muda o significado da consulta.

## Explicação técnica
Se o código faz `"SELECT * FROM users WHERE email = '" + email + "'"`, um valor contendo aspas e operadores SQL altera a lógica (ex.: transforma o filtro em sempre verdadeiro). Variantes: *in-band* (o resultado aparece na resposta), *blind* (inferido por tempo ou por diferença de resposta) e *out-of-band*. Classificação: **CWE-89**; está na categoria *Injection* do OWASP Top 10.

## Exemplo prático (defensivo)
Errado: concatenação de strings. Certo: **consulta parametrizada**, em que o banco recebe o comando e os dados separadamente:

```python
cur.execute("SELECT id FROM users WHERE email = %s", (email,))
```

## Onde aparece no mercado
Aplicações legadas, painéis administrativos, APIs que montam filtros dinâmicos, relatórios com `ORDER BY` vindo do usuário. É testada em pentests e por ferramentas DAST/SAST.

## Riscos e impactos
Vazamento de dados (LGPD), alteração ou exclusão de registros, bypass de login e, em alguns bancos, execução de comandos no servidor.

## Como se proteger
- Consultas parametrizadas / *prepared statements* ou ORM usado corretamente.
- Validação por *allowlist* para identificadores (nome de coluna, direção de ordenação).
- Usuário do banco com **privilégio mínimo**.
- WAF como camada extra (não como solução).
- SAST no CI e DAST em homologação.

## Exercícios
1. Por que "escapar aspas" manualmente não é uma defesa confiável?
2. O que é SQLi *blind* baseada em tempo?
3. Qual CWE descreve SQL Injection?
