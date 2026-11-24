---
titulo: Segurança ofensiva e defensiva
resumo: Red team, blue team e purple team: como ataque autorizado e defesa se complementam.
nivel: iniciante
categorias: [carreira, operacoes]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://attack.mitre.org/, https://www.planalto.gov.br/ccivil_03/_ato2011-2014/2012/lei/l12737.htm]
---
# Segurança ofensiva e defensiva
## Em uma frase
**Ofensiva** simula atacantes (com autorização) para achar falhas; **defensiva** previne, detecta e responde; juntas, melhoram a segurança real.

## Explicação técnica
- **Red team / pentest**: testes autorizados com escopo e regras de engajamento por escrito; pentest busca falhas, red team emula um adversário completo.
- **Blue team**: SOC, engenharia de detecção, resposta a incidentes, hardening.
- **Purple team**: os dois trabalham juntos, técnica por técnica (ATT&CK®), para medir e melhorar a detecção.
- No Brasil, invadir dispositivo sem autorização é crime (art. 154-A do Código Penal, incluído pela Lei 12.737/2012 e alterado pela Lei 14.155/2021).

## Exemplo prático
Exercício *purple*: o red team executa uma técnica de despejo de credenciais em laboratório; o blue team verifica se o EDR alertou e cria a regra que faltava.

## Onde aparece no mercado
Carreiras de pentester, analista de SOC, engenheiro de detecção; certificações como CySA+ (defensiva) e certificações práticas de pentest.

## Riscos e impactos
Teste sem autorização formal é ilegal; testes mal planejados podem derrubar produção.

## Boas práticas
- Contrato e escopo assinados antes de qualquer teste.
- Ambientes de laboratório e plataformas autorizadas para estudo (CTFs, labs).
- Relatórios com recomendações acionáveis e reteste.

## Exercícios
1. Qual a diferença entre pentest e red team?
2. O que é purple teaming?
3. O que a lei brasileira diz sobre invasão de dispositivo?
