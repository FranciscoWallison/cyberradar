---
titulo: Zero-day (dia zero)
resumo: Vulnerabilidade explorada antes de existir correção disponível.
nivel: intermediario
categorias: [ameacas, gestao]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://www.cisa.gov/known-exploited-vulnerabilities-catalog, https://projectzero.google/]
---
# Zero-day (dia zero)
## Em uma frase
Falha que atacantes exploram **antes** de o fabricante publicar uma correção — o defensor teve "zero dias" para se preparar.

## Explicação técnica
O termo descreve a janela entre a descoberta/exploração e o patch. Um *zero-day* pode ser vendido em mercados privados, usado por grupos de espionagem ou, depois de divulgado, virar um "n-day" (já corrigido, mas ainda explorado onde ninguém atualizou). Muitos itens do catálogo KEV começam como zero-days em dispositivos de borda (VPN, firewall, e-mail).

## Exemplo prático
Um fabricante publica um aviso dizendo que a falha "está sendo explorada" e que o patch sai em alguns dias: até lá, só mitigações (desabilitar recurso, restringir acesso) e monitoramento.

## Onde aparece no mercado
Programas de *bug bounty*, pesquisas como as do Google Project Zero, boletins de fabricantes e notícias de incidentes com dispositivos expostos.

## Riscos e impactos
Não existe correção para aplicar; ataques costumam ser direcionados e silenciosos; a exploração em massa começa logo após a divulgação.

## Como se proteger
- Reduzir a superfície exposta à internet (inventário e segmentação).
- Aplicar mitigações do fabricante imediatamente e o patch assim que sair.
- Detecção por comportamento (EDR, logs, *threat hunting*), não só por assinatura.
- Plano de resposta a incidentes testado.

## Exercícios
1. Qual a diferença entre zero-day e n-day?
2. Por que mitigação e monitoramento são essenciais antes do patch?
3. Que tipo de equipamento costuma aparecer em zero-days do KEV?
