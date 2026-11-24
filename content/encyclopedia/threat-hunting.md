---
titulo: Threat Hunting
resumo: Busca proativa por ameaças que escaparam das defesas automáticas.
nivel: avancado
categorias: [operacoes, soc]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://attack.mitre.org/, https://www.cisa.gov/resources-tools/resources/eviction-strategies-tool]
---
# Threat Hunting
## Em uma frase
Em vez de esperar um alerta, o analista **formula hipóteses** sobre como um atacante agiria e procura evidências nos dados.

## Explicação técnica
Ciclo: hipótese (ex.: "credenciais roubadas estão sendo usadas fora do horário") → coleta de dados (EDR, SIEM, identidade) → investigação → resultado (incidente, nova detecção ou descarte) → automação da detecção. O MITRE ATT&CK® ajuda a escolher técnicas e medir cobertura. Fontes úteis: notícias e o KEV (TTPs recentes).

## Exemplo prático
Após um aviso de exploração em VPN, o time procura nos logs logins da VPN seguidos de criação de contas administrativas nas 48 horas seguintes.

## Onde aparece no mercado
SOCs maduros, serviços de MDR e equipes de CTI; cobrado em vagas de analista nível 2/3 e no CySA+.

## Riscos e impactos
Sem dados de qualidade (logs, EDR) não há caça; sem documentação, o conhecimento se perde.

## Como aplicar bem
- Hipóteses baseadas em inteligência atual e no seu ambiente.
- Toda caçada bem-sucedida vira regra de detecção.
- Registrar consultas e resultados.

## Exercícios
1. Qual a diferença entre detecção e threat hunting?
2. Formule uma hipótese baseada em uma vulnerabilidade do KEV.
3. O que fazer quando a caçada não encontra nada?
