---
titulo: Segurança em nuvem
resumo: Proteger cargas de trabalho em IaaS, PaaS e SaaS — começando pelo modelo de responsabilidade compartilhada.
nivel: intermediario
categorias: [nuvem]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://www.cisa.gov/resources-tools/resources/cloud-security-technical-reference-architecture, https://cloudsecurityalliance.org/research/cloud-controls-matrix]
---
# Segurança em nuvem
## Em uma frase
Na nuvem o provedor protege a infraestrutura; **configuração, identidades e dados continuam sendo responsabilidade do cliente**.

## Explicação técnica
- **Responsabilidade compartilhada**: em IaaS o cliente cuida de SO, rede virtual, aplicações e dados; em SaaS cuida principalmente de identidades, configurações e dados.
- Riscos mais comuns: **configuração incorreta** (bucket público, porta aberta), **identidades com permissões excessivas**, chaves de acesso vazadas e falta de logs.
- Ferramentas: CSPM (postura), CWPP (cargas), CIEM (permissões), CNAPP (plataforma integrada).

## Exemplo prático
Um bucket de armazenamento com acesso público expõe backups de clientes; um alerta de CSPM e uma política de "bloquear acesso público" na conta evitariam o incidente.

## Onde aparece no mercado
Certificações de provedores, frameworks como o CSA Cloud Controls Matrix e requisitos de auditoria (ISO 27017, SOC 2).

## Riscos e impactos
Vazamentos em massa, mineração de criptomoeda com contas roubadas (custos altos), sequestro de ambientes.

## Como se proteger
- MFA forte e privilégio mínimo em todas as contas; nada de chaves de longa duração.
- Guardrails (políticas) que impedem recursos públicos por padrão.
- Logs de auditoria ativados e centralizados.
- Infraestrutura como código revisada e escaneada.

## Exercícios
1. Em IaaS, quem corrige o sistema operacional das VMs?
2. O que faz uma ferramenta CSPM?
3. Por que chaves de acesso de longa duração são perigosas?
