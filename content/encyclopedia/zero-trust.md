---
titulo: Zero Trust
resumo: Modelo em que nenhum acesso é confiável por padrão — tudo é verificado a cada pedido.
nivel: intermediario
categorias: [arquitetura, identidade]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://csrc.nist.gov/pubs/sp/800/207/final, https://www.cisa.gov/zero-trust-maturity-model]
---
# Zero Trust

## Em uma frase
"Nunca confie, sempre verifique": estar dentro da rede **não** dá acesso; cada pedido é avaliado por identidade, dispositivo e contexto.

## Explicação técnica
Definido no **NIST SP 800-207**. Componentes: *Policy Decision Point* (decide), *Policy Enforcement Point* (aplica), fontes de sinal (identidade, postura do dispositivo, risco). Princípios: privilégio mínimo, microsegmentação, autenticação forte e contínua, e monitoramento de tudo. O modelo de maturidade da CISA organiza em pilares: identidade, dispositivos, redes, aplicações e dados.

## Exemplo prático
Substituir a VPN "tudo-ou-nada" por acesso por aplicação (ZTNA): o colaborador acessa só o sistema de RH, com MFA e dispositivo gerenciado — não a rede inteira.

## Onde aparece no mercado
ZTNA/SSE, gestão de identidade (IdP, SSO, MFA), EDR para postura de dispositivo, microsegmentação em data centers e nuvem.

## Riscos e impactos
Zero Trust não é produto único: projetos falham quando viram só "compra de ferramenta". Exige inventário, identidade bem gerida e mudança de processos.

## Como se proteger (como começar)
1. Inventário de usuários, dispositivos e aplicações.
2. MFA forte em tudo, começando por acesso remoto e administradores.
3. Acesso por aplicação em vez de rede.
4. Segmentar ativos críticos.
5. Registrar e revisar decisões de acesso.

## Exercícios
1. Por que a VPN tradicional conflita com Zero Trust?
2. O que faz um Policy Enforcement Point?
3. Qual publicação do NIST define a arquitetura Zero Trust?
