---
titulo: Ransomware
resumo: Malware que sequestra dados ou sistemas e cobra resgate — hoje quase sempre com roubo de dados antes.
nivel: iniciante
categorias: [malware, resposta-a-incidentes]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://www.cisa.gov/stopransomware, https://attack.mitre.org/techniques/T1486/, https://www.nomoreransom.org/]
---
# Ransomware

## Em uma frase
Ataque em que criminosos **criptografam** sistemas e/ou **roubam dados** e exigem pagamento para devolver o acesso ou não vazar as informações.

## Explicação técnica
Fluxo típico: acesso inicial (credencial vazada, phishing, **vulnerabilidade em VPN ou firewall exposto**) → escalada de privilégio → movimentação lateral → desativação de backups e defesas → **exfiltração** → criptografia (MITRE ATT&CK® T1486) → extorsão dupla ou tripla. Muitos grupos operam como *Ransomware-as-a-Service* (afiliados alugam a ferramenta).

## Exemplo prático
O catálogo KEV da CISA marca quando uma vulnerabilidade tem **uso conhecido em campanhas de ransomware** — este portal destaca esse sinal na página de cada CVE.

## Onde aparece no mercado
Hospitais, prefeituras, indústria, varejo e escritórios de contabilidade. Seguro cibernético, planos de continuidade e exigências de backup imutável surgiram em resposta.

## Riscos e impactos
Parada total da operação, perda de dados, multas e processos (LGPD), custos de recuperação e dano à reputação. Pagar não garante a devolução nem o não vazamento.

## Como se proteger
- Corrigir rapidamente itens do KEV em ativos expostos (VPN, firewall, e-mail, RDP).
- MFA resistente a phishing, principalmente em acesso remoto e contas administrativas.
- Backups 3-2-1 com cópia **offline/imutável** e testes de restauração.
- Segmentação de rede e privilégio mínimo.
- EDR, monitoramento e plano de resposta a incidentes ensaiado.

## Exercícios
1. O que é extorsão dupla?
2. Por que o backup online não basta?
3. Cite três vetores comuns de acesso inicial.
