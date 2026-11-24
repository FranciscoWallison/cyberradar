---
titulo: Segurança de redes
resumo: Fundamentos para proteger o tráfego e reduzir a superfície de ataque.
nivel: iniciante
categorias: [rede]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://csrc.nist.gov/pubs/sp/800/41/r1/final, https://www.cisa.gov/topics/cybersecurity-best-practices]
---
# Segurança de redes
## Em uma frase
Controlar **quem fala com quem, por quais portas e protocolos**, e enxergar o que passa pela rede.

## Explicação técnica
Camadas e controles: firewalls (filtragem por estado/aplicação), segmentação (VLANs, microsegmentação), VPN/ZTNA para acesso remoto, IDS/IPS, proxies, DNS seguro, NAC (controle de acesso à rede) e monitoramento (NetFlow, NDR). Protocolos inseguros (Telnet, FTP, SMBv1) devem ser substituídos por versões cifradas.

## Exemplo prático
Separar a rede de câmeras/IoT da rede corporativa impede que um equipamento vulnerável vire ponte para os servidores.

## Onde aparece no mercado
Projetos de firewall e SD-WAN, auditorias de configuração, Network+ e CyberOps.

## Riscos e impactos
Rede "plana" facilita movimentação lateral de ransomware; equipamentos de borda desatualizados são alvo frequente do KEV.

## Como se proteger
- Negar por padrão e liberar só o necessário.
- Segmentar ativos críticos e IoT.
- Atualizar firewalls, VPNs e roteadores com prioridade.
- Monitorar DNS e tráfego de saída.

## Exercícios
1. O que é movimentação lateral?
2. Por que segmentar IoT?
3. Cite dois protocolos inseguros e seus substitutos.
