---
titulo: SIEM, SOAR, EDR e XDR
resumo: As principais ferramentas de detecção e resposta de um SOC e como se complementam.
nivel: intermediario
categorias: [operacoes, soc]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation, https://attack.mitre.org/]
---
# SIEM, SOAR, EDR e XDR
## Em uma frase
**SIEM** centraliza e correlaciona logs; **SOAR** automatiza a resposta; **EDR** vigia e age nos computadores e servidores; **XDR** integra vários sensores em uma só plataforma de detecção.

## Explicação técnica
| Ferramenta | Fonte de dados | Função principal |
|---|---|---|
| SIEM | Logs de rede, servidores, nuvem, aplicações | Coleta, retenção, correlação, alertas, investigação |
| SOAR | Alertas do SIEM/EDR, inteligência de ameaças | *Playbooks* automatizados (enriquecer, isolar, abrir chamado) |
| EDR | Telemetria do endpoint (processos, arquivos, rede) | Detecção comportamental, isolamento da máquina, investigação |
| XDR | Endpoint + e-mail + identidade + nuvem + rede | Correlação nativa entre camadas, resposta unificada |

As regras de detecção costumam ser mapeadas para técnicas do MITRE ATT&CK® para medir cobertura.

## Exemplo prático
O EDR detecta um processo do Office abrindo o PowerShell; o SIEM correlaciona com um login de país incomum; o SOAR isola a máquina e abre um chamado com tudo anexado.

## Onde aparece no mercado
Centros de operações de segurança (SOC), MSSPs/MDR e exigências de auditoria (retenção de logs).

## Riscos e impactos
Excesso de alertas (fadiga), custo de armazenamento de logs, automação mal configurada que derruba sistemas legítimos.

## Como aplicar bem
- Começar pelos logs de maior valor: identidade, EDR, borda e e-mail.
- Casos de uso priorizados por ameaças reais (KEV, ransomware).
- Playbooks com aprovação humana para ações destrutivas.
- Revisar e testar as detecções periodicamente.

## Exercícios
1. Qual ferramenta isola uma estação comprometida?
2. Para que serve um playbook de SOAR?
3. O que o XDR adiciona em relação ao EDR?
