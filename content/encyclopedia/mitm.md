---
titulo: Man-in-the-Middle (MITM)
resumo: Quando um atacante se coloca entre duas partes para ler ou alterar a comunicação.
nivel: iniciante
categorias: [rede, criptografia]
cwe: [CWE-300, CWE-295]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://attack.mitre.org/techniques/T1557/, https://cwe.mitre.org/data/definitions/295.html, https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security]
---
# Man-in-the-Middle (MITM)

## Em uma frase
O atacante intercepta o tráfego entre a vítima e o serviço, podendo **espionar ou modificar** os dados.

## Explicação técnica
Técnicas: envenenamento de ARP ou DNS em rede local, Wi-Fi falso (*evil twin*), proxies maliciosos e *downgrade* de HTTPS para HTTP. Quando a aplicação **não valida o certificado TLS** (CWE-295), o atacante apresenta um certificado próprio e a conexão "segura" passa por ele. MITRE ATT&CK® T1557 (*Adversary-in-the-Middle*). Kits de phishing modernos fazem MITM na camada de aplicação para roubar sessões.

## Exemplo prático
App móvel que aceita qualquer certificado para "evitar erro em homologação" e vai assim para produção: em um Wi-Fi público, credenciais podem ser capturadas.

## Onde aparece no mercado
Pentests de redes e apps móveis, avaliações de IoT e auditorias de configuração TLS.

## Riscos e impactos
Roubo de credenciais e sessões, alteração de transações e injeção de malware em downloads não assinados.

## Como se proteger
- TLS em tudo, com **validação correta de certificado** e **HSTS**.
- *Certificate pinning* em apps críticos (com plano de rotação).
- DNSSEC/DoH quando aplicável; proteção contra ARP spoofing em switches gerenciados.
- MFA resistente a phishing (FIDO2 vincula a autenticação ao domínio real).

## Exercícios
1. Por que desativar a validação de certificado é perigoso?
2. O que o HSTS impede?
3. Qual técnica do MITRE ATT&CK® descreve MITM?
