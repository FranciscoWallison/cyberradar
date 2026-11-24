---
titulo: Phishing e engenharia social
resumo: Golpes que exploram a confiança das pessoas para obter credenciais, dinheiro ou acesso.
nivel: iniciante
categorias: [engenharia-social, conscientizacao]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://attack.mitre.org/techniques/T1566/, https://cartilha.cert.br/, https://www.cisa.gov/secure-our-world/recognize-and-report-phishing]
---
# Phishing e engenharia social

## Em uma frase
**Engenharia social** é manipular pessoas; **phishing** é a versão por mensagem (e-mail, SMS, WhatsApp, redes sociais) que leva a vítima a clicar, digitar dados ou executar algo.

## Explicação técnica
Variações: *spear phishing* (direcionado), *whaling* (executivos), *smishing* (SMS), *vishing* (voz), *quishing* (QR code), *BEC* (fraude de e-mail corporativo, comum em pagamentos). Kits modernos usam **proxy reverso** para capturar a sessão mesmo com MFA por código (*adversary-in-the-middle*). MITRE ATT&CK® T1566.

## Exemplo prático
Mensagem "seu boleto venceu" com link para um domínio parecido com o real (`banco-seguro-atendimento[.]com`) e página idêntica de login.

## Onde aparece no mercado
É o vetor inicial mais comum em incidentes; motiva treinamentos de conscientização, simulações de phishing e filtros de e-mail.

## Riscos e impactos
Roubo de contas, fraudes financeiras (Pix, transferência para fornecedor falso), instalação de malware e porta de entrada para ransomware.

## Como se proteger
- **MFA resistente a phishing** (chaves FIDO2/passkeys).
- SPF, DKIM e **DMARC** com política `reject` no domínio.
- Confirmar pedidos de pagamento por outro canal.
- Treinamento contínuo e canal fácil para reportar mensagens suspeitas.
- Filtros de URL e isolamento de anexos.

## Exercícios
1. Por que um código de SMS não protege contra phishing com proxy reverso?
2. O que o DMARC verifica?
3. O que é BEC?
