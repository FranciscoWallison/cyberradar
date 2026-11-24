---
titulo: Criptografia (fundamentos)
resumo: Como proteger confidencialidade e integridade com algoritmos e chaves.
nivel: iniciante
categorias: [criptografia]
cwe: [CWE-327, CWE-326]
revisado_por: pendente
atualizado_em: 2026-11-24
fontes: [https://csrc.nist.gov/projects/post-quantum-cryptography, https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html, https://cwe.mitre.org/data/definitions/327.html]
---
# Criptografia (fundamentos)
## Em uma frase
Técnicas matemáticas para que só quem tem a chave leia (confidencialidade), para detectar alterações (integridade) e para provar autoria (autenticidade).

## Explicação técnica
- **Simétrica** (mesma chave): AES — rápida, usada para dados em massa.
- **Assimétrica** (par de chaves): RSA, curvas elípticas (ECDH/ECDSA) — troca de chaves e assinaturas.
- **Hash**: SHA-256/SHA-3 — impressão digital; para **senhas** use funções lentas como Argon2id, scrypt ou bcrypt.
- **TLS 1.3** combina tudo para proteger dados em trânsito.
- **Pós-quântica**: o NIST publicou em 2024 os padrões FIPS 203 (ML-KEM), 204 (ML-DSA) e 205 (SLH-DSA) para preparar a migração.

## Exemplo prático
Guardar senhas com SHA-256 simples é um erro (rápido demais para ataques de dicionário); o correto é Argon2id com *salt*.

## Onde aparece no mercado
HTTPS, VPNs, discos criptografados, assinaturas de código, carteiras digitais, gestão de chaves (KMS/HSM) e exigências da LGPD e do PCI DSS.

## Riscos e impactos
Algoritmos fracos ou obsoletos (CWE-327), chaves curtas (CWE-326), chaves no código-fonte e implementação caseira de criptografia.

## Como se proteger
- Usar bibliotecas maduras e padrões atuais; nunca "inventar" algoritmo.
- Gerenciar chaves em KMS/HSM, com rotação.
- TLS 1.2+ (preferir 1.3) e HSTS.
- Inventário criptográfico para planejar a migração pós-quântica.

## Exercícios
1. Qual a diferença entre criptografia simétrica e assimétrica?
2. Por que hash rápido não serve para senhas?
3. O que são os padrões FIPS 203/204/205?
