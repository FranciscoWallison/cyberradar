# Configuração — o que VOCÊ precisa fazer manualmente

Tudo é **gratuito e sem cartão**. O projeto funciona já no passo 3. Os demais passos só melhoram limites, resumos e alertas.
Tempo estimado: 20 min (mínimo) a 1h30 (tudo).

> Regra de ouro: **chaves e tokens só em _Secrets_ do GitHub** (ou no seu `.env` local, que nunca vai para o git).
> Nunca cole tokens em issues, commits, prints ou no chat.

---

## 1. Criar o repositório (obrigatório)
1. Crie um repositório **público** novo no GitHub (ex.: `cyberradar`). Precisa ser público: o Actions é ilimitado e o Pages é gratuito só assim.
2. Copie **todo o conteúdo desta pasta** (`plataforma-ciberseguranca/cyberradar/`) para a **raiz** do novo repositório, inclusive as pastas ocultas `.github/` e o `.gitignore`:
   ```bash
   cp -r plataforma-ciberseguranca/cyberradar/. ../cyberradar/
   cd ../cyberradar && git init -b main && git add . && git commit -m "CyberRadar: projeto inicial"
   git remote add origin https://github.com/SEU-USUARIO/cyberradar.git && git push -u origin main
   ```
   > Os workflows só rodam quando estão em `.github/workflows/` na **raiz** do repositório e na branch padrão.

## 2. Segurança da conta e do repositório (obrigatório, 5 min)
- [ ] Conta GitHub com **2FA** (de preferência passkey ou chave de segurança).
- [ ] *Settings → Code security*: ative **Secret scanning**, **Push protection**, **Dependabot alerts** e **Private vulnerability reporting**.
- [ ] *Settings → Actions → General*:
  - "Workflow permissions" pode ficar em **Read repository contents** (os workflows pedem só o que precisam).
  - Em "Fork pull request workflows", deixe exigida a aprovação para colaboradores de fora.
- [ ] Se você proteger a branch `main` (branch protection/rulesets), permita que o **GitHub Actions** faça push (o pipeline commita `data/`). Do contrário o commit de dados falha.

## 3. Ativar o GitHub Pages (obrigatório)
1. *Settings → Pages → Build and deployment → Source*: escolha **GitHub Actions**.
2. *Settings → Secrets and variables → Actions → aba **Variables*** → crie:

| Variável | Valor | Exemplo |
|---|---|---|
| `SITE_URL` | domínio do Pages, sem barra final | `https://seu-usuario.github.io` |
| `SITE_BASE_PATH` | `/` + nome do repositório (vazio se usar domínio próprio) | `/cyberradar` |
| `FEEDBACK_URL` | *(opcional)* link de um formulário Tally/Google Forms para "reportar erro" | `https://tally.so/r/xxxx` |
| `PIPELINE_ENABLED` | *(opcional)* `false` pausa a coleta | — |
| `ALERTS_ENABLED` | *(opcional)* `false` pausa alertas e anúncios | — |

3. *Actions → pipeline → Run workflow* para a primeira execução. Em ~5–10 min o site estará em `SITE_URL + SITE_BASE_PATH`.

✅ **A partir daqui o site já funciona**: KEV, NVD (limite menor), EPSS, GitHub Advisory, notícias e resumos automáticos (sem IA).

## 4. Chave gratuita do NVD (recomendado)
1. Peça em <https://nvd.nist.gov/developers/request-an-api-key> (chega por e-mail; ative em até 7 dias).
2. Secret: `NVD_API_KEY`. Aumenta o limite de 5 para 50 requisições por 30 s.

## 5. IA gratuita (recomendado — escolha uma ou mais)
O pipeline tenta na ordem de `config/settings.toml` e pula os provedores sem chave. Confira os limites no painel de cada um e ajuste `daily_limit` para **abaixo** do limite real.

| Provedor | Onde criar a chave | Secret(s) | Observação |
|---|---|---|---|
| **Groq** (principal) | <https://console.groq.com/keys> | `GROQ_API_KEY` | Sem cartão |
| **OpenRouter** | <https://openrouter.ai/settings/keys> | `OPENROUTER_API_KEY` | Modelos `:free` têm ~50 req/dia. Em *Settings → Privacy*, desative provedores que treinam com os prompts |
| **Google Gemini** | <https://aistudio.google.com/apikey> | `GEMINI_API_KEY` | No plano grátis o Google **pode usar os prompts para treino**: só dados públicos (o projeto já respeita isso) |
| **Cloudflare Workers AI** | Dashboard → *AI → Workers AI* (Account ID) e *My Profile → API Tokens* (token com permissão "Workers AI: Read") | `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN` | 10 mil Neurons/dia |
| **Mistral** | <https://console.mistral.ai/api-keys> | `MISTRAL_API_KEY` | Plano Experiment: **desligue o uso para treino** em *Admin → Privacy* |

> Os nomes dos modelos mudam. Se aparecer erro "model not found" nos logs, troque o `model` do provedor em `config/settings.toml` por um listado no painel.

Teste local (opcional), sem gastar cota do Actions:
```bash
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
cp .env.example .env   # preencha só o que quiser testar
python -m cyberradar status
python -m cyberradar update
SITE_BASE_PATH= python -m cyberradar build
python -m cyberradar serve      # abre http://localhost:8000
```

### IA local com Ollama (opcional, custo zero e sem limite)
1. Instale o Ollama (<https://ollama.com>) e rode `ollama pull qwen3:4b` (ou outro modelo Apache/MIT).
2. No `.env` local: `OLLAMA_BASE_URL=http://localhost:11434/v1`.
3. Rode `python -m cyberradar process` no seu PC e faça `git push` dos dados. O Actions continua cuidando da coleta.

## 6. Alertas (opcional)
### Telegram (canal público)
1. No Telegram, fale com **@BotFather** → `/newbot` → guarde o token.
2. Crie um **canal** público (ex.: `@cyberradarbr`) e adicione o bot como **administrador** com permissão de postar.
3. Secrets: `TELEGRAM_BOT_TOKEN` (token do bot) e `TELEGRAM_CHAT_ID` (`@nome_do_canal`).

### Discord
1. Servidor → canal → *Editar canal → Integrações → Webhooks → Novo webhook* → copiar a URL.
2. Secret: `DISCORD_WEBHOOK_URL`.

### Bluesky
1. Crie a conta e, na bio, informe que é uma conta automatizada.
2. *Configurações → Privacidade e segurança → Senhas de app* → crie uma.
3. Secrets: `BLUESKY_HANDLE` (ex.: `cyberradar.bsky.social`) e `BLUESKY_APP_PASSWORD`. **Nunca** use a senha principal.

> Na **primeira** execução com um canal configurado, o sistema só marca as vulnerabilidades existentes como "já vistas", para não disparar dezenas de alertas antigos. Os alertas começam na execução seguinte.
> Ajuste `[alerts] min_priority` e `max_per_run` em `config/settings.toml`.

## 7. Newsletter, analytics e feedback (opcional, fora do código)
- **Newsletter**: crie a conta no Kit ou no Beehiiv e configure o "RSS to email" com `SITE_URL/SITE_BASE_PATH/feed.xml` (ou cole o boletim semanal manualmente).
- **Analytics sem cookies**: Cloudflare Web Analytics. Ele injeta um script de `static.cloudflareinsights.com`, então será preciso liberar esse domínio na CSP de `cyberradar/site/templates/base.html` (`script-src` e `connect-src`).
- **Formulário de erros**: crie no Tally e coloque o link na variável `FEEDBACK_URL`.

## 8. "Caso da semana" (opcional, precisa de IA configurada)
Toda terça o workflow `learning-draft` gera, com IA, um estudo de caso + 3 questões + 3 flashcards sobre a vulnerabilidade mais relevante da semana e **abre um Pull Request** para você revisar.
- [ ] Ative *Settings → Actions → General → "Allow GitHub Actions to create and approve pull requests"*.
- Na revisão: corrija o que precisar e troque `"status": "in_review"` por `"published"` nos itens aprovados. Só itens `published` aparecem no site.
- Teste manual: *Actions → learning-draft → Run workflow*.

## 9. Revisões editoriais (contínuo)
- Os 20 verbetes em `content/encyclopedia/` estão com `revisado_por: pendente` até você revisar. Revise, ajuste e mude para `humano`.
- `content/learning/fundamentos.json`: mapeie `objectives.code` para os códigos **oficiais** dos PDFs de objetivos (ex.: Security+ SY0-801) e rode `python -m cyberradar validate`.
- Revise os feeds em `config/settings.toml`: alguns endereços (CTIR Gov, Project Zero) estão `enabled = false` até você confirmar a URL.

## 10. Domínio próprio (opcional, ~R$ 40/ano)
1. Registre o domínio (Registro.br para `.com.br`).
2. *Settings → Pages → Custom domain*. Antes, **verifique o domínio** em *Settings (da conta) → Pages → Verified domains* (evita sequestro de subdomínio).
3. Ajuste `SITE_URL=https://seudominio.com.br` e `SITE_BASE_PATH=` (vazio).

## 11. Antes de monetizar
Os termos do GitHub Pages proíbem SaaS comercial. Para cobrar, publique o mesmo `_site/` no **Cloudflare Workers Static Assets/Pages** (gratuito):
```bash
npx wrangler pages deploy _site --project-name cyberradar
```
Também é preciso remover as fontes "só para uso não comercial" que você tiver adicionado (ex.: Shodan CVEDB, VirusTotal). Veja os documentos 13 (riscos) e 18 (o que é grátis) do planejamento.

---

## Solução de problemas
| Sintoma | Causa provável | Ação |
|---|---|---|
| Site com CSS quebrado | `SITE_BASE_PATH` errado | Use `/nome-do-repo` exatamente |
| Commit de dados falha (`403`/`protected branch`) | Proteção de branch | Permita push do GitHub Actions ou desative a regra para `data/` |
| `NVD HTTP 403/503` | Limite ou instabilidade do NVD | Adicione `NVD_API_KEY`; o cursor é mantido e a próxima hora recupera |
| Resumos continuam "Automático" | Nenhuma chave de IA, cota esgotada ou modelo inexistente | `python -m cyberradar status`; veja os logs "IA …" no Actions |
| Cron parou de rodar | O GitHub desativa após 60 dias sem atividade | *Actions → pipeline → Enable workflow* |
| Nenhum alerta chegou | 1ª execução só marca como visto, ou o bot não é admin do canal | Aguarde a próxima hora; confira as permissões do bot |
