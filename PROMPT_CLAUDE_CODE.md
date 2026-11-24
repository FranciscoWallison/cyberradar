# Prompt para configurar o CyberRadar na sua máquina (Claude Code + MCP)

## 0. Preparação (uma vez, no seu terminal)
```bash
# GitHub CLI autenticado na sua conta (abre o navegador)
gh auth login

# MCP de navegador para o Claude abrir as páginas dos provedores com você
claude mcp add playwright -- npx -y @playwright/mcp@latest

# Clonar o repositório de estudos (o projeto ainda está no branch da sessão, não na main)
git clone -b claude/affectionate-meitner-9znz0c https://github.com/FranciscoWallison/Estudos--motorSO.git
cd Estudos--motorSO && claude
```
> O MCP do Playwright abre um navegador **separado**: você faz login nas suas contas nessa janela, e o Claude navega e mostra onde clicar.
> Os tokens **nunca** devem passar pelo chat: você mesmo os grava com `gh secret set` em **outro terminal** (a entrada fica oculta).

## 1. Cole este prompt no Claude Code

```text
Você vai me ajudar a colocar no ar o projeto CyberRadar, que está em plataforma-ciberseguranca/cyberradar/
deste repositório. Leia antes: plataforma-ciberseguranca/cyberradar/README.md e CONFIGURACAO.md.

REGRAS DE SEGURANÇA (obrigatórias):
- Nunca me peça para colar tokens, senhas ou chaves no chat e nunca leia/transcreva valores de tokens que
  apareçam na tela do navegador. Se um token aparecer numa página, não o copie: apenas me diga para copiá-lo.
- Para gravar segredos, me mostre o comando `gh secret set NOME --repo DONO/REPO` para eu rodar em OUTRO
  terminal (a entrada é oculta). Você pode conferir depois com `gh secret list` (mostra só os nomes).
- Antes de qualquer ação irreversível ou que publique algo (criar repositório, ativar Pages, rodar workflow,
  postar em canal), descreva o que vai fazer e espere meu "ok".
- Não crie contas em meu nome nem aceite termos de uso por mim: navegue até a página e eu faço a parte de
  login, cadastro, verificação e aceite.
- Use o navegador (MCP playwright) só para me guiar nas páginas oficiais dos provedores.

ETAPAS:
1. Verificar pré-requisitos: `gh auth status`, Python 3.12+, git. Rodar os testes do projeto
   (python -m venv .venv, pip install -r requirements.txt, python -m pytest -q) dentro da pasta do projeto.
2. Criar um repositório PÚBLICO novo na minha conta chamado "cyberradar" (confirme o nome comigo),
   copiar para a RAIZ dele todo o conteúdo de plataforma-ciberseguranca/cyberradar/ (inclusive .github/ e
   .gitignore), fazer o commit inicial com meu nome/e-mail do git e o push para main.
3. Configurar o repositório via `gh`/`gh api` (me mostre cada comando antes):
   - Pages com origem "GitHub Actions" (build_type=workflow);
   - Variáveis do Actions: SITE_URL=https://<meu-usuario>.github.io e SITE_BASE_PATH=/cyberradar;
   - Permitir que o GitHub Actions crie pull requests (para o workflow learning-draft);
   - Ativar secret scanning, push protection, Dependabot alerts e private vulnerability reporting
     (se algum não estiver disponível pela API, me guie pela interface).
4. Rodar o workflow "pipeline" (gh workflow run pipeline.yml), acompanhar com `gh run watch`, analisar os logs
   se falhar e me dar o link do site quando o deploy terminar.
5. Me guiar, UM PROVEDOR POR VEZ, abrindo a página oficial no navegador e dizendo exatamente onde clicar:
   a) NVD API key: https://nvd.nist.gov/developers/request-an-api-key  → secret NVD_API_KEY
   b) Groq: https://console.groq.com/keys → GROQ_API_KEY
   c) OpenRouter: https://openrouter.ai/settings/keys → OPENROUTER_API_KEY (e me mostre em Settings → Privacy
      como bloquear provedores que treinam com os prompts)
   d) Google AI Studio: https://aistudio.google.com/apikey → GEMINI_API_KEY (lembre que o plano grátis pode
      usar os dados para treino)
   e) Cloudflare Workers AI: Account ID e API Token com permissão Workers AI → CLOUDFLARE_ACCOUNT_ID e
      CLOUDFLARE_API_TOKEN
   f) Mistral (opcional): https://console.mistral.ai/api-keys → MISTRAL_API_KEY, e me mostre onde desligar o
      uso para treino (Admin → Privacy)
   g) Telegram: me oriente no @BotFather e na criação do canal público; o bot precisa ser administrador
      → TELEGRAM_BOT_TOKEN e TELEGRAM_CHAT_ID (@nome_do_canal)
   h) Discord: webhook do canal → DISCORD_WEBHOOK_URL
   i) Bluesky: senha de app em Configurações → Privacidade e segurança → Senhas de app
      → BLUESKY_HANDLE e BLUESKY_APP_PASSWORD
   Depois de cada um: eu gravo com `gh secret set`, você confere com `gh secret list` e roda
   `gh workflow run pipeline.yml` quando eu pedir, verificando nos logs a linha "Provedores de IA ativos" /
   "Canais de alerta ativos".
6. Conferir nos painéis dos provedores os limites atuais do plano gratuito e os nomes de modelos disponíveis,
   e ajustar daily_limit/model em config/settings.toml (abaixo do limite real). Mostre o diff antes de commitar.
7. Opcional, se eu quiser: Cloudflare Web Analytics (lembre de ajustar a CSP em
   cyberradar/site/templates/base.html), formulário Tally para FEEDBACK_URL e newsletter (Kit ou Beehiiv)
   apontando para o feed.xml do site.
8. No final, me entregue um checklist do que ficou configurado, do que ficou pendente e de quais tokens
   devo rotacionar periodicamente.
```

## 2. Dicas
- Pode pausar a qualquer momento e retomar depois com: *"continue a configuração do CyberRadar de onde paramos; confira com `gh secret list` e `gh variable list` o que já existe"*.
- Se preferir usar o seu próprio Chrome (já logado) em vez de um navegador separado, use a integração de navegador do Claude Code se estiver disponível na sua versão (veja `/help` ou a documentação). A regra de não transcrever tokens continua valendo.
- Para revogar um token exposto por engano: apague-o no painel do provedor, crie outro e rode `gh secret set` de novo.
