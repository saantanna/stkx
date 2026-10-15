# STKX SaaS — site + banco de dados + painel com notificações

Sem dependências: usa só o Node.js (versão 22.13 ou mais nova) e o SQLite embutido nele.

## Rodar

```bash
cp .env.example .env        # ajuste se quiser
npm run create-admin        # cria seu usuário do painel (senha com 12+ caracteres)
npm start                   # http://127.0.0.1:3000   painel: /admin/
```

O banco fica em `data/stkx.db` (permissão 600). Faça backup dessa pasta. Ela não vai para o Git.

## Publicar com segurança

1. Coloque atrás de HTTPS (Caddy, Nginx, Cloudflare ou a hospedagem). Exemplo com Caddy:
   `seudominio.com { reverse_proxy 127.0.0.1:3000 }`
2. No `.env`: `NODE_ENV=production` (ativa cookie Secure + HSTS) e `TRUST_PROXY=1`.
3. O proxy precisa repassar o cabeçalho `Host` original (Caddy já faz; no Nginx use `proxy_set_header Host $host;`).
4. Troque `SEU-DOMINIO` em `public/.well-known/security.txt` e renove a data `Expires` uma vez por ano.
5. Mantenha o Node atualizado.

## Alertas de novos pedidos

- **Com o painel aberto:** aviso na tela, som e notificação do navegador (clique em "Ativar alertas"). O título da aba mostra quantos pedidos novos existem.
- **Com o painel fechado (celular):** configure `NTFY_URL` (app ntfy) ou `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` no `.env`. O aviso leva só nome e tipo do projeto.

## O que foi protegido

- Cabeçalhos: CSP restritiva (sem scripts/estilos inline), HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP.
- Servidor de arquivos só entrega a pasta `public/` (bloqueia `..`, arquivos ocultos e o banco).
- Formulário: validação no servidor, lista fixa de opções, limite de tamanho, campo isca + tempo mínimo anti-robô, limite por IP, checagem de origem, consentimento LGPD registrado.
- Banco: consultas parametrizadas (sem injeção de SQL); IP guardado só como hash.
- Painel: senha com scrypt, sessão em cookie HttpOnly + SameSite=Strict (8 h), token CSRF, bloqueio após 8 falhas em 15 min, tudo renderizado como texto (sem XSS), CSV protegido contra injeção de fórmula.
- Retenção: pedidos com mais de 365 dias são apagados sozinhos (`RETENTION_DAYS`).
