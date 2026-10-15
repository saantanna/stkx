'use strict';
// Cria (ou redefine a senha de) um usuário do painel.
//   npm run create-admin
// ou, sem interação:  ADMIN_USER=voce ADMIN_PASSWORD='uma senha longa' node create-admin.js
require('./env');
const readline = require('node:readline');
const { db } = require('./db');
const { hashPassword } = require('./auth');

function ask(q, hidden) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const orig = rl._writeToOutput;
    rl._writeToOutput = function (s) {
      if (rl._muted) rl.output.write(/[\r\n]/.test(s) ? s : '*');
      else orig.call(rl, s);
    };
    rl.question(q, (a) => { rl.close(); resolve(a); });
    rl._muted = !!hidden;
  });
}
const fail = (m) => { console.error('Erro: ' + m); process.exit(1); };

(async () => {
  const user = (process.env.ADMIN_USER || await ask('Usuário do painel: ')).trim();
  let pw = process.env.ADMIN_PASSWORD;
  if (!pw) {
    pw = await ask('Senha (mínimo 12 caracteres): ', true);
    if (pw !== await ask('Repita a senha: ', true)) fail('as senhas não conferem.');
  }
  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(user)) fail('usuário deve ter 3-32 caracteres (letras, números, _ . -).');
  if (pw.length < 12 || pw.length > 200) fail('a senha deve ter entre 12 e 200 caracteres.');

  const hash = await hashPassword(pw);
  const ex = db.prepare('SELECT id FROM admins WHERE username = ?').get(user);
  if (ex) {
    db.prepare('UPDATE admins SET pass_hash = ? WHERE id = ?').run(hash, ex.id);
    db.prepare('DELETE FROM sessions WHERE admin_id = ?').run(ex.id); // derruba sessões antigas
    console.log('Senha de "' + user + '" atualizada.');
  } else {
    db.prepare('INSERT INTO admins (username, pass_hash) VALUES (?, ?)').run(user, hash);
    console.log('Usuário "' + user + '" criado.');
  }
})();
