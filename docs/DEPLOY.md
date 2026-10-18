# Instalação no batatarp

Execute um bloco por vez e confira o resultado. Destino: Ubuntu 24.04, systemd 255,
Python 3.12, nó Tailscale `batatarp`, porta pública 443 → `127.0.0.1:8780`.
A CLI descrita aqui é o contrato da T12: antes de executar, T12 e seus testes precisam
estar concluídos. Este guia não significa que a implantação ou a revisão T16 já ocorreu.

## 1. Preparar o servidor

O Tailscale já deve estar instalado e autenticado. Tenha sudo e um autenticador TOTP.
Não publique outro serviço no hostname do BatataSwap, nem em outra porta.
Na política da tailnet, permita o atributo `funnel` somente para a tag do nó que publica.
Confira o sistema, a versão e o nome DNS real:

```bash
cat /etc/os-release
systemd --version
python3.12 --version
tailscale status --json
sudo tailscale funnel reset
tailscale funnel status
```

`tailscale funnel reset` também apaga a configuração Serve existente.
O Funnel deve continuar desligado durante a instalação. Anote o `DNSName` do nó
`batatarp` sem o ponto final. Instale o Git se necessário:

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/Batatonez/BatataSwap ~/BatataSwap
cd ~/BatataSwap
```

## 2. Instalar o SHA revisado

Informe o SHA de 40 hex revisado e registrado em `docs/STATUS.md`. O script instala em `/opt/batataswap`,
com dono root, cria usuário/pastas e copia as units. Pode ser repetido; não sobrescreve
config existente, não gera chave/senha e não habilita serviço ou timers.

```bash
read -r -p 'SHA revisado (40 hex): ' SHA
sudo bash deploy/instalar.sh "$SHA"
```

Não execute o instalador sobre uma instância em uso para atualizar: use o passo 11.

## 3. Editar a configuração

```bash
sudoedit /etc/batataswap/batataswap.toml
```

Troque `SEU-TAILNET` no `public_origin` pelo nome real, em minúsculas, sem barra final
nem `:443`. Mantenha `bind_host = "127.0.0.1"`, porta 8780 e os caminhos padrão.
Mantenha a lista CIMD do Claude e `allowed_mcp_origins = []` (o spike não enviou Origin).
A origem da Vercel é opcional: só descomente com a origem HTTPS exata já publicada.
Configure também essa mesma origem da API em `web/config.js` e no CSP da Vercel,
na tarefa de integração do painel; nunca envie conteúdo de memória para a Vercel.

```bash
sudo chown root:batataswap /etc/batataswap/batataswap.toml
sudo chmod 0640 /etc/batataswap/batataswap.toml
```

## 4. Inicializar presencialmente

Em terminal privado, sem gravação, gere a credencial como root e depois inicialize
pelo wrapper, nesta ordem:

```bash
sudo /opt/batataswap/.venv/bin/python -m batataswap key-init
sudo batataswap-admin init
```

`key-init` gera 32 bytes e os envia pelo stdin para
`systemd-creds encrypt --name=batataswap-master - /etc/credstore.encrypted/batataswap-master`.
Recusa credencial existente sem `--substituir` e não toca no banco. Não substitua uma
chave em uso. `init` cria o banco, pede senha, mostra QR e confirma o TOTP.
Não fotografe o QR nem cole segredos em conversa.

Antes de iniciar qualquer serviço, confira a entrega sem imprimir conteúdo:

```bash
sudo systemd-run --quiet --wait --pipe --collect --expand-environment=no --uid=batataswap --gid=batataswap -p LoadCredentialEncrypted=batataswap-master:/etc/credstore.encrypted/batataswap-master /bin/sh -c 'stat -c "%U %a" "$CREDENTIALS_DIRECTORY/batataswap-master"'
```

Portão obrigatório: esperado `batataswap 400` (0400) ou `root 440` (0440,
root:root com ACL em systemd ≥ 256). Qualquer outro resultado → pare; confira dono,
grupo e ACL na unit transitória e corrija a entrega antes de prosseguir. A exceção
root:root só vale quando o caminho da cripto vem de `$CREDENTIALS_DIRECTORY`.

## 5. Guardar a chave de recuperação

```bash
sudo batataswap-admin key-export
```

Guarde a saída base32 com checksum no gerenciador de senhas. Ela aparece uma vez.
Guarde também a senha e a recuperação do autenticador. Não redirecione para arquivo
no repositório nem para logs. As cópias do banco não contêm a chave e a credencial
cifrada do host antigo não substitui essa exportação num host novo.

## 6. Iniciar localmente e agendar manutenção

```bash
sudo systemctl enable --now batataswap.service
sudo systemctl --no-pager --lines=8 status batataswap.service
sudo journalctl -u batataswap -f
```

Saia do acompanhamento com Ctrl+C. Os logs devem conter somente eventos, ids,
tamanhos e status, nunca conteúdo, senha, TOTP, cookies ou tokens.
O serviço já inicia no boot e reinicia após falha. Ainda não ligue o Funnel.

```bash
sudo systemctl enable --now batataswap-backup.timer batataswap-restore-test.timer batataswap-cleanup.timer
systemctl list-timers 'batataswap-*'
```

Backup diário 03:17 (atraso aleatório até 5 min), teste domingo 04:17 e faxina horária,
no fuso do servidor (`timedatectl`). Timers persistentes recuperam execuções perdidas.
O backup usa a API online do SQLite, valida integridade e FKs, produz `.db` e manifesto
`.json` com hash e contagens da própria cópia. Retenção: 14 diários e 8 semanais,
até 56 dias. O restore-test valida hash, integridade, FKs, migrações e decifra todas
as linhas, comparando contagens com o manifesto; falha deve gerar prioridade `err`.

```bash
sudo batataswap-admin backup
sudo batataswap-admin restore-test
sudo journalctl -u batataswap-backup -u batataswap-restore-test --no-pager --lines=20
```

Opcional: copie backups para outro computador pela tailnet. No servidor, escolha
um par real (substitua `copia` pelo nome) e prepare cópias privadas com sudo interativo:

```bash
install -d -m 0700 ~/batataswap-transferencia
sudo install -o "$(id -un)" -g "$(id -gn)" -m 0600 /var/backups/batataswap/copia.db /var/backups/batataswap/copia.json ~/batataswap-transferencia/
```

No outro computador:

```bash
install -d -m 0700 ~/Backups/batataswap
scp batatonez@batatarp:batataswap-transferencia/copia.db batatonez@batatarp:batataswap-transferencia/copia.json ~/Backups/batataswap/
chmod 0600 ~/Backups/batataswap/copia.*
```

Toda semana, confira falhas dos jobs; backup e restore-test acionam uma unit que
escreve no journal com prioridade crit:

```bash
sudo journalctl -p crit -u 'batataswap*' --since '1 week ago'
```

## T13b — ensaio com banco descartável

Este é um ensaio acompanhado pelo orquestrador, dependente de T13 e T14. A publicação
permanente exige T16. A abertura temporária do Funnel aqui é exclusivamente para o
ensaio autorizado, sem dados reais; feche ao terminar. Use host/instância descartável
com os mesmos caminhos, nunca o banco de produção. Não mantenha outra aplicação no
mesmo hostname. Use senha e TOTP de teste e execute os passos 1–6 nessa instância.

- [ ] T13 passa; banco novo sem memórias, chave/senha/TOTP exclusivos de teste.
- [ ] Abra temporariamente: `sudo tailscale funnel --bg http://127.0.0.1:8780`.
- [ ] Nas duas contas, adicione `https://<DNSName>/mcp` em Personalizar → Conectores.
- [ ] Faça senha + TOTP, consentimento com `conta-1` / `conta-2` e troca de código.
- [ ] Confira `tools/call` com dados fictícios e continuidade entre as contas.
- [ ] Force access curto por ajuste temporário acompanhado na implementação de teste
  (não há campo TTL no Config); valide refresh, rotação e reconexão nas duas contas.
- [ ] Teste token de audiência errada: precisa ser recusado; nunca cole token em logs
  ou comandos com argumento visível. Use o cliente do ensaio T13.
- [ ] Feche: `sudo tailscale funnel reset`; remova conectores de teste das duas contas.
- [ ] Pare serviço e timers com os comandos de emergência abaixo.
- [ ] Descarte os segredos de teste com os comandos abaixo, somente na instância de ensaio.
- [ ] Apague a entrada TOTP de teste no aplicativo autenticador e remova os conectores.
- [ ] Restaure a configuração revisada e registre evidências sem segredos.

Depois do ensaio, com serviço e manutenção parados:

```bash
sudo systemctl stop batataswap-backup.timer batataswap-restore-test.timer batataswap-cleanup.timer
sudo systemctl stop batataswap.service batataswap-backup.service batataswap-restore-test.service batataswap-cleanup.service
sudo batataswap-admin wipe --incluir-backups
sudo rm /etc/credstore.encrypted/batataswap-master
sudo rm -rf /var/lib/batataswap
sudo find /var/backups/batataswap -mindepth 1 -delete
```

Para produção, após apagar o TOTP de teste, crie tudo do zero e repita o portão `stat`
do passo 4 antes de iniciar:

```bash
sudo /opt/batataswap/.venv/bin/python -m batataswap key-init
sudo batataswap-admin init
```

## 7. Publicar depois da T16

Só prossiga quando T16 não tiver nenhum achado crítico ou importante aberto e o ensaio
T13b estiver concluído. Na instalação definitiva, confirme chave/senha/TOTP novos.

```bash
sudo tailscale funnel --bg http://127.0.0.1:8780
tailscale funnel status
```

O Funnel publica 443 → loopback 8780 e persiste no estado do tailscaled após reboot.
Nas duas contas Claude, em Personalizar → Conectores, adicione a mesma URL
`https://<DNSName>/mcp`. Substitua `<DNSName>` pelo nome anotado no passo 1.
Faça login e consentimento em cada conta com o rótulo correspondente. O conector
aparece também no Claude Code web. Confira web, app e celular na T17.

## 8. Restaurar uma cópia

Agende a interrupção. Pare também os timers e aguarde serviços de manutenção em curso
antes de restaurar, para evitar concorrência. O wrapper recusa restore/wipe enquanto qualquer `batataswap.service`,
`batataswap-*.service` ou `batataswap-*.timer` estiver active/activating.
Escolha o caminho completo da cópia dentro de `/var/backups/batataswap`;
o manifesto `.json` correspondente deve estar junto e legível pelo usuário batataswap.

```bash
sudo systemctl stop batataswap-backup.timer batataswap-restore-test.timer batataswap-cleanup.timer
sudo systemctl stop batataswap-backup.service batataswap-restore-test.service batataswap-cleanup.service
sudo systemctl stop batataswap.service
read -r -p 'Caminho absoluto do backup .db: ' BACKUP
sudo batataswap-admin restore "$BACKUP"
sudo systemctl start batataswap.service
sudo systemctl start batataswap-backup.timer batataswap-restore-test.timer batataswap-cleanup.timer
```

Restore aceita banco atual inexistente (host novo). A CLI deve conferir
manifesto/integridade e, se existir, guardar banco atual com WAL e SHM em
`antes-do-restore-<data>`, trocar o banco e remover WAL/SHM antigos. Deve invalidar
grants, tokens, transações, códigos, sessões, aparelhos e confirmações pendentes,
incrementar `restore_epoch` e ajustar `totp_last_step` ao máximo com o horário atual.
O TOTP permanece o mesmo; reconecte ambas as contas com senha + TOTP.

## 9. Recuperar em host novo

Instale o Ubuntu/Tailscale e execute os passos 1–3 no host limpo. Não rode init para
gerar outra chave. Recupere do gerenciador a chave exportada, e execute como root:

```bash
sudo env BATATASWAP_CONFIG=/etc/batataswap/batataswap.toml /opt/batataswap/.venv/bin/python -m batataswap key-import
```

A CLI lê do stdin: digite/cole no terminal privado, sem colocar a chave em argumentos,
variáveis do shell ou histórico. Ela valida checksum e recria a credencial cifrada
com `systemd-creds encrypt` no host novo. Copie o par `.db`/`.json` para
`/var/backups/batataswap`, dono `batataswap:batataswap`, modo 0600.
No host novo, prepare a pasta de entrada:

```bash
install -d -m 0700 ~/batataswap-transferencia
```

No computador que guarda as cópias, envie o par ao host novo (substitua `HOST-NOVO`
e `copia` pelos valores reais):

```bash
scp ~/Backups/batataswap/copia.db ~/Backups/batataswap/copia.json batatonez@HOST-NOVO:batataswap-transferencia/
```

No host novo, execute:

```bash
sudo install -o batataswap -g batataswap -m 0600 ~/batataswap-transferencia/copia.db ~/batataswap-transferencia/copia.json /var/backups/batataswap/
sudo batataswap-admin restore /var/backups/batataswap/copia.db
sudo batataswap-admin restore-test
```

A sequência é `key-import` como root, depois `restore` pelo wrapper; não execute init.
Se o DNS mudar, ajuste `public_origin` no TOML e refaça os conectores nas duas contas.
Depois habilite serviço e timers (passo 6).
Revalide a URL pública e configure o nó dedicado antes de publicar (passo 7).

## 10. Emergência: desligar tudo

```bash
sudo tailscale funnel reset
sudo systemctl disable --now batataswap-backup.timer batataswap-restore-test.timer batataswap-cleanup.timer
sudo systemctl stop batataswap-backup.service batataswap-restore-test.service batataswap-cleanup.service
sudo systemctl disable --now batataswap.service
tailscale funnel status
```

Para revogar um acesso antes de retomar: `sudo batataswap-admin grants`, seguido de
`sudo batataswap-admin revoke conta-1` (ou o rótulo comprometido).
`sudo batataswap-admin unlock` destranca login após investigar o bloqueio.
Não apague a chave nem os backups durante a investigação.

## T17 — validação real

Somente após T16 e a publicação do passo 7. Acompanhe com o orquestrador:

- [ ] Duas contas × web, app e celular: login, consentimento, ferramentas e continuidade.
- [ ] Sem Bearer em `/mcp`: 401 com descoberta; token de outra audiência recusado.
- [ ] Headers `Forwarded`, `X-Forwarded-*`, `X-Real-IP` forjados são ignorados;
  não alteram origem/Host nem o rate limit (use testes T13 sem expor credenciais).
- [ ] Login errado aciona limite/trancamento; `unlock` administrativo permite recuperação.
- [ ] Credencial aprovada no portão obrigatório do passo 4 (0400 ou root:root 0440).
- [ ] Reboot: `sudo reboot`; depois conferir serviço, timers e Funnel.
- [ ] Queda: `sudo systemctl kill --signal=SIGKILL batataswap.service`; aguardar
  reinício e conferir `systemctl status batataswap.service` e `/saude` pela URL pública.
- [ ] Criar backup; restaurar de verdade com o passo 8; conferir dados e necessidade
  de reconectar nas duas contas; nenhum acesso revogado pode ressuscitar.
- [ ] Recuperação em host limpo com chave exportada + manifesto + banco (passo 9),
  em ambiente isolado; decifrar tudo via `restore-test`, sem trocar o nó de produção.
- [ ] Conferir retenção e logs sem conteúdo/segredos, e registrar evidências sanitizadas.

## 11. Atualizar

Confira o SHA revisado de 40 hex registrado em `docs/STATUS.md` e tenha backup válido:

```bash
sudo batataswap-admin backup
read -r -p 'SHA revisado (40 hex): ' SHA
sudo bash /opt/batataswap/deploy/atualizar.sh "$SHA"
```

O script para serviço e manutenção, faz fetch, checkout detached do SHA e confere HEAD.
Recria o venv vazio (preserva o antigo para diagnóstico), instala ambos os locks com
hashes e instala o pacote sem rede, dependências ou isolamento de build. Atualiza
units/admin, executa `migrate` pelo wrapper antes de iniciar e retoma serviço/timers
se o serviço estava ativo. Se falhar, mantenha tudo parado e consulte o journal.

Exportação privada para arquivo:

```bash
(umask 077; sudo batataswap-admin export --out - > ~/memoria.json)
```

### Credencial cifrada e TPM

Sem TPM, quem copia o disco inteiro pode obter também o `credential.secret` do systemd
e abrir a credencial cifrada. A cifra nesse modo não protege contra cópia integral do disco.
Execute `systemd-creds has-tpm2` para consultar a disponibilidade e o modo de suporte TPM2;
confira também a saída de `systemd-creds encrypt` ao provisionar a credencial.

### Lixeira e restauração de memória

Use `sudo batataswap-admin lixeira` para listar id, tipo, data de apagado e origem,
sem nomes nem conteúdo. Use `sudo batataswap-admin restaurar <id>` para restaurar
um registro e os filhos apagados junto com ele, durante os 30 dias de retenção.
Ambos usam `--pipe`. Este comando é diferente de `restore`, que recupera um backup.

A migração 0003 invalida as chaves antigas de idempotência de lotes, pois a migração
SQL não tem acesso à chave mestra para convertê-las em HMAC. Mensagens são preservadas;
um reenvio de lote antigo após migrar pode duplicá-las. Novas chaves ficam somente como HMAC.
