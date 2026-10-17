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

O Funnel deve continuar desligado durante a instalação. Anote o `DNSName` do nó
`batatarp` sem o ponto final. Instale o Git se necessário:

```bash
sudo apt-get update
sudo apt-get install -y git
git clone https://github.com/Batatonez/BatataSwap ~/BatataSwap
cd ~/BatataSwap
```

## 2. Instalar a branch revisada

Informe a branch que o orquestrador liberou. O script instala em `/opt/batataswap`,
com dono root, cria usuário/pastas e copia as units. Pode ser repetido; não sobrescreve
config existente, não gera chave/senha e não habilita serviço ou timers.

```bash
read -r -p 'Branch revisada: ' BRANCH
sudo bash deploy/instalar.sh "$BRANCH"
```

Não execute o instalador sobre uma instância em uso para atualizar: use o passo 12.

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

Execute diretamente como root em terminal privado, sem gravação de sessão:

```bash
sudo env BATATASWAP_CONFIG=/etc/batataswap/batataswap.toml /opt/batataswap/.venv/bin/python -m batataswap init
```

Fluxo esperado da T12: gerar 32 bytes aleatórios de chave mestra, cifrar usando
`systemd-creds encrypt --name=batataswap-master` para
`/etc/credstore.encrypted/batataswap-master`, preparar o banco com dono `batataswap`
e pasta 0700, pedir e confirmar a senha (guardada apenas como scrypt), mostrar o QR
e pedir um código do autenticador para confirmar o cadastro TOTP. Não fotografe o QR
nem cole a chave/senha em conversa. O comando precisa suportar terminal interativo;
não use o wrapper para esse primeiro init, pois ainda não existe a credencial.
Se o fluxo implementado divergir, pare e ajuste a T12 antes de prosseguir.

Confira a entrega da credencial sem imprimir seu conteúdo:

```bash
sudo systemd-run --quiet --wait --pipe --collect --uid=batataswap --gid=batataswap -p LoadCredentialEncrypted=batataswap-master:/etc/credstore.encrypted/batataswap-master /bin/sh -c 'stat -c "%U:%G %a" "$CREDENTIALS_DIRECTORY/batataswap-master"'
```

O resultado esperado é `batataswap:batataswap 400`, sem ACL adicional; a cripto recusa
0400 incompatível ou permissões ampliadas. Confira com `getfacl` dentro de uma unit
transitória equivalente se houver ACL configurada no host.

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

Puxe as cópias para outro computador pela tailnet. Por exemplo, no outro computador,
com acesso sudo autorizado e destino privado (não habilite sudo amplo só para isso):

```bash
mkdir -p ~/Backups/batataswap
chmod 0700 ~/Backups/batataswap
rsync -av --rsync-path='sudo rsync' batatonez@batatarp:/var/backups/batataswap/ ~/Backups/batataswap/
```

## T13b — ensaio com banco descartável

Este é um ensaio acompanhado pelo orquestrador, dependente de T13 e T14. A publicação
permanente exige T16. A abertura temporária do Funnel aqui é exclusivamente para o
ensaio autorizado, sem dados reais; feche ao terminar. Use host/instância descartável
com os mesmos caminhos, nunca o banco de produção. Não mantenha outra aplicação no
mesmo hostname. Use senha e TOTP de teste e execute os passos 1–6 nessa instância.

- [ ] T13 passa; banco novo sem memórias, chave/senha/TOTP exclusivos de teste.
- [ ] Abra temporariamente: `sudo tailscale funnel --bg 8780`.
- [ ] Nas duas contas, adicione `https://<DNSName>/mcp` em Personalizar → Conectores.
- [ ] Faça senha + TOTP, consentimento com `conta-1` / `conta-2` e troca de código.
- [ ] Confira `tools/call` com dados fictícios e continuidade entre as contas.
- [ ] Force access curto por ajuste temporário acompanhado na implementação de teste
  (não há campo TTL no Config); valide refresh, rotação e reconexão nas duas contas.
- [ ] Teste token de audiência errada: precisa ser recusado; nunca cole token em logs
  ou comandos com argumento visível. Use o cliente do ensaio T13.
- [ ] Feche: `sudo tailscale funnel reset`; remova conectores de teste das duas contas.
- [ ] Pare serviço e timers com os comandos de emergência abaixo.
- [ ] Execute `sudo batataswap-admin wipe --incluir-backups` e confirme a destruição
  somente na instância descartável. Isso não substitui apagar a chave/TOTP de teste.
- [ ] Descarte integralmente a instância/volume de teste, incluindo banco, credencial,
  backups, senha e cadastro TOTP. Não reaproveite seus segredos na produção.
- [ ] Restaure a configuração revisada, sem TTL curto, e registre evidências sem segredos.

## 7. Publicar depois da T16

Só prossiga quando T16 não tiver nenhum achado crítico ou importante aberto e o ensaio
T13b estiver concluído. Na instalação definitiva, confirme chave/senha/TOTP novos.

```bash
sudo tailscale funnel --bg 8780
tailscale funnel status
```

O Funnel publica 443 → loopback 8780 e persiste no estado do tailscaled após reboot.
Nas duas contas Claude, em Personalizar → Conectores, adicione a mesma URL
`https://<DNSName>/mcp`. Substitua `<DNSName>` pelo nome anotado no passo 1.
Faça login e consentimento em cada conta com o rótulo correspondente. O conector
aparece também no Claude Code web. Confira web, app e celular na T17.

## 8. Restaurar uma cópia

Agende a interrupção. Pare também os timers e aguarde serviços de manutenção em curso
antes de restaurar, para evitar concorrência. Escolha o caminho completo da cópia;
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

A CLI deve conferir manifesto/integridade, guardar banco atual com WAL e SHM em
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
Execute o passo 8 e depois habilite serviço e timers (passo 6).
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
- [ ] Credencial entregue ao usuário do serviço com modo 0400 e sem ACL extra.
- [ ] Reboot: `sudo reboot`; depois conferir serviço, timers e Funnel.
- [ ] Queda: `sudo systemctl kill --signal=SIGKILL batataswap.service`; aguardar
  reinício e conferir `systemctl status batataswap.service` e `/saude` pela URL pública.
- [ ] Criar backup; restaurar de verdade com o passo 8; conferir dados e necessidade
  de reconectar nas duas contas; nenhum acesso revogado pode ressuscitar.
- [ ] Recuperação em host limpo com chave exportada + manifesto + banco (passo 9),
  em ambiente isolado; decifrar tudo via `restore-test`, sem trocar o nó de produção.
- [ ] Conferir retenção e logs sem conteúdo/segredos, e registrar evidências sanitizadas.

## 12. Atualizar

Confira a revisão da branch e tenha uma cópia válida antes da atualização:

```bash
sudo batataswap-admin backup
sudo bash /opt/batataswap/deploy/atualizar.sh
```

O script faz pull fast-forward da branch atual, instala lock com hashes e pacote sem
dependências, atualiza units/admin e executa daemon-reload. Reinicia apenas se o serviço
estiver ativo e mostra status curto. Se falhar, pare e consulte o journal; não force
reset do Git nem restaure banco antigo sem o procedimento do passo 8.
