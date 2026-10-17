CREATE TABLE owner (
  id               INTEGER PRIMARY KEY CHECK (id = 1),
  password_hash    TEXT    NOT NULL,             -- scrypt (formato do §9)
  totp_secret_ct   BLOB    NOT NULL,             -- AAD "bsw1|owner|totp"
  totp_last_step   INTEGER NOT NULL DEFAULT 0,
  updated_at       INTEGER NOT NULL
) STRICT;

CREATE TABLE projects (
  id          INTEGER PRIMARY KEY,
  public_id   TEXT    NOT NULL UNIQUE,           -- "proj_…"
  name_mac    BLOB    NOT NULL UNIQUE,           -- HMAC(chave mac-projeto, nome normalizado); aleatório depois do expurgo
  name_ct     BLOB,                              -- AAD "bsw1|project|<public_id>"; NULL depois do expurgo
  created_at  INTEGER NOT NULL,
  trashed_at  INTEGER,
  trash_root  TEXT,                              -- public_id da operação de apagar que mandou pra lixeira
  purged_at   INTEGER,
  CHECK (purged_at IS NULL OR name_ct IS NULL),
  CHECK (purged_at IS NOT NULL OR name_ct IS NOT NULL),
  CHECK ((trashed_at IS NULL) = (trash_root IS NULL))
) STRICT;

CREATE TABLE contexts (                          -- uma linha por versão; conteúdo nunca muda
  id            INTEGER PRIMARY KEY,
  public_id     TEXT    NOT NULL UNIQUE,         -- "ctx_…"
  project_id    INTEGER NOT NULL REFERENCES projects(id),
  version       INTEGER NOT NULL,
  created_at    INTEGER NOT NULL,
  grant_id      INTEGER REFERENCES oauth_grants(id),
  source_label  TEXT    NOT NULL,                -- "conta-1", "conta-2", "painel", "cli"
  content_ct    BLOB,                            -- NULL depois de expurgado
  content_size  INTEGER NOT NULL,
  trashed_at    INTEGER,                         -- na lixeira (apagar pelo MCP)
  trash_root    TEXT,
  purged_at     INTEGER,                         -- conteúdo destruído (painel/CLI/faxina)
  UNIQUE (project_id, version),
  CHECK (purged_at IS NULL OR content_ct IS NULL),
  CHECK (purged_at IS NOT NULL OR content_ct IS NOT NULL),
  CHECK ((trashed_at IS NULL) = (trash_root IS NULL))
) STRICT;

CREATE TABLE preferences (
  id             INTEGER PRIMARY KEY,
  public_id      TEXT    NOT NULL UNIQUE,        -- "pref_…"
  supersedes_id  INTEGER REFERENCES preferences(id),
  version        INTEGER NOT NULL DEFAULT 1,
  created_at     INTEGER NOT NULL,
  grant_id       INTEGER REFERENCES oauth_grants(id),
  source_label   TEXT    NOT NULL,
  text_ct        BLOB,
  text_size      INTEGER NOT NULL,
  trashed_at     INTEGER,
  trash_root     TEXT,
  purged_at      INTEGER,
  CHECK (purged_at IS NULL OR text_ct IS NULL),
  CHECK (purged_at IS NOT NULL OR text_ct IS NOT NULL),
  CHECK ((trashed_at IS NULL) = (trash_root IS NULL))
) STRICT;

CREATE TABLE conversations (
  id          INTEGER PRIMARY KEY,
  public_id   TEXT    NOT NULL UNIQUE,           -- "conv_…"
  name_mac    BLOB    NOT NULL UNIQUE,           -- HMAC(chave idx-conversa, nome normalizado)
  name_ct     BLOB,                              -- AAD "bsw1|conv|<public_id>"; NULL depois do expurgo
  project_id  INTEGER REFERENCES projects(id),
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,                  -- última mensagem anexada
  total_bytes INTEGER NOT NULL DEFAULT 0,
  trashed_at  INTEGER,
  trash_root  TEXT,
  purged_at   INTEGER,
  CHECK (purged_at IS NULL OR name_ct IS NULL),
  CHECK (purged_at IS NOT NULL OR name_ct IS NOT NULL),
  CHECK ((trashed_at IS NULL) = (trash_root IS NULL))
) STRICT;

CREATE TABLE message_batches (                   -- uma chamada de anexar_mensagens
  id               INTEGER PRIMARY KEY,
  public_id        TEXT    NOT NULL UNIQUE,      -- "lote_…"
  conversation_id  INTEGER NOT NULL REFERENCES conversations(id),
  grant_id         INTEGER NOT NULL REFERENCES oauth_grants(id),  -- QUEM ENVIOU (verificado)
  created_at       INTEGER NOT NULL,
  client_batch_key TEXT,                         -- idempotência opcional enviada pelo Claude
  payload_mac      BLOB    NOT NULL,             -- HMAC(mac-lote, JSON canônico das mensagens)
  first_seq        INTEGER NOT NULL,
  last_seq         INTEGER NOT NULL,
  UNIQUE (conversation_id, grant_id, client_batch_key)
) STRICT;

CREATE TABLE messages (
  id               INTEGER PRIMARY KEY,
  public_id        TEXT    NOT NULL UNIQUE,      -- "msg_…"
  conversation_id  INTEGER NOT NULL REFERENCES conversations(id),
  batch_id         INTEGER NOT NULL REFERENCES message_batches(id),
  seq              INTEGER NOT NULL,             -- posição na conversa
  claimed_author   TEXT    NOT NULL CHECK (claimed_author IN ('usuario', 'claude')), -- ALEGADO pelo Claude
  created_at       INTEGER NOT NULL,
  text_ct          BLOB,
  text_size        INTEGER NOT NULL,
  trashed_at       INTEGER,
  trash_root       TEXT,
  purged_at        INTEGER,
  UNIQUE (conversation_id, seq),
  CHECK (purged_at IS NULL OR text_ct IS NULL),
  CHECK (purged_at IS NOT NULL OR text_ct IS NOT NULL),
  CHECK ((trashed_at IS NULL) = (trash_root IS NULL))
) STRICT;

CREATE TABLE oauth_clients (
  id             INTEGER PRIMARY KEY,
  client_id      TEXT    NOT NULL UNIQUE,
  kind           TEXT    NOT NULL CHECK (kind IN ('cimd', 'static')),
  metadata_json  TEXT    NOT NULL,               -- só metadados públicos
  fetched_at     INTEGER NOT NULL,
  cache_until    INTEGER NOT NULL
) STRICT;

CREATE TABLE oauth_transactions (
  id_hash         BLOB    PRIMARY KEY,           -- SHA-256 do id
  browser_hash    BLOB    NOT NULL,              -- SHA-256 do cookie __Host-bsw_tx
  client_row_id   INTEGER NOT NULL REFERENCES oauth_clients(id),
  redirect_uri    TEXT    NOT NULL,
  resource        TEXT    NOT NULL,
  scope           TEXT    NOT NULL,
  code_challenge  TEXT    NOT NULL,
  state           TEXT,                          -- exatamente o recebido (pode ser NULL)
  authenticated_at INTEGER,                      -- login ok
  expires_at      INTEGER NOT NULL,              -- 10 min
  used_at         INTEGER
) STRICT;

CREATE TABLE oauth_grants (
  id             INTEGER PRIMARY KEY,
  public_id      TEXT    NOT NULL UNIQUE,        -- "grant_…"
  client_row_id  INTEGER NOT NULL REFERENCES oauth_clients(id),
  label          TEXT    NOT NULL,
  resource       TEXT    NOT NULL,
  scope          TEXT    NOT NULL,
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,               -- teto absoluto
  last_used_at   INTEGER,
  revoked_at     INTEGER
) STRICT;
CREATE UNIQUE INDEX one_active_label ON oauth_grants(label, client_row_id) WHERE revoked_at IS NULL;
-- grants vencidos são marcados revoked_at antes de criar outro (§4.5), então o índice nunca trava por expiração

CREATE TABLE oauth_codes (
  code_hash       BLOB    PRIMARY KEY,
  grant_id        INTEGER NOT NULL REFERENCES oauth_grants(id),
  redirect_uri    TEXT    NOT NULL,
  resource        TEXT    NOT NULL,
  code_challenge  TEXT    NOT NULL,
  expires_at      INTEGER NOT NULL,
  used_at         INTEGER
) STRICT;

CREATE TABLE oauth_tokens (
  token_hash   BLOB    PRIMARY KEY,
  kind         TEXT    NOT NULL CHECK (kind IN ('access', 'refresh')),
  grant_id     INTEGER NOT NULL REFERENCES oauth_grants(id),
  family_id    TEXT    NOT NULL,
  code_hash    BLOB,                             -- código que originou (revogar em reuso)
  expires_at   INTEGER NOT NULL,
  used_at      INTEGER,
  revoked_at   INTEGER
) STRICT;

CREATE TABLE known_devices (
  token_hash  BLOB PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  revoked_at  INTEGER
) STRICT;
CREATE TABLE panel_sessions (                    -- só T18
  token_hash  BLOB PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  last_seen   INTEGER NOT NULL, revoked_at INTEGER
) STRICT;

CREATE TABLE pending_deletions (
  confirm_hash  BLOB    PRIMARY KEY,
  target        TEXT    NOT NULL,                -- public_id
  grant_id      INTEGER NOT NULL REFERENCES oauth_grants(id),
  expires_at    INTEGER NOT NULL,                -- 5 min
  used_at       INTEGER
) STRICT;

CREATE TABLE daily_usage (
  day TEXT PRIMARY KEY, writes INTEGER NOT NULL, bytes INTEGER NOT NULL
) STRICT;
CREATE TABLE audit (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, event TEXT NOT NULL,
  grant_id INTEGER, target TEXT                  -- public_id, nunca conteúdo
) STRICT;
CREATE TABLE meta (                              -- restore_epoch, versão do esquema etc.
  key TEXT PRIMARY KEY, value TEXT NOT NULL
) STRICT;

CREATE INDEX oauth_tokens_grant ON oauth_tokens(grant_id);
CREATE INDEX oauth_tokens_family ON oauth_tokens(family_id);
CREATE INDEX audit_at ON audit(at);

CREATE INDEX oauth_tokens_code ON oauth_tokens(code_hash);
CREATE INDEX conversations_project ON conversations(project_id);
CREATE INDEX contexts_trash_root ON contexts(trash_root) WHERE trash_root IS NOT NULL;
CREATE INDEX conversations_trash_root ON conversations(trash_root) WHERE trash_root IS NOT NULL;
CREATE INDEX messages_trash_root ON messages(trash_root) WHERE trash_root IS NOT NULL;
