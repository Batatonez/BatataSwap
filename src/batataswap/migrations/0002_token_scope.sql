-- Scope efetivo de cada token (T08, revisão S3). NULL = herda o scope do grant (linhas antigas).
ALTER TABLE oauth_tokens ADD COLUMN scope TEXT;
