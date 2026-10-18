-- O migrador não tem a chave: invalida chaves antigas, sem apagar mensagens.
UPDATE message_batches SET client_batch_key = NULL;
ALTER TABLE oauth_transactions ADD COLUMN device_key TEXT;
CREATE INDEX transactions_device ON oauth_transactions(device_key, expires_at);
CREATE INDEX audit_grant_event ON audit(grant_id,event,at);
CREATE INDEX deletion_grant_pending ON pending_deletions(grant_id, expires_at) WHERE used_at IS NULL;
CREATE INDEX refresh_family_usage ON oauth_tokens(family_id, used_at) WHERE kind = 'refresh';
