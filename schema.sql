-- schema.sql — applied as vault_owner. The application never runs this.

CREATE SCHEMA IF NOT EXISTS vault;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Encrypted cards. ciphertext = AES-256-GCM(nonce || ct || tag) over JSON {pan, exp_month, exp_year}.
CREATE TABLE vault.cards (
  token       text        PRIMARY KEY CHECK (token ~ '^tok_[0-9a-f]{32}$'),
  ciphertext  bytea       NOT NULL,
  last4       text        NOT NULL CHECK (last4 ~ '^[0-9]{4}$'),
  key_version int         NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Wrapped data-encryption keys. wrapped = KMS-encrypted 32-byte DEK. Highest version is current.
CREATE TABLE vault.deks (
  version    int         PRIMARY KEY,
  wrapped    bytea       NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only access log. Written only by functions.
CREATE TABLE vault.access_log (
  id          bigserial   PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  token       text        NOT NULL,
  op          text        NOT NULL,            -- 'put' | 'get'
  caller      text                             -- client cert serial for 'get'; null for 'put'
);
CREATE INDEX ON vault.access_log (at);
CREATE INDEX ON vault.access_log (token, at);

CREATE FUNCTION vault.put_card(p_token text, p_ciphertext bytea, p_last4 text, p_key_version int)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = vault, pg_temp AS $$
BEGIN
  INSERT INTO cards (token, ciphertext, last4, key_version)
  VALUES (p_token, p_ciphertext, p_last4, p_key_version);
  INSERT INTO access_log (token, op) VALUES (p_token, 'put');
END $$;

CREATE FUNCTION vault.get_card(p_token text, p_caller text)
RETURNS TABLE (ciphertext bytea, key_version int)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = vault, pg_temp AS $$
DECLARE
  global_recent int;
  token_recent  int;
BEGIN
  -- Serialize lookups so concurrent calls cannot all pass the count before any inserts (TOCTOU).
  PERFORM pg_advisory_xact_lock(hashtext('vault.get_card'));

  SELECT count(*) INTO global_recent FROM access_log
   WHERE op = 'get' AND at > now() - interval '1 minute';
  IF global_recent >= 300 THEN
    RAISE EXCEPTION 'vault: global lookup velocity exceeded' USING ERRCODE = 'P0001';
  END IF;

  SELECT count(*) INTO token_recent FROM access_log
   WHERE op = 'get' AND token = p_token AND at > now() - interval '1 hour';
  IF token_recent >= 20 THEN
    RAISE EXCEPTION 'vault: per-token lookup velocity exceeded' USING ERRCODE = 'P0001';
  END IF;

  INSERT INTO access_log (token, op, caller) VALUES (p_token, 'get', p_caller);
  RETURN QUERY SELECT c.ciphertext, c.key_version FROM cards c WHERE c.token = p_token;
END $$;

CREATE FUNCTION vault.list_deks()
RETURNS TABLE (version int, wrapped bytea)
LANGUAGE sql SECURITY DEFINER SET search_path = vault, pg_temp AS $$
  SELECT version, wrapped FROM deks ORDER BY version;
$$;

CREATE FUNCTION vault.add_dek(p_wrapped bytea)
RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = vault, pg_temp AS $$
DECLARE v int;
BEGIN
  SELECT coalesce(max(version), 0) + 1 INTO v FROM deks;
  INSERT INTO deks (version, wrapped) VALUES (v, p_wrapped);
  RETURN v;
END $$;

-- Roles. On Cloud SQL both are IAM-authenticated users; no passwords exist.
CREATE ROLE vault_app     LOGIN;   -- the running service
CREATE ROLE vault_rotator LOGIN;   -- the DEK rotation job

REVOKE ALL ON ALL TABLES    IN SCHEMA vault FROM PUBLIC, vault_app, vault_rotator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA vault FROM PUBLIC;
GRANT USAGE ON SCHEMA vault TO vault_app, vault_rotator;

GRANT EXECUTE ON FUNCTION vault.put_card(text, bytea, text, int) TO vault_app;
GRANT EXECUTE ON FUNCTION vault.get_card(text, text)             TO vault_app;
GRANT EXECUTE ON FUNCTION vault.list_deks()                      TO vault_app, vault_rotator;
GRANT EXECUTE ON FUNCTION vault.add_dek(bytea)                   TO vault_rotator;
