ALTER TABLE relay.mail_telegram_claims
    ADD CONSTRAINT mail_telegram_claims_machine_key_unique UNIQUE (requested_by_machine, idempotency_key);
