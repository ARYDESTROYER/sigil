-- 0003_billing: subscription records and the processed-webhook ledger for the
-- billing layer (Phase 45).
--
-- It applies cleanly ON TOP OF 0002_devices and touches NOTHING in
-- sigil_vault_ops, sigil_devices, sigil_enrollment_tokens or
-- sigil_device_grants: the op-log rows and their tamper-evidence hash chain, and
-- the whole device-auth model, are untouched. A database migrated from 0001/0002
-- keeps serving every existing mode byte-for-byte unchanged, and a deployment
-- that never enables billing simply has two empty tables.
--
-- ############################ NO CARD DATA #################################
--
-- There is deliberately NO column here that can hold a primary account number,
-- a CVV, an expiry date, a cardholder name or a billing address — and none that
-- can hold an email address or a phone number either. sigild uses HOSTED
-- checkout only: the payment instrument exists solely between the customer's
-- browser and the payment provider, so this database never enters PCI scope.
--
-- What IS stored is a set of OPAQUE PROVIDER HANDLES (customer_ref,
-- subscription_ref, event_id). They let an operator reconcile a record against
-- the provider dashboard. They cannot be used to charge anyone.
--
-- ZERO-KNOWLEDGE, unchanged: nothing here relates to vault contents. This is
-- pure DDL; it performs no cryptography and decodes nothing.

-- One billing record per subject. `subject` is OUR identifier for the payer —
-- in the current dev model the enrolled device ID that ran checkout — never a
-- provider identifier and never an email address.
--
-- `status` is the subscription state machine's state
-- ('none' | 'trialing' | 'active' | 'past_due' | 'canceled'); the legal
-- transitions are defined in internal/billing/state.go and enforced in the
-- application, inside the same transaction that dedupes the event.
--
-- `last_event_at` is the ORDERING GUARD: an inbound webhook older than this is
-- discarded, so an out-of-order delivery cannot regress a live subscription.
CREATE TABLE IF NOT EXISTS sigil_subscriptions (
	subject            text        PRIMARY KEY,
	provider           text        NOT NULL,
	customer_ref       text        NOT NULL DEFAULT '',
	subscription_ref   text        NOT NULL DEFAULT '',
	status             text        NOT NULL,
	current_period_end timestamptz,
	last_event_at      timestamptz,
	created_at         timestamptz NOT NULL DEFAULT now(),
	updated_at         timestamptz NOT NULL DEFAULT now()
);

-- Subject resolution: most provider events name only their own subscription
-- handle, so the server looks the subject up by (provider, subscription_ref).
-- The partial index skips rows that have not been bound to a provider
-- subscription yet.
CREATE INDEX IF NOT EXISTS sigil_subscriptions_by_provider_ref
	ON sigil_subscriptions (provider, subscription_ref)
	WHERE subscription_ref <> '';

-- The processed-webhook ledger. Every payment provider redelivers events —
-- on its own retry schedule, and again whenever an operator replays one from a
-- dashboard — so handling MUST be idempotent.
--
-- The (provider, event_id) PRIMARY KEY is what makes it idempotent, and it is
-- enforced by the DATABASE, not by application timing: the insert is an
-- ON CONFLICT DO NOTHING inside the SAME transaction that applies the state
-- change, so two concurrent deliveries of one event resolve to exactly one
-- applied transition and one no-op.
--
-- event_type is the NORMALIZED type (checkout_completed, subscription_renewed,
-- ...), never the provider's raw payload — the payload is never persisted.
CREATE TABLE IF NOT EXISTS sigil_billing_processed_events (
	provider     text        NOT NULL,
	event_id     text        NOT NULL,
	event_type   text        NOT NULL DEFAULT '',
	subject      text        NOT NULL DEFAULT '',
	processed_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (provider, event_id)
);

-- Operational: retention sweeps and "what happened to this subject" queries.
CREATE INDEX IF NOT EXISTS sigil_billing_processed_events_by_time
	ON sigil_billing_processed_events (processed_at);
