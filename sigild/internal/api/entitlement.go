package api

// ENTITLEMENT ENFORCEMENT (Phase 55).
//
// Until this file, entitlement was REPORTED and never ENFORCED (ADR 0040,
// limitation 8): GET /v1/billing/subscription would tell a client its account
// was canceled, and every route served it anyway. This closes that gap — very
// deliberately, and very narrowly.
//
// ---------------------------------------------------------------------------
// ⭐ THE ONE RULE THIS FILE EXISTS TO PROTECT: READS ARE NEVER REFUSED.
// ---------------------------------------------------------------------------
//
// This product holds a customer's second factor. Gating it on payment status
// means a declined card can lock a person out of their own bank login. That is
// not a billing inconvenience; it is a security failure we would have caused.
// So the asymmetry is not a policy toggle, it is the SHAPE OF THE CODE:
//
//   - requireEntitlement is called from exactly THREE handlers, and all three
//     are WRITES: opsAppend, keyEnvelopePut, vaultGrantCreate.
//   - NO read handler calls it. Not opsList, not opsVerify, not keyEnvelopeGet,
//     not deviceKeyEnvelopeIndex, not keyEnvelopeList, not the hybrid-key fetch,
//     not the account or device listings, and not any billing route.
//     The read path contains NO entitlement code at all: there is nothing to
//     misconfigure, no store to be down, and no branch that could refuse.
//   - entitlement_test.go PARSES THIS PACKAGE'S AST and fails if that call set
//     ever changes. The asymmetry is mechanically enforced, not remembered.
//
// A customer whose subscription has fully lapsed can therefore always: read
// every op in every vault they hold (i.e. generate every 2FA code they already
// have), collect every key envelope addressed to them, enumerate which vaults
// hold a key for them, publish a hybrid key, enroll and revoke devices, delete a
// stale envelope, mint an invite, and run checkout to pay.
//
// ---------------------------------------------------------------------------
// ⭐ AND — ESTABLISHING KEY ACCESS WITHIN YOUR OWN ACCOUNT IS ALSO NEVER REFUSED
// ---------------------------------------------------------------------------
//
// "Reads are never refused" was not enough, and a live reproduction showed why.
// Past grace, a customer whose phone had just died could enroll a replacement —
// and then could not receive the VAULT KEY for it (PUT …/keys/{device} => 402),
// so the new phone downloaded ciphertext it could never decrypt, and printing a
// RECOVERY KIT was refused too. A read-only guarantee over data you cannot
// decrypt is not a guarantee. GETTING YOUR DATA OUT IS NEVER REFUSED, and that
// necessarily includes establishing the key material needed to read it:
//
//	sameAccountRecipient() exempts a key-envelope deposit AND the grant that
//	accompanies it whenever the recipient device belongs to the CALLER'S OWN
//	ACCOUNT — which covers replacing a lost device and generating or covering a
//	recovery kit (a kit is an ordinary member device of the same account).
//
// What is still refused after grace: new op-log WRITES, and shares to a device
// of a DIFFERENT account. Those grow what we store for a non-paying customer, or
// extend the product to somebody else; neither is "getting your own data out".
//
// A device with no account (a pre-0005 row) is exempt from the gate entirely, so
// the exemption cannot be reached by forging an empty account id — there is no
// account id on the wire anywhere (ADR 0040 §2).
//
// ---------------------------------------------------------------------------
// THE GRACE PERIOD
// ---------------------------------------------------------------------------
//
// Refusal never follows a payment event directly. billing.Status already models
// past_due as ENTITLED (a failed renewal is a retry window, not a cancellation),
// and on top of that this adds a configurable grace period measured from the
// LATER of the subscription's last update and its paid-through date. Inside
// grace everything still works and the client is WARNED — response headers on
// every gated write, an additive block on GET /v1/billing/subscription, an audit
// line and a metric. Only after grace expires does a write get a 402.
//
// ---------------------------------------------------------------------------
// FAIL OPEN, ALWAYS
// ---------------------------------------------------------------------------
//
// Every uncertainty resolves to ALLOW:
//
//	enforcement not configured        -> allow (and do no store work at all)
//	the subscription store errors     -> allow  (a database blip must never cost
//	                                             a customer their vault)
//	the account row cannot be read    -> allow
//	no anchor date can be established -> allow  (we will not date a lapse we
//	                                             cannot date)
//	the device carries no account     -> allow  (that is an AUTHORIZATION state,
//	                                             already refused upstream with a
//	                                             403; it must never be re-served
//	                                             as a payment problem)
//
// ---------------------------------------------------------------------------
// 402 IS NOT 401 AND NOT 403
// ---------------------------------------------------------------------------
//
// A refusal is HTTP 402 Payment Required with its own machine-readable body
// (error code "payment_required"), never the coarse "unauthorized"/"forbidden"
// envelopes. That is deliberate on both sides:
//
//   - a client must be able to tell "pay to continue" from "your key is wrong"
//     and from "you may not touch this vault", and act on it (the body names the
//     checkout route);
//   - the coarse auth bodies exist so a prober cannot learn WHICH check failed.
//     No such oracle is created here, because the gate runs strictly AFTER
//     authentication AND authorization have both succeeded. An unauthenticated
//     or unauthorized caller gets its 401/403 exactly as before and can never
//     see a 402 — so the only party who learns an account's billing state is a
//     verified member of that account, which GET /v1/billing/subscription
//     already tells them.
//
// ZERO-KNOWLEDGE, unchanged: nothing here reads a blob, a key, a password or a
// plaintext. The audit lines and the metric carry an account id, a status from
// the closed billing enum, a timestamp and a fixed surface name — never a token,
// key, signature, nonce or one byte of ciphertext.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// DefaultEntitlementGrace is the grace period applied when enforcement is on and
// no explicit duration was configured: FOURTEEN DAYS after entitlement lapses,
// on top of whatever retry window the provider already gave past_due.
//
// It is deliberately long. The cost of being too generous is that somebody uses
// the product free for two extra weeks. The cost of being too strict is that
// somebody cannot log in to their bank. Those are not comparable.
//
// It is exported so cmd/server and this package share ONE default rather than
// two that can drift.
const DefaultEntitlementGrace = 14 * 24 * time.Hour

// Response headers that WARN a client its account is not currently entitled.
// They are set on gated WRITE responses only — inside grace (on the successful
// 2xx) and on the 402 itself. An entitled account's responses carry none of
// them, so nothing about the normal path changes.
const (
	// headerEntitlement is "grace" or "lapsed".
	headerEntitlement = "X-Sigil-Entitlement"
	// headerEntitlementStatus is the billing status from the closed enum.
	headerEntitlementStatus = "X-Sigil-Entitlement-Status"
	// headerEntitlementGraceEnds is the RFC3339 instant at which writes stop.
	headerEntitlementGraceEnds = "X-Sigil-Entitlement-Grace-Ends"
)

// entitlementOutcome is the verdict of one check. It is a CLOSED set: it is the
// only label on the enforcement metric, and metrics.go materializes exactly
// these four.
type entitlementOutcome string

const (
	// entitlementEntitled: the account's subscription is live (including
	// past_due, which billing.Status.Entitled deliberately includes).
	entitlementEntitled entitlementOutcome = "entitled"
	// entitlementGrace: entitlement has lapsed but the grace period is still
	// running. The request is SERVED and the client is warned.
	entitlementGrace entitlementOutcome = "grace"
	// entitlementRefused: lapsed, and grace has expired. WRITES only -> 402.
	entitlementRefused entitlementOutcome = "refused"
	// entitlementFailOpen: the check could not be completed (store fault,
	// unreadable account, or no anchor date). The request is SERVED.
	entitlementFailOpen entitlementOutcome = "fail_open"
)

// entitlementOutcomes is that closed set in a stable order.
var entitlementOutcomes = []entitlementOutcome{
	entitlementEntitled, entitlementGrace, entitlementRefused, entitlementFailOpen,
}

// Enforcement surfaces. A fixed enum recorded in the audit line (never a metric
// label) so an operator can see WHICH write was refused. All three are writes;
// there is no read surface, by construction.
const (
	entitlementSurfaceOpsAppend      = "ops_append"
	entitlementSurfaceKeyEnvelopePut = "key_envelope_put"
	entitlementSurfaceVaultGrant     = "vault_grant"
)

// entitlementPolicy is the configured enforcement policy. The ZERO VALUE IS OFF,
// which is what makes "unset behaves exactly as before" structural rather than
// conditional: an un-opted-in router holds a zero policy and requireEntitlement
// returns on its first line.
type entitlementPolicy struct {
	// Active is true only when enforcement was explicitly switched on AND the
	// device model AND billing are both live (NewRouter checks all three).
	Active bool
	// Grace is how long after entitlement lapses writes keep working.
	Grace time.Duration
}

// entitlementDecision is one evaluation's result.
type entitlementDecision struct {
	Outcome entitlementOutcome
	// Status is the account's billing status (StatusNone when it never
	// subscribed). Safe to surface to a member of that account.
	Status billing.Status
	// GraceEndsAt is when writes stop (grace), or when they stopped (refused).
	// Zero for entitled / fail_open.
	GraceEndsAt time.Time
	// FailOpenReason is a fixed enum naming WHY the check could not complete. It
	// goes to the audit log only, and is empty unless Outcome is fail_open.
	FailOpenReason string
}

// Warn reports whether the client should be told something is wrong.
func (d entitlementDecision) Warn() bool {
	return d.Outcome == entitlementGrace || d.Outcome == entitlementRefused
}

// Fail-open reasons. Audit-log only; never a response body, never a metric label.
const (
	failOpenStoreError   = "subscription_store_error"
	failOpenNoAccountRow = "account_unreadable"
	failOpenNoAnchor     = "no_lapse_anchor"
)

// decide is the PURE half of the policy: given a status, the instant entitlement
// last plausibly held (the "anchor"), and now, what happens?
//
// The anchor is never in the future-proofing business: a ZERO anchor means "we
// cannot date this lapse", and an undatable lapse is served, not refused.
func (p entitlementPolicy) decide(status billing.Status, anchor, now time.Time) entitlementDecision {
	if status.Entitled() {
		return entitlementDecision{Outcome: entitlementEntitled, Status: status}
	}
	if anchor.IsZero() {
		return entitlementDecision{
			Outcome: entitlementFailOpen, Status: status, FailOpenReason: failOpenNoAnchor,
		}
	}
	grace := p.Grace
	if grace <= 0 {
		grace = DefaultEntitlementGrace
	}
	ends := anchor.Add(grace)
	if now.Before(ends) {
		return entitlementDecision{Outcome: entitlementGrace, Status: status, GraceEndsAt: ends}
	}
	return entitlementDecision{Outcome: entitlementRefused, Status: status, GraceEndsAt: ends}
}

// lapseAnchor returns the instant from which a lapsed subscription's grace runs:
// the LATER of the record's last update and its paid-through date.
//
// Taking the later of the two is the customer-favouring choice, on purpose. A
// subscription canceled mid-period keeps working until the period it was ALREADY
// PAID FOR ends, and only then does grace start. Any later touch of the row
// (including a fresh StartCheckout) pushes the anchor forward, which can only
// EXTEND service — the direction a mistake here must always fail in.
func lapseAnchor(sub store.Subscription) time.Time {
	anchor := sub.UpdatedAt
	if sub.CurrentPeriodEnd.After(anchor) {
		anchor = sub.CurrentPeriodEnd
	}
	return anchor
}

// evaluateEntitlement reads the account's billing state and decides.
//
// TWO ANCHORS, ONE RULE:
//
//   - A subject WITH a subscription record anchors on lapseAnchor(record).
//   - A subject with NO record has never subscribed, and anchors on its ACCOUNT
//     CREATION time. That makes the grace period double as the window in which a
//     new account must buy — otherwise "never subscribe" would be a permanent
//     free tier and enforcement would close nothing. It is a trial by side
//     effect and it is named as such in the deployment notes; there is no
//     separate trial mechanism in this server.
//
// Every failure path returns fail_open.
func (h *handlers) evaluateEntitlement(ctx context.Context, accountID string, now time.Time) entitlementDecision {
	subs := h.cfg.Billing.Subscriptions
	if subs == nil {
		return entitlementDecision{Outcome: entitlementFailOpen, FailOpenReason: failOpenStoreError}
	}

	sub, err := subs.GetSubscription(ctx, accountID)
	switch {
	case err == nil:
		status := sub.Status
		if status == "" {
			status = billing.StatusNone
		}
		if status.Entitled() {
			// The common case: one store read, no account lookup, no clock maths.
			return entitlementDecision{Outcome: entitlementEntitled, Status: status}
		}
		return h.policy().decide(status, lapseAnchor(sub), now)

	case errors.Is(err, store.ErrSubscriptionNotFound):
		// Never subscribed. Anchor on the account's creation.
		if h.devices == nil {
			return entitlementDecision{
				Outcome: entitlementFailOpen, Status: billing.StatusNone,
				FailOpenReason: failOpenNoAccountRow,
			}
		}
		acct, aerr := h.devices.GetAccount(ctx, accountID)
		if aerr != nil {
			return entitlementDecision{
				Outcome: entitlementFailOpen, Status: billing.StatusNone,
				FailOpenReason: failOpenNoAccountRow,
			}
		}
		return h.policy().decide(billing.StatusNone, acct.CreatedAt, now)

	default:
		return entitlementDecision{
			Outcome: entitlementFailOpen, FailOpenReason: failOpenStoreError,
		}
	}
}

// policy returns this router's configured enforcement policy.
func (h *handlers) policy() entitlementPolicy { return h.entitlement }

// entitlementActive reports whether this router enforces entitlement at all.
func (h *handlers) entitlementActive() bool { return h.entitlement.Active }

// paymentRequiredResponse is the 402 body. It is MACHINE-READABLE and ACTIONABLE
// on purpose: a client must be able to distinguish this from an auth failure
// without parsing prose, tell the user exactly what is still available, and send
// them straight to checkout.
//
// It contains no secret and no data the caller could not already read from
// GET /v1/billing/subscription — which it has been authenticated and authorized
// to call throughout.
type paymentRequiredResponse struct {
	// Error is the stable code. Deliberately NOT "unauthorized"/"forbidden".
	Error  string `json:"error"`
	Detail string `json:"detail"`
	// SubscriptionStatus is the caller's own account status, from the closed
	// billing enum.
	SubscriptionStatus string `json:"subscription_status"`
	// GraceEndedAt is when writes stopped, RFC3339.
	GraceEndedAt string `json:"grace_ended_at,omitempty"`
	// ReadsAllowed / KeyRecoveryAllowed are ALWAYS true, and BOTH are now
	// actually true — KeyRecoveryAllowed used to claim more than the code did.
	// It means: depositing a wrapped vault key to a device of THIS account, and
	// the grant that goes with it, are exempt from this gate, so a replacement
	// device can still be given the keys and a recovery kit can still be created
	// or extended. It does NOT mean sharing to another account.
	ReadsAllowed       bool `json:"reads_allowed"`
	KeyRecoveryAllowed bool `json:"key_recovery_allowed"`
	// CheckoutPath is where to go to fix it.
	CheckoutPath string `json:"checkout_path"`
}

// writePaymentRequired writes the 402.
func writePaymentRequired(w http.ResponseWriter, dec entitlementDecision) {
	resp := paymentRequiredResponse{
		Error: "payment_required",
		Detail: "this account's subscription has lapsed and its grace period has ended, " +
			"so new writes are refused; reading your existing vault contents, collecting " +
			"your key envelopes, and giving another device of THIS account the key to a " +
			"vault (including creating a recovery kit) are NOT affected",
		SubscriptionStatus: string(dec.Status),
		ReadsAllowed:       true,
		KeyRecoveryAllowed: true,
		CheckoutPath:       "/v1/billing/checkout",
	}
	if !dec.GraceEndsAt.IsZero() {
		resp.GraceEndedAt = dec.GraceEndsAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusPaymentRequired, resp)
}

// setEntitlementHeaders warns the client on a response that is still being
// served (grace) or is being refused (lapsed). Called before any body is
// written, so the headers land on both.
func setEntitlementHeaders(w http.ResponseWriter, dec entitlementDecision) {
	switch dec.Outcome {
	case entitlementGrace:
		w.Header().Set(headerEntitlement, "grace")
	case entitlementRefused:
		w.Header().Set(headerEntitlement, "lapsed")
	default:
		return
	}
	w.Header().Set(headerEntitlementStatus, string(dec.Status))
	if !dec.GraceEndsAt.IsZero() {
		w.Header().Set(headerEntitlementGraceEnds, dec.GraceEndsAt.UTC().Format(time.RFC3339))
	}
}

// requireEntitlement is THE gate, and the ONLY exported-to-the-package entry
// point of this file.
//
// ⚠️ CALL IT FROM WRITE HANDLERS ONLY, AND ONLY AFTER authentication AND
// authorization have both succeeded. Both halves matter: calling it from a read
// handler would break the guarantee this whole file exists to make, and calling
// it before authorization would turn the 402 into an oracle on account billing
// state for callers who were going to be refused anyway.
//
// It reports whether the request may proceed. When it returns false it has
// ALREADY written the 402 response.
func (h *handlers) requireEntitlement(w http.ResponseWriter, r *http.Request, dev store.Device, surface string) bool {
	if !h.entitlementActive() {
		// Not configured: no store read, no header, no log line, no metric.
		// Byte-identical to a server built before this file existed.
		return true
	}
	if dev.AccountID == "" {
		// An authorization data state (a device enrolled by a pre-account binary),
		// already refused with a coarse 403 by authorizeVault. It must never be
		// re-served as a payment problem, and there is no subject to evaluate.
		return true
	}

	dec := h.evaluateEntitlement(r.Context(), dev.AccountID, time.Now().UTC())
	h.metrics.incEntitlement(dec.Outcome)

	switch dec.Outcome {
	case entitlementEntitled:
		return true
	case entitlementFailOpen:
		h.auditEntitlementFailOpen(r, dev.AccountID, surface, dec.FailOpenReason)
		return true
	case entitlementGrace:
		setEntitlementHeaders(w, dec)
		h.auditEntitlementGrace(r, dev.AccountID, dev.ID, surface, dec)
		return true
	default: // entitlementRefused
		setEntitlementHeaders(w, dec)
		h.auditEntitlementRefused(r, dev.AccountID, dev.ID, surface, dec)
		writePaymentRequired(w, dec)
		return false
	}
}

// sameAccountRecipient reports whether recipientDeviceID names a device in the
// SAME account as the authenticated caller.
//
// ⭐ THIS IS THE "GETTING YOUR OWN DATA OUT IS NEVER REFUSED" TEST. A true
// verdict exempts the request from requireEntitlement, because delivering a
// vault key to your own device — a replacement phone, or a recovery kit, which
// is just another member device — is how a lapsed customer keeps access to data
// they already have. A false verdict (another account's device, an unknown
// device, no account, no registry) changes nothing: the gate runs as usual.
//
// It is DELIBERATELY conservative. Any doubt resolves to "not exempt", so a
// store fault cannot be used to bypass enforcement — and enforcement is itself
// fail-open, so the customer is never the one who pays for the ambiguity.
func (h *handlers) sameAccountRecipient(ctx context.Context, dev store.Device, recipientDeviceID string) bool {
	if h.devices == nil || dev.AccountID == "" || recipientDeviceID == "" {
		return false
	}
	if recipientDeviceID == dev.ID {
		return true
	}
	recipient, err := h.devices.GetDevice(ctx, recipientDeviceID)
	if err != nil {
		return false
	}
	return recipient.AccountID != "" && recipient.AccountID == dev.AccountID
}

// entitlementJSON is the ADDITIVE block on GET /v1/billing/subscription. It is
// omitted entirely when enforcement is off, so that response stays byte-identical
// for every server that has not opted in.
//
// It is the WARNING CHANNEL FOR READ-ONLY CLIENTS. A client that only ever reads
// is never refused and never sees a warning header, so without this it would
// discover the lapse only when it first tried to write. Here it can tell the
// user days ahead.
type entitlementJSON struct {
	// Enforced is always true when this block is present.
	Enforced bool `json:"enforced"`
	// Writes is "allowed" (entitled or fail-open), "grace", or "refused".
	Writes string `json:"writes"`
	// Reads is ALWAYS "allowed". It is a constant on purpose: it states the
	// guarantee in the payload rather than only in the documentation.
	Reads string `json:"reads"`
	// GraceEndsAt is when writes stop, or stopped. Omitted when not applicable.
	GraceEndsAt string `json:"grace_ends_at,omitempty"`
}

// entitlementBlock renders a decision for the subscription route, or nil when
// enforcement is off.
func entitlementBlock(active bool, dec entitlementDecision) *entitlementJSON {
	if !active {
		return nil
	}
	writes := "allowed"
	switch dec.Outcome {
	case entitlementGrace:
		writes = "grace"
	case entitlementRefused:
		writes = "refused"
	}
	block := &entitlementJSON{Enforced: true, Writes: writes, Reads: "allowed"}
	if !dec.GraceEndsAt.IsZero() {
		block.GraceEndsAt = dec.GraceEndsAt.UTC().Format(time.RFC3339)
	}
	return block
}
