//! ENTITLEMENT — what the server has actually told *this* client about its
//! subscription, and what that means for what still works.
//!
//! # STATUS: PRE-AUDIT — UNAUDITED — DEV / LOCALHOST / PLAIN HTTP
//!
//! [ADR 0043](../../../docs/decisions/0043-entitlement-enforcement.md) made the
//! server able to refuse a lapsed account — and only in one direction. The
//! asymmetry is the whole point, and it is what this module exists to render
//! honestly:
//!
//! | | lapsed past grace |
//! |---|---|
//! | new op-log **writes** (push) | ⛔ refused with `402` |
//! | **reads** — pulling every vault, generating every code you already have | ✅ never refused |
//! | **key recovery within your own account** — giving a replacement device the vault key, generating or covering a RECOVERY KIT | ✅ never refused |
//!
//! A client that renders a `402` as "HTTP error 402" turns a billing problem
//! into what looks like data loss. So the refusal is parsed into
//! [`EntitlementView`], which states the status, when writes stopped, where to
//! pay, and — loudly — what is **still** available.
//!
//! # What this client can and cannot observe
//!
//! ⚠️ **Stated plainly because the gap is real.** `sigild` emits three
//! entitlement signals: the `402` body, `X-Sigil-Entitlement*` **response
//! headers** on gated writes that are in grace, and an additive `entitlement`
//! block on `GET /v1/billing/subscription`.
//!
//! The desktop consumes **two** of them:
//!
//! * the **`402` body**, through the `sigil-cli` library calls it already makes
//!   ([`EntitlementView::from_payment_required`]);
//! * the **subscription block**, through
//!   [`DeviceConfig::subscription`](crate::net::DeviceConfig::subscription)
//!   ([`EntitlementView::from_subscription_block`]).
//!
//! ⭐ The second one is what makes **grace** reachable, and it had to be: the
//! `402` can only ever say *already too late*, so a client that reads nothing
//! else learns about a lapse at the moment it is refused — which is precisely the
//! surprise a grace period exists to prevent. It is fetched with the library's
//! own signed transport, so there is still no second HTTP client and no second
//! request-signing path under `desktop/`.
//!
//! What the desktop still cannot see is the **response headers** on a
//! served-in-grace write: the library's transport returns a body and drops
//! headers. That costs nothing here, because the subscription route carries the
//! same warning and is polled at startup, after a server is configured, and after
//! each push.

use crate::DesktopError;

/// Writes are refused: the value of `writes` when the account has lapsed past
/// its grace period.
pub const WRITES_REFUSED: &str = "refused";
/// Writes still work, but the account has lapsed and the clock is running.
pub const WRITES_GRACE: &str = "grace";
/// Writes are being served.
pub const WRITES_ALLOWED: &str = "allowed";
/// Nothing has been observed yet (which is also what an un-enforcing server
/// looks like — the two are deliberately indistinguishable from out here).
pub const WRITES_UNKNOWN: &str = "unknown";

/// The two guarantees [ADR 0043](../../../docs/decisions/0043-entitlement-enforcement.md)
/// states as constants rather than as documentation. They are `"allowed"` in
/// every state, including a fully lapsed one.
pub const ALWAYS_ALLOWED: &str = "allowed";

/// What a UI should say about entitlement. PUBLIC facts only — this carries no
/// card data, no customer identity and no key material, and there is no such
/// field to add: the server never sends one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementView {
    /// Whether the server has actually told this client anything. `false` means
    /// "not observed" — NOT "entitled".
    pub known: bool,
    /// `"allowed"`, `"grace"`, `"refused"` or `"unknown"`.
    pub writes: String,
    /// Always [`ALWAYS_ALLOWED`]. Reading your existing vaults and generating
    /// the codes you already have is never gated on payment.
    pub reads: String,
    /// Always [`ALWAYS_ALLOWED`]. Depositing a vault key to another device of
    /// YOUR OWN account — a replacement phone, or a recovery kit — is exempt.
    pub key_recovery: String,
    /// The account's own subscription status from the server's closed billing
    /// enum (`none`/`trialing`/`active`/`past_due`/`canceled`), or `""`.
    pub subscription_status: String,
    /// RFC 3339 instant at which writes stop, or stopped. `""` when unknown.
    pub grace_ends_at: String,
    /// The server-named route to go and pay. `""` when unknown.
    pub checkout_path: String,
    /// A human sentence safe to render. Never secret.
    pub detail: String,
}

impl Default for EntitlementView {
    fn default() -> Self {
        Self::unknown()
    }
}

impl EntitlementView {
    /// The starting state: nothing observed.
    ///
    /// ⚠️ Deliberately NOT rendered as "you are paid up". A server with
    /// enforcement switched off and a server that simply has not refused
    /// anything yet look identical from a client, and claiming the happy answer
    /// for both would be a claim this client cannot support.
    #[must_use]
    pub fn unknown() -> Self {
        EntitlementView {
            known: false,
            writes: WRITES_UNKNOWN.to_string(),
            reads: ALWAYS_ALLOWED.to_string(),
            key_recovery: ALWAYS_ALLOWED.to_string(),
            subscription_status: String::new(),
            grace_ends_at: String::new(),
            checkout_path: String::new(),
            detail: "Nothing observed yet. This client learns about entitlement from the server's \
                     answer to a write; a server with enforcement switched off looks exactly the \
                     same from here."
                .to_string(),
        }
    }

    /// What a client knows after a gated write was SERVED.
    ///
    /// It proves the account was not refused. It does **not** prove the account
    /// is fully paid up: an account inside its grace period is also served, and
    /// the warning that says so travels in a response header this client cannot
    /// see (see the module note).
    #[must_use]
    pub fn write_accepted() -> Self {
        EntitlementView {
            known: true,
            writes: WRITES_ALLOWED.to_string(),
            detail: "The server accepted this device's last write. (An account inside its grace \
                     period is also served; that warning travels in a response header this client \
                     does not see.)"
                .to_string(),
            ..Self::unknown()
        }
    }

    /// What a client knows after reading a subscription from a server that does
    /// NOT enforce entitlement — the DEFAULT for every `sigild`.
    ///
    /// ⚠️ It is a fact about the SERVER, not a claim about the account: nothing
    /// is being refused because nothing is being enforced. A UI must show
    /// nothing at all for this state ([`Self::needs_attention`] is false).
    #[must_use]
    pub fn not_enforced(subscription_status: &str) -> Self {
        EntitlementView {
            known: true,
            writes: WRITES_ALLOWED.to_string(),
            subscription_status: subscription_status.to_string(),
            detail: "This server does not enforce payment, so nothing is being refused. (That is \
                     the default for a sigild; it says nothing about this account's billing.)"
                .to_string(),
            ..Self::unknown()
        }
    }

    /// Whether a UI should show a warning banner.
    #[must_use]
    pub fn needs_attention(&self) -> bool {
        self.writes == WRITES_REFUSED || self.writes == WRITES_GRACE
    }

    /// Parse the machine-readable `402` body
    /// (`{"error":"payment_required", ...}`), returning `None` for anything that
    /// is not one.
    ///
    /// ⭐ It only ever *reads*: an unparseable or hostile body downgrades to a
    /// generic refusal message rather than to a claim about the account.
    #[must_use]
    pub fn from_payment_required(body: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        if v.get("error").and_then(serde_json::Value::as_str)? != "payment_required" {
            return None;
        }
        let s = |k: &str| {
            v.get(k)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        Some(EntitlementView {
            known: true,
            writes: WRITES_REFUSED.to_string(),
            reads: ALWAYS_ALLOWED.to_string(),
            key_recovery: ALWAYS_ALLOWED.to_string(),
            subscription_status: s("subscription_status"),
            grace_ends_at: s("grace_ended_at"),
            checkout_path: s("checkout_path"),
            detail: {
                let d = s("detail");
                if d.is_empty() {
                    "This account's subscription has lapsed and its grace period has ended, so \
                     NEW WRITES are refused. Reading your vaults, generating the codes you \
                     already have, and giving another device of this account a vault key \
                     (including a recovery kit) are NOT affected."
                        .to_string()
                } else {
                    d
                }
            },
        })
    }

    /// Parse the additive `entitlement` block from
    /// `GET /v1/billing/subscription` — the **warning channel**, and the only
    /// signal that can say `"grace"`.
    ///
    /// Fetched by
    /// [`DeviceConfig::subscription`](crate::net::DeviceConfig::subscription),
    /// which drives the `sigil-cli` library's signed transport — so this is the
    /// one and only interpretation of the block under `desktop/`.
    ///
    /// `body` is the whole subscription response; a response with no
    /// `entitlement` key (enforcement off — the default for every sigild) yields
    /// `None`, which the caller reports as [`Self::not_enforced`].
    #[must_use]
    pub fn from_subscription_block(body: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        let block = v.get("entitlement")?;
        let writes = block
            .get("writes")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(WRITES_UNKNOWN)
            .to_string();
        let grace_ends_at = block
            .get("grace_ends_at")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let status = v
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_string();
        let detail = match writes.as_str() {
            WRITES_GRACE => format!(
                "⚠️ This account's subscription has LAPSED. Writes still work{}, then new writes \
                 will be refused. Reading your vaults and giving another of your own devices a \
                 vault key are never refused.",
                if grace_ends_at.is_empty() {
                    String::new()
                } else {
                    format!(" until {grace_ends_at}")
                }
            ),
            WRITES_REFUSED => "This account's subscription has lapsed and its grace period has \
                               ended, so NEW WRITES are refused. Reads and same-account key \
                               recovery are not."
                .to_string(),
            _ => {
                "The server is enforcing entitlement and this account is being served.".to_string()
            }
        };
        Some(EntitlementView {
            known: true,
            writes,
            reads: ALWAYS_ALLOWED.to_string(),
            key_recovery: ALWAYS_ALLOWED.to_string(),
            subscription_status: status,
            grace_ends_at,
            checkout_path: String::new(),
            detail,
        })
    }
}

/// If `e` is a payment refusal, the entitlement it carries.
///
/// A helper so a caller can update its cached view without matching the error
/// shape at every call site.
#[must_use]
pub fn observed(e: &DesktopError) -> Option<&EntitlementView> {
    match e {
        DesktopError::PaymentRequired { entitlement, .. } => Some(entitlement),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact body `sigild`'s `writePaymentRequired` produces (ADR 0043 §4).
    const BODY_402: &str = r#"{
      "error": "payment_required",
      "detail": "this account's subscription has lapsed and its grace period has ended, so new writes are refused; reading your existing vault contents, collecting your key envelopes, and giving another device of THIS account the key to a vault (including creating a recovery kit) are NOT affected",
      "subscription_status": "canceled",
      "grace_ended_at": "2026-07-01T00:00:00Z",
      "reads_allowed": true,
      "key_recovery_allowed": true,
      "checkout_path": "/v1/billing/checkout"
    }"#;

    #[test]
    fn a_402_body_becomes_an_actionable_view() {
        let v = EntitlementView::from_payment_required(BODY_402).expect("a 402 body");
        assert!(v.known && v.needs_attention());
        assert_eq!(v.writes, WRITES_REFUSED);
        // ⭐ The two guarantees are constants, in every state.
        assert_eq!(v.reads, ALWAYS_ALLOWED);
        assert_eq!(v.key_recovery, ALWAYS_ALLOWED);
        assert_eq!(v.subscription_status, "canceled");
        assert_eq!(v.grace_ends_at, "2026-07-01T00:00:00Z");
        assert_eq!(v.checkout_path, "/v1/billing/checkout");
        assert!(v.detail.contains("NOT affected"));
    }

    /// Anything that is not a payment refusal must not be read as one — a 403
    /// body, a 401 body, prose, or empty.
    #[test]
    fn other_bodies_are_never_read_as_a_refusal() {
        for body in [
            r#"{"error":"forbidden"}"#,
            r#"{"error":"unauthorized"}"#,
            "not json at all",
            "",
            "{}",
        ] {
            assert!(
                EntitlementView::from_payment_required(body).is_none(),
                "misread {body:?}"
            );
        }
    }

    /// The GRACE warning — the state this client cannot yet reach over the
    /// network, but must render correctly the moment it can.
    #[test]
    fn the_subscription_block_carries_the_grace_warning() {
        let body = r#"{"status":"canceled","entitlement":{"enforced":true,"writes":"grace",
                       "reads":"allowed","grace_ends_at":"2026-08-11T00:00:00Z"}}"#;
        let v = EntitlementView::from_subscription_block(body).expect("block");
        assert_eq!(v.writes, WRITES_GRACE);
        assert!(v.needs_attention(), "grace must warn, not stay silent");
        assert!(v.detail.contains("2026-08-11T00:00:00Z"), "{}", v.detail);
        assert_eq!(v.reads, ALWAYS_ALLOWED);
        assert_eq!(v.subscription_status, "canceled");

        // Enforcement OFF: the block is absent and the response is unchanged.
        assert!(
            EntitlementView::from_subscription_block(r#"{"status":"active"}"#).is_none(),
            "an un-enforcing server must not produce a view"
        );
    }

    /// A server with enforcement OFF is a fact about the SERVER, not a claim
    /// about the account — and must render as NOTHING.
    #[test]
    fn an_unenforcing_server_needs_no_attention() {
        let v = EntitlementView::not_enforced("active");
        assert!(
            v.known,
            "we did observe something: that nothing is enforced"
        );
        assert!(
            !v.needs_attention(),
            "a server that enforces nothing must raise no banner"
        );
        assert_eq!(v.writes, WRITES_ALLOWED);
        assert_eq!(v.reads, ALWAYS_ALLOWED);
        assert_eq!(v.key_recovery, ALWAYS_ALLOWED);
        assert_eq!(v.subscription_status, "active");
        assert!(v.detail.contains("does not enforce"), "{}", v.detail);
    }

    /// "Not observed" must never masquerade as "paid up".
    #[test]
    fn unknown_is_not_a_claim() {
        let v = EntitlementView::unknown();
        assert!(!v.known && !v.needs_attention());
        assert_eq!(v.writes, WRITES_UNKNOWN);
        assert_eq!(v.reads, ALWAYS_ALLOWED);
        let ok = EntitlementView::write_accepted();
        assert!(ok.known && !ok.needs_attention());
        assert_eq!(ok.writes, WRITES_ALLOWED);
    }
}
