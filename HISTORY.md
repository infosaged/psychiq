# Psychic IQ — Development History

## 2026-07-23

### AdMob & Billing go live
- AdMob app verification cleared ("Getting ready" status was normal new-app throttling, not an error); ads began serving same day.
- Confirmed a real in-app purchase (card back) completed end-to-end on Internal testing (versionCode 9).
- Promoted versionCode 9 to Production (Submission 8, published same day) — this was the first production build with any working ads/IAP at all; the original production release (versionCode 8) had shipped with no native ad/billing bridge.

### Target API level (Play policy deadline)
- Play Console flagged a hard Aug 31 2026 deadline: app must target API 36, was targeting 35.
- Bumped `targetSdkVersion` 35 → 36 in `app/build.gradle` (`compileSdkVersion` was already 36, so no dependency changes needed).

### Certificate screen cleanup
- Removed the public share-URL text shown at the top and bottom of the "View my certificate" screen (`psychic-test.html`) — share/copy-link buttons unaffected.
- Fixed a "Wrong! 2 **lifes** left" → "lives" pluralization typo in game-over messaging.
- (Caught mid-flow: the cert-URL fix had been edited locally but never pushed/deployed — Railway was still serving the old version. Pushed it properly.)

### Store listing review (ASO)
- Found two of five phone screenshots showing a visible tester account name ("May16TesterDRW") — needs re-capture from a clean account before relying on these for App Campaigns or search ranking.
- Noted the screenshot set is missing an actual end-of-game results screen (final score/achievements/certificate), arguably the strongest conversion asset for this app.

### Purchase entitlement sync bug (real money affected)
- User's $2.99 Stats (`analytics_dashboard`) purchase didn't survive a reinstall/login; a card-back purchase appeared to survive but was actually an illusion — the *selected* card design (`card_back_id`) persists via a separate profile field, decoupled from actual purchase entitlement (`purchases` column).
- Root cause, confirmed via `railway logs --http --path /api/purchases` (zero requests ever reached the backend) and a direct production DB query: `onPurchaseResult`/`onRestorePurchases` posted to `/api/purchases` fire-and-forget, silently swallowing any failure with no retry. Additionally, the native `restorePurchases()` bridge method existed but was **never called from JS** — no self-healing path.
- Fix: added a localStorage-backed pending-purchase retry queue (`syncPurchase`/`flushPendingPurchases`); wired `restorePurchases()` + queue flush into `afterLogin()` (single choke point for login/local-fallback/cold-start restore); fixed `LauncherActivity.java`'s `restorePurchases()` to pass real purchase tokens back to JS (previously sent bare product IDs, which would 400 against production's required receipt verification).
- Manually granted the two lost entitlements (`analytics_dashboard`, `special_celestial_powers`) directly in the production DB since the user had already paid for both.
- Shipped as versionCode 11 (1.8), uploaded to Internal testing, verified working, promoted to Production.

### Password reset email — actually never worked
- Discovered the "forgot password" flow had never delivered a single email in production, for any account, since the feature was built 2026-07-09 — `SMTP_HOST` and `APP_URL` were coded/documented but never actually set as Railway variables.
- Set `APP_URL=https://psychicscore.com`. Configured Gmail SMTP (App Password) — hit `ENETUNREACH` (Railway has no IPv6 route to Gmail's resolved address), worked around with forced IPv4 DNS resolution, then hit `Connection timeout` even over IPv4.
- Root cause: **Railway blocks outbound SMTP ports (25/465/587) entirely** — a platform-level anti-abuse policy, not fixable via credentials or DNS config.
- Migrated password reset email from `nodemailer`/SMTP to **Resend's HTTP API** (goes over HTTPS, which isn't blocked). Reused the account's existing verified `perseitylabs.com` domain (from the Personal Media Agent project) rather than verifying `psychicscore.com` separately — sends as `Psychic IQ <noreply@perseitylabs.com>`. Removed the `nodemailer` dependency and the now-unneeded IPv4 DNS hack. Confirmed delivered end-to-end.
- **Lesson for future features**: any outbound email or SMTP-dependent integration on this Railway deployment must use an HTTP-API provider (Resend, SendGrid, etc.) — raw SMTP is categorically blocked here regardless of setup.

### End of day
- versionCode 11 (1.8) — targetSdk 36, cert screen fix, purchase sync fix — promoted from Internal testing to Production.
- Password reset email fully functional via Resend.

## 2026-07-27

### Security review and fixes
- Full code/architecture review of the repo turned up an exploitable stored-XSS chain:
  `PUT /api/users/me` accepted `avatarData` with no validation, and the leaderboard/public
  cert pages rendered it via `innerHTML` as `<img src="...">` unescaped — any registered user
  could inject script that ran in every other visitor's browser (JWT lives in `localStorage`,
  so this was a full account-takeover path). Fixed on both ends: server now rejects anything
  that isn't a real `data:image/...;base64,...` URI, client escapes and re-validates before
  rendering.
- Also found the repo's local git remote had a live GitHub PAT embedded in the HTTPS URL —
  revoked it and switched the remote to the already-working SSH key instead.
- Hardening pass: rate-limited login/register/forgot-password (20 req/15min/IP), removed the
  hardcoded `JWT_SECRET` fallback (now a random per-process secret if unset, so a missing
  secret fails closed instead of open — confirmed Railway already has a real one set), capped
  `displayName` at 40 characters.

### Moved project to Code/Perseity Labs
- Relocated the whole project from `/home/infosage/Documents/Psychic IQ` to
  `/home/infosage/Code/Perseity Labs/Psychic IQ`, matching where every other active project
  already lives. Git history, notes, and this file moved with it.
- Folded the separate Bubblewrap/TWA project (previously its own untracked folder at
  `~/twa-psychicscore`) in as a `twa-psychicscore/` subfolder here, updating the signing
  keystore path in `twa-manifest.json` to match.
- Re-linked the Railway CLI from the new path and re-verified the full pipeline (push →
  GitHub → Railway deploy → live health check) and the Bubblewrap build both still work
  unchanged from the new location.
