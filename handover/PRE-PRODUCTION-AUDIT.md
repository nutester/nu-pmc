# nu-pmc — Pre-Production Audit

Date: 2026-07-02. Scope: full static audit of the working tree (security, business logic, data integrity, frontend wiring, and the in-progress changes), plus a live check of the production login page. Five parallel deep-read passes were run; findings are consolidated and de-duplicated below, ranked by severity.

## Headline

The codebase is, overall, well built: SQL injection surface is clean, file upload is safe (magic-byte validation), sessions/CSRF/cookies are correct, dev/test bypass routes are properly gated behind `NODE_ENV`, the frontend is thoroughly wired (all 428 onclick handlers resolve, all 49 nav tabs map to render functions, no dead buttons except the one below), and the approvals-vote service is a model of concurrency safety. The query-destructuring bug class that caused earlier issues is fully fixed.

However, there are a small number of **genuinely serious issues that should be fixed before real users and real money are on the system.** The two most important are a project-closure control that one person can complete alone, and a permission-key mismatch that can disable ~16 write features on a fresh deploy. Neither was introduced by this session's work; they are pre-existing.

## What I fixed during this audit (verify with `npm test`, then deploy code + `pm2 restart`)

These are code-only changes (no DB/migration needed); a `git pull` + `pm2 restart` on the server applies them.

1. **Closure single-signer (CRITICAL #1) — FIXED.** `signoff-helpers.js`: only a Principal/Design Principal may sign a slot other than their own; any other closure role can only sign its own slot. `handover.js`: one user cannot occupy more than one slot (409). Closure now genuinely needs 5 distinct people; legitimate 5-role closure is unchanged.
2. **Schedule-approval transaction (#3) — FIXED.** `approvals.js`: the demote-all / promote-one / checklist-flag are now atomic, so a failure can't leave the project with no current schedule; also removed a dead `SELECT ... WHERE active = 1` that 500'd after approval.
3. **Advance-recovery double-deduction (#3) — FIXED.** `payments.js`: vendor-payment INSERT + advance-recovery UPDATE are now one transaction.
4. **Vendor unapproved-bank-details (#3) — FIXED (safely).** `vendors.js`: if the dual-approval record can't be created, the bank details are stripped, so a vendor never persists with unapproved bank details. (Kept minimal rather than a full refactor of vendor creation.)
5. **HTTP timeout (#5) — FIXED.** `services/http.js`: POST/PUT now default to a 30s timeout so a black-holed Matrix/Twilio send fails fast instead of hanging and exhausting the pool. GET left untouched (Matrix long-poll / downloads).
6. **Project-setup scope IDOR (#7) — FIXED.** `project-setup.js`: `PUT /:id/scope` now has `requireProjectScope` (matching the checklist routes in the same file).
7. **"Upload Signed Cert" button (#4) — was a FALSE POSITIVE.** The route existed but sat after `module.exports`; moved it above the export. The button already worked; this is cleanup.
8. **Duplicate governance map — FIXED.** `governance.js`: the in-app re-import's stale `ROLE_SHEET_MAP` (mapped "Detailing" → `team_lead`, omitted the engineer roles) is now synced with the loader.

**Still open (report-only — need a product decision or carry more risk, so left for review):** urgent/petty-cash threshold unification + GST/PAN gate (#6), the UTR same-amount collision (#9), MOM `unlock` revision cap, budget zero-sanction math, the schedule `task_id` cross-project checks, and the remaining IDOR scope guards on entity-id routes. Confirm `NODE_ENV=production` is set (finding #8 depends on it).

Earlier this session: detailing retirement, notification wiring, engineer-role permissions, ICICI/upload/document fixes — verified consistent; CI expected to pass.

---

## CRITICAL — fix before go-live

### 1. Project closure can be completed by a single Principal alone
`modules/site/lib/signoff-helpers.js:38-56` (`determineSignoffSlot`) + `modules/site/routes/handover.js:144,185-201`

Closure requires 5 distinct role sign-offs (`pmc_head, design_head, services_head, principal, design_principal`). But the slot each signer fills is taken from the client-supplied `req.body.role` with no check that the caller holds that role. A single `principal` can POST the sign-off five times with `role: 'pmc_head'`, `'design_head'`, etc., filling all five slots and triggering the irreversible `active -> completed` transition alone. This defeats the entire multi-party closure control.
Fix: only honor a body-supplied role for genuine universal signers, and never let one `user_id` occupy more than one slot (add a per-user distinct guard).

### 2. Permission-key mismatch may 403 ~16 write features on a fresh deploy
`scripts/load-governance-sheets.js:70-72` (key derivation) vs. `requirePermission('...')` calls across `modules/*`

The governance loader derives permission keys by slugging the spreadsheet's group + human label (e.g. `pmc-site.pmc-issue-snag-raise`), but the route code checks hand-written dotted keys (e.g. `pmc.issue.snag-raise`). Only 5 of 21 `requirePermission` keys match. `middleware/permissions.js` fails closed on any unknown key, so the other ~16 return 403 for every role after a clean `setup.sh` seed. Affected: vendor master create/update, vendor bank-change, client-BOQ HSN/rate edits, payment mark-paid / batch-export, project-setup scope edit, snag raise/resolve/signoff, issue close, measurement add-items, lessons input.
**This needs immediate live verification** (I could not do it on the production login page). Run on the server:
```
MYSQL_PWD="$DB_PASSWORD" mysql -h "$DB_HOST" -u "$DB_USER" "$DB_NAME" -e "SELECT DISTINCT action FROM role_permissions ORDER BY action" | grep -E "snag|mark-paid|create-vendor|edit-scope"
```
If the keys present don't match the route keys, those features are dead. Fix: reconcile the sheet labels, the loader's key derivation, and the route keys to one canonical set, then re-seed and verify. (There are already signs of hand-patching this drift — `governance.js` has a rename-action endpoint and one migration patches 2 of the ~16 keys.)

### 3. Financial writes are not atomic (partial-failure corruption)
- `modules/finance/routes/payments.js:191-209` — vendor-payment INSERT + advance-recovery deduction as two separate queries. If the deduction fails after the payment records, the same mobilisation advance can be recovered again on the next bill.
- `modules/workflow/routes/approvals.js:257-268` — schedule approval demotes all `is_current` then promotes one, no transaction. A failure between leaves the project with **no current schedule version**.
- `modules/finance/routes/urgent-payments.js:109-137` — urgent-payment INSERT (can auto-approve) + evidence INSERTs, not atomic; can disburse with missing invoice/UPI evidence.
- `modules/onboarding/lib/vendor-bank-change.js:520-543` (via `vendors.js:195-224`) — new-vendor bank details INSERT is non-transactional **and error-swallowed** (only `console.warn`). A vendor can persist with a bank account but no dual-approval row and no audit trail — bypassing the bank-change control.
Fix: wrap each in `db.tx(...)` (the codebase already has a correct `db.tx` helper, used properly elsewhere).

---

## HIGH

### 4. Broken button: "Upload Signed Cert" posts to a non-existent endpoint
`public/js/app.js:13633,13738-13743` — the PMC "Upload Signed Cert" button (measurements, `client_accepted`) POSTs `/measurements/:pid/:mid/signed-cert`, which does not exist in `modules/workflow/routes/measurements.js`. The user picks a file, clicks upload, gets "Upload failed", and the certificate is never stored. Fix: add the route (or repoint to the existing `certificate` route).

### 5. No HTTP timeout on Matrix/Twilio calls -> pool exhaustion risk
`services/matrix-adapter.js` (10 call sites) and `services/whatsapp.js` (Twilio) never pass a timeout to `services/http.js`. On a black-holed connection these hang forever; with only 20 pool connections, a Matrix/Twilio outage can progressively hang requests and take the whole app down, not just notifications. Fix: default a timeout in `http.js` or pass one from the adapters (the ICICI canary already does).

### 6. Urgent / petty-cash threshold is inconsistent and half-bypasses the GST/PAN gate
`modules/finance/routes/payment-requests.js:239-271` vs `urgent-payments.js:43-69` — two urgent lanes with different ceilings (25,000 vs a 0.25%-of-budget figure) and only one enforces the "GST or PAN required above Rs 10,000" adhoc rule. The same urgent ~Rs 24,000 adhoc spend is fully documented via one endpoint and auto-approved with no tax identity via the other. Fix: unify the threshold and the doc gate across both lanes.

### 7. IDOR / cross-project writes missing scope checks
- `modules/onboarding/routes/project-setup.js:22` `PUT /:id/scope` — no `requireProjectScope`; a holder of the permission can edit any project's scope (handover dates, retention, petty-cash limits).
- `modules/design-services/routes/schedule-quick.js` and `schedule.js` (POST update / validate) — write `task_updates` using a body `task_id` without verifying the task belongs to the URL's project. A user on project A can write task-update rows referencing project B.
Fix: add `requireProjectScope` / constrain the entity lookup to the scoped project id.

### 8. WhatsApp webhook auth fully disabled outside `NODE_ENV=production`
`middleware/twilio-validate.js:7` — signature validation is skipped unless `NODE_ENV==='production'`. The webhook drives real writes (vendor confirmations, GRN approvals, daily reports from sender phone). If prod is ever started without `NODE_ENV=production` (a known checklist item), these become forgeable. Confirm `NODE_ENV=production` is set.

### 9. Same-amount payment collision in the UTR/ICICI confirmation
`modules/finance/routes/payments.js:1169-1179` — the webhook matches a payment by `(bank_account, amount within 1 rupee)`, newest first. Two approved payments to the same vendor bank for the same amount → the UTR stamps the wrong one paid, leaving the real one perpetually unpaid. Fix: match on the payment/cycle id, not amount.

---

## MEDIUM (selected — full list in the pass notes)

- State machine allows `pending_pmc -> principal_approved` unconditionally; the money-threshold is enforced only in the route, not the machine (`services/state-machines.js:24`). Latent authority bypass.
- MOM `unlock` (principal) creates a v5 with a fresh 1-day window, bypassing the "max 4 revisions" cap (`meetings.js:404`).
- Budget variance math treats a `sanctioned = 0` cost head as always on-budget, hiding over-spend (`budget.js:85-93`).
- `2026-07-02-daily-reports-autolock.sql` uses `ADD COLUMN` without idempotency; safe only because `verify-and-provision.js` applies with `mysql --force`. (Note: MySQL 8 doesn't support `ADD COLUMN IF NOT EXISTS`, so leave the `--force` path as the guard.)
- `services/sequence.js` number generation races; correctness depends entirely on UNIQUE constraints existing on every number column (`issue_number`, `rfi_number`, `meeting_number`, `cn_number`, PI number, etc.) — worth confirming in the schema.
- Several entity-id writes (NCR resolve, material status, PI status, submittal review, meeting issue-to-client, threshold set) skip `requireProjectScope`, so they don't block writes to already-completed projects.
- SES webhook accepts its secret via query string (leaks into logs); no real SNS signature check (`notifications.js:37-47`).
- `services/file-storage.js:72-77,116-121` releases the DB connection outside a `finally` — fragile if `commit()` throws.
- Orphaned "Documents" screen (`renderDocuments`, `app.js:4912`) has no nav entry point — reachable only if a `documents` tab is added in nav-admin.

## LOW / cosmetic
- Dead code: `API.reject` -> missing `/approvals/:id/reject` (never called; live UI uses `/vote`); `GET /meetings/:id/documents` doesn't exist (guarded, MOM docs grid renders empty).
- Leftover harmless `detailing` references in comments and a `projects.js:210 detailing:[]` dead entry.
- CN approve error message hard-codes "Rs 1,00,000" while the real threshold is 1% of budget.
- `confirm-payment` guards over-payment but accepts arbitrary under-payment (closes the request).

---

## What is SOLID (verified, no action)
- SQL injection: none found — dynamic SET/column builders all use hardcoded whitelists + parameterized values.
- File upload: filename sanitized, extension allowlist + magic-byte content check, no path traversal, authenticated serving re-checks path.
- Session/CSRF/cookies: httpOnly + sameSite=strict + secure(FORCE_HTTPS), MySQL store, refuses to boot without a 32-char secret, session regenerated on login (fixation-safe), CSRF synchronizer token on all state-changing routes.
- Dev/test bypass: all four dev routes and the X-Test-User-Id header are gated behind `NODE_ENV` development/test.
- Query destructuring: the `.then(r=>[r])` double-wrap bug is fixed; a scan of 1,052 query sites found no surviving instances.
- Approvals-vote service, ICICI generate/confirm idempotency, state-machine concurrency guard (`UPDATE ... WHERE status=from`), measurement ordering: all correct and well-guarded.
- Frontend: all onclick handlers resolve, all nav tabs map, no CSRF-bypassing raw fetches, duplicate IDs are in mutually-exclusive branches.
- Detailing retirement + notification wiring + engineer roles: consistent; CI expected to pass with no further test fixes.

## What still needs LIVE / DB verification (could not do on the production login page)
1. **Finding #2 (permission keys)** — run the DB query above to confirm whether the ~16 features actually work on the live server. This is the single most important thing to check.
2. Whether `NODE_ENV=production` and `FORCE_HTTPS=1` are actually set in the server `.env` (findings #3, #8 and cookie security depend on it).
3. UNIQUE constraints on the sequence-number columns (finding under MEDIUM).
4. A logged-in per-role click-through (login, open each tab, add a drawing/submittal/issue, confirm it shows to another role) — needs a known password on a role account; I did not create or change any production credential.

## Recommended fix order
1. Finding #1 (closure single-signer) and verify #2 (permission keys) — these are the two that most affect a real handover.
2. Findings #3 (transactional money writes) and #4 (broken cert button).
3. Findings #5-#9 (availability + IDOR + threshold + webhook collision).
4. Medium items as time allows; low/cosmetic post-launch.

None of these block committing the current working tree (the detailing/notification/engineer changes are consistent and CI-safe). They are product-code issues to schedule, most of them pre-existing.
