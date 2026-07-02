// routes/vendors.js — Vendor master + project engagements
// ============================================================
// VENDOR DATA — 4 SURFACES, 4 LEGITIMATE CONCERNS (healthy split)
//
// nu PMC's vendor data is intentionally split across four surfaces. Each
// surface answers a different question, has different access rules, and
// changes for different reasons. DO NOT MERGE.
//
//   1. THIS FILE — vendor MASTER + project ENGAGEMENT.
//      • Master: firm-level. One row per vendor across all projects.
//        Bank details, GST, contact, status. Lifecycle owned by finance.
//      • Engagement: per-project. "This vendor is doing X on project Y
//        for ₹Z, signed this contract." Lifecycle owned by PMC head.
//      Both live here because the same human (M/P or Finance) edits them
//      together when onboarding a vendor to a new project.
//
//   2. modules/onboarding/routes/vendor-public.js — TOKEN side.
//      The wa.me-link landing page. Vendor (unauthenticated) confirms
//      bank details / submits onboarding details via a single-use token.
//      Different audience (vendor, not staff), different auth (token,
//      not session), different surface (public HTML, not JSON API).
//
//   3. modules/onboarding/lib/vendor-bank-change.js — BANK-CHANGE helper.
//      The state machine + transaction wrapper for the "vendor wants to
//      change their bank account" flow. Includes the dual-approval
//      (PMC + principal) requirement and the re-confirmation token. Lives
//      in /lib because it's called from BOTH the staff side (this file)
//      and the vendor-public side (token confirmation).
//
//   4. services/vendor-onboarding.js — TOKEN issuance + lifecycle service.
//      Issues / looks up / consumes / expires the wa.me tokens. Stateless
//      service used by routes/vendors.js (issue) and routes/vendor-public.js
//      (lookup + consume).
//
// Verified healthy split with Principal during the Concept-Map Audit (May 2026).
// ============================================================
const express = require('express');
const db      = require('../../../middleware/db');
const { validators } = require('../../../middleware/validate');
const { requireAuth, requirePMC, requirePrincipal, requireRole, requireProjectScope } = require('../../../middleware/auth');
const xl      = require('../../../middleware/excel');
const { upload } = require('../../../middleware/upload');
const lookup = require('../../../services/lookup');
const dateUtil = require('../../../services/date-util');
const router     = express.Router();

const fuzzy      = require('../../../services/fuzzy-match');
const budgetCheck = require('../../../services/budget-check');
const ai         = require('../../../services/ai');
const waLink     = require('../../../services/wa-link');
const asyncHandler = require('../../../middleware/asyncHandler');
const audit = require('../../../services/audit');
const users = require('../../../services/users-lookup');
const {
  ALL_HEADS: HEADS_ROLES,
  PMC_ROLES,
  PRINCIPALS,
  CLIENT_RATE_ROLES: RATE_VISIBLE,
} = require('../../../services/roles');

const { requirePermission } = require('../../../middleware/permissions');

// ── HELPER: vendor-clearance notification recipients (Decision 4, May 2026)
// Returns the user-id list for "vendor pending finance clearance" alerts:
// finance_admins + PMC heads + the stream-specific head matching the trade.
//
// Trade→stream mapping mirrors the canonical version in
// modules/finance/routes/payment-requests.js:412 (DESIGN_TRADES /
// SERVICES_TRADES). Duplication noted as a future consolidation —
// candidate for services/trade-stream.js.
async function _vendorClearanceRecipients(trade) {
  const DESIGN_TRADES   = new Set(['civil','structural','finishes','architectural','interior']);
  const SERVICES_TRADES = new Set(['electrical','hvac','plumbing','fire','it','mep']);
  const t = (trade || '').toLowerCase();
  let streamHeadRole = null;
  if (DESIGN_TRADES.has(t))        streamHeadRole = 'design_head';
  else if (SERVICES_TRADES.has(t)) streamHeadRole = 'services_head';

  const finance = await users.usersByRole('finance_admin', 'id');
  const pmc     = await users.usersByRole('pmc_head', 'id');
  const stream  = streamHeadRole
    ? await users.usersByRole(streamHeadRole, 'id')
    : [];

  // Dedupe by id (e.g. a user with multiple roles or future overlaps).
  const seen = new Set();
  return [...finance, ...pmc, ...stream].filter(u => {
    if (seen.has(u.id)) return false;
    seen.add(u.id);
    return true;
  });
}

// ── VENDOR MASTER

// Role gate for READING the vendor master list. Kept wider than the create
// permission because GET is lower-risk (PII is redacted in the read serializer
// where applicable) and design/services heads legitimately need to browse
// vendors to plan engagements. WRITE ops use permissions.js 'vendors.create'
// which is narrower (principal, DP, pmc_head, senior_site_manager) — enforced
// at each POST/PATCH/DELETE below.
const VENDOR_MASTER_READ_ROLES = [
  'principal','design_principal','pmc_head','design_head','services_head','finance_admin',
  'senior_site_manager',
];

// GET /api/vendors/master — full master list (all registered vendors)
// Gated to vendor-master roles — bank details and GSTINs are PII.
router.get('/master', requireAuth, requireRole(...VENDOR_MASTER_READ_ROLES), asyncHandler(async (req, res) => {
    const [vendors] = await db.query(
      `SELECT * FROM vendors WHERE is_active = 1 ORDER BY trade, vendor_name`
    );
    const Auth = require('../../auth/contract');
    const users = await Auth.functions.getUsers(vendors.map(v => v.registered_by).filter(Boolean));
    vendors.forEach(v => { v.registered_by_name = users.get(v.registered_by)?.full_name || null; });
    res.json({ vendors });
  }));

// GET /api/vendors/master/check?name=X&trade=Y — fuzzy duplicate check (same gate)
router.get('/master/check', requireAuth, requireRole(...VENDOR_MASTER_READ_ROLES), asyncHandler(async (req, res) => {
    const { name, trade } = req.query;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const result = await fuzzy.checkVendorDuplicate(db, name, trade||null);
    res.json(result);
  }));

// GET /api/vendors/master/search?trade=Civil&q=ramesh — trade-filtered search for picker
router.get('/master/search', requireAuth, requireRole(...VENDOR_MASTER_READ_ROLES), asyncHandler(async (req, res) => {
    const { trade, q } = req.query;
    const limit  = Math.min(parseInt(req.query.limit, 10)  || 50, 100);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
    const [vendors] = await db.query(
      `SELECT id, vendor_name, trade, contact_person, phone, bank_account, bank_ifsc, gst_number AS gstin
       FROM vendors
       WHERE is_active=1
       ${trade ? 'AND trade=?' : ''}
       ${q ? 'AND (vendor_name LIKE ? OR contact_person LIKE ?)' : ''}
       ORDER BY vendor_name LIMIT ? OFFSET ?`,
      [
        ...(trade ? [trade] : []),
        ...(q ? ['%'+q+'%','%'+q+'%'] : []),
        limit, offset,
      ]
    );
    res.json({ vendors, limit, offset, has_more: vendors.length === limit });
  }));

// POST /api/vendors/master — register new vendor master (form entry)
// Lands as clearance_status='pending'; finance must clear before PR can be raised.
//
// v6.02 audit decision: role-scoped initiation.
//   PMC heads → can initiate any vendor.
//   Design head → can only initiate vendors with design-stream trades.
//   Services head → can only initiate vendors with services-stream trades.
//   Principals → unrestricted.
//
// On creation, fires vendor_onboarding signoff (Finance → Principal sequence)
// in addition to the clearance notification.
router.post('/master', requireAuth, requirePermission('admin.vendor.create'), asyncHandler(async (req, res) => {
    const { VendorMaster, parseOr400 } = require('../../../services/schemas');
    const body = parseOr400(VendorMaster, req, res);
    if (!body) return;

    // v6.02: trade gate for stream heads.
    // Design trades vs services trades — same sets used by _vendorClearanceRecipients.
    const me = req.session.user;
    if (me.role === 'design_head' || me.role === 'services_head') {
      const DESIGN_TRADES   = new Set(['civil','structural','finishes','architectural','interior']);
      const SERVICES_TRADES = new Set(['electrical','hvac','plumbing','fire','it','mep']);
      const t = (body.trade || '').toLowerCase();
      const tradeStream = DESIGN_TRADES.has(t) ? 'design'
                        : SERVICES_TRADES.has(t) ? 'services'
                        : null;
      const expectedStream = me.role === 'design_head' ? 'design' : 'services';
      // If trade is in a known set and doesn't match, deny.
      // Unknown trades fall through (PMC oversight catches it).
      if (tradeStream && tradeStream !== expectedStream) {
        return res.status(403).json({
          error: `Trade '${body.trade}' is in ${tradeStream} stream. ` +
                 `As ${me.role}, you can only initiate vendors in your stream. Ask PMC head to initiate this one.`,
          code: 'TRADE_STREAM_MISMATCH',
        });
      }
    }

    // Uniqueness — GSTIN (if provided) is the primary key; otherwise (name, trade)
    if (body.gst_number) {
      const [[exGst]] = await db.query('SELECT id, vendor_name FROM vendors WHERE gst_number = ?', [body.gst_number.toUpperCase()]);
      if (exGst) return res.status(409).json({ error: `GSTIN already registered for ${exGst.vendor_name}`, existing_id: exGst.id });
    } else {
      const [[exNT]] = await db.query('SELECT id FROM vendors WHERE vendor_name = ? AND trade = ?', [body.vendor_name, body.trade]);
      if (exNT) return res.status(409).json({ error: 'Vendor with this name and trade already exists', existing_id: exNT.id });
    }

    const [result] = await db.query(
      `INSERT INTO vendors
         (trade, vendor_name, contact_person, phone, gst_number,
          bank_name, bank_account, bank_ifsc, notes, registered_by, clearance_status)
       VALUES (?,?,?,?,?,?,?,?,?,?,'pending')`,
      [body.trade, body.vendor_name, body.contact_person, body.phone,
       body.gst_number ? body.gst_number.toUpperCase() : null,
       body.bank_name, body.bank_account,
       body.bank_ifsc ? body.bank_ifsc.toUpperCase() : null,
       body.notes, req.session.user.id]
    );

    // V8 — new vendor creation with bank details requires dual approval.
    // (V8 spec line 57-61: applies to new vendor CREATION, not just changes.)
    // Trigger vendor confirmation poll if bank fields were provided.
    if (body.bank_account || body.bank_ifsc) {
      try {
        const vendorBankChange = require('../lib/vendor-bank-change');
        await vendorBankChange.proposeNewVendorBankDetails({
          proposer:   req.session.user,
          vendorId:   result.insertId,
          vendorName: body.vendor_name,
          bankAccount: body.bank_account || null,
          bankIfsc:    body.bank_ifsc    || null,
          bankName:    body.bank_name    || null,
        });
      } catch (e) {
        console.warn('[vendor.create V8 bank-approval]', e.message);
        // If the dual-approval record could not be created, strip the bank
        // details so the vendor never persists with UNAPPROVED bank details
        // (the V8 control). They can be re-added later, which re-triggers approval.
        await db.query(
          'UPDATE vendors SET bank_account=NULL, bank_ifsc=NULL, bank_name=NULL WHERE id=?',
          [result.insertId]
        ).catch(() => {});
      }
    }

    // Notify clearance-track recipients per Decision 4 (May 2026):
    // finance_admins (all, not just first) + all PMC heads + the stream-
    // specific head matching the vendor's trade.
    //
    // (Earlier: an array-first-element truthiness check meant only the first
    // finance admin in the result was ever notified — single-recipient bug.
    // Fixed below by iterating the full recipients list.)
    try {
      const notif = require('../../../services/notifications');
      const recipients = await _vendorClearanceRecipients(body.trade);
      for (const r of recipients) {
        await notif.notify(r.id, 'vendor_pending_clearance',
          `${body.vendor_name} added by ${req.session.user.full_name || 'a head'} — pending finance clearance.`);
      }
    } catch (e) { console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message); }

    // Audit log: redact phone to last 4 digits (phone_tail). Plaintext PII in
    // audit_log was a privacy gap — anyone with audit-log access could read
    // every vendor's full phone number even though they don't need to. Pattern
    // matches the existing phone_tail convention in this file (line ~701).
    const phoneTail = body.phone ? String(body.phone).replace(/\D/g, '').slice(-4) : null;
    audit.log({ userId: req.session.user.id, action: 'vendor.create',
      entityType: 'vendors', entityId: result.insertId,
      details: { vendor_name: body.vendor_name, trade: body.trade, gst_number: body.gst_number ? body.gst_number.toUpperCase() : null, contact_person: body.contact_person, phone_tail: phoneTail }, req });

    // v6.02: vendor_onboarding signoff — Finance clears, then Principal approves.
    // Non-blocking: vendor row is created regardless; onboarding workflow tracks
    // the approval state separately. Vendor stays clearance_status='pending'
    // until Finance clears (existing flow).
    try {
      const signoffGate = require('../../../services/signoff-gate');
      await signoffGate.triggerSignoff(
        'vendor_onboarding',
        result.insertId,
        null,  // not project-scoped — vendor master is firm-wide
        {
          question: `New vendor — ${body.vendor_name} (${body.trade}) — initiated by ${me.full_name || me.role}. Approve onboarding?`,
          documentRow: { id: result.insertId, raised_by: me.id },
          triggeredBy: me.id,
        }
      );
    } catch (e) {
      console.warn('[vendor.create vendor_onboarding signoff]', e.message);
    }

    res.json({ success: true, id: result.insertId,
      message: `${body.vendor_name} added — pending finance clearance before payments can be raised.` });
  }));

// GET /api/vendors/master/pending-clearance — finance dashboard of vendors awaiting clearance
router.get('/master/pending-clearance', requireAuth, requireRole('finance_admin','principal','design_principal'), asyncHandler(async (req, res) => {
    const [vendors] = await db.query(
      `SELECT id, vendor_name, trade, contact_person, phone, gst_number,
              pan_number, bank_name, bank_account, bank_ifsc,
              ai_flags, created_at, registered_by,
              bank_validated_by_vendor, bank_validation_method
       FROM vendors
       WHERE clearance_status = 'pending' AND is_active = 1
       ORDER BY created_at DESC`
    );
    const Auth = require('../../auth/contract');
    const users = await Auth.functions.getUsers(vendors.map(v => v.registered_by).filter(Boolean));
    vendors.forEach(v => { v.uploaded_by_name = users.get(v.registered_by)?.full_name || null; });
    res.json({ vendors });
  }));

// PATCH /api/vendors/master/:id/clear — finance marks vendor as cleared for payments
router.patch('/master/:id/clear', requireAuth, requireRole('finance_admin','principal','design_principal'), asyncHandler(async (req, res) => {
    const me = req.session.user;
    const { corrections } = req.body || {};

    // v5.24 (build-commit lock): if corrections include any bank field,
    // the vendor must confirm the new details via wa.me before payments
    // can be released. Track which fields were touched so we can reset
    // bank_validated_by_vendor appropriately.
    const BANK_FIELDS = new Set(['bank_name', 'bank_account', 'bank_ifsc']);
    const correctionTouchesBank = corrections && typeof corrections === 'object'
      && Object.keys(corrections).some(k => BANK_FIELDS.has(k) && corrections[k] !== undefined);

    await db.tx(async (conn) => {
      if (corrections && typeof corrections === 'object') {
        const allowed = ['vendor_name','contact_person','phone','gst_number','pan_number','bank_name','bank_account','bank_ifsc'];
        const fields = [], values = [];
        for (const k of allowed) {
          if (corrections[k] !== undefined) {
            fields.push(`${k} = ?`);
            values.push(corrections[k] || null);
          }
        }
        // If bank fields touched, also reset bank_validated_by_vendor so the
        // ICICI guard refuses payments until vendor confirms via wa.me.
        if (correctionTouchesBank) {
          fields.push('bank_validated_by_vendor = 0');
          fields.push('bank_validated_at = NULL');
          fields.push('bank_validation_method = NULL');
        }
        if (fields.length) {
          values.push(req.params.id);
          await conn.query(`UPDATE vendors SET ${fields.join(', ')} WHERE id = ?`, values);
        }
      }

      const sm = require('../../../services/state-machines').vendor;
      await sm.transition({
        id: parseInt(req.params.id, 10), from: 'pending', to: 'cleared',
        extraCols: {
          cleared_by: me.id, cleared_at: new Date(), rejection_reason: null,
        },
        conn,
      });
    });

    audit.log({ userId: me.id, action: 'vendor.cleared', entityType: 'vendors', entityId: req.params.id,
                details: { corrections: corrections || null, bank_corrections_require_vendor_confirm: correctionTouchesBank }, req });
    res.json({
      success: true,
      message: correctionTouchesBank
        ? 'Vendor cleared, but bank corrections require vendor confirmation via WhatsApp before payments are released.'
        : 'Vendor cleared — payments may now be raised.',
      bank_validation_pending: correctionTouchesBank,
    });
  }));

// PATCH /api/vendors/master/:id/reject — finance rejects a vendor
router.patch('/master/:id/reject', requireAuth, requireRole('finance_admin','principal','design_principal'), asyncHandler(async (req, res) => {
    const me = req.session.user;
    const { reason } = req.body || {};
    if (!reason || String(reason).trim().length < 5) {
      return res.status(400).json({ error: 'Rejection reason required (min 5 chars)' });
    }
    const [[cur]] = await db.query('SELECT clearance_status FROM vendors WHERE id = ?', [req.params.id]);
    if (!cur) return res.status(404).json({ error: 'Vendor not found' });
    const sm = require('../../../services/state-machines').vendor;
    try {
      await sm.transition({
        id: parseInt(req.params.id, 10), from: cur.clearance_status, to: 'rejected',
        extraCols: {
          rejection_reason: String(reason).trim(),
          cleared_by: me.id, cleared_at: new Date(),
        },
      });
    } catch (err) { return sm.handleRouteError(err, res); }
    audit.log({ userId: me.id, action: 'vendor.rejected', entityType: 'vendors', entityId: req.params.id,
                details: { reason: String(reason).trim() }, req });
    res.json({ success: true, message: 'Vendor rejected.' });
  }));

// POST /api/vendors/master/upload — bulk upload from Excel with validation pipeline
// Deterministic format checks → GSTIN/IFSC/PAN lookups → AI cross-field sanity →
// persist with clearance_status='pending' and ai_flags JSON. Returns per-row
// report so the uploader can fix obvious issues before finance review.
router.post('/master/upload', requireAuth, requirePMC, upload.single('vendors'), asyncHandler(async (req, res) => {
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'No file uploaded' });

    const rows = await xl.readFile(file.path);

    // Header accessor — handles template drift (e.g. 'Vendor Name *', 'Trade / Discipline *')
    const pick = (row, ...keys) => {
      for (const k of keys) {
        for (const actualKey of Object.keys(row)) {
          if (actualKey.toLowerCase().replace(/\s*\*/, '').trim() === k.toLowerCase()) {
            const v = row[actualKey];
            if (v !== null && v !== undefined && String(v).trim() !== '') return String(v).trim();
          }
        }
      }
      return null;
    };

    // Deterministic format checks — canonical patterns from middleware/validate.js
    const { GSTIN_PATTERN, PAN_PATTERN, IFSC_PATTERN, PHONE_PATTERN } = require('../../../middleware/validate');

    const report = [];
    let added = 0, skipped = 0;

    for (const row of rows) {
      const name  = pick(row, 'Vendor Name', 'vendor_name');
      const trade = pick(row, 'Trade', 'Trade / Discipline', 'trade');
      if (!name || !trade) { skipped++; continue; }
      if (name.toLowerCase().startsWith('example:')) { skipped++; continue; }

      const contact = pick(row, 'Contact Person', 'contact_person');
      // Phone — route through normalisePhone for consistency with wa.me link
      // generation. Empty input → null. Garbled input → null with surfaced
      // error so Principal sees which row to fix.
      const phoneRaw = (pick(row, 'Phone', 'Phone (WhatsApp)', 'WhatsApp', 'phone') || '').toString().trim();
      const phone    = phoneRaw ? waLink.normalisePhone(phoneRaw) : null;
      if (phoneRaw && !phone) { report.push({ name, trade, status: 'skipped', reason: `Invalid phone '${phoneRaw}'` }); skipped++; continue; }
      const gstin   = (pick(row, 'GSTIN', 'GST Number', 'gst_number', 'gstin') || '').toUpperCase() || null;
      const pan     = (pick(row, 'PAN', 'pan') || '').toUpperCase() || null;
      const bankAcc = pick(row, 'Bank Account Number', 'Account Number', 'bank_account');
      const bankIfsc= (pick(row, 'Bank IFSC Code', 'IFSC', 'bank_ifsc') || '').toUpperCase() || null;
      const bankName= pick(row, 'Bank Name', 'bank_name');

      // Uniqueness check — GSTIN unique where present, otherwise (name, trade)
      let existingId = null;
      if (gstin) {
        const [[exGst]] = await db.query('SELECT id FROM vendors WHERE gst_number = ?', [gstin]);
        if (exGst) existingId = exGst.id;
      }
      if (!existingId) {
        const [[exNT]] = await db.query('SELECT id FROM vendors WHERE vendor_name = ? AND trade = ?', [name, trade]);
        if (exNT) existingId = exNT.id;
      }
      if (existingId) {
        report.push({ name, trade, status: 'skipped', reason: 'Already exists in master' });
        skipped++;
        continue;
      }

      // Build deterministic flags
      const flags = {
        gstin_format: gstin ? (GSTIN_PATTERN.test(gstin) ? 'ok' : 'invalid') : 'missing',
        pan_format:   pan   ? (PAN_PATTERN.test(pan)     ? 'ok' : 'invalid') : 'missing',
        ifsc_format:  bankIfsc ? (IFSC_PATTERN.test(bankIfsc) ? 'ok' : 'invalid') : 'missing',
        phone_format: phone ? (PHONE_PATTERN.test(phone) ? 'ok' : 'invalid') : 'missing',
      };
      const notes = [];

      // Lookups — only on well-formed values; swallow network errors silently
      let gstLookup = null, ifscLookup = null;
      if (gstin && flags.gstin_format === 'ok') {
        try { gstLookup = await lookup.lookupGSTIN(gstin); flags.gstin_verified = gstLookup ? 'ok' : 'unavailable'; }
        catch { flags.gstin_verified = 'unavailable'; }
      }
      if (bankIfsc && flags.ifsc_format === 'ok') {
        try { ifscLookup = await lookup.lookupIFSC(bankIfsc); flags.ifsc_verified = ifscLookup ? 'ok' : 'unavailable'; }
        catch { flags.ifsc_verified = 'unavailable'; }
      }

      // AI cross-field sanity — non-blocking, advisory
      const aiRow = { name, trade, contact, phone, gstin, pan, bank_name: bankName, bank_account: bankAcc, bank_ifsc: bankIfsc };
      const aiResult = await ai.validateVendor({ row: aiRow, gstLookup, ifscLookup })
        .catch(() => ({ status: 'amber', notes: ['AI unavailable'] }));

      // Roll up overall status
      const hasRed = ['gstin_format','pan_format','ifsc_format'].some(k => flags[k] === 'invalid');
      const hasAmber = aiResult?.status === 'amber' || flags.gstin_verified === 'unavailable';
      const overall = hasRed ? 'red' : (aiResult?.status === 'red' ? 'red' : (hasAmber ? 'amber' : 'green'));
      if (aiResult?.notes?.length) notes.push(...aiResult.notes);

      const aiFlags = {
        overall,
        deterministic: flags,
        gst_lookup: gstLookup || null,
        ifsc_lookup: ifscLookup || null,
        ai: aiResult || null,
        notes,
      };

      // Insert as pending clearance
      const [result] = await db.query(
        `INSERT INTO vendors
           (trade, vendor_name, contact_person, phone, gst_number, pan_number,
            bank_name, bank_account, bank_ifsc, registered_by,
            clearance_status, ai_flags)
         VALUES (?,?,?,?,?,?,?,?,?,?,'pending',?)`,
        [trade, name, contact, phone, gstin, pan, bankName, bankAcc, bankIfsc,
         req.session.user.id, JSON.stringify(aiFlags)]
      );
      added++;
      report.push({ id: result.insertId, name, trade, status: overall, notes, flags: aiFlags });
    }

    // Notify clearance-track recipients per Decision 4 (May 2026): finance +
    // PMC + stream head. For bulk uploads with mixed trades, dedupe across
    // rows so each recipient gets exactly one notification.
    try {
      const notif = require('../../../services/notifications');
      const trades = [...new Set(report.map(r => r.trade).filter(Boolean))];
      const recipientIds = new Set();
      for (const t of trades) {
        const recipients = await _vendorClearanceRecipients(t);
        for (const r of recipients) recipientIds.add(r.id);
      }
      if (added > 0 && recipientIds.size > 0) {
        for (const id of recipientIds) {
          await notif.notify(id, 'vendor_pending_clearance',
            `${added} new vendor${added === 1 ? '' : 's'} uploaded by ${req.session.user.full_name || 'PMC'} — pending finance clearance.`);
        }
      }
    } catch (e) { console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message); }

    audit.log({ userId: req.session.user.id, action: 'vendor.bulk_upload',
      entityType: 'vendors', entityId: null,
      details: { added, skipped, file_path: file.path }, req });

    res.json({ success: true, added, skipped, report,
      message: `${added} vendor(s) landed as pending finance clearance. ${skipped} skipped.` });
  }));

// PATCH /api/vendors/master/:id — update vendor master details
router.patch('/master/:id', requireAuth, requirePermission('admin.vendor.update'), asyncHandler(async (req, res) => {
    const { VendorMasterUpdate, parseOr400 } = require('../../../services/schemas');
    const body = parseOr400(VendorMasterUpdate, req, res);
    if (!body) return;
    const { contact_person, phone, gst_number, bank_name, bank_account, bank_ifsc, notes } = body;

    // Bug B36: changing bank or GST identity fields effectively makes this a
    // different vendor for payment purposes. Re-trigger finance clearance so
    // Finance Admin verifies the new bank/GST before any payment is raised against
    // the updated record. Phone/contact/notes don't reset clearance.
    const [[before]] = await db.query(
      `SELECT gst_number, bank_name, bank_account, bank_ifsc, clearance_status
       FROM vendors WHERE id = ?`,
      [req.params.id]
    );
    if (!before) return res.status(404).json({ error: 'Vendor not found' });

    const newGst  = gst_number === undefined ? before.gst_number : (gst_number || null);
    const newBank = bank_name === undefined ? before.bank_name : (bank_name || null);
    const newAcct = bank_account === undefined ? before.bank_account : (bank_account || null);
    const newIfsc = bank_ifsc === undefined ? before.bank_ifsc : (bank_ifsc || null);

    const gstChanged  = newGst  !== before.gst_number;
    const bankChanged =
      newBank !== before.bank_name   ||
      newAcct !== before.bank_account||
      newIfsc !== before.bank_ifsc;
    const sensitiveChanged = gstChanged || bankChanged;

    // Only reset bank_validated_by_vendor when BANK identity fields specifically
    // change. GST changes need finance re-clearance (sensitiveChanged path) but
    // don't invalidate the vendor's prior bank confirmation — the bank account
    // hasn't changed, so the vendor's "yes, that's my account" still holds.
    const bankValidationResetSql = bankChanged
      ? `, bank_validated_by_vendor = 0,
           bank_validated_at = NULL,
           bank_validation_method = NULL`
      : '';

    if (sensitiveChanged && before.clearance_status === 'cleared') {
      // First: update the non-status fields. If bank changed, also reset
      // the vendor-side validation flag so ICICI guard refuses payments
      // until the vendor reconfirms via wa.me.
      await db.query(
        `UPDATE vendors
            SET contact_person=?, phone=?, gst_number=?, bank_name=?, bank_account=?, bank_ifsc=?, notes=?
                ${bankValidationResetSql}
          WHERE id=?`,
        [contact_person||null, phone||null, gst_number||null, bank_name||null, bank_account||null, bank_ifsc||null, notes||null, req.params.id]
      );
      // Then: flip clearance_status back to 'pending' through the state machine
      // (cleared → pending edge models bank-change re-validation, B36 Layer 1)
      const sm = require('../../../services/state-machines').vendor;
      await sm.transition({
        id: parseInt(req.params.id, 10), from: 'cleared', to: 'pending',
        extraCols: { cleared_by: null, cleared_at: null },
      });
      audit.log({ userId: req.session.user.id, action: 'vendor.update_reset_clearance',
        entityType: 'vendors', entityId: req.params.id,
        details: { fields: Object.keys(body), gst_changed: gstChanged, bank_changed: bankChanged,
          reason: 'bank/GST identity changed — finance must re-clear' + (bankChanged ? '; bank_validated_by_vendor reset' : '') }, req });
      return res.json({ success: true, clearance_reset: true,
        bank_validation_pending: bankChanged,
        message: bankChanged
          ? 'Bank changed — clearance reset and vendor must re-confirm bank details. Send onboarding link via WhatsApp.'
          : 'GST changed — clearance reset. Finance must re-clear before payments.' });
    }

    // Non-cleared path: still reset bank_validated_by_vendor when bank
    // identity fields change. (A pending-status vendor whose bank flips
    // mid-onboarding still needs vendor confirmation of the new details.)
    if (bankChanged) {
      await db.query(
        `UPDATE vendors
            SET contact_person=?, phone=?, gst_number=?, bank_name=?, bank_account=?, bank_ifsc=?, notes=?,
                bank_validated_by_vendor = 0,
                bank_validated_at = NULL,
                bank_validation_method = NULL
          WHERE id=?`,
        [contact_person||null, phone||null, gst_number||null, bank_name||null, bank_account||null, bank_ifsc||null, notes||null, req.params.id]
      );
    } else {
      await db.query(
        `UPDATE vendors SET contact_person=?, phone=?, gst_number=?, bank_name=?, bank_account=?, bank_ifsc=?, notes=? WHERE id=?`,
        [contact_person||null, phone||null, gst_number||null, bank_name||null, bank_account||null, bank_ifsc||null, notes||null, req.params.id]
      );
    }
    audit.log({ userId: req.session.user.id, action: 'vendor.update', entityType: 'vendors', entityId: req.params.id,
      details: { fields: Object.keys(body), bank_changed: bankChanged, gst_changed: gstChanged }, req });
    res.json({ success: true });
  }));

// ════════════════════════════════════════════════════════════════════════════
// V8 — VENDOR BANK CHANGE: dual-approval workflow (Layers 2 + 3)
// ════════════════════════════════════════════════════════════════════════════
// Layer 1 (auto-uncheck on bank change) lives above, in the PATCH /master/:id
// handler — that's the legacy single-actor path that flips clearance back to
// 'pending'. The routes below add the new explicit dual-approval mode:
//   POST   /master/:id/bank-change/propose
//   POST   /master/bank-change/:approval_id/approve
//   POST   /master/bank-change/:approval_id/reject
//   POST   /master/bank-change/:approval_id/cancel
//   GET    /master/bank-changes/pending
//
// Service: modules/onboarding/lib/vendor-bank-change.js
// Tables : vendor_bank_change_approvals, vendor_alerts (v5.22)
// Spec   : handoff-2026-04-28/2_ForMe/V8-vendor-bank-protection-SPEC.md
// ════════════════════════════════════════════════════════════════════════════

const vendorBankChange = require('../lib/vendor-bank-change');

// POST /api/vendors/master/:id/bank-change/propose — propose a change
// Body: { bank_name?, bank_account?, bank_ifsc?, reason }
// At least one bank_* field must differ from current. Reason is required.
router.post('/master/:id/bank-change/propose',
  requireAuth,
  requirePermission('admin.vendor.bank-change.propose'),
  asyncHandler(async (req, res) => {
    try {
      const { bank_name, bank_account, bank_ifsc, reason } = req.body || {};
      const result = await vendorBankChange.propose({
        proposer: req.session.user,
        vendorId: parseInt(req.params.id, 10),
        changes: { bank_name, bank_account, bank_ifsc },
        reason,
        req,
      });
      res.json({ success: true, ...result });
    } catch (err) {
      if (err instanceof vendorBankChange.BankChangeError) {
        return res.status(err.status).json({ error: err.message, code: err.code });
      }
      throw err;
    }
  }));

// POST /api/vendors/master/bank-change/:approval_id/approve — approver approves
router.post('/master/bank-change/:approval_id/approve',
  requireAuth,
  requirePermission('admin.vendor.bank-change.approve'),
  asyncHandler(async (req, res) => {
    try {
      const result = await vendorBankChange.approve({
        approver: req.session.user,
        approvalId: parseInt(req.params.approval_id, 10),
        req,
      });
      res.json({ success: true, ...result });
    } catch (err) {
      if (err instanceof vendorBankChange.BankChangeError) {
        return res.status(err.status).json({ error: err.message, code: err.code });
      }
      throw err;
    }
  }));

// POST /api/vendors/master/bank-change/:approval_id/reject — approver rejects
router.post('/master/bank-change/:approval_id/reject',
  requireAuth,
  requirePermission('admin.vendor.bank-change.approve'),
  asyncHandler(async (req, res) => {
    try {
      const result = await vendorBankChange.reject({
        approver: req.session.user,
        approvalId: parseInt(req.params.approval_id, 10),
        reason: req.body?.reason,
        req,
      });
      res.json({ success: true, ...result });
    } catch (err) {
      if (err instanceof vendorBankChange.BankChangeError) {
        return res.status(err.status).json({ error: err.message, code: err.code });
      }
      throw err;
    }
  }));

// POST /api/vendors/master/bank-change/:approval_id/cancel — proposer cancels
router.post('/master/bank-change/:approval_id/cancel',
  requireAuth,
  asyncHandler(async (req, res) => {
    try {
      const result = await vendorBankChange.cancel({
        caller: req.session.user,
        approvalId: parseInt(req.params.approval_id, 10),
        req,
      });
      res.json({ success: true, ...result });
    } catch (err) {
      if (err instanceof vendorBankChange.BankChangeError) {
        return res.status(err.status).json({ error: err.message, code: err.code });
      }
      throw err;
    }
  }));

// GET /api/vendors/master/bank-changes/pending — list pending proposals
// Filters by who-can-approve-what based on the caller's role.
router.get('/master/bank-changes/pending',
  requireAuth,
  asyncHandler(async (req, res) => {
    const rows = await vendorBankChange.listPending({ approverRole: req.session.user.role });
    res.json({ pending: rows });
  }));

// POST /api/vendors/master/:id/onboard-link — issue a wa.me onboarding link
// Body: { purpose?: 'onboard'|'re_validation'|'bank_confirm', approval_id?, contact_role? }
//   - default purpose = 'onboard'
//   - contact_role: which vendor_contacts row to address; defaults to vendor.phone
//   - approval_id (bank_confirm only): links the token to a V8 approval row
//
// Returns: { token, expires_at, wa_url, public_url, vendor_phone }
//
// The internal user gets the wa_url and opens it — wa.me launches WhatsApp
// pre-populated with the message containing the public_url. The vendor taps
// the public_url to confirm or reject.
router.post('/master/:id/onboard-link',
  requireAuth,
  requirePermission('admin.vendor.update'),
  asyncHandler(async (req, res) => {
    const onboarding = require('../../../services/vendor-onboarding');
    const purpose    = req.body?.purpose || 'onboard';
    const approvalId = req.body?.approval_id || null;
    const contactRole = req.body?.contact_role || null;

    const [[vendor]] = await db.query(
      `SELECT id, vendor_name, phone, bank_name, bank_account, bank_ifsc
         FROM vendors WHERE id = ?`,
      [req.params.id]
    );
    if (!vendor) return res.status(404).json({ error: 'Vendor not found' });

    // Pick the contact phone. If contact_role given, look up vendor_contacts;
    // otherwise default to vendors.phone.
    let phone = vendor.phone;
    if (contactRole) {
      const [[c]] = await db.query(
        `SELECT phone FROM vendor_contacts WHERE vendor_id = ? AND role = ? LIMIT 1`,
        [vendor.id, contactRole]
      );
      if (c?.phone) phone = c.phone;
    }
    if (!phone) {
      return res.status(400).json({
        error: 'No phone on file for this vendor — add one before sending the link',
        code: 'NO_PHONE',
      });
    }
    // Validate the phone parses cleanly to a wa.me-compatible number BEFORE
    // we write a token row to DB. Otherwise an unparseable phone leaves a
    // dead token sitting in vendor_onboarding_tokens until expiry.
    const normalised = waLink.normalisePhone(phone);
    if (!normalised) {
      return res.status(400).json({
        error: `Phone "${phone}" cannot be used as a WhatsApp number`,
        code: 'PHONE_INVALID',
      });
    }

    // Snapshot what's being confirmed. For bank_confirm we need the V8
    // approval row's before/after; for onboard/re_validation, just current state.
    let payload;
    if (purpose === 'bank_confirm') {
      if (!approvalId) {
        return res.status(400).json({ error: 'approval_id required for bank_confirm', code: 'APPROVAL_REQUIRED' });
      }
      const [[ap]] = await db.query(
        `SELECT before_bank_name, before_bank_account, before_bank_ifsc,
                after_bank_name,  after_bank_account,  after_bank_ifsc, status
           FROM vendor_bank_change_approvals WHERE id = ? AND vendor_id = ?`,
        [approvalId, vendor.id]
      );
      if (!ap) return res.status(404).json({ error: 'Approval row not found', code: 'APPROVAL_NOT_FOUND' });
      if (ap.status !== 'pending') {
        return res.status(409).json({ error: `Approval is ${ap.status}, not pending`, code: 'APPROVAL_NOT_PENDING' });
      }
      payload = {
        before: { bank_name: ap.before_bank_name, bank_account: ap.before_bank_account, bank_ifsc: ap.before_bank_ifsc },
        after:  { bank_name: ap.after_bank_name,  bank_account: ap.after_bank_account,  bank_ifsc: ap.after_bank_ifsc  },
      };
    } else {
      payload = {
        snapshot: {
          bank_name: vendor.bank_name,
          bank_account: vendor.bank_account,
          bank_ifsc: vendor.bank_ifsc,
        },
      };
    }

    const issued = await onboarding.issue({
      vendorId: vendor.id,
      purpose,
      issuedBy: req.session.user.id,
      payload,
      approvalId,
    });

    // SECURITY: APP_URL MUST be set in production. The fallback to
    // req.protocol + req.get('host') is user-controllable (Host header
    // spoof) — an attacker setting `Host: evil.com` would cause the wa.me
    // message to embed an evil.com link, leaking the vendor token.
    // Dev/test path keeps the fallback for convenience but logs a warning.
    let baseUrl = process.env.APP_URL;
    if (!baseUrl) {
      if (process.env.NODE_ENV === 'production') {
        return res.status(500).json({
          error: 'APP_URL env not set — refusing to derive base URL from request host (security)',
          code: 'APP_URL_NOT_SET',
        });
      }
      console.warn('[vendor.onboard_link] APP_URL not set — falling back to req.host (DEV ONLY).');
      baseUrl = `${req.protocol}://${req.get('host')}`;
    }
    const publicUrl = `${baseUrl}/vendor-onboard/${issued.token}`;
    const waUrl = waLink.buildOnboardLink({
      phone, vendorName: vendor.vendor_name, tokenUrl: publicUrl, purpose,
    });
    // Defensive: phone was validated above, but if buildOnboardLink ever
    // returned null for a non-phone reason (encoding edge case), we'd
    // rather audit the orphaned token than serve a malformed link.
    if (!waUrl) {
      return res.status(500).json({
        error: 'Could not build WhatsApp URL — token issued but unusable',
        code: 'WA_URL_FAILED',
        token_id: issued.id,
      });
    }

    // Phone redacted in audit log details — store last 4 digits only.
    // Full phone is in vendor master; auditors can join via vendor_id if
    // legitimately needed. Reduces PII exposure for downstream log readers.
    const phoneTail = phone ? phone.slice(-4) : null;
    audit.log({
      userId: req.session.user.id,
      action: 'vendor.onboard_link.issued',
      entityType: 'vendor_onboarding_tokens',
      entityId: issued.id,
      details: { vendor_id: vendor.id, purpose, approval_id: approvalId, phone_tail: phoneTail },
      req,
    });

    res.json({
      success: true,
      token: issued.token,
      expires_at: issued.expiresAt,
      // Human-readable validity string ("48h" / "72h" / "5 days") so the
      // frontend toast can stay in sync with VENDOR_TOKEN_HOURS without
      // hardcoding. Sourced from services/vendor-onboarding centrally.
      validity: require('../../../services/vendor-onboarding').humanReadableValidity(),
      wa_url: waUrl,
      public_url: publicUrl,
      vendor_phone: phone,
    });
  }));

// ── VENDOR ENGAGEMENTS (project-specific)

// GET /api/vendors/:project_id/engagements — vendors on this project
//
// Bug B37: previously the scope was inferred from requireRole only.
// A site_manager from Project A could hit /api/vendors/B/engagements and
// see Project B's vendor list, including bank details if their role is
// in CLIENT_RATE_ROLES. Now: project scope enforced.
router.get('/:project_id/engagements', requireAuth, requireProjectScope(),
  requireRole('principal','design_principal','pmc_head','design_head','services_head','finance_admin','senior_site_manager','site_manager','team_lead','coordinator','jr_architect','services_engineer','jr_engineer'),
  asyncHandler(async (req, res) => {
    const me        = req.session.user;
    const pid       = req.params.project_id;
    const showRates = RATE_VISIBLE.includes(me.role);

    const [engagements] = await db.query(
      `SELECT ve.*, v.trade, v.vendor_name, v.contact_person, v.phone, v.gst_number,
              v.bank_name, v.bank_account, v.bank_ifsc, v.clearance_status,
              ${showRates ? 've.contract_value' : 'NULL AS contract_value'}
       FROM vendor_engagements ve
       JOIN vendors v ON ve.vendor_id = v.id
       WHERE ve.project_id = ? AND ve.is_active = 1
       ORDER BY v.trade, v.vendor_name`,
      [pid]
    );
    const Auth = require('../../auth/contract');
    const users = await Auth.functions.getUsers(
      engagements.flatMap(e => [e.engaged_by, e.approved_by].filter(Boolean))
    );
    engagements.forEach(e => {
      e.engaged_by_name  = users.get(e.engaged_by)?.full_name  || null;
      e.approved_by_name = users.get(e.approved_by)?.full_name || null;
    });
    res.json({ engagements });
  }));

// POST /api/vendors/:project_id/engagements — engage a master vendor on a project
// M03 workflow: PMC + heads initiate (lands as approval_status='pending'),
// principals approve/reject. Payment requests blocked until approved.
router.post('/:project_id/engagements', requireAuth, requireProjectScope(),
  requireRole('principal','design_principal','pmc_head','design_head','services_head'),
  validators.vendorEngagement, async (req, res) => {
  try {
    const me = req.session.user;
    const { vendor_id, scope, contract_value } = req.body;
    if (!vendor_id || !scope) return res.status(400).json({ error: 'Vendor and scope required' });

    const { validateAmount } = require('../../../services/payment-validation');
    let validContractValue = null;
    if (contract_value !== undefined && contract_value !== null && contract_value !== '') {
      const cv = validateAmount(contract_value, 'Contract value', { allowZero: true });
      if (!cv.ok) return res.status(400).json({ error: cv.error });
      validContractValue = cv.amount;
    }

    // Check vendor exists and is cleared by finance (clearance_status='cleared').
    // Pending / rejected vendors cannot be engaged — M01 clearance gate applies
    // here upstream of payment-request raise.
    const [[vendor]] = await db.query('SELECT * FROM vendors WHERE id = ? AND is_active = 1', [vendor_id]);
    if (!vendor) return res.status(404).json({ error: 'Vendor not found in master list' });
    if (vendor.clearance_status === 'rejected') {
      return res.status(403).json({ error: `${vendor.vendor_name} was rejected by finance — cannot be engaged.` });
    }

    // Budget check
    if (req.body.boq_item_id && validContractValue && validContractValue > 0) {
      const budgetResult = await budgetCheck.checkBudget(
        db, req.params.project_id, null,
        parseInt(req.body.boq_item_id, 10), validContractValue, 'engagement'
      );
      if (!budgetResult.allowed) {
        return res.status(400).json({
          error: 'Budget hard block — ' + budgetResult.blocks.map(b=>b.message).join('. '),
          blocks: budgetResult.blocks,
        });
      }
      if (budgetResult.flags.length) {
        budgetCheck.persistAndNotify(db, req.params.project_id, null,
          budgetResult, me.id, 'engagement').catch(e => console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message));
      }
    }

    // Principals self-approve — if Principal/Design Principal initiates, skip the pending step.
    const isPrincipal = ['principal','design_principal'].includes(me.role);
    const approvalStatus = isPrincipal ? 'approved' : 'pending';
    const approvedBy     = isPrincipal ? me.id      : null;
    const approvedAt     = isPrincipal ? new Date() : null;

    const [result] = await db.query(
      `INSERT INTO vendor_engagements
         (vendor_id, project_id, scope, contract_value, engaged_by,
          approval_status, approved_by, approved_at)
       VALUES (?,?,?,?,?,?,?,?)`,
      [vendor_id, req.params.project_id, scope, validContractValue, me.id,
       approvalStatus, approvedBy, approvedAt]
    );

    // Notify principals if this needs their sign-off
    if (!isPrincipal) {
      try {
        const notif = require('../../../services/notifications');
        const [principals] = await db.query(
          "SELECT id FROM users WHERE role IN ('principal','design_principal') AND is_active=1"
        );
        for (const p of principals) {
          await notif.notify(p.id, 'engagement_pending_approval',
            `${vendor.vendor_name} engaged by ${me.full_name || me.role} — pending your approval.`);
        }
      } catch (e) { console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message); }
    }

    audit.log({ userId: me.id, action: 'engagement.create', entityType: 'vendor_engagements',
                entityId: result.insertId,
                details: { vendor_id, scope, contract_value: validContractValue, approval_status: approvalStatus }, req });

    res.json({
      success: true, id: result.insertId,
      approval_status: approvalStatus,
      message: isPrincipal
        ? `${vendor.vendor_name} engaged. Bank details and GST carried from master.`
        : `${vendor.vendor_name} engaged — pending principal approval before payments can be raised.`
    });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Vendor already engaged on this project' });
    console.error('[vendors] engagement create error:', err);
    res.status(500).json({ error: 'Failed to engage vendor' });
  }
});

// PATCH /api/vendors/:project_id/engagements/:id/approve — principals sign off
router.patch('/:project_id/engagements/:id/approve', requireAuth, requirePrincipal, asyncHandler(async (req, res) => {
    const me = req.session.user;
    const [[eng]] = await db.query(
      'SELECT * FROM vendor_engagements WHERE id = ? AND project_id = ?',
      [req.params.id, req.params.project_id]
    );
    if (!eng) return res.status(404).json({ error: 'Engagement not found' });
    if (eng.approval_status === 'approved') return res.status(400).json({ error: 'Already approved' });

    const sm = require('../../../services/state-machines').vendorEngagementApproval;
    try {
      await sm.transition({
        id: parseInt(req.params.id, 10), from: eng.approval_status, to: 'approved',
        extraCols: { approved_by: me.id, approved_at: new Date(), rejection_reason: null },
      });
    } catch (err) { return sm.handleRouteError(err, res); }
    audit.log({ userId: me.id, action: 'engagement.approve', entityType: 'vendor_engagements',
                entityId: req.params.id, req });

    // Notify the person who initiated
    try {
      const notif = require('../../../services/notifications');
      await notif.notify(eng.engaged_by, 'engagement_approved',
        `Your vendor engagement has been approved by ${me.full_name || 'principal'}.`);
    } catch (e) { console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message); }

    res.json({ success: true, message: 'Engagement approved. Payment requests can now be raised.' });
  }));

// PATCH /api/vendors/:project_id/engagements/:id/reject — principals reject with reason
router.patch('/:project_id/engagements/:id/reject', requireAuth, requirePrincipal, asyncHandler(async (req, res) => {
    const me = req.session.user;
    const { reason } = req.body || {};
    if (!reason || String(reason).trim().length < 5) {
      return res.status(400).json({ error: 'Rejection reason required (min 5 chars)' });
    }
    const [[eng]] = await db.query(
      'SELECT * FROM vendor_engagements WHERE id = ? AND project_id = ?',
      [req.params.id, req.params.project_id]
    );
    if (!eng) return res.status(404).json({ error: 'Engagement not found' });

    const sm = require('../../../services/state-machines').vendorEngagementApproval;
    try {
      await sm.transition({
        id: parseInt(req.params.id, 10), from: eng.approval_status, to: 'rejected',
        extraCols: {
          approved_by: me.id, approved_at: new Date(),
          rejection_reason: String(reason).trim(),
        },
      });
    } catch (err) { return sm.handleRouteError(err, res); }
    audit.log({ userId: me.id, action: 'engagement.reject', entityType: 'vendor_engagements',
                entityId: req.params.id, details: { reason: String(reason).trim() }, req });

    try {
      const notif = require('../../../services/notifications');
      await notif.notify(eng.engaged_by, 'engagement_rejected',
        `Your vendor engagement was rejected. Reason: ${String(reason).trim().substring(0, 150)}`);
    } catch (e) { console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message); }

    res.json({ success: true, message: 'Engagement rejected. Initiator notified.' });
  }));

// PATCH /api/vendors/:project_id/engagements/:id/status — update mobilisation status
router.patch('/:project_id/engagements/:id/status', requireAuth, requireRole(...HEADS_ROLES), async (req, res) => {
  try {
    const me     = req.session.user;
    const { status, notes } = req.body;
    const valid = ['not_started','active','partially_complete','complete','off_site'];
    if (!valid.includes(status)) return res.status(400).json({ error: 'Invalid status' });

    // Read current state + verify scope (engagement belongs to this project)
    const [[cur]] = await db.query(
      'SELECT mobilisation_status, mobilisation_date FROM vendor_engagements WHERE id = ? AND project_id = ?',
      [req.params.id, req.params.project_id]
    );
    if (!cur) return res.status(404).json({ error: 'Engagement not found in this project' });

    const extraCols = { notes: notes || null };
    // mobilisation_date — set on first transition to active, otherwise preserve
    if (status === 'active' && !cur.mobilisation_date) {
      extraCols.mobilisation_date = dateUtil.todayIST();
    }
    if (status === 'complete') extraCols.completion_date = dateUtil.todayIST();

    const sm = require('../../../services/state-machines').vendorEngagementMobilisation;
    try {
      await sm.transition({
        id: parseInt(req.params.id, 10), from: cur.mobilisation_status, to: status, extraCols,
      });
    } catch (err) { return sm.handleRouteError(err, res); }
    audit.log({ userId: me.id, action: 'engagement.status_update',
      entityType: 'vendor_engagements', entityId: parseInt(req.params.id, 10),
      details: { project_id: parseInt(req.params.project_id, 10), from: cur.mobilisation_status, new_status: status, notes: notes || null, mobilisation_date: extraCols.mobilisation_date || null, completion_date: extraCols.completion_date || null }, req });
    res.json({ success: true });
  } catch (_err) { res.status(500).json({ error: 'Status update failed' }); }
});

// PATCH /api/vendors/:project_id/engagements/:id/contract — revise contract value with history
router.patch('/:project_id/engagements/:id/contract', requireAuth, requireRole(...PMC_ROLES), asyncHandler(async (req, res) => {
    const me = req.session.user;
    const { ContractRevision, parseOr400 } = require('../../../services/schemas');
    const body = parseOr400(ContractRevision, req, res);
    if (!body) return;
    const { revised_value, reason, change_notice_id } = body;

    const [[engagement]] = await db.query('SELECT * FROM vendor_engagements WHERE id = ? AND project_id = ?', [req.params.id, req.params.project_id]);
    if (!engagement) return res.status(404).json({ error: 'Engagement not found' });

    // Bug B39: history INSERT + value UPDATE used to be separate queries.
    // If the UPDATE failed, history showed a revision that never took effect;
    // if the INSERT failed and UPDATE succeeded, the audit trail was missing
    // the previous_value record. Now: both in one tx.
    await db.tx(async (conn) => {
      await conn.query(
        'INSERT INTO vendor_contract_history (engagement_id, previous_value, revised_value, reason, change_notice_id, revised_by) VALUES (?,?,?,?,?,?)',
        [engagement.id, engagement.contract_value, revised_value, reason, change_notice_id||null, me.id]
      );
      await conn.query('UPDATE vendor_engagements SET contract_value = ? WHERE id = ?', [revised_value, engagement.id]);
    });

    // Bug B40: audit the revision.
    audit.log({ userId: me.id, action: 'engagement.contract_revised',
      entityType: 'vendor_engagements', entityId: engagement.id,
      details: { project_id: parseInt(req.params.project_id, 10), previous_value: parseFloat(engagement.contract_value), revised_value: parseFloat(revised_value), reason, change_notice_id: change_notice_id || null }, req });

    res.json({ success: true, message: 'Contract value revised. History preserved.' });
  }));

// GET /api/vendors/:project_id/engagements/:id/history — contract revision history
router.get('/:project_id/engagements/:id/history', requireAuth, requireRole(...HEADS_ROLES), asyncHandler(async (req, res) => {
    const me = req.session.user;
    const [history] = await db.query(
      `SELECT vch.*, cn.cn_number
       FROM vendor_contract_history vch
       LEFT JOIN change_notices cn ON vch.change_notice_id = cn.id
       WHERE vch.engagement_id = ?
       ORDER BY vch.revised_at DESC`,
      [req.params.id]
    );
    const Auth = require('../../auth/contract');
    const users = await Auth.functions.getUsers(history.map(h => h.revised_by).filter(Boolean));
    history.forEach(h => { h.revised_by_name = users.get(h.revised_by)?.full_name || null; });
    res.json({ history });
  }));

// PATCH /api/vendors/fee-schedule/:id/revise — revise fee schedule item with history
router.patch('/fee-schedule/:id/revise', requireAuth, requireRole(...PRINCIPALS), asyncHandler(async (req, res) => {
    const me = req.session.user;
    const { FeeScheduleRevision, parseOr400 } = require('../../../services/schemas');
    const body = parseOr400(FeeScheduleRevision, req, res);
    if (!body) return;
    const { revised_amount, reason } = body;

    const [[item]] = await db.query('SELECT * FROM fee_schedule WHERE id = ?', [req.params.id]);
    if (!item) return res.status(404).json({ error: 'Fee schedule item not found' });

    // Bug B41: history INSERT + amount UPDATE used to be separate queries
    // with no transaction. Same risk as B39: half-applied state if either
    // query failed. Now both in one tx.
    await db.tx(async (conn) => {
      await conn.query(
        'INSERT INTO fee_schedule_history (fee_schedule_id, previous_amount, revised_amount, reason, revised_by) VALUES (?,?,?,?,?)',
        [item.id, item.amount, revised_amount, reason, me.id]
      );
      await conn.query('UPDATE fee_schedule SET amount = ? WHERE id = ?', [revised_amount, item.id]);
    });

    audit.log({ userId: me.id, action: 'fee_schedule.revise',
      entityType: 'fee_schedule', entityId: item.id,
      details: { project_id: item.project_id, milestone_name: item.milestone_name, previous_amount: parseFloat(item.amount), revised_amount: parseFloat(revised_amount), reason }, req });

    res.json({ success: true, message: 'Fee item revised. History preserved.' });
  }));

// PATCH /api/vendors/master/:id/validate-pan — finance_admin or principals validate PAN before first payment
router.patch('/master/:id/validate-pan', requireAuth, asyncHandler(async (req, res) => {
    const me = req.session.user;
    const allowed = ['principal','design_principal','finance_admin'];
    if (!allowed.includes(me.role)) {
      return res.status(403).json({ error: 'PAN validation — finance admin or principals only' });
    }
    const { pan_number } = req.body;
    if (!pan_number) return res.status(400).json({ error: 'PAN number required' });

    const validation = await lookup.validatePAN(pan_number);

    // Bug B42: previously the UPDATE ran unconditionally, so an invalid PAN
    // still set pan_validated=1 — opening payments to a vendor whose PAN
    // validation lookup actually failed. Now: only mark validated when the
    // lookup confirms valid; otherwise return 400 with the lookup's reason.
    if (!validation || validation.valid !== true) {
      return res.status(400).json({
        error: 'PAN validation failed',
        pan:   pan_number.toUpperCase(),
        valid: false,
        note:  validation?.note || 'PAN could not be verified',
      });
    }

    await db.query(
      `UPDATE vendors SET pan_number=?, pan_validated=1, pan_validated_by=?, pan_validated_at=NOW() WHERE id=?`,
      [pan_number.toUpperCase(), me.id, req.params.id]
    );
    audit.log({ userId: me.id, action: 'vendor.pan_validated', entityType: 'vendors', entityId: req.params.id, details: { pan: pan_number.toUpperCase(), entity_type: validation.entity_type }, req });

    res.json({
      success: true,
      pan:     pan_number.toUpperCase(),
      valid:   true,
      entity_type: validation.entity_type,
      note:    validation.note || null,
      message: 'PAN recorded — vendor cleared for payment.',
    });
  }));

// POST /api/vendors/:project_id/engagements/bulk-upload — bulk engage vendors on a project
router.post('/:project_id/engagements/bulk-upload', requireAuth, requireRole(...HEADS_ROLES), upload.single('engagements'), asyncHandler(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file' });
    const rows = await xl.readFile(req.file.path);
    const pid  = req.params.project_id;

    // Header-tolerant accessor — matches ignoring case, trailing '*' and
    // surrounding whitespace (ExcelJS can leave a stray space on a header key,
    // which broke exact `row['Vendor Name']` lookups → "No valid rows").
    // Same normalisation the vendor-master upload uses.
    const pick = (row, ...keys) => {
      for (const k of keys) {
        for (const actualKey of Object.keys(row)) {
          if (actualKey.toLowerCase().replace(/\s*\*/, '').trim() === k.toLowerCase()) {
            const v = row[actualKey];
            if (v !== null && v !== undefined && String(v).trim() !== '') return String(v).trim();
          }
        }
      }
      return null;
    };

    // Validate and collect rows first
    const parsed = [];
    let skipped = 0;
    for (const row of rows) {
      const vendorName    = pick(row, 'Vendor Name', 'vendor_name', 'Vendor') || '';
      const scope         = pick(row, 'Scope', 'Scope of Work', 'Work Scope') || '';
      const contractValue = parseFloat(pick(row, 'Contract Value', 'contract_value') || 0);
      const trade         = pick(row, 'Trade', 'Trade / Discipline', 'trade') || '';
      if (!vendorName || !scope) { skipped++; continue; }
      parsed.push({
        vendorName, scope, contractValue, trade,
        contact: pick(row, 'Contact Person', 'Contact'), phone: pick(row, 'Phone', 'WhatsApp'),
        account: pick(row, 'Account Number', 'Bank Account Number', 'Account'), ifsc: pick(row, 'IFSC', 'Bank IFSC Code'),
      });
    }

    if (!parsed.length) return res.json({ success: true, added: 0, skipped, vendors_created: 0, message: 'No valid rows' });

    // Fetch all existing vendors matching our names in ONE query
    const names = [...new Set(parsed.map(p => p.vendorName))];
    const [existingVendors] = await db.query(
      `SELECT id, vendor_name FROM vendors WHERE vendor_name IN (${names.map(()=>'?').join(',')})`,
      names
    );
    const vendorMap = {};
    existingVendors.forEach(v => { vendorMap[v.vendor_name] = v.id; });

    // Fetch existing engagements on this project in ONE query
    const existingIds = existingVendors.map(v => v.id);
    let existingEng = {};
    if (existingIds.length) {
      const [rows2] = await db.query(
        `SELECT vendor_id FROM vendor_engagements WHERE project_id=? AND vendor_id IN (${existingIds.map(()=>'?').join(',')})`,
        [pid, ...existingIds]
      );
      rows2.forEach(r => { existingEng[r.vendor_id] = true; });
    }

    // TRANSACTION — create missing vendors + all engagements atomically
    const result = await db.tx(async (conn) => {
      let added = 0, created = 0, localSkipped = 0;
      const toInsertEng = [];

      for (const p of parsed) {
        let vid = vendorMap[p.vendorName];
        if (!vid) {
          const [vr] = await conn.query(
            `INSERT INTO vendors (vendor_name, trade, contact_person, phone, bank_account, bank_ifsc, registered_by, clearance_status)
             VALUES (?,?,?,?,?,?,?, 'pending')`, // B10: enter finance-clearance pipeline, don't bypass it
            [p.vendorName, p.trade||'General', p.contact, p.phone, p.account, p.ifsc, req.session.user.id]
          );
          vid = vr.insertId;
          vendorMap[p.vendorName] = vid;
          created++;
        } else if (existingEng[vid]) {
          localSkipped++;
          continue;
        }
        toInsertEng.push([vid, pid, p.scope, p.contractValue||null, req.session.user.id]);
        added++;
      }

      // Batch-insert all engagements in one query
      if (toInsertEng.length) {
        const placeholders = toInsertEng.map(()=>'(?,?,?,?,?)').join(',');
        const flat = toInsertEng.flat();
        await conn.query(
          `INSERT INTO vendor_engagements (vendor_id, project_id, scope, contract_value, engaged_by) VALUES ${placeholders}`,
          flat
        );
      }
      return { added, created, localSkipped };
    });

    audit.log({ userId: req.session.user.id, action: 'engagement.bulk_upload',
      entityType: 'vendor_engagements', entityId: null,
      details: { project_id: parseInt(pid, 10), engagements_added: result.added, vendors_created: result.created, skipped: skipped + result.localSkipped, file_path: req.file.path }, req });

    res.json({
      success: true,
      added: result.added,
      skipped: skipped + result.localSkipped,
      vendors_created: result.created,
      message: `${result.added} engagements created, ${result.created} new vendors, ${skipped + result.localSkipped} skipped`,
    });
  }));

// ── PATCH /master/:id/matrix-room ─────────────────────────────────────────
// Register (or clear) the Matrix bridge room for a vendor.
//
// Called by IT Admin after the etke.cc WhatsApp bridge provisions a portal
// room for a vendor who joined via the bridge. Once set, all vendor
// notification paths (notifyVendorDefectRaised, notifyPaymentConfirmed,
// notifyVendor) route directly to the Matrix room instead of creating a
// manual external_comm task.
//
// Accepts:
//   { matrix_room_id: "!abc:matrix.server" }
//   { matrix_room_id: null }  — clears the room (vendor left / ban / re-invite)
//
// matrix_user_id and matrix_status are set automatically:
//   • On set:   matrix_status = 'joined', matrix_user_id derived from phone
//   • On clear: matrix_status = 'not_invited', matrix_user_id = null
router.patch('/master/:id/matrix-room',
  requireAuth,
  requireRole('it_admin', 'principal', 'design_principal'),
  asyncHandler(async (req, res) => {
    const vendorId = parseInt(req.params.id, 10);
    if (!Number.isFinite(vendorId) || vendorId < 1) {
      return res.status(400).json({ error: 'Invalid vendor id' });
    }

    const { matrix_room_id } = req.body;

    // matrix_room_id must be a valid Matrix room ID or null/empty
    if (matrix_room_id !== null && matrix_room_id !== undefined && matrix_room_id !== '') {
      // Matrix room IDs start with ! and contain a colon
      if (typeof matrix_room_id !== 'string' || !/^![^:]+:.+$/.test(matrix_room_id)) {
        return res.status(400).json({ error: 'matrix_room_id must be a valid Matrix room ID (e.g. !abc:matrix.server) or null' });
      }
    }

    const [[vendor]] = await db.query(
      `SELECT id, vendor_name, phone FROM vendors WHERE id = ? AND is_active = 1 LIMIT 1`,
      [vendorId]
    );
    if (!vendor) return res.status(404).json({ error: 'Vendor not found or inactive' });

    const clearing = !matrix_room_id;

    if (clearing) {
      await db.query(
        `UPDATE vendors SET matrix_room_id = NULL, matrix_user_id = NULL,
           matrix_status = 'not_invited' WHERE id = ?`,
        [vendorId]
      );
    } else {
      // Derive a Matrix user ID from the vendor's phone if available.
      // Pattern: @+<phone>:<homeserver_domain>  (bridge convention for WA bridge).
      let matrixUserId = null;
      if (vendor.phone) {
        const botUser = process.env.MATRIX_BOT_USER_ID || '';
        const domainMatch = botUser.match(/^@[^:]+:(.+)$/);
        if (domainMatch) {
          // Strip leading '+' or country prefix formatting, keep digits
          const digits = vendor.phone.replace(/\D/g, '');
          matrixUserId = `@+${digits}:${domainMatch[1]}`;
        }
      }
      await db.query(
        `UPDATE vendors SET matrix_room_id = ?, matrix_user_id = ?,
           matrix_status = 'joined' WHERE id = ?`,
        [matrix_room_id, matrixUserId, vendorId]
      );
    }

    audit.log({
      userId:     req.session.user.id,
      action:     clearing ? 'vendor.matrix_room.cleared' : 'vendor.matrix_room.set',
      entityType: 'vendors',
      entityId:   vendorId,
      details:    { matrix_room_id: matrix_room_id || null, vendor_name: vendor.vendor_name },
      req,
    });

    res.json({
      success: true,
      vendor_id:     vendorId,
      matrix_room_id: clearing ? null : matrix_room_id,
      matrix_status:  clearing ? 'not_invited' : 'joined',
    });
  }));

module.exports = router;
