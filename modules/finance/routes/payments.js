// routes/payments.js — Vendor payments, RA bills, advances, ICICI wiring
const express = require('express');
const db      = require('../../../middleware/db');
const users = require('../../../services/users-lookup');
const dateUtil = require('../../../services/date-util');
const { requireAuth, requirePMC, requirePrincipal, requireRole, requireFinance, requireProjectScope } = require('../../../middleware/auth');
const { requirePermission } = require('../../../middleware/permissions');
const { upload } = require('../../../middleware/upload');
const notif   = require('../../../services/notifications');
const ai      = require('../../../services/ai');
const pf      = require('../../../services/payment-format');
const asyncHandler = require('../../../middleware/asyncHandler');
const audit = require('../../../services/audit');
const router  = express.Router();

// ── GET payment sheet for a project (weekly Saturday auto-build)
router.get('/:project_id/sheet', requireAuth, requirePMC, asyncHandler(async (req, res) => {
    const pid = req.params.project_id;

    // Get all active engagements with current RA bill data
    const [engagements] = await db.query(`
      SELECT ve.id AS engagement_id, ve.vendor_id, ve.scope, ve.contract_value,
             ve.mobilisation_status,
             COALESCE(SUM(vp.actual_amount),0) AS total_paid,
             MAX(vp.payment_date) AS last_payment_date
      FROM vendor_engagements ve
      LEFT JOIN vendor_payments vp ON vp.engagement_id = ve.id AND vp.status = 'processed'
      WHERE ve.project_id = ? AND ve.is_active = 1
      GROUP BY ve.id`, [pid]);
    const Onboarding = require('../../onboarding/contract');
    const engVendors = await Onboarding.functions.getVendorsByIds(engagements.map(e => e.vendor_id));
    engagements.forEach(e => {
      const v = engVendors.get(e.vendor_id);
      e.vendor_name  = v?.vendor_name || null;
      e.trade        = v?.trade || null;
      e.phone        = v?.phone || null;
      e.bank_account = v?.bank_account || null;
      e.bank_ifsc    = v?.bank_ifsc || null;
      e.bank_name    = v?.bank_name || null;
      e.gst_number   = v?.gst_number || null;
    });

    // Get advance recoveries outstanding — filter by our engagement ids (already fetched)
    const engIds = engagements.map(e => e.engagement_id);
    const [advances] = engIds.length ? await db.query(`
      SELECT * FROM advance_recovery_schedule
      WHERE engagement_id IN (${engIds.map(()=>'?').join(',')}) AND fully_recovered = 0`,
      engIds
    ) : [[]];
    // vendor_id needed for filtering below — look it up from engagements array
    const engVendorMap = new Map(engagements.map(e => [e.engagement_id, e.vendor_id]));
    advances.forEach(a => { a.vendor_id = engVendorMap.get(a.engagement_id); });

    // Build payment sheet rows
    const sheet = engagements.map(e => {
      const pendingAdvance = advances
        .filter(a => a.vendor_id === e.vendor_id)
        .reduce((s,a) => s + parseFloat(a.advance_amount) - parseFloat(a.total_recovered), 0);
      return {
        engagement_id:      e.engagement_id,
        vendor_id:          e.vendor_id,
        vendor_name:        e.vendor_name,
        trade:              e.trade,
        phone:              e.phone,
        bank_account:       e.bank_account,
        bank_ifsc:          e.bank_ifsc,
        bank_name:          e.bank_name,
        contract_value:     parseFloat(e.contract_value||0),
        total_paid:         parseFloat(e.total_paid||0),
        balance_payable:    parseFloat(e.contract_value||0) - parseFloat(e.total_paid||0),
        pending_advance_recovery: pendingAdvance,
        last_payment_date:  e.last_payment_date,
        ra_bill_amount:     0,   // filled by PMC
        recommended_amount: 0,   // filled by PMC
        deductions:         0,   // filled by PMC
        net_payable:        0,   // auto-calc
      };
    });

    res.json({ sheet, week_ending: dateUtil.todayIST() });
  }));

// ── POST payment request — PMC raises RA bill / advance
router.post('/:project_id/raise', requireAuth, requireProjectScope(), requirePMC, asyncHandler(async (req, res) => {
    const { VendorPaymentRaise, parseOr400 } = require('../../../services/schemas');
    const body = parseOr400(VendorPaymentRaise, req, res);
    if (!body) return;

    const validAmount     = body.amount_requested;
    const validDeductions = body.deductions;
    const validWorkPct    = body.work_done_pct ?? null;

    // Check three-strike rule
    const [[excCount]] = await db.query(
      'SELECT COUNT(*) AS cnt FROM vendor_payment_exceptions WHERE engagement_id = ?',
      [body.engagement_id]
    );

    // Check BOQ evidence
    const [[boqCheck]] = await db.query(
      'SELECT COUNT(*) AS cnt FROM vendor_boq_items WHERE engagement_id = ?', [body.engagement_id]
    );
    const hasBoq = boqCheck.cnt > 0;

    if (!hasBoq) {
      const strikes = excCount.cnt;

      // D12 — Strike thresholds are per-project (v5.25 migration). Read from
      // projects table; CHECK constraint enforces warn < block. Using the
      // current project's row.
      const [[proj]] = await db.query(
        'SELECT strike_warn_until, strike_block_until FROM projects WHERE id = ?',
        [req.params.project_id]
      );
      const warnUntil  = proj?.strike_warn_until  ?? 0;
      const blockUntil = proj?.strike_block_until ?? 1;

      if (strikes <= warnUntil) {
        // Strike 1 — soft warn, INSERT exception row, alert PMC head only.
        await db.query(
          `INSERT INTO vendor_payment_exceptions (engagement_id, exception_count, reason, approved_by)
           VALUES (?,?,'No BOQ on record — first exception',?)`,
          [body.engagement_id, strikes + 1, req.session.user.id]
        );
        // Alert project's PMC heads (DB-driven, project-scoped, responds to
        // assignment changes — same pattern as urgent-UTR confirmation).
        const Auth = require('../../auth/contract');
        const pmcHeads = await Auth.functions.getPmcHeadsForProject(req.params.project_id);
        for (const p of pmcHeads) {
          await notif.notify(p.id, 'payment_exception',
            `Payment exception: vendor payment raised without BOQ — strike 1. Project ${req.params.project_id}.`
          ).catch(e => console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message));
        }
      } else if (strikes <= blockUntil) {
        // Strike 2 — soft-block requiring PMC confirmation. Alert PMC heads
        // + finance_admins so both arms know this engagement just hit strike 2
        // and a confirmation request is now active.
        const Auth = require('../../auth/contract');
        const pmcHeads = await Auth.functions.getPmcHeadsForProject(req.params.project_id);
        for (const p of pmcHeads) {
          await notif.notify(p.id, 'payment_exception',
            `Payment exception STRIKE 2: vendor payment without BOQ — confirmation needed. Project ${req.params.project_id}.`
          ).catch(e => console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message));
        }
        const financeAdmins = await users.financeAdmins('id');
        for (const f of financeAdmins) {
          await notif.notify(f.id, 'payment_exception',
            `Payment exception STRIKE 2: vendor payment without BOQ on project ${req.params.project_id}. PMC confirmation pending.`
          ).catch(e => console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message));
        }
        return res.status(400).json({
          error: 'Second payment without BOQ evidence — PMC confirmation required',
          requires_confirmation: true,
          strike: 2,
        });
      } else {
        // Strike 3+ — hard block. Override flow goes through principal sign-off
        // separately (not a notification at this moment; the user must request
        // override which triggers its own approval flow).
        return res.status(400).json({
          error: 'HARD BLOCK: payments without BOQ at or above strike 3. Raise BOQ before proceeding. Principal/Design Principal override required.',
          hard_block: true,
          strike: strikes + 1,
        });
      }
    }

    // Calculate advance recovery deduction
    const [[advRec]] = await db.query(
      'SELECT * FROM advance_recovery_schedule WHERE engagement_id = ? AND fully_recovered = 0 LIMIT 1',
      [body.engagement_id]
    );
    let autoDeduction = 0;
    if (advRec) {
      autoDeduction = Math.round(validAmount * parseFloat(advRec.recovery_pct_per_bill) / 100);
    }

    const recommended = validAmount - autoDeduction - validDeductions;

    // Check anomaly — if recommended differs >20% from RA bill, flag it
    let anomalyNote = null;
    if (Math.abs(recommended - validAmount) / validAmount > 0.2) {
      anomalyNote = await ai.narratePaymentAnomaly(
        '', validAmount, recommended, [], body.notes
      );
    }

    const Onboarding = require('../../onboarding/contract');
    const insertEng = await Onboarding.functions.getVendorEngagement(body.engagement_id);
    if (!insertEng) return res.status(400).json({ error: 'Engagement not found' });
    // Payment INSERT + advance-recovery deduction must be atomic. If the UPDATE
    // failed after the INSERT, the payment would be recorded but the advance
    // never debited — the same advance could then be recovered again next bill.
    let paymentId;
    await db.tx(async (conn) => {
      const [result] = await conn.query(`
      INSERT INTO vendor_payments
        (project_id, vendor_id, engagement_id, payment_type, amount_requested,
         work_done_pct, recommended_amount, notes, raised_by, week_ending)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [req.params.project_id, insertEng.vendor_id, body.engagement_id, body.payment_type, validAmount,
         validWorkPct, recommended, body.notes, req.session.user.id,
         body.week_ending || dateUtil.todayIST()]
      );
      paymentId = result.insertId;

      // Update advance recovery
      if (advRec && autoDeduction > 0) {
        const newTotal = parseFloat(advRec.total_recovered) + autoDeduction;
        const fullyRecovered = newTotal >= parseFloat(advRec.advance_amount);
        await conn.query(
          'UPDATE advance_recovery_schedule SET total_recovered=?, fully_recovered=? WHERE id=?',
          [newTotal, fullyRecovered?1:0, advRec.id]
        );
      }
    });

    res.json({
      success:          true,
      payment_id:       paymentId,
      recommended:      recommended,
      auto_deduction:   autoDeduction,
      anomaly_note:     anomalyNote,
      message:          'Payment raised — pending PMC Head approval before ICICI upload.',
    });
    audit.log({ userId: req.session.user.id, action: 'vendor_payment.raise',
      entityType: 'vendor_payments', entityId: paymentId,
      details: { project_id: parseInt(req.params.project_id, 10), engagement_id: body.engagement_id, vendor_id: insertEng.vendor_id, payment_type: body.payment_type, amount_requested: validAmount, recommended, auto_deduction: autoDeduction, work_done_pct: validWorkPct, has_boq: hasBoq }, req });
  }));

// ── PATCH approve payment — PMC Head approves
router.patch('/:project_id/payments/:id/approve', requireAuth, requireProjectScope(), requirePMC, asyncHandler(async (req, res) => {
    const { actual_amount, adjustment_reason } = req.body;
    const { validateAmount, fmtRupee } = require('../../../services/payment-validation');

    // Load the original payment to compare. vendor_payments uses amount_requested
    // for the claimed amount; amount_auto_calc / recommended_amount track the
    // validated amount; actual_amount is the approved/paid figure.
    const [[vp]] = await db.query(
      'SELECT amount_requested, status, raised_by FROM vendor_payments WHERE id = ? AND project_id = ?',
      [req.params.id, req.params.project_id]
    );
    if (!vp) return res.status(404).json({ error: 'Payment not found' });

    let validActual = parseFloat(vp.amount_requested);
    if (actual_amount !== undefined && actual_amount !== null && actual_amount !== '') {
      const v = validateAmount(actual_amount, 'Actual amount');
      if (!v.ok) return res.status(400).json({ error: v.error });
      validActual = v.amount;
      // If adjusted from requested, require a reason. (Bug fix: vp.amount
      // was referenced here but the SELECT above only fetches amount_requested.
      // parseFloat(undefined) is NaN, so the comparison was always false and
      // the guard never fired — adjustments slipped through without reasons.)
      if (Math.abs(validActual - parseFloat(vp.amount_requested)) > 0.01 && !adjustment_reason) {
        return res.status(400).json({
          error: `Amount adjusted from ${fmtRupee(vp.amount_requested)} to ${fmtRupee(validActual)} — adjustment reason is required`
        });
      }
    }

    const sm = require('../../../services/state-machines').vendorPayment;
    try {
      await sm.transition({
        id: parseInt(req.params.id, 10), from: vp.status, to: 'approved',
        extraCols: {
          approved_by: req.session.user.id, approved_at: new Date(),
          actual_amount: validActual, adjustment_reason: adjustment_reason || null,
        },
      });
    } catch (err) { return sm.handleRouteError(err, res); }
    audit.log({ userId: req.session.user.id, action: 'vendor_payment.approve',
      entityType: 'vendor_payments', entityId: parseInt(req.params.id, 10),
      details: { project_id: parseInt(req.params.project_id, 10), amount_requested: parseFloat(vp.amount_requested), actual_amount: validActual, adjustment_reason: adjustment_reason || null, adjusted: Math.abs(validActual - parseFloat(vp.amount_requested)) > 0.01 }, req });
    res.json({ success: true, message: 'Payment approved — ready for ICICI upload.' });
    try { require('../../../modules/system/routes/sse').notifyProject(req.params.project_id, 'payment_update', { project_id: req.params.project_id }); } catch(_e) {}

    // Tell the PMC user who raised the request that it cleared PMC approval and is
    // now queued for ICICI upload. Fire-and-forget after the transition committed;
    // 'payment_request_pmc_approved' is a seeded trigger.
    if (vp.raised_by) {
      const amtFmt = '₹' + parseFloat(validActual).toLocaleString('en-IN');
      notif.notify(vp.raised_by, 'payment_request_pmc_approved',
        `nu PMC: Vendor payment (${amtFmt}) approved by PMC Head — ready for ICICI upload.`)
        .catch(e => console.warn('[' + require('path').basename(__filename) + '] payment approve notify swallowed:', e.message));
    }
  }));

// ── POST generate ICICI bulk payment Excel
// Shared: gather approved payments with vendor + validation details
async function gatherApprovedPayments(projectId, paymentIds) {
  const [payments] = await db.query(`
    SELECT *
    FROM vendor_payments
    WHERE id IN (?) AND status = 'approved' AND project_id = ?`,
    [paymentIds, projectId]
  );
  if (payments.length) {
    const Onboarding = require('../../onboarding/contract');
    const [pProj, vMap, eMap] = await Promise.all([
      Onboarding.functions.getProject(projectId),
      Onboarding.functions.getVendorsByIds(payments.map(p => p.vendor_id)),
      Onboarding.functions.getEngagementsByIds(payments.map(p => p.engagement_id)),
    ]);
    payments.forEach(p => {
      const v = vMap.get(p.vendor_id);
      const e = eMap.get(p.engagement_id);
      p.vendor_name   = v?.vendor_name || null;
      p.bank_account  = v?.bank_account || null;
      p.bank_ifsc     = v?.bank_ifsc || null;
      p.bank_name     = v?.bank_name || null;
      p.trade         = v?.trade || null;
      p.pan_validated = v?.pan_validated || null;
      // v5.24 ICICI guard: surface vendor's bank_validated_by_vendor flag
      // so generate-Excel can block batches containing unvalidated vendors.
      p.bank_validated_by_vendor = v?.bank_validated_by_vendor ? 1 : 0;
      p.scope         = e?.scope || null;
    });
    payments.forEach(p => {
      p.project_name = pProj?.name || null;
      p.project_code = pProj?.code || null;
    });
  }
  return payments;
}

// GET /api/payments/:project_id/icici/preview — returns what the ICICI Excel WOULD contain
// No state change, no file created. UI uses this for the "Review before generate" modal.
router.get('/:project_id/icici/preview', requireAuth, requirePMC, asyncHandler(async (req, res) => {
    const paymentIdsRaw = req.query.payment_ids;
    if (!paymentIdsRaw) return res.status(400).json({ error: 'payment_ids query param required' });
    const paymentIds = String(paymentIdsRaw).split(',').map(s => parseInt(s.trim(), 10)).filter(Boolean);
    if (!paymentIds.length) return res.status(400).json({ error: 'No valid payment IDs' });

    const payments = await gatherApprovedPayments(req.params.project_id, paymentIds);
    if (!payments.length) return res.status(400).json({ error: 'No approved payments found' });

    const unvalidatedPan  = payments.filter(p => !p.pan_validated).map(p => p.vendor_name);
    const unvalidatedBank = payments.filter(p => !p.bank_validated_by_vendor).map(p => p.vendor_name);
    const total = payments.reduce((s,p)=>s+parseFloat(p.actual_amount||p.recommended_amount||0),0);

    const blockers = (unvalidatedPan.length || unvalidatedBank.length) ? {
      ...(unvalidatedPan.length  ? { pan_not_validated:  unvalidatedPan  } : {}),
      ...(unvalidatedBank.length ? { bank_not_validated: unvalidatedBank } : {}),
    } : null;

    let warning;
    if (unvalidatedPan.length) {
      warning = 'PAN not validated for some vendors — generation blocked until Finance Admin validates.';
    } else if (unvalidatedBank.length) {
      warning = 'Vendor has not yet confirmed their bank details — send onboarding link via WhatsApp before generating.';
    } else {
      warning = 'This Excel will move these payments to status=processed. Cannot be undone easily.';
    }

    res.json({
      payment_count: payments.length,
      total,
      total_in_words: total.toLocaleString('en-IN', { style:'currency', currency:'INR' }),
      rows: payments.map(p => ({
        vendor_name: p.vendor_name,
        bank_account: p.bank_account,
        bank_ifsc: p.bank_ifsc,
        amount: parseFloat(p.actual_amount || p.recommended_amount || 0),
        pan_validated: !!p.pan_validated,
        bank_validated_by_vendor: !!p.bank_validated_by_vendor,
      })),
      blockers,
      can_generate: !unvalidatedPan.length && !unvalidatedBank.length,
      warning,
    });
  }));

// POST /api/payments/:project_id/icici/generate — ACTUALLY generates the Excel and moves payments to processed
// Body MUST include: { confirmation: 'GENERATE', expected_total: <sum> } — total must match to the paise
// to prevent generating the wrong batch after data changed.
router.post('/:project_id/icici/generate', requireAuth, requireProjectScope(), requirePMC, asyncHandler(async (req, res) => {
    const { payment_ids, confirmation, expected_total } = req.body;
    if (!payment_ids?.length) return res.status(400).json({ error: 'Payment IDs required' });
    if (confirmation !== 'GENERATE') {
      return res.status(400).json({
        error: "Must pass { confirmation: 'GENERATE', expected_total: <sum> }",
        code: 'CONFIRMATION_MISSING'
      });
    }

    const payments = await gatherApprovedPayments(req.params.project_id, payment_ids);
    if (!payments.length) return res.status(400).json({ error: 'No approved payments found' });

    const unvalidated = payments.filter(p => !p.pan_validated).map(p => p.vendor_name);
    if (unvalidated.length) {
      return res.status(400).json({
        error: `PAN not validated for: ${unvalidated.join(', ')}. Finance Admin must validate PAN before payment.`,
        code: 'PAN_NOT_VALIDATED',
        unvalidated,
      });
    }

    // v5.24 ICICI guard (per build-commit Iteration 1): refuse to generate
    // the bank batch if any vendor in the batch hasn't confirmed their bank
    // details via the wa.me onboarding flow. Defence-in-depth — the V8 layer
    // also blocks unvalidated changes, but this is the LAST line before
    // money actually moves.
    const unvalidatedBank = payments.filter(p => !p.bank_validated_by_vendor).map(p => p.vendor_name);
    if (unvalidatedBank.length) {
      return res.status(400).json({
        error: `Vendor bank details not confirmed by vendor for: ${unvalidatedBank.join(', ')}. Send onboarding link via WhatsApp and wait for vendor confirmation before generating.`,
        code: 'BANK_NOT_VALIDATED',
        unvalidated: unvalidatedBank,
      });
    }

    // Verify total matches what UI showed user — prevents stale-UI catastrophes
    const total = payments.reduce((s,p)=>s+parseFloat(p.actual_amount||p.recommended_amount||0),0);
    if (expected_total !== undefined && Math.abs(parseFloat(expected_total) - total) > 0.01) {
      return res.status(409).json({
        error: `Total mismatch: you confirmed ₹${expected_total} but current total is ₹${total}. Data changed since preview. Reload and try again.`,
        code: 'TOTAL_MISMATCH',
        your_total: parseFloat(expected_total),
        current_total: total,
      });
    }

    const projectCode = (payments[0].project_code || 'PROJ').substring(0,10);
    const now2 = new Date();
    const dd = String(now2.getDate()).padStart(2,'0');
    const mm = String(now2.getMonth()+1).padStart(2,'0');
    const yyyy = now2.getFullYear();
    const date = `${dd}-${mm}-${yyyy}`;

    // Debit account from company_entities — never hardcoded.
    const [[entity]] = await db.query(
      `SELECT ce.bank_account_no FROM company_entities ce
         JOIN projects p ON p.entity_id = ce.id
        WHERE p.id = ? LIMIT 1`,
      [req.params.project_id]
    );
    if (!entity?.bank_account_no) {
      return res.status(500).json({
        error: 'Company bank account not configured — set bank_account_no on the entity record.',
        code: 'ENTITY_BANK_MISSING',
      });
    }

    const paymentData = payments.map(p => ({
      vendor: { vendor_name:p.vendor_name, bank_account:p.bank_account, bank_ifsc:p.bank_ifsc, trade:p.trade },
      engagement: { scope: p.scope },
      payment: { recommended_amount: p.actual_amount || p.recommended_amount },
    }));

    // FIX: await the promise! Original code left `filePath` as a Promise.
    const filePath = await pf.generateBulkPaymentExcel(paymentData, projectCode, date, entity.bank_account_no);

    // Atomic: cycle record + payment status change together
    const cycleId = await db.tx(async (conn) => {
      const [cycle] = await conn.query(
        'INSERT INTO vendor_payment_cycles (project_id, cycle_date, generated_by) VALUES (?,CURDATE(),?)',
        [req.params.project_id, req.session.user.id]
      );
      const sm = require('../../../services/state-machines').vendorPayment;
      await sm.transitionMany({
        ids: payment_ids, from: 'approved', to: 'processed',
        extraCols: { payment_cycle_id: cycle.insertId },
        conn,
      });
      return cycle.insertId;
    });

    // Audit log — who, what, how much, to whom
    audit.log({
      userId: req.session.user.id,
      action: 'icici_excel_generated',
      entityType: 'vendor_payment_cycles',
      entityId: cycleId,
      details: {
        payment_count: payments.length,
        total,
        vendor_names: payments.map(p => p.vendor_name),
        payment_ids,
        file_path: filePath,
      },
      req
    });

    res.json({
      success: true,
      cycle_id: cycleId,
      file_path: filePath,
      payment_count: payments.length,
      total,
      message: `ICICI Excel generated for ₹${total.toLocaleString('en-IN')}. Send to Finance Admin for bank upload.`,
    });
  }));

// GET /api/payments/:project_id/icici/cycles — batch cycles awaiting confirmation.
// Powers the Cycle ID picker on the "Upload ICICI Confirmation" modal so finance
// selects a real cycle instead of typing an unknown number. Returns generated /
// uploaded (not-yet-confirmed) cycles, newest first.
router.get('/:project_id/icici/cycles', requireAuth, requireProjectScope(),
  requireRole('principal','design_principal','pmc_head','finance_admin'),
  asyncHandler(async (req, res) => {
    const [cycles] = await db.query(
      `SELECT c.id, c.cycle_date, c.status,
              (SELECT COUNT(*) FROM vendor_payments vp WHERE vp.payment_cycle_id = c.id) AS payment_count
         FROM vendor_payment_cycles c
        WHERE c.project_id = ?
          AND c.status IN ('icici_generated','icici_uploaded')
        ORDER BY c.id DESC
        LIMIT 30`,
      [req.params.project_id]
    );
    res.json({ cycles });
  }));

// ── POST upload ICICI confirmation — parse and fire WhatsApp
// POST /api/payments/:project_id/icici/confirm/preview — parse ICICI confirmation Excel
// Returns matched rows, no DB changes, no WhatsApp.
// UI renders as a confirmation table for user review.
router.post('/:project_id/icici/confirm/preview', requireAuth, requireProjectScope(), requireRole('principal','design_principal','pmc_head','finance_admin'), upload.single('confirmation'), asyncHandler(async (req, res) => {
    const file = req.file;
    const { cycle_id } = req.body;
    if (!file || !cycle_id) return res.status(400).json({ error: 'File and cycle_id required' });

    // Validate uploaded file extension (defense-in-depth)
    const ext = require('path').extname(file.originalname).toLowerCase();
    if (ext !== '.xlsx' && ext !== '.xls') {
      // Clean up uploaded file since it is invalid
      const fs = require('fs');
      if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
      return res.status(400).json({ error: 'Invalid file type. Only Excel files (.xlsx, .xls) are allowed.' });
    }

    const confirmations = await pf.parseConfirmationExcel(file.path); // N3 fix: was un-awaited (async) -> .map crashed
    const [cyclePayments] = await db.query(`
      SELECT * FROM vendor_payments WHERE payment_cycle_id = ?`, [cycle_id]
    );
    const Onboarding = require('../../onboarding/contract');
    const cpEngs = await Onboarding.functions.getEngagementsByIds(cyclePayments.map(p => p.engagement_id));
    cyclePayments.forEach(p => {
      const eng = cpEngs.get(p.engagement_id);
      p.vendor_name  = eng?.vendor_name   || null;
      p.bank_account = eng?.bank_account  || null;
      p.phone        = eng?.vendor_phone  || null;
      p.scope        = eng?.scope         || null;
    });

    const matched = pf.matchConfirmationsToVendors(confirmations, cyclePayments.map(p=>({
      vendor: { id:p.vendor_id, vendor_name:p.vendor_name, bank_account:p.bank_account },
      engagement: { id:p.engagement_id },
      payment: { id:p.id },
    })));

    // Classify each row
    const rows = matched.map(conf => {
      const payment = cyclePayments.find(p => p.id === conf.payment_id);
      const success = conf.status?.toLowerCase().includes('success') && conf.utr;
      return {
        payment_id: conf.payment_id,
        vendor_name: payment?.vendor_name,
        vendor_phone: payment?.phone,
        amount: conf.amount,
        utr: conf.utr || null,
        payment_date: conf.payment_date || null,
        status: conf.status,
        will_mark_paid: !!success,
        will_notify_vendor: !!(success && payment?.phone),
      };
    });

    const successCount = rows.filter(r => r.will_mark_paid).length;
    const failCount = rows.length - successCount;
    const totalToNotify = rows.filter(r => r.will_notify_vendor).length;

    // Generate secure cryptographically random token
    const crypto = require('crypto');
    const fileToken = crypto.randomBytes(16).toString('hex');

    if (!req.session.icici_previews) {
      req.session.icici_previews = {};
    }
    req.session.icici_previews[fileToken] = {
      path: file.path,
      originalName: file.originalname,
      userId: req.session.user.id,
      projectId: req.params.project_id,
      cycleId: parseInt(cycle_id, 10),
      createdAt: Date.now()
    };

    res.json({
      preview: rows,
      summary: {
        total_rows: rows.length,
        will_mark_paid: successCount,
        will_require_manual: failCount,
        will_notify_vendors: totalToNotify,
      },
      file_token: fileToken,
      cycle_id: parseInt(cycle_id, 10),
      warning: `If confirmed: ${successCount} payments will be marked paid, ${totalToNotify} vendors will receive WhatsApp with UTR details. ${failCount} rows will need manual follow-up.`,
    });
  }));

// POST /api/payments/:project_id/icici/confirm — APPLY the confirmation
// Body MUST include: { confirmation: 'CONFIRM_PAID', file_token: '<from-preview>', cycle_id, expected_success_count }
// Marks matched payments as paid, sends WhatsApp to vendors with UTR.
router.post('/:project_id/icici/confirm', requireAuth, requireProjectScope(), requireRole('principal','design_principal','pmc_head','finance_admin'), asyncHandler(async (req, res) => {
    const { confirmation, file_token, cycle_id, expected_success_count } = req.body;
    if (!file_token || !cycle_id) return res.status(400).json({ error: 'file_token and cycle_id required (call /preview first)' });
    if (confirmation !== 'CONFIRM_PAID') {
      return res.status(400).json({
        error: "Must pass { confirmation: 'CONFIRM_PAID', file_token, cycle_id, expected_success_count }",
        code: 'CONFIRMATION_MISSING'
      });
    }

    // Retrieve file preview info from session
    const preview = req.session.icici_previews?.[file_token];
    if (!preview) {
      return res.status(400).json({ error: 'Invalid or expired confirmation preview token' });
    }

    // Validate ownership and session context
    if (preview.userId !== req.session.user.id) {
      return res.status(403).json({ error: 'Unauthorised. Upload session owner mismatch.' });
    }
    if (preview.projectId !== req.params.project_id) {
      return res.status(400).json({ error: 'Project mismatch for this confirmation token' });
    }
    if (preview.cycleId !== parseInt(cycle_id, 10)) {
      return res.status(400).json({ error: 'Cycle ID mismatch for this confirmation token' });
    }

    // Validate token expiry (15 minutes = 900,000 ms)
    if (Date.now() - preview.createdAt > 900000) {
      const fs = require('fs');
      if (fs.existsSync(preview.path)) fs.unlinkSync(preview.path);
      delete req.session.icici_previews[file_token];
      return res.status(400).json({ error: 'Confirmation token has expired (15 minute limit)' });
    }

    // Validate file type again (defense-in-depth)
    const ext = require('path').extname(preview.originalName).toLowerCase();
    if (ext !== '.xlsx' && ext !== '.xls') {
      const fs = require('fs');
      if (fs.existsSync(preview.path)) fs.unlinkSync(preview.path);
      delete req.session.icici_previews[file_token];
      return res.status(400).json({ error: 'Invalid file type on token metadata' });
    }

    // Verify file still exists on disk
    const fs = require('fs');
    if (!fs.existsSync(preview.path)) {
      delete req.session.icici_previews[file_token];
      return res.status(400).json({ error: 'Confirmation file not found on server' });
    }

    const file_path = preview.path;

    try {
      // Re-parse the same file
      const confirmations = await pf.parseConfirmationExcel(file_path); // N3 fix
      const [cyclePayments] = await db.query(`
        SELECT * FROM vendor_payments WHERE payment_cycle_id = ?`, [cycle_id]
      );
      const Onboarding2 = require('../../onboarding/contract');
      const cpEngs2 = await Onboarding2.functions.getEngagementsByIds(cyclePayments.map(p => p.engagement_id));
      cyclePayments.forEach(p => {
        const eng = cpEngs2.get(p.engagement_id);
        p.vendor_name  = eng?.vendor_name   || null;
        p.bank_account = eng?.bank_account  || null;
        p.phone        = eng?.vendor_phone  || null;
        p.scope        = eng?.scope         || null;
      });

      const matched = pf.matchConfirmationsToVendors(confirmations, cyclePayments.map(p=>({
        vendor: { id:p.vendor_id, vendor_name:p.vendor_name, bank_account:p.bank_account },
        engagement: { id:p.engagement_id },
        payment: { id:p.id },
      })));

      // Count successes again — compare with expected from preview
      const willSucceed = matched.filter(c => c.status?.toLowerCase().includes('success') && c.utr).length;
      if (expected_success_count !== undefined && parseInt(expected_success_count, 10) !== willSucceed) {
        return res.status(409).json({
          error: `Preview showed ${expected_success_count} would succeed, now ${willSucceed}. Re-preview and confirm.`,
          code: 'COUNT_MISMATCH',
          expected: parseInt(expected_success_count, 10),
          actual: willSucceed,
        });
      }

      // Audit BEFORE any state change
      audit.log({
        userId: req.session.user.id,
        action: 'icici_confirmation_applied',
        entityType: 'vendor_payment_cycles',
        entityId: cycle_id,
        details: { will_mark_paid: willSucceed, total_rows: matched.length },
        req
      });

      let successCount = 0, failCount = 0;
      const notifyTargets = [];
      const sm = require('../../../services/state-machines').vendorPayment;
      for (const conf of matched) {
        if (conf.status?.toLowerCase().includes('success') && conf.utr) {
          try {
            await sm.transition({
              id: conf.payment_id, from: 'processed', to: 'paid',
              extraCols: {
                utr_number: conf.utr,
                payment_date: conf.payment_date || dateUtil.todayIST(),
              },
            });
          } catch (err) {
            // If a row isn't in 'processed' state, skip — it's been previously paid
            // or rolled back. Don't fail the whole batch.
            console.warn('[payments] paid transition skipped for', conf.payment_id, err.message);
            failCount++;
            continue;
          }
          const payment = cyclePayments.find(p => p.id === conf.payment_id);
          if (payment?.phone) {
            notifyTargets.push({ payment, conf });
          }
          successCount++;
        } else {
          failCount++;
        }
      }

      // Send WhatsApp to vendors — outside the loop so status updates are done first
      const sendResults = [];
      for (const { payment, conf } of notifyTargets) {
        try {
          await notif.notifyPaymentConfirmed(
            payment.phone, payment.vendor_name,
            conf.amount, conf.utr,
            conf.payment_date || new Date().toLocaleDateString('en-IN')
          );
          sendResults.push({ vendor: payment.vendor_name, sent: true });
        } catch (e) {
          sendResults.push({ vendor: payment.vendor_name, sent: false, error: e.message });
        }
      }

      // Notify the finance user who completed the batch via Matrix DM.
      const me = req.session.user;
      if (me.matrix_room_id) {
        const matrixAdapter = require('../../../services/matrix-adapter');
        await matrixAdapter.sendText({
          roomId: me.matrix_room_id,
          body: `✅ ICICI confirmation applied — ${successCount} paid, ${failCount} failed. ${sendResults.filter(r=>r.sent).length} vendors notified.`,
          recipientUid: me.id,
        }).catch(e => console.warn('[payments.confirm-batch] Matrix DM failed:', e.message));
      }

      res.json({
        success: true,
        successCount,
        failCount,
        notification_results: sendResults,
        message: `${successCount} payments marked paid. ${sendResults.filter(r=>r.sent).length} vendor notifications sent.${failCount ? ' ' + failCount + ' require manual follow-up.' : ''}`,
      });

    } finally {
      // Ensure session entry is deleted and file is cleaned up under both success and failure
      if (fs.existsSync(file_path)) {
        try {
          fs.unlinkSync(file_path);
        } catch (err) {
          console.warn('[payments] Temp file cleanup failed:', err.message);
        }
      }
      if (req.session.icici_previews) {
        delete req.session.icici_previews[file_token];
      }
      // Force saving the session since this finally block runs after res.json()
      if (typeof req.session.save === 'function') {
        req.session.save();
      }
    }
  }));

// ── GET payment history for a project
router.get('/:project_id/history', requireAuth, requireProjectScope(),
  requireRole('principal','design_principal','pmc_head','finance_admin'),
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    // requireRole above already gates this to the exact set that can see amounts.
    // Audit role bypasses role gates on GETs globally (blockAuditWrites in server.js).

    const [payments] = await db.query(`
      SELECT * FROM vendor_payments
      WHERE project_id = ?
      ORDER BY raised_at DESC LIMIT 100`, [req.params.project_id]
    );
    const Onboarding = require('../../onboarding/contract');
    const histVendors = await Onboarding.functions.getVendorsByIds(payments.map(p => p.vendor_id));
    payments.forEach(p => {
      const v = histVendors.get(p.vendor_id);
      p.vendor_name = v?.vendor_name || null;
      p.trade       = v?.trade || null;
    });
    const Auth = require('../../auth/contract');
    const users = await Auth.functions.getUsers(
      payments.flatMap(p => [p.raised_by, p.approved_by].filter(Boolean))
    );
    payments.forEach(p => {
      p.raised_by_name   = users.get(p.raised_by)?.full_name   || null;
      p.approved_by_name = users.get(p.approved_by)?.full_name || null;
    });

    res.json({ payments });
  }));

// GET /api/payments/:project_id/icici-excel — generate ICICI bulk payment Excel for download
//
// GATE NOTE: this endpoint uses `requireFinance` (which adds finance_admin to
// PMC's role set) while sibling endpoints `/icici/preview`, `/icici/generate`,
// `/icici/confirm/preview`, `/icici/confirm` use `requirePMC` (PMC roles only).
// This is INTENTIONAL separation of duties:
//   - PMC owns the payment-flow lifecycle (preview, generate, confirm).
//   - Finance owns final disbursement — they need to download the Excel to
//     send to ICICI for bank processing.
// Permission `finance.payment.bulk-batch-export` further narrows access.
// Earlier audit notes flagged this as a "role mismatch" — leaving a marker
// here so future readers don't `git blame` and try to "fix" the inconsistency.
router.get('/:project_id/icici-excel', requireAuth, requireFinance,
  requirePermission('finance.payment.bulk-batch-export'),
  asyncHandler(async (req, res) => {
    const me = req.session.user;

    const [payments] = await db.query(
      `SELECT *
       FROM payment_requests
       WHERE project_id=? AND status='principal_approved'
       ORDER BY id`,
      [req.params.project_id]
    );

    if (!payments.length) return res.status(404).json({ error: 'No approved payments for this project' });

    const Onboarding = require('../../onboarding/contract');
    const excProj = await Onboarding.functions.getProject(req.params.project_id);
    const excEngs = await Onboarding.functions.getEngagementsByIds(payments.map(p => p.engagement_id));
    payments.forEach(p => {
      const eng = p.engagement_id ? excEngs.get(p.engagement_id) : null;
      if (eng) {
        p.vendor_name  = eng.vendor_name  || null;
        p.bank_account = eng.bank_account || null;
        p.bank_ifsc    = eng.bank_ifsc    || null;
        p.scope        = eng.scope        || null;
        p.bank_validated_by_vendor = eng.bank_validated_by_vendor ? 1 : 0;
      } else {
        p.vendor_name  = p.adhoc_name || null;
        p.bank_account = p.adhoc_bank_account || null;
        p.bank_ifsc    = p.adhoc_bank_ifsc || null;
        p.scope        = p.reason || null;
        p.bank_validated_by_vendor = 1;
      }
      p.project_name = excProj?.name || null;
    });

    // v5.24 ICICI guard — refuse to emit the Excel if any vendor in the
    // batch hasn't confirmed their bank details. Same defence-in-depth
    // applied to the newer /icici/generate path.
    const unvalidatedBank = payments
      .filter(p => !p.bank_validated_by_vendor)
      .map(p => p.vendor_name);
    if (unvalidatedBank.length) {
      return res.status(400).json({
        error: `Vendor bank details not confirmed by vendor for: ${unvalidatedBank.join(', ')}. Send onboarding link via WhatsApp and wait for confirmation before generating.`,
        code: 'BANK_NOT_VALIDATED',
        unvalidated: unvalidatedBank,
      });
    }

    // sort by vendor_name now that hydrated
    payments.sort((a, b) => (a.vendor_name || '').localeCompare(b.vendor_name || ''));

    const pf  = require('../../../services/payment-format');
    const _d  = new Date();
    const dd  = String(_d.getDate()).padStart(2,'0');
    const mm  = String(_d.getMonth()+1).padStart(2,'0');
    const date = dd + '-' + mm + '-' + _d.getFullYear();

    // Debit account comes from company_entities — never hardcoded.
    // excProj.entity_id is set at project creation (project-setup.js).
    const [[entity]] = await db.query(
      `SELECT bank_account_no FROM company_entities WHERE id = ? LIMIT 1`,
      [excProj.entity_id]
    );
    if (!entity?.bank_account_no) {
      return res.status(500).json({
        error: 'Company bank account not configured — set bank_account_no on the entity record.',
        code: 'ENTITY_BANK_MISSING',
      });
    }

    const proj = { name: await users.projectName(req.params.project_id) };
    const code = (proj?.name||'PROJECT').split(' ').slice(0,2).join('').toUpperCase().replace(/[^A-Z0-9]/g,'');

    const payData = payments.map(p => ({
      vendor:     { vendor_name: p.vendor_name, bank_account: p.bank_account, bank_ifsc: p.bank_ifsc },
      engagement: { scope: p.scope },
      payment:    { recommended_amount: parseFloat(p.pmc_amount || p.amount_requested) },
    }));

    const filePath = await pf.generateBulkPaymentExcel(payData, code, date, entity.bank_account_no);

    const total = payments.reduce((s,p) => s + parseFloat(p.pmc_amount || p.amount_requested), 0);
    const filename = `ICICI_Bulk_Payment_${code}_${date.replace(/-/g,'')}.xlsx`;

    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('X-Payment-Count', payments.length);
    res.setHeader('X-Payment-Total', total.toFixed(2));
    res.sendFile(require('path').resolve(filePath));
  }));

// POST /api/payments/:project_id/compliance-check — PMC triggers schedule check before Saturday
router.post('/:project_id/compliance-check', requireAuth, requireProjectScope(), requirePMC, asyncHandler(async (req, res) => {
    const pid = req.params.project_id;

    // Get all pending payment requests
    const [pending] = await db.query(
      `SELECT * FROM payment_requests
       WHERE project_id=? AND status='pending_pmc'`,
      [pid]
    );
    const Onboarding = require('../../onboarding/contract');
    const pEngs = await Onboarding.functions.getEngagementsByIds(pending.map(p => p.engagement_id));
    pending.forEach(p => {
      const eng = pEngs.get(p.engagement_id);
      p.vendor_name = eng?.vendor_name || null;
      p.scope       = eng?.scope       || null;
    });

    const results = [];
    for (const pr of pending) {
      // Check if vendor's BOQ items have sufficient progress
      const [[progress]] = await db.query(
        `SELECT AVG(tu.pct_complete) AS avg_pct
         FROM task_updates tu
         JOIN schedule_tasks st ON tu.task_id=st.id
         JOIN vendor_boq_items vbi ON vbi.engagement_id=?
         JOIN boq_items bi ON vbi.boq_item_id=bi.id
         WHERE st.project_id=? AND bi.trade=st.trade
         AND tu.report_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)`,
        [pr.engagement_id, pid]
      );

      const avgPct    = parseFloat(progress?.avg_pct || 0);
      const compliant = avgPct >= 25; // minimum 25% progress to release payment

      results.push({
        payment_id:  pr.id,
        vendor:      pr.vendor_name,
        amount:      pr.amount_requested,
        avg_progress: avgPct.toFixed(1),
        compliant,
        reason: compliant ? 'Sufficient progress' : 'Insufficient site progress — ' + avgPct.toFixed(0) + '% recorded',
      });

      // Auto-mark compliant ones as cleared
      if (compliant) {
        await db.query(
          "UPDATE payment_requests SET schedule_compliant=1, compliance_checked_by=?, compliance_checked_at=NOW() WHERE id=?",
          [req.session.user.id, pr.id]
        );
      }
    }

    const cleared = results.filter(r => r.compliant).length;
    const held    = results.filter(r => !r.compliant).length;

    audit.log({ userId: req.session.user.id, action: 'payment.compliance_check',
      entityType: 'payment_requests', entityId: null,
      details: { project_id: parseInt(pid, 10), checked_count: results.length, cleared, held }, req });

    res.json({
      success: true, results, cleared, held,
      message: cleared + ' payment' + (cleared !== 1 ? 's' : '') + ' cleared, ' +
               held + ' held pending sufficient progress.',
    });
  }));

// POST /api/payments/:project_id/batch-approve — Principal approves all cleared payments for a project
router.post('/:project_id/batch-approve', requireAuth, requireProjectScope(), requirePrincipal, asyncHandler(async (req, res) => {
    const [rows] = await db.query(
      'SELECT id FROM payment_requests WHERE project_id = ? AND status = ?',
      [req.params.project_id, 'pmc_approved']
    );
    const { paymentRequest: prSM } = require('../../../services/state-machines');
    const approvedIds = [];
    const failedIds = [];
    for (const row of rows) {
      try {
        await prSM.transition({
          id: row.id, from: 'pmc_approved', to: 'principal_approved',
          extraCols: {
            principal_reviewed_by: req.session.user.id,
            principal_reviewed_at: new Date(),
          },
          audit: { userId: req.session.user.id, req, details: { batch: true } },
        });
        approvedIds.push(row.id);
      } catch (e) {
        if (e.code !== 'INVALID_STATE_TRANSITION') throw e;
        // Row's state changed between SELECT and UPDATE — track for caller visibility
        failedIds.push(row.id);
      }
    }
    // Batch is now fully approved — tell finance (who does the ICICI upload)
    // and the project's PMC heads so disbursement can proceed. Fire-and-forget:
    // the approvals already committed above; a notification failure must not
    // fail the request. 'payment_request_principal_approved' is a seeded trigger.
    if (approvedIds.length) {
      (async () => {
        const projName = await users.projectName(req.params.project_id);
        const msg = `nu PMC: ${approvedIds.length} vendor payment${approvedIds.length !== 1 ? 's' : ''} `
          + `principal-approved for ${projName || ('project ' + req.params.project_id)}. Ready for ICICI upload.`;
        const financeAdmins = await users.financeAdmins('id');
        for (const f of financeAdmins) await notif.notify(f.id, 'payment_request_principal_approved', msg);
        const Auth = require('../../auth/contract');
        const pmcHeads = await Auth.functions.getPmcHeadsForProject(req.params.project_id);
        for (const p of pmcHeads) await notif.notify(p.id, 'payment_request_principal_approved', msg);
      })().catch(e => console.warn('[' + require('path').basename(__filename) + '] batch-approve notify swallowed:', e.message));
    }

    res.json({
      success: true,
      approved: approvedIds.length,
      approved_ids: approvedIds,
      skipped: failedIds,
      message: approvedIds.length + ' payment' + (approvedIds.length !== 1 ? 's' : '') + ' approved' +
               (failedIds.length ? `, ${failedIds.length} skipped (state changed)` : '') + '.',
    });
  }));

// POST /api/payments/pre-upload-check — beneficiary validation + duplicate check
router.post('/pre-upload-check',
  requireAuth,
  requirePermission('finance.payment.pre-upload-check'),
  asyncHandler(async (req, res) => {
    const me = req.session.user;

    const { payment_ids } = req.body;
    if (!payment_ids?.length) return res.status(400).json({ error: 'No payment IDs' });

    const [payments] = await db.query(
      `SELECT id, amount_requested, pmc_amount, vendor_id, engagement_id
       FROM payment_requests
       WHERE id IN (${payment_ids.map(()=>'?').join(',')})`,
      payment_ids
    );
    const Onboarding = require('../../onboarding/contract');
    const preVendors = await Onboarding.functions.getVendorsByIds(payments.map(p => p.vendor_id));
    payments.forEach(p => {
      const v = preVendors.get(p.vendor_id);
      p.vendor_name  = v?.vendor_name || null;
      p.bank_account = v?.bank_account || null;
      p.bank_ifsc    = v?.bank_ifsc || null;
      p.pan_number   = v?.pan_number || null;
    });

    const results = [];
    for (const p of payments) {
      const issues = [];
      const warnings = [];

      // 1. Bank account validation
      if (!p.bank_account || !p.bank_ifsc) {
        issues.push('Missing bank account or IFSC — cannot process');
      } else {
        // IFSC format check — canonical pattern
        const { IFSC_PATTERN } = require('../../../middleware/validate');
        if (!IFSC_PATTERN.test(p.bank_ifsc)) {
          issues.push('IFSC format invalid: ' + p.bank_ifsc);
        }
        // Account number basic check
        if (p.bank_account.length < 9 || p.bank_account.length > 18) {
          issues.push('Bank account number length unusual: ' + p.bank_account.length + ' digits');
        }
      }

      // 2. Duplicate payment check — last 30 days
      const amount = parseFloat(p.pmc_amount || p.amount_requested);
      const [[dup]] = await db.query(
        `SELECT pr2.id, pr2.payment_date FROM payment_requests pr2
         JOIN vendor_engagements ve2 ON pr2.engagement_id=ve2.id
         WHERE ve2.vendor_id = (SELECT vendor_id FROM vendor_engagements WHERE id=(
           SELECT engagement_id FROM payment_requests WHERE id=?
         ))
         AND ABS(pr2.actual_paid - ?) < 1
         AND pr2.payment_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
         AND pr2.id != ?
         AND pr2.status IN ('paid','principal_approved')
         LIMIT 1`,
        [p.id, amount, p.id]
      );
      if (dup) {
        warnings.push('Possible duplicate — same vendor paid ₹' + amount.toLocaleString('en-IN') + ' on ' + dup.payment_date);
      }

      results.push({
        payment_id:  p.id,
        vendor:      p.vendor_name,
        amount,
        bank_account: p.bank_account ? p.bank_account.replace(/(\d{4})(?=\d)/g,'$1 ') : null,
        ifsc:        p.bank_ifsc,
        issues,
        warnings,
        cleared:     issues.length === 0,
      });
    }

    const allClear  = results.every(r => r.cleared);
    const issueCount = results.filter(r => !r.cleared).length;
    const warnCount  = results.filter(r => r.warnings.length > 0).length;

    res.json({
      success: true, results,
      summary: {
        total:   results.length,
        cleared: results.filter(r=>r.cleared).length,
        issues:  issueCount,
        warnings: warnCount,
        ready_to_upload: allClear,
      },
      message: allClear
        ? 'All ' + results.length + ' payments validated. Safe to upload.'
        : issueCount + ' payment' + (issueCount>1?'s':'') + ' have issues — resolve before uploading.',
    });
  }));

// POST /api/payments/utr-webhook — ICICI pushes UTR when payment clears
//
// IDEMPOTENCY:
// ICICI may re-deliver the same webhook (network retry, etc). When that
// happens, the matched payment_request will already be in status='paid' and
// the state machine's `transition({ from: 'principal_approved', to: 'paid' })`
// will throw INVALID_STATE_TRANSITION. That throw is caught silently below
// and we return 200 — this is correct idempotent behaviour for a webhook.
// Do NOT add logic to detect and short-circuit pre-transition; rely on the
// state machine's atomic check. Same-row double-writes are prevented there.
router.post('/utr-webhook', async (req, res) => {
  try {
    // Verify webhook secret — ICICI includes X-Webhook-Secret header or ?secret= query
    const expected = process.env.ICICI_WEBHOOK_SECRET;
    if (!expected) {
      // HARD refuse — an unprotected payment webhook in production could accept forged UTRs
      console.error('[UTR-Webhook] ICICI_WEBHOOK_SECRET not set — refusing to process');
      return res.status(503).json({ error: 'Webhook not configured' });
    }
    const got = req.get('X-Webhook-Secret') || req.query.secret || req.body._secret;
    // Use timing-safe comparison to prevent secret-length leak via timing attack.
    // timingSafeEqual requires equal-length buffers; pad/truncate to expected.length
    // so a too-short or missing token never short-circuits early.
    const crypto = require('crypto');
    const expectedBuf = Buffer.from(expected);
    const gotBuf     = Buffer.alloc(expectedBuf.length);
    if (got) Buffer.from(String(got)).copy(gotBuf);
    const secretOk = crypto.timingSafeEqual(expectedBuf, gotBuf) && !!got;
    if (!secretOk) {
      console.warn('[UTR-Webhook] Invalid/missing webhook secret');
      return res.status(401).json({ error: 'Unauthorised' });
    }

    // ICICI webhook payload
    const { utr, account_number, amount, status, payment_ref } = req.body;
    if (!utr || !account_number) return res.status(400).json({ error: 'Invalid webhook payload' });

    // Match payment by vendor bank account
    const [[payment]] = await db.query(
      `SELECT pr.id, pr.project_id, ve.vendor_id, ve.is_active AS eng_active,
              v.vendor_name, v.phone AS vendor_phone, pr.is_urgent
       FROM payment_requests pr
       JOIN vendor_engagements ve ON pr.engagement_id=ve.id
       JOIN vendors v ON ve.vendor_id=v.id
       WHERE v.bank_account=? AND pr.status='principal_approved'
       AND ABS(pr.pmc_amount - ?) < 1
       ORDER BY pr.principal_reviewed_at DESC LIMIT 1`,
      [account_number.replace(/\s/g,''), parseFloat(amount||0)]
    );

    if (!payment) {
      console.log('[UTR-Webhook] No matching payment for account:', account_number, 'amount:', amount);
      return res.status(200).json({ received: true, matched: false });
    }

    // Update payment record via state machine
    const { paymentRequest: prSM } = require('../../../services/state-machines');
    await prSM.transition({
      id: payment.id, from: 'principal_approved', to: 'paid',
      extraCols: {
        utr_number: utr,
        payment_date: dateUtil.todayIST(),
        paid_by: null,   // NULL = system webhook (no user). 0 would violate FK to users.id.
      },
      audit: { userId: null, req, details: { source: 'utr_webhook', utr } },
    });

    const formattedAmt = '₹' + parseFloat(amount).toLocaleString('en-IN');

    // Send UTR to vendor — Matrix if vendor is on Element X, else skip (wa.me bridge handles it).
    {
      const [[vendor]] = await db.query(
        `SELECT id, matrix_room_id, phone FROM vendors
           JOIN vendor_engagements ve ON ve.vendor_id = vendors.id
           JOIN payment_requests pr ON pr.engagement_id = ve.id
          WHERE pr.id = ? LIMIT 1`,
        [payment.id]
      );
      const msgBody = `💰 Payment confirmed — ${payment.vendor_name}\nAmount: ${formattedAmt}\nUTR: ${utr}\nDate: ${new Date().toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'})}\n\nThank you.`;
      if (vendor?.matrix_room_id) {
        const matrixAdapter = require('../../../services/matrix-adapter');
        await matrixAdapter.sendText({
          roomId: vendor.matrix_room_id,
          body:   msgBody,
        }).catch(e => console.warn('[payments.utr-webhook] vendor Matrix DM failed:', e.message));
      } else if (vendor?.phone) {
        // Tier B vendor — assign to finance admin for manual WhatsApp send.
        const { assignExternalComm } = require('../../../services/external-comm');
        await assignExternalComm({
          activityType:  'payment_utr_confirm',
          vendorId:      vendor.id,
          documentId:    payment.id,
          documentTable: 'payment_requests',
          vendorPhone:   vendor.phone,
          messageBody:   msgBody,
        }).catch(e => console.warn('[payments.utr-webhook] assignExternalComm:', e.message));
      }
    }

    // Notify PMC
    const Auth = require('../../auth/contract');
    const pmcHeads = await Auth.functions.getPmcHeadsForProject(payment.project_id);

    if (payment.is_urgent) {
      // Urgent — post to project's internal room so the whole team sees it.
      const matrixAdapter = require('../../../services/matrix-adapter');
      const projectRoom = await matrixAdapter.getProjectRoomId(payment.project_id, 'internal');
      if (projectRoom) {
        await matrixAdapter.sendText({
          roomId: projectRoom,
          body: `💰 Urgent payment UTR confirmed — ${payment.vendor_name} ${formattedAmt} — UTR: ${utr}`,
        }).catch(e => console.warn('[payments.utr-webhook] urgent Matrix post failed:', e.message));
      }
    } else {
      // Weekly batch — check if all Saturday payments done, then send consolidated in-app
      const [[pending]] = await db.query(
        "SELECT COUNT(*) AS cnt FROM payment_requests WHERE project_id=? AND status='principal_approved'",
        [payment.project_id]
      );
      if (pending.cnt === 0) {
        // All done — consolidated in-app notification to PMC
        for (const p of pmcHeads) {
          await notif.notify(p.id, 'utr_consolidated',
             'All vendor payments confirmed for this project. All UTRs sent to vendors.');
        }
      }
    }

    // Step 4 — first-payment alert to Principal when paying to a recently-changed
    // bank account. Window is configurable via security_config.vendor_bank_alert_days.
    try {
      const [[cfg]] = await db.query(
        `SELECT config_value FROM security_config WHERE config_key = 'vendor_bank_alert_days' LIMIT 1`
      );
      const alertDays = parseInt(cfg?.config_value || '90', 10);
      const [[recentChange]] = await db.query(
        `SELECT vbca.id, vbca.after_bank_account, vbca.after_bank_ifsc,
                vbca.committed_at
           FROM vendor_bank_change_approvals vbca
           JOIN vendor_engagements ve ON ve.vendor_id = vbca.vendor_id
           JOIN payment_requests pr   ON pr.engagement_id = ve.id
          WHERE pr.id = ?
            AND vbca.status = 'approved'
            AND vbca.committed_at IS NOT NULL
            AND vbca.committed_at > DATE_SUB(NOW(), INTERVAL ? DAY)
          ORDER BY vbca.committed_at DESC LIMIT 1`,
        [payment.id, alertDays]
      );
      if (recentChange) {
        const matrixAdapter = require('../../../services/matrix-adapter');
        const principalRoomId  = await matrixAdapter.getInternalRoomId('internal_principal');
        if (principalRoomId) {
          await matrixAdapter.sendText({
            roomId: principalRoomId,
            body: `💰 FYI — first payment to ${payment.vendor_name} on recently-changed ` +
                  `bank account (changed ${new Date(recentChange.committed_at).toLocaleDateString('en-IN',{day:'2-digit',month:'short',year:'numeric'})}). ` +
                  `Amount: ${formattedAmt}  UTR: ${utr}. Awareness only.`,
          });
        }
      }
    } catch (step4Err) {
      console.warn('[UTR-Webhook] step-4 Principal alert failed:', step4Err.message);
    }

    res.status(200).json({ received: true, matched: true });
  } catch (err) {
    // Webhook caller (ICICI) gets 200 to prevent retry storms, but the error
    // is logged so we can diagnose. State-machine INVALID_STATE_TRANSITION on
    // re-delivery is expected (idempotency) — that case is intentionally quiet.
    if (err?.code !== 'INVALID_STATE_TRANSITION') {
      console.error('[UTR-Webhook] processing error:', err.message, err.stack);
    }
    res.status(200).json({ received: true, error: 'Processing error' });
  }
});

module.exports = router;
