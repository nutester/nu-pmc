// routes/measurements.js — Joint Measurement & Certification
const express = require('express');
const db      = require('../../../middleware/db');
const path    = require('path');
const fs      = require('fs');
const PDFDoc  = require('pdfkit');
const { requireAuth, requireRole, requireProjectScope } = require('../../../middleware/auth');
const { requirePermission } = require('../../../middleware/permissions');
const { validators } = require('../../../middleware/validate');
const { upload, UPLOAD_DIR } = require('../../../middleware/upload');
const fileUrls = require('../../../services/file-url');
const asyncHandler = require('../../../middleware/asyncHandler');
const audit = require('../../../services/audit');
const {
  PMC_ROLES,
  STREAM_HEADS_OR_PRINCIPAL: STREAM_HEADS,
  CLIENT_RATE_ROLES: RATE_ROLES,
} = require('../../../services/roles');
const router  = express.Router();

// GET /api/measurements/:project_id — list all measurement records
router.get('/:project_id', requireAuth, requireProjectScope(), asyncHandler(async (req, res) => {
    const me = req.session.user;
    if (me.role !== 'audit' && !RATE_ROLES.includes(me.role)) return res.status(403).json({ error: 'Not authorised' });

    const [measurements] = await db.query(
      `SELECT * FROM measurements
       WHERE project_id = ?
       ORDER BY created_at DESC`,
      [req.params.project_id]
    );
    const Onboarding = require('../../onboarding/contract');
    const proj = await Onboarding.functions.getProject(req.params.project_id);
    measurements.forEach(m => { m.project_name = proj?.name || null; });
    const Auth = require('../../auth/contract');
    const users = await Auth.functions.getUsers(
      measurements.flatMap(m => [m.recorded_by, m.checked_by, m.approved_by].filter(Boolean))
    );
    measurements.forEach(m => {
      m.recorded_by_name = users.get(m.recorded_by)?.full_name || null;
      m.checked_by_name  = users.get(m.checked_by)?.full_name  || null;
      m.approved_by_name = users.get(m.approved_by)?.full_name || null;
      m.signed_certificate_url = m.signed_certificate_path
        ? fileUrls.fileUrl(m.signed_certificate_path, { defaultSubdir: 'documents' }) : null; // B12
    });

    res.json({ measurements });
  }));

// GET /api/measurements/:project_id/:measurement_id/items — line items
router.get('/:project_id/:measurement_id/items', requireAuth, asyncHandler(async (req, res) => {
    const me = req.session.user;
    if (me.role !== 'audit' && !RATE_ROLES.includes(me.role)) return res.status(403).json({ error: 'Not authorised' });

    const [items] = await db.query(
      `SELECT mi.*, cb.item_name, cb.unit, cb.client_rate, cb.trade, cb.item_code
       FROM measurement_items mi
       JOIN client_boq_items cb ON mi.client_boq_item_id = cb.id
       WHERE mi.measurement_id = ?
       ORDER BY cb.trade, cb.display_order`,
      [req.params.measurement_id]
    );

    res.json({ items });
  }));

// POST /api/measurements/:project_id — create new measurement
router.post('/:project_id', requireAuth, requireProjectScope(),
  requirePermission('pmc.measurement.create'),
  validators.measurement, asyncHandler(async (req, res) => {
    const me  = req.session.user;
    const pid = req.params.project_id;

    const { ra_bill_number, discipline, measurement_date, notes } = req.body;

    // ra_bill_number is user-provided (not auto-sequenced) — no race condition here.
    const [result] = await db.query(
      `INSERT INTO measurements
         (project_id, ra_bill_number, discipline, measurement_date, notes, recorded_by, status)
       VALUES (?,?,?,?,?,?,?)`,
      [pid, ra_bill_number, discipline, measurement_date, notes || null, me.id, 'draft']
    );

    // W10: measurements feed billing — every create needs an audit trail.
    audit.log({ userId: me.id, action: 'measurement.create',
      entityType: 'measurements', entityId: result.insertId,
      details: { project_id: parseInt(pid), ra_bill_number, discipline, measurement_date }, req });

    // Notify PMC Head — measurement created and pending technical sign-off.
    const Auth = require('../../auth/contract');
    const notif = require('../../../services/notifications');
    Auth.functions.getUsersByRole('pmc_head', pid).then(async heads => {
      for (const h of heads) {
        await notif.notify(h.id, 'measurement',
          `Measurement recorded — RA Bill ${ra_bill_number} (${discipline}) by ${me.full_name}. Pending technical sign-off.`
        );
      }
    }).catch(e => console.warn('[measurements] PMC notify swallowed:', e.message));

    res.json({ success: true, id: result.insertId });
  }));

// POST /api/measurements/:project_id/:measurement_id/items — add/update measured quantities
router.post('/:project_id/:measurement_id/items', requireAuth, requireProjectScope(),
  requirePermission('pmc.measurement.add-items'),
  asyncHandler(async (req, res) => {
    const me = req.session.user;

    const { items } = req.body; // array of { client_boq_item_id, measured_qty, quality_note }
    if (!items?.length) return res.status(400).json({ error: 'Items required' });

    for (const item of items) {
      await db.query(
        `INSERT INTO measurement_items
           (measurement_id, client_boq_item_id, measured_qty, quality_note)
         VALUES (?,?,?,?)
         ON DUPLICATE KEY UPDATE
           measured_qty   = VALUES(measured_qty),
           quality_note   = VALUES(quality_note)`,
        [req.params.measurement_id, item.client_boq_item_id, item.measured_qty, item.quality_note || null]
      );
    }

    // W11: measured quantities feed RA bills — audit each batch save.
    audit.log({ userId: me.id, action: 'measurement.items.save',
      entityType: 'measurements', entityId: parseInt(req.params.measurement_id),
      details: { project_id: parseInt(req.params.project_id), items_count: items.length }, req });

    res.json({ success: true, items_saved: items.length });
  }));

// POST /api/measurements/:project_id/:measurement_id/rs-signoff — R/S technical sign-off
router.post('/:project_id/:measurement_id/rs-signoff', requireAuth, requireProjectScope(), requireRole(...STREAM_HEADS), asyncHandler(async (req, res) => {
    const me = req.session.user;
    const { notes } = req.body;

    // Read current state + verify scope
    const [[cur]] = await db.query(
      'SELECT status FROM measurements WHERE id = ? AND project_id = ?',
      [req.params.measurement_id, req.params.project_id]
    );
    if (!cur) return res.status(404).json({ error: 'Measurement not found in this project' });

    const sm = require('../../../services/state-machines').measurement;
    try {
      await sm.transition({
        id: parseInt(req.params.measurement_id), from: cur.status, to: 'rs_signed',
        extraCols: {
          checked_by: me.id, checked_at: new Date(), rs_notes: notes || null,
        },
      });
    } catch (err) { return sm.handleRouteError(err, res); }

    audit.log({ userId: me.id, action: 'measurement.rs_signoff',
      entityType: 'measurements', entityId: parseInt(req.params.measurement_id),
      details: { project_id: parseInt(req.params.project_id), signer_role: me.role, notes: notes || null }, req });

    // Services Head approval poll (D3, friction-reduction brief)
    // Poll: ✅ Approved — proceed to claim / ❌ Disputed — recheck required
    try {
      const signoffGate = require('../../../services/signoff-gate');
      await signoffGate.triggerSignoff(
        'measurement_approval',
        parseInt(req.params.measurement_id),
        parseInt(req.params.project_id),
        {
          question: `Measurement signed by ${me.full_name} — approve to proceed to claim?`,
          triggeredBy: me.id,
        }
      );
    } catch (e) {
      console.warn('[measurements] approval poll failed:', e.message);
    }

    res.json({ success: true, message: 'Technical sign-off recorded' });
  }));

// POST /api/measurements/:project_id/:measurement_id/client-acceptance — record client sign-off
router.post('/:project_id/:measurement_id/client-acceptance',
  requireAuth, requireProjectScope(), requireRole(...PMC_ROLES), upload.single('signed_certificate'), asyncHandler(async (req, res) => {
    const me = req.session.user;
    const { client_rep_name, client_rep_designation, acceptance_date, deductions_notes } = req.body;
    if (!client_rep_name || !acceptance_date) {
      return res.status(400).json({ error: 'Client rep name and acceptance date required' });
    }

    const signedFilePath = req.file ? req.file.path : null;

    // Read current state + verify scope
    const [[cur]] = await db.query(
      'SELECT status FROM measurements WHERE id = ? AND project_id = ?',
      [req.params.measurement_id, req.params.project_id]
    );
    if (!cur) return res.status(404).json({ error: 'Measurement not found in this project' });

    const sm = require('../../../services/state-machines').measurement;
    try {
      await sm.transition({
        id: parseInt(req.params.measurement_id), from: cur.status, to: 'client_accepted',
        extraCols: {
          client_rep_name, client_rep_designation: client_rep_designation || null,
          client_accepted_at: acceptance_date,
          deductions_notes: deductions_notes || null,
          signed_certificate_path: signedFilePath,
        },
      });
    } catch (err) { return sm.handleRouteError(err, res); }

    // W12: client acceptance locks measurement for billing — every accept is auditable.
    audit.log({ userId: me.id, action: 'measurement.client_accept',
      entityType: 'measurements', entityId: parseInt(req.params.measurement_id),
      details: { project_id: parseInt(req.params.project_id), client_rep_name, client_rep_designation: client_rep_designation || null, acceptance_date, has_signed_cert: !!signedFilePath }, req });

    // Client acceptance unlocks the measurement for claiming — tell PMC (project-
    // scoped) and the principals so a claim can be raised. Fire-and-forget after
    // the transition committed; 'measurement' is allowlisted for direct sends.
    const notif = require('../../../services/notifications');
    const usersLookup = require('../../../services/users-lookup');
    (async () => {
      const [[meas]] = await db.query(
        'SELECT ra_bill_number, discipline FROM measurements WHERE id = ?',
        [req.params.measurement_id]
      );
      const msg = `nu PMC: Measurement client-accepted — RA Bill ${meas?.ra_bill_number || ''}`
        + `${meas?.discipline ? ' (' + meas.discipline + ')' : ''}. Ready to raise claim.`;
      const Auth = require('../../auth/contract');
      const pmcHeads = await Auth.functions.getUsersByRole('pmc_head', req.params.project_id);
      for (const h of pmcHeads) await notif.notify(h.id, 'measurement', msg);
      const principals = await usersLookup.principals();
      for (const p of principals) await notif.notify(p.id, 'measurement', msg);
    })().catch(e => console.warn('[measurements] client-accept notify swallowed:', e.message));

    res.json({ success: true, message: 'Client acceptance recorded' });
  }));

// GET /api/measurements/:project_id/:measurement_id/certificate — generate PDF
// Quantities ONLY — no rates, no amounts
router.get('/:project_id/:measurement_id/certificate', requireAuth, asyncHandler(async (req, res) => {
    const me = req.session.user;
    if (me.role !== 'audit' && !RATE_ROLES.includes(me.role)) return res.status(403).json({ error: 'Not authorised' });

    // Get measurement details
    const [[meas]] = await db.query(
      `SELECT * FROM measurements WHERE id = ? AND project_id = ?`,
      [req.params.measurement_id, req.params.project_id]
    );

    if (!meas) return res.status(404).json({ error: 'Measurement not found' });

    const Onboarding = require('../../onboarding/contract');
    const mproj = await Onboarding.functions.getProject(meas.project_id);
    meas.project_name = mproj?.name || null;
    meas.client       = mproj?.client || null;

    // Fetch firm identity for PDF footer via project → entity
    const [[measEntity]] = await db.query(
      `SELECT legal_name, address_line1, gstin, email_primary
       FROM company_entities WHERE id = ? LIMIT 1`,
      [mproj?.entity_id || 0]
    );

    const Auth = require('../../auth/contract');
    const mUsers = await Auth.functions.getUsers([meas.recorded_by, meas.checked_by].filter(Boolean));
    meas.recorded_by_name = mUsers.get(meas.recorded_by)?.full_name || null;
    meas.checked_by_name  = mUsers.get(meas.checked_by)?.full_name  || null;

    // Get items — NO rates, quantities only
    const [items] = await db.query(
      `SELECT mi.measured_qty, mi.quality_note,
         cb.item_code, cb.item_name, cb.unit, cb.quantity AS boq_qty, cb.trade
       FROM measurement_items mi
       JOIN client_boq_items cb ON mi.client_boq_item_id = cb.id
       WHERE mi.measurement_id = ?
       ORDER BY cb.trade, cb.display_order`,
      [req.params.measurement_id]
    );

    // Generate PDF
    const doc = new PDFDoc({ margin: 50, size: 'A4' });
    const outPath = path.join(UPLOAD_DIR, 'documents',
      `cert_${req.params.project_id}_${req.params.measurement_id}_${Date.now()}.pdf`);

    const writeStream = fs.createWriteStream(outPath);
    doc.pipe(writeStream);

    // ── HEADER
    doc.fontSize(16).font('Helvetica-Bold')
       .text('MEASUREMENT CERTIFICATE', { align: 'center' });
    doc.fontSize(10).font('Helvetica')
       .text('QUANTITIES ONLY — RATES NOT SHOWN', { align: 'center' });
    doc.moveDown(0.5);

    // Divider
    doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
    doc.moveDown(0.5);

    // Project info
    doc.fontSize(10).font('Helvetica-Bold').text('Project: ', { continued: true })
       .font('Helvetica').text(meas.project_name);
    doc.font('Helvetica-Bold').text('Client: ', { continued: true })
       .font('Helvetica').text(meas.client);
    doc.font('Helvetica-Bold').text('Discipline: ', { continued: true })
       .font('Helvetica').text(meas.discipline);
    doc.font('Helvetica-Bold').text('RA Bill No: ', { continued: true })
       .font('Helvetica').text(meas.ra_bill_number);
    doc.font('Helvetica-Bold').text('Measurement Date: ', { continued: true })
       .font('Helvetica').text(new Date(meas.measurement_date).toLocaleDateString('en-IN'));
    doc.moveDown(0.5);

    doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
    doc.moveDown(0.5);

    // Table header
    const cols = { code: 50, name: 200, unit: 60, boq: 80, measured: 80, note: 75 };
    const startX = 50;
    let y = doc.y;

    doc.fontSize(9).font('Helvetica-Bold');
    doc.text('Code',     startX,                    y, { width: cols.code });
    doc.text('Item',     startX + cols.code,         y, { width: cols.name });
    doc.text('Unit',     startX + cols.code + cols.name, y, { width: cols.unit });
    doc.text('BOQ Qty',  startX + cols.code + cols.name + cols.unit, y, { width: cols.boq });
    doc.text('Measured', startX + cols.code + cols.name + cols.unit + cols.boq, y, { width: cols.measured });
    doc.text('Notes',    startX + cols.code + cols.name + cols.unit + cols.boq + cols.measured, y, { width: cols.note });
    doc.moveDown(0.3);

    doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
    doc.moveDown(0.2);

    // Group by trade
    const byTrade = {};
    items.forEach(item => {
      if (!byTrade[item.trade]) byTrade[item.trade] = [];
      byTrade[item.trade].push(item);
    });

    doc.fontSize(9).font('Helvetica');
    Object.entries(byTrade).forEach(([trade, tradeItems]) => {
      // Trade header
      doc.font('Helvetica-Bold').text(trade.toUpperCase(), startX, doc.y);
      doc.font('Helvetica');

      tradeItems.forEach(item => {
        y = doc.y;
        doc.text(item.item_code || '—', startX, y, { width: cols.code });
        doc.text(item.item_name,         startX + cols.code, y, { width: cols.name });
        doc.text(item.unit,              startX + cols.code + cols.name, y, { width: cols.unit });
        doc.text(parseFloat(item.boq_qty).toFixed(2),
                 startX + cols.code + cols.name + cols.unit, y, { width: cols.boq, align: 'right' });
        doc.text(parseFloat(item.measured_qty).toFixed(2),
                 startX + cols.code + cols.name + cols.unit + cols.boq, y, { width: cols.measured, align: 'right' });
        doc.text(item.quality_note || '',
                 startX + cols.code + cols.name + cols.unit + cols.boq + cols.measured, y, { width: cols.note });
        doc.moveDown(0.2);

      });
      doc.moveDown(0.3);
    });

    // Divider before sign-off
    doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
    doc.moveDown(1);

    // Sign-off block — NO Principal, good faith
    const signY = doc.y;
    doc.fontSize(9).font('Helvetica-Bold');
    doc.text('Prepared by (PMC):', 50, signY);
    doc.font('Helvetica').text(meas.recorded_by_name || '_______________', 50, signY + 12);
    doc.text('Signature: _______________', 50, signY + 24);
    doc.text('Date: _______________', 50, signY + 36);

    doc.font('Helvetica-Bold');
    doc.text('Checked by (Design / Services):', 200, signY);
    doc.font('Helvetica').text(meas.checked_by_name || '_______________', 200, signY + 12);
    doc.text('Signature: _______________', 200, signY + 24);
    doc.text('Date: _______________', 200, signY + 36);

    doc.font('Helvetica-Bold');
    doc.text('Client Representative:', 380, signY);
    doc.font('Helvetica').text('Name: _______________', 380, signY + 12);
    doc.text('Designation: _______________', 380, signY + 24);
    doc.text('Signature: _______________', 380, signY + 36);
    doc.text('Date: _______________', 380, signY + 48);

    doc.moveDown(4);
    doc.moveTo(50, doc.y).lineTo(545, doc.y).stroke();
    doc.moveDown(0.3);

    // HSN note
    doc.moveDown(0.5);
    doc.fontSize(8).font('Helvetica-Oblique').fillColor('grey')
       .text('HSN codes are shown on the invoice generated by finance. This certificate contains quantities only.', { align: 'center' });
    doc.fillColor('black');

    // Footer
    const footerName = measEntity?.legal_name    || '';
    const footerAddr = measEntity?.address_line1 || '';
    const footerGstn = measEntity?.gstin         || '';
    const footerMail = measEntity?.email_primary || '';
    doc.fontSize(8).font('Helvetica').fillColor('grey')
       .text(`${footerName}${footerAddr ? ' — ' + footerAddr : ''}`, { align: 'center' })
       .text(`${footerGstn ? 'GSTIN: ' + footerGstn : ''}${footerMail ? '  ·  ' + footerMail : ''}`, { align: 'center' });

    doc.end();

    await new Promise((resolve, reject) => {
      writeStream.on('finish', resolve);
      writeStream.on('error', reject);
    });

    // Return file path for download
    res.json({
      success:   true,
      file_path: outPath,
      file_name: `MeasurementCertificate_${meas.discipline}_RA${meas.ra_bill_number}.pdf`,
      message:   'Certificate generated — download and share with client manually'
    });

  }));

// POST /api/measurements/:project_id/:measurement_id/signed-cert — upload signed cert after acceptance
router.post('/:project_id/:measurement_id/signed-cert',
  requireAuth, requireProjectScope(), requireRole(...PMC_ROLES), upload.single('signed_certificate'),
  asyncHandler(async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'File required' });
    const [[meas]] = await db.query(
      'SELECT id, status FROM measurements WHERE id = ? AND project_id = ?',
      [req.params.measurement_id, req.params.project_id]
    );
    if (!meas) return res.status(404).json({ error: 'Measurement not found' });
    if (meas.status !== 'client_accepted') return res.status(400).json({ error: 'Measurement must be client_accepted' });
    await db.query(
      'UPDATE measurements SET signed_certificate_path = ? WHERE id = ?',
      [req.file.path, req.params.measurement_id]
    );
    const audit = require('../../../services/audit');
    audit.log({ userId: req.session.user.id, action: 'measurement.signed_cert.upload',
      entityType: 'measurements', entityId: parseInt(req.params.measurement_id),
      details: { project_id: parseInt(req.params.project_id) }, req });
    res.json({ success: true });
  }));

module.exports = router;
