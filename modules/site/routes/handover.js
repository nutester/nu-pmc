// modules/site/routes/handover.js
//
// Handover module — document checklist + project closure.
//
// Note: snags (DLP punch list) used to live here but were collapsed into the
// issues module as `issue_type='snag'` (v5.7 migration). See issues.js for
// snag endpoints. The signoff helper is shared via lib/signoff-helpers.js.
//
// Endpoints:
//   GET   /api/handover/:project_id/checklist                     list checklist items
//   POST  /api/handover/:project_id/checklist/initialise          seed from template
//   POST  /api/handover/:project_id/checklist/:item_id/upload     attach document
//   GET   /api/handover/:project_id/closure                       list signoffs + status
//   POST  /api/handover/:project_id/closure/signoff               record one role's signoff

'use strict';

const express = require('express');
const db      = require('../../../middleware/db');
const { requireAuth, requireProjectScope, requireScopeFromEntity, requirePMC, requireRole } = require('../../../middleware/auth');
const { requirePermission } = require('../../../middleware/permissions');
const { upload } = require('../../../middleware/upload');
const asyncHandler = require('../../../middleware/asyncHandler');
const audit = require('../../../services/audit');
const { determineSignoffSlot } = require('../lib/signoff-helpers');
// Shared file-URL helper — converts uploads/... paths to authenticated
// /api/files/:subdir/:filename URLs. Must not expose raw filesystem paths.
const fileUrls = require('../../../services/file-url');

const router = express.Router();

// Roles that must each sign off before a project can be marked completed.
// Design Principal added per closure-authority requirement. These roles are
// ALSO the ones allowed to reach the upload/signoff endpoints (see gates
// below) — previously those used requirePMC, which excluded design_head /
// services_head, so their required slots could never be signed and no project
// could ever close.
const CLOSURE_SIGNOFF_ROLES = ['pmc_head', 'design_head', 'services_head', 'principal', 'design_principal'];

// ── CHECKLIST ──────────────────────────────────────────────────────────────

router.get('/:project_id/checklist',
  requireAuth, requireProjectScope(),
  asyncHandler(async (req, res) => {
    const projectId = parseInt(req.params.project_id, 10);
    const [items] = await db.query(
      `SELECT id, item_name, discipline, is_applicable, file_path, uploaded_at, sort_order
       FROM handover_checklist_items
       WHERE project_id = ?
       ORDER BY discipline, sort_order, item_name`,
      [projectId]
    );

    const total      = items.filter(i => i.is_applicable).length;
    const submitted  = items.filter(i => i.is_applicable && i.file_path).length;
    const completion_pct = total === 0 ? 0 : Math.round((submitted / total) * 100);

    // Convert raw filesystem paths to authenticated /api/files/ URLs so the
    // frontend can render download links without ever accessing /uploads directly.
    items.forEach(item => {
      item.file_url = fileUrls.fileUrl(item.file_path, { defaultSubdir: 'documents' });
      // Keep file_path for server-side use only; do not send raw path to client.
      delete item.file_path;
    });

    res.json({ items, total, submitted, completion_pct });
  })
);

router.post('/:project_id/checklist/initialise',
  requireAuth, requireProjectScope(), requirePMC,
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const projectId = parseInt(req.params.project_id, 10);

    const [[exists]] = await db.query(
      'SELECT COUNT(*) AS c FROM handover_checklist_items WHERE project_id = ?',
      [projectId]
    );
    if (exists.c > 0) {
      return res.json({ success: true, items_created: 0, message: 'Already initialised' });
    }

    const [template] = await db.query(
      `SELECT item_name, discipline, sort_order
       FROM handover_checklist_template WHERE is_active = 1
       ORDER BY sort_order`
    );
    if (!template.length) {
      return res.status(500).json({ error: 'No template items found — seed missing' });
    }

    const values = template.map(t => [projectId, t.item_name, t.discipline, t.sort_order]);
    await db.query(
      `INSERT INTO handover_checklist_items
       (project_id, item_name, discipline, sort_order)
       VALUES ?`,
      [values]
    );

    audit.log({ userId: me.id, action: 'handover.checklist.init',
      entityType: 'projects', entityId: projectId,
      details: { items_created: template.length }, req });

    res.json({ success: true, items_created: template.length });
  })
);

router.post('/:project_id/checklist/:item_id/upload',
  requireAuth, requireProjectScope(), requireRole(...CLOSURE_SIGNOFF_ROLES),
  upload.single('doc'),
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const itemId = parseInt(req.params.item_id, 10);
    if (!req.file) return res.status(400).json({ error: 'doc file required' });

    await db.query(
      `UPDATE handover_checklist_items
       SET file_path=?, uploaded_by=?, uploaded_at=NOW()
       WHERE id = ?`,
      [req.file.path, me.id, itemId]
    );
    audit.log({ userId: me.id, action: 'handover.checklist.upload',
      entityType: 'handover_checklist_items', entityId: itemId, req });

    res.json({ success: true });
  })
);

// ── CLOSURE ────────────────────────────────────────────────────────────────

router.get('/:project_id/closure',
  requireAuth, requireProjectScope(),
  asyncHandler(async (req, res) => {
    const projectId = parseInt(req.params.project_id, 10);
    const [signoffs] = await db.query(
      `SELECT s.signed_for_role AS role, s.signed_at, u.full_name AS signed_by_name
       FROM handover_closure_signoffs s
       JOIN users u ON s.signed_by_user_id = u.id
       WHERE s.project_id = ?`,
      [projectId]
    );
    const signedRoles = new Set(signoffs.map(s => s.role));
    const complete = CLOSURE_SIGNOFF_ROLES.every(r => signedRoles.has(r));
    res.json({ signoffs, complete, required_roles: CLOSURE_SIGNOFF_ROLES });
  })
);

router.post('/:project_id/closure/signoff',
  requireAuth, requireProjectScope(), requireRole(...CLOSURE_SIGNOFF_ROLES),
  asyncHandler(async (req, res) => {
    const me = req.session.user;
    const projectId = parseInt(req.params.project_id, 10);
    const { notes, role: bodyRole } = req.body || {};

    const slot = await determineSignoffSlot(me, projectId, CLOSURE_SIGNOFF_ROLES, bodyRole);
    if (!slot) {
      return res.status(403).json({
        error: 'You are not in a closure signoff slot and not a deputy for one.',
        code:  'NO_SIGNOFF_SLOT',
        required_slots: CLOSURE_SIGNOFF_ROLES,
      });
    }

    // S39: signoff INSERT and project status UPDATE were separate. Same
    // pattern as snag-signoff. Both must succeed together or neither.
    let allSigned = false;
    let dupSlot = false;
    let alreadyAnotherSlot = false;

    await db.tx(async (conn) => {
      // SECURITY: one person cannot fill more than one closure slot. The quorum
      // requires distinct signers, not distinct role labels from a single
      // universal signer — otherwise one principal could sign all five slots and
      // complete closure alone.
      const [mine] = await conn.query(
        `SELECT signed_for_role FROM handover_closure_signoffs
          WHERE project_id = ? AND signed_by_user_id = ?`,
        [projectId, me.id]
      );
      if (mine.some(r => r.signed_for_role !== slot)) {
        alreadyAnotherSlot = true;
        return;
      }
      try {
        await conn.query(
          `INSERT INTO handover_closure_signoffs (project_id, signed_for_role, signed_by_user_id, notes)
           VALUES (?,?,?,?)`,
          [projectId, slot, me.id, notes || null]
        );
      } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          dupSlot = true;
          return;
        }
        throw err;
      }

      const [[counts]] = await conn.query(
        `SELECT COUNT(DISTINCT signed_for_role) AS c
         FROM handover_closure_signoffs WHERE project_id = ? AND signed_for_role IN (?)`,
        [projectId, CLOSURE_SIGNOFF_ROLES]
      );

      if (counts.c >= CLOSURE_SIGNOFF_ROLES.length) {
        const [[curProj]] = await conn.query('SELECT status FROM projects WHERE id = ?', [projectId]);
        if (curProj && curProj.status !== 'completed') {
          const sm = require('../../../services/state-machines').project;
          await sm.transition({
            id: projectId, from: curProj.status, to: 'completed',
            conn,
          });
        }
        allSigned = true;
      }
    });

    if (alreadyAnotherSlot) {
      return res.status(409).json({
        error: 'You have already signed a different closure slot; one person cannot fill multiple slots.',
        code:  'ONE_SLOT_PER_USER',
      });
    }

    if (dupSlot) {
      return res.status(409).json({ error: `Slot '${slot}' already signed` });
    }

    // Alert Principal on closure initiation (first signoff) and completion
    if (!dupSlot) {
      const matrixAdapter = require('../../../services/matrix-adapter');
      const [[proj]] = await db.query('SELECT code, name FROM projects WHERE id = ?', [projectId]);
      const [principals] = await db.query(
        `SELECT matrix_room_id FROM users
          WHERE role IN ('principal','design_principal') AND is_active = 1 AND matrix_room_id IS NOT NULL`
      );
      const pwaUrl = `${process.env.PWA_BASE_URL}/handover/${projectId}`;
      const msg = allSigned
        ? `✅ ${proj?.code} — Project closure complete. All signatures collected. ${pwaUrl}`
        : `📋 ${proj?.code} — Project closure initiated by ${me.full_name} (${slot}). ${CLOSURE_SIGNOFF_ROLES.length - 1} more signatures needed. ${pwaUrl}`;
      for (const p of principals) {
        await matrixAdapter.sendText({ roomId: p.matrix_room_id, body: msg })
          .catch(e => console.warn('[closure] Principal alert failed:', e.message));
      }
    }

    if (allSigned) {
      try {
        const Reporting = require('../../reporting/contract');
        Reporting.functions.generateAIDraftForProject(projectId).catch(err => {
          console.error('[closure] AI draft generation failed:', err.message);
        });
      } catch { /* fall through */ }
    }

    audit.log({ userId: me.id, action: 'handover.closure.signoff',
      entityType: 'projects', entityId: projectId,
      details: { slot, all_signed: allSigned }, req });

    res.json({ success: true, slot, all_signed: allSigned });
  })
);

module.exports = router;
