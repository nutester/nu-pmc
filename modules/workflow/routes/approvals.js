// routes/approvals.js
const express = require('express');
const db      = require('../../../middleware/db');
const users = require('../../../services/users-lookup');
const { requireAuth, requirePrincipal, requireRole } = require('../../../middleware/auth');
const asyncHandler = require('../../../middleware/asyncHandler');
const audit = require('../../../services/audit');
const router  = express.Router();

// GET /api/approvals — all pending approvals visible to this user.
//
// Two sources are merged:
//   UNIFIED  — approvals table, filtered by services/approvals.pendingForUser()
//              (role gate against signer_roles_json + project membership)
//   SIGNOFF  — signoff_instances where current user is current_approver
//              (Matrix relay safety net for when a poll is missed)
//
// Legacy wa_pending_actions source has been retired. All new approval
// workflows go through approvals.open() / approval_type_config.
router.get('/', requireAuth, asyncHandler(async (req, res) => {
    const me = req.session.user;

    // ── UNIFIED: approvals ───────────────────────────────────────────────
    const approvalsService = require('../../../services/approvals');
    const Onboarding = require('../../onboarding/contract');
    const projectIds = (me.projects || []).map(p => p.id).filter(Boolean);
    const unifiedRaw = await approvalsService.pendingForUser({
      userId: me.id, role: me.role, projectIds,
    });
    // Hydrate project name on unified rows (pendingForUser doesn't join projects)
    const unifiedProjs = await Onboarding.functions.getProjectsByIds(unifiedRaw.map(u => u.project_id));
    const unifiedRows = unifiedRaw.map(u => ({
      id: u.id,
      action_type: u.approval_type,
      title: u.title,
      details: u.details,
      project_id: u.project_id,
      project_name: u.project_id ? (unifiedProjs.get(u.project_id)?.name || null) : null,
      project_code: u.project_id ? (unifiedProjs.get(u.project_id)?.code || null) : null,
      raised_at: u.raised_at,
      status: 'pending',
      user_id: u.raised_by,
      user_id_name: u.raised_by_name || null,
      label: u.label,
      quorum: u.quorum,
      expires_at: u.expires_at,
      vendor_id: u.vendor_id,
      ref_table: u.ref_table,
      ref_id: u.ref_id,
      source: 'unified',
    }));

    // ── SIGNOFF-GATE: signoff_instances (Matrix relay safety net) ─────
    // Surfaced here so the pending tab catches items where Matrix is down
    // or a poll was missed. Actions are still taken via Matrix; no in-app
    // approve/reject buttons are rendered for signoff rows.
    const [signoffRows] = await db.query(
      `SELECT si.id, si.workflow_type, si.document_id, si.project_id,
              si.question, si.status AS si_status, si.current_approver_id,
              si.closes_at, si.created_at,
              sw.quorum_required
         FROM signoff_instances si
         JOIN signoff_workflows sw ON sw.workflow_type = si.workflow_type AND sw.active = 1
        WHERE si.current_approver_id = ?
          AND si.status IN ('pending', 'in_progress')
        ORDER BY si.created_at DESC`,
      [me.id]
    );
    const signoffProjs = signoffRows.length
      ? await Onboarding.functions.getProjectsByIds(signoffRows.map(s => s.project_id))
      : new Map();
    const signoffMapped = signoffRows.map(s => ({
      id: `signoff_${s.id}`,
      action_type: s.workflow_type,
      title: s.question || `${s.workflow_type} — document #${s.document_id}`,
      details: null,
      project_id: s.project_id,
      project_name: s.project_id ? (signoffProjs.get(s.project_id)?.name || null) : null,
      project_code: s.project_id ? (signoffProjs.get(s.project_id)?.code || null) : null,
      raised_at: s.created_at,
      status: 'pending',
      user_id: null,
      user_id_name: null,
      signoff_instance_id: s.id,
      document_id: s.document_id,
      closes_at: s.closes_at,
      quorum: s.quorum_required,
      source: 'signoff',
    }));

    // ── Merge + sort newest-pending first
    const merged = [...unifiedRows, ...signoffMapped].sort((a, b) => {
      const aTs = new Date(a.raised_at || 0).getTime();
      const bTs = new Date(b.raised_at || 0).getTime();
      return bTs - aTs;
    });

    res.json({ approvals: merged });
  }));

// POST /api/approvals — raise approval request via unified approvals table.
// Previously wrote to wa_pending_actions; now uses approvals.open() so the
// item is visible in the GET /api/approvals unified list and actionable via
// POST /api/approvals/v2/:id/vote.
//
// approval_type_config must have an active row for the given action_type
// (schedule_change and weekly_report are seeded in seed-config.sql).
const APPROVAL_RAISERS = ['principal','design_principal','pmc_head','design_head','services_head','finance_admin'];
router.post('/', requireAuth, requireRole(...APPROVAL_RAISERS), asyncHandler(async (req, res) => {
    const me = req.session.user;
    const { project_id, action_type, message_sent, drift_days } = req.body;
    if (!project_id || !action_type || !message_sent) return res.status(400).json({ error: 'Missing required fields' });

    const approvalsService = require('../../../services/approvals');
    const result = await approvalsService.open({
      approvalType:  action_type,
      refTable:      'projects',
      refId:         parseInt(project_id, 10),
      projectId:     parseInt(project_id, 10),
      raisedBy:      me.id,
      raisedByRole:  me.role,
      title:         message_sent,
      details:       drift_days ? `Drift: +${drift_days}d` : null,
    });

    audit.log({ userId: me.id, action: 'approval.create',
      entityType: 'approvals', entityId: result.id,
      details: { action_type, project_id: parseInt(project_id, 10), drift_days: drift_days || null }, req });

    const { notifyApprovalNeeded } = require('../../../services/notifications');
    const proj = { name: await users.projectName(project_id) };
    notifyApprovalNeeded(action_type, message_sent, proj?.name||'').catch(e => console.warn('[' + require('path').basename(__filename) + '] swallowed:', e.message));

    res.json({ success: true, id: result.id });
  }));

module.exports = router;

// ════════════════════════════════════════════════════════════════════════════
// UNIFIED API (build-commit lock #7) — /api/approvals/v2/*
// These endpoints operate on the new approvals + approval_signoffs tables.
// The merged GET above tags rows with source='unified' so the frontend
// knows to call these endpoints rather than the legacy /:id/approve path.
// ════════════════════════════════════════════════════════════════════════════

const approvalsService = require('../../../services/approvals');

// GET /api/approvals/v2/:id — single approval row + its signoffs
router.get('/v2/:id', requireAuth, asyncHandler(async (req, res) => {
  const result = await approvalsService.get(parseInt(req.params.id, 10));
  if (!result) return res.status(404).json({ error: 'Approval not found' });
  res.json(result);
}));

// POST /api/approvals/v2/:id/vote — cast a vote on a unified approval
// Body: { vote: 'approve' | 'reject', comment?: string }
//
// Quorum + reject-veto rules live in the service. The route enforces
// auth (requireAuth), then delegates. The service raises ApprovalError
// with status codes 400/403/404/409 — translate those to HTTP responses.
router.post('/v2/:id/vote', requireAuth, asyncHandler(async (req, res) => {
  const me = req.session.user;
  const { vote, comment } = req.body || {};
  try {
    const r = await approvalsService.vote({
      approvalId: parseInt(req.params.id, 10),
      signerId: me.id,
      signerRole: me.role,
      vote,
      comment: comment || null,
    });
    audit.log({
      userId: me.id,
      action: r.newStatus === 'approved' ? 'approval.v2.approved'
            : r.newStatus === 'rejected' ? 'approval.v2.rejected'
            : 'approval.v2.voted',
      entityType: 'approvals',
      entityId: parseInt(req.params.id, 10),
      details: { vote, quorum_progress: r.quorumProgress },
      req,
    });
    res.json({ success: true, ...r });
  } catch (err) {
    if (err.name === 'ApprovalError') {
      return res.status(err.status || 400).json({ error: err.message, code: err.code });
    }
    throw err;
  }
}));

// POST /api/approvals/v2/:id/cancel — proposer withdraws their approval
// Body: { reason?: string }
router.post('/v2/:id/cancel', requireAuth, asyncHandler(async (req, res) => {
  const me = req.session.user;
  const { reason } = req.body || {};
  // Only the proposer may cancel — verify by reading the approval first.
  const result = await approvalsService.get(parseInt(req.params.id, 10));
  if (!result) return res.status(404).json({ error: 'Approval not found' });
  if (result.approval.raised_by !== me.id) {
    return res.status(403).json({
      error: 'Only the proposer may cancel an approval',
      code: 'NOT_PROPOSER',
    });
  }
  if (result.approval.status !== 'pending') {
    return res.status(409).json({
      error: `Approval is ${result.approval.status} — cannot cancel`,
      code: 'NOT_PENDING',
    });
  }
  const r = await approvalsService.cancel({
    approvalId: parseInt(req.params.id, 10),
    cancelledBy: me.id,
    reason: reason || null,
  });
  // TOCTOU: between the route's status-check above and the UPDATE inside
  // cancel(), another signer's vote could have flipped status to approved/
  // rejected. The cancel() UPDATE is gated on `status = 'pending'`, so it
  // affects 0 rows in that case. Surface that to the client (409) instead
  // of silently returning success — the proposer needs to know their
  // cancel didn't take effect.
  if (!r.cancelled) {
    return res.status(409).json({
      error: 'Approval status changed before cancel could take effect',
      code: 'CANCEL_RACED',
    });
  }
  audit.log({
    userId: me.id,
    action: 'approval.v2.cancelled',
    entityType: 'approvals',
    entityId: parseInt(req.params.id, 10),
    details: { reason: reason || null },
    req,
  });
  res.json({ success: true, ...r });
}));

// POST /api/approvals/:id/approve — legacy principal approval route (schedule_change).
// New unified approvals use POST /api/approvals/v2/:id/vote instead.
router.post('/:id/approve', requirePrincipal, asyncHandler(async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const me = req.session.user;

  const [[approval]] = await db.query(
    `SELECT id, request_type, project_id, ref_table, ref_id
       FROM wa_pending_actions WHERE id = ? AND status = 'pending'`,
    [id]
  );
  if (!approval) return res.status(404).json({ error: 'Approval not found' });

  if (approval.ref_table === 'schedule_versions') {
    const [[ver]] = await db.query(
      `SELECT label, drift_days FROM schedule_versions WHERE id = ?`,
      [approval.ref_id]
    );
    // Demote-all + promote-one + checklist flag must be atomic, else a failure
    // between them leaves the project with NO current schedule version.
    await db.tx(async (conn) => {
      await conn.query(
        `UPDATE schedule_versions SET is_current = 0 WHERE project_id = ? AND id != ?`,
        [approval.project_id, approval.ref_id]
      );
      await conn.query(
        `UPDATE schedule_versions SET is_current = 1, approved_by = ?, approved_at = NOW() WHERE id = ?`,
        [me.id, approval.ref_id]
      );
      await conn.query(
        `UPDATE project_checklists SET schedule_approved = 1 WHERE project_id = ?`,
        [approval.project_id]
      );
    });
  }

  res.json({ success: true });
}));
