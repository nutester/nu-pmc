// routes/project-setup.js — Project scope, dates, statutory, design programme
const express = require('express');
const db      = require('../../../middleware/db');
const storage = require('../../../services/file-storage');
const users = require('../../../services/users-lookup');
const { requireAuth, requirePrincipal, requirePMC, requireProjectScope } = require('../../../middleware/auth');
const { requirePermission } = require('../../../middleware/permissions');
const { upload } = require('../../../middleware/upload');
const ai      = require('../../../services/ai');
const notif   = require('../../../services/notifications');
const asyncHandler = require('../../../middleware/asyncHandler');
const audit = require('../../../services/audit');
const router  = express.Router();

// GET /api/project-setup/:id/scope
router.get('/:id/scope', requireAuth, asyncHandler(async (req, res) => {
    const [[scope]] = await db.query('SELECT * FROM project_scope WHERE project_id = ?', [req.params.id]);
    res.json({ scope: scope || null });
  }));

// PUT /api/project-setup/:id/scope — any of 5 setup roles can update their section
router.put('/:id/scope', requireAuth, requireProjectScope(req => req.params.id),
  requirePermission('onboarding.project-setup.edit-scope'),
  asyncHandler(async (req, res) => {
    const me = req.session.user;

    // Verify project exists — prevents FK constraint error turning into 500
    const [[proj]] = await db.query('SELECT id FROM projects WHERE id = ?', [req.params.id]);
    if (!proj) return res.status(404).json({ error: 'Project not found' });

    const {
      scope_type, sqft_area, num_floors, num_blocks, description,
      requires_statutory_approvals, dlp_months, planned_handover_date,
      retention_amount, retention_due_date, petty_cash_limit, petty_cash_txn_limit,
      entity_id, billing_account,
    } = req.body;

    // Entity selection — principals and finance_admin only
    if (entity_id) {
      const canSetEntity = ['principal','design_principal','finance_admin'].includes(me.role);
      if (!canSetEntity) return res.status(403).json({ error: 'Entity selection — principals or finance admin only' });
      await db.query(
        'UPDATE projects SET entity_id=?, billing_account=? WHERE id=?',
        [entity_id, billing_account||'primary', req.params.id]
      );
    }

    await db.query(`
      INSERT INTO project_scope
        (project_id, scope_type, sqft_area, num_floors, num_blocks, description,
         requires_statutory_approvals, dlp_months, planned_handover_date,
         retention_amount, retention_due_date, petty_cash_limit, petty_cash_txn_limit, updated_by)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE
        scope_type=VALUES(scope_type), sqft_area=VALUES(sqft_area),
        num_floors=VALUES(num_floors), num_blocks=VALUES(num_blocks),
        description=VALUES(description),
        requires_statutory_approvals=VALUES(requires_statutory_approvals),
        dlp_months=VALUES(dlp_months), planned_handover_date=VALUES(planned_handover_date),
        retention_amount=VALUES(retention_amount), retention_due_date=VALUES(retention_due_date),
        petty_cash_limit=VALUES(petty_cash_limit), petty_cash_txn_limit=VALUES(petty_cash_txn_limit),
        updated_by=VALUES(updated_by)`,
      [req.params.id, scope_type||'pmc', sqft_area||null, num_floors||null, num_blocks||null,
       description||null, requires_statutory_approvals?1:0, dlp_months||12,
       planned_handover_date||null, retention_amount||null, retention_due_date||null,
       petty_cash_limit||null, petty_cash_txn_limit||null, me.id]
    );

    // Trigger AI date sanity check if handover date provided and schedule exists
    if (planned_handover_date) {
      setImmediate(async () => {
        try {
          const DS = require('../../design-services/contract');
          const hasSv = await DS.functions.hasCurrentScheduleVersion(req.params.id);
          const proj = { name: await users.projectName(req.params.id) };
          const dates = { planned_handover: planned_handover_date, dlp_months, retention_due: retention_due_date };
          const result = await ai.checkDateSanity(proj?.name||'', sqft_area||0, dates, hasSv ? 'uploaded' : null);
          if (result) {
            await db.query(
              `INSERT INTO date_sanity_checks (project_id, check_trigger, dates_checked, issues, warnings, verdict)
               VALUES (?,?,?,?,?,?)`,
              [req.params.id, 'entry', JSON.stringify(dates),
               JSON.stringify(result.issues||[]), JSON.stringify(result.warnings||[]), result.verdict||'']
            );
          }
        } catch (e) { console.warn('[project-setup]', e.message); }
      });
    }

    audit.log({ userId: me.id, action: 'project_setup.scope_set',
      entityType: 'project_scope', entityId: parseInt(req.params.id, 10),
      details: { scope_type: scope_type || 'pmc', sqft_area: sqft_area || null, num_floors: num_floors || null, num_blocks: num_blocks || null, dlp_months: dlp_months || 12, planned_handover_date: planned_handover_date || null, entity_id_set: !!entity_id }, req });

    res.json({ success: true });
  }));

// POST /api/project-setup/:id/documents — upload appointment letter etc
router.post('/:id/documents', requireAuth, requirePrincipal, upload.single('doc'), asyncHandler(async (req, res) => {
    const { doc_type, doc_date, notes } = req.body;
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'File required' });
    const isClassified = ['appointment_letter','contract'].includes(doc_type) ? 1 : 0;
    await storage.saveDocument({
      projectId: req.params.id, file, uploadedBy: req.session.user.id,
      docType: doc_type || 'other',
      notes: notes || null, docDate: doc_date || null,
      isClassified,
    });
    audit.log({ userId: req.session.user.id, action: 'project_setup.document.upload',
      entityType: 'project_documents', entityId: null,
      details: { project_id: parseInt(req.params.id, 10), doc_type: doc_type || 'other', doc_date: doc_date || null, classified: !!isClassified }, req });
    res.json({ success: true, classified: isClassified === 1 });
  }));

// GET /api/project-setup/:id/documents
router.get('/:id/documents', requireAuth, asyncHandler(async (req, res) => {
    const me = req.session.user;
    const isPrincipal = ['principal','design_principal'].includes(me.role);
    const [docs] = await db.query(
      `SELECT * FROM project_documents
       WHERE project_id = ? ${isPrincipal ? '' : 'AND is_classified = 0'}
       ORDER BY uploaded_at DESC`,
      [req.params.id]
    );
    const Auth = require('../../auth/contract');
    const users = await Auth.functions.getUsers(docs.map(d => d.uploaded_by).filter(Boolean));
    docs.forEach(d => { d.uploaded_by_name = users.get(d.uploaded_by)?.full_name || null; });
    res.json({ documents: docs });
  }));

// GET /api/project-setup/:id/sanity-checks — PMC Head and principals can view
router.get('/:id/sanity-checks', requireAuth, requirePMC, asyncHandler(async (req, res) => {
    const [checks] = await db.query(
      `SELECT * FROM date_sanity_checks
       WHERE project_id = ? ORDER BY checked_at DESC LIMIT 10`,
      [req.params.id]
    );
    const Auth = require('../../auth/contract');
    const users = await Auth.functions.getUsers(checks.map(c => c.acknowledged_by).filter(Boolean));
    checks.forEach(c => { c.acknowledged_by_name = users.get(c.acknowledged_by)?.full_name || null; });
    res.json({ checks });
  }));

// PATCH /api/project-setup/:id/sanity-checks/:check_id/acknowledge — PMC Head acknowledges
router.patch('/:id/sanity-checks/:check_id/acknowledge', requireAuth, requirePMC, asyncHandler(async (req, res) => {
    await db.query(
      'UPDATE date_sanity_checks SET acknowledged_by = ?, acknowledged_at = NOW() WHERE id = ? AND project_id = ?',
      [req.session.user.id, req.params.check_id, req.params.id]
    );
    // Notify principals in-app — not a gate
    const principals = await users.principals();
    for (const p of principals) {
      await notif.notify(p.id, 'sanity_check', `Date sanity check acknowledged by PMC Head on project ${req.params.id}.`);
    }
    audit.log({ userId: req.session.user.id, action: 'project_setup.sanity_check.acknowledge',
      entityType: 'date_sanity_checks', entityId: parseInt(req.params.check_id, 10),
      details: { project_id: parseInt(req.params.id, 10) }, req });
    res.json({ success: true });
  }));
// GET /api/project-setup/entities — list company entities for selector
router.get('/entities', requireAuth, asyncHandler(async (req, res) => {
    const [entities] = await db.query(
      'SELECT id, entity_code, legal_name, gstin, bank_account_no, bank_name FROM company_entities WHERE is_active = 1'
    );
    res.json({ entities });
  }));

// ============================================================================
// PROJECT SETUP CHECKLIST - Configurable onboarding tracker
// ============================================================================

// Role-to-category visibility mapping
const ROLE_VISIBILITY = {
  principal: ['core', 'boq', 'vendors', 'drawings', 'schedule', 'finance'], // sees everything
  design_principal: ['core', 'boq', 'vendors', 'drawings', 'schedule', 'finance'], // sees everything
  pmc_head: ['core', 'boq', 'vendors', 'drawings', 'schedule', 'finance'], // orchestrates, sees everything
  finance_admin: ['core', 'boq', 'vendors', 'finance'], // sees finance-relevant items
  design_head: ['drawings'], // only design stream
  services_head: ['drawings'], // only services stream
  site_manager: ['schedule', 'vendors'], // operational readiness
};

// Predefined validation registry using named validation identifiers mapped to safe handlers
const VALIDATION_REGISTRY = {
  project_team_assigned: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(DISTINCT role) AS cnt 
       FROM project_assignments 
       WHERE project_id = ? AND is_active = 1 
         AND role IN ('pmc_head', 'design_head', 'services_head', 'site_manager')`,
      [projectId]
    );
    return (rows[0]?.cnt || 0) > 0;
  },
  client_details_complete: async (projectId) => {
    const [rows] = await db.query(
      `SELECT c.gstin, c.pan 
       FROM clients c 
       JOIN projects p ON c.id = p.client_id 
       WHERE p.id = ?`,
      [projectId]
    );
    if (rows.length === 0) return false;
    return ['gstin', 'pan'].every(f => rows[0][f] != null && rows[0][f] !== '');
  },
  internal_boq_uploaded: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM boq_versions WHERE project_id = ?`,
      [projectId]
    );
    return rows[0].cnt >= 1;
  },
  boq_has_items: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM boq_items WHERE project_id = ?`,
      [projectId]
    );
    return rows[0].cnt >= 1;
  },
  client_boq_uploaded: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM client_boq_items WHERE project_id = ?`,
      [projectId]
    );
    return rows[0].cnt >= 1;
  },
  vendors_cleared: async () => {
    const [rows] = await db.query(
      // vendors.clearance_status ENUM is ('pending','cleared','rejected') —
      // 'approved' is not a valid value and never matched, so this gate was
      // permanently failing. Correct value is 'cleared'.
      `SELECT COUNT(*) as cnt FROM vendors WHERE clearance_status = 'cleared'`
    );
    return rows[0].cnt > 0;
  },
  vendor_engagements_approved: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM vendor_engagements WHERE project_id = ? AND approval_status = 'approved'`,
      [projectId]
    );
    return rows[0].cnt > 0;
  },
  boq_vendor_mapping_complete: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM vendor_boq_mapping WHERE project_id = ?`,
      [projectId]
    );
    return rows[0].cnt >= 1;
  },
  drawing_register_design_initialized: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM drawing_register WHERE project_id = ? AND stream = 'design'`,
      [projectId]
    );
    return rows[0].cnt > 0;
  },
  drawing_register_services_initialized: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM drawing_register WHERE project_id = ? AND stream = 'services'`,
      [projectId]
    );
    return rows[0].cnt > 0;
  },
  r0_schedule_baselined: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM schedule_versions WHERE project_id = ? AND version_number = 1`,
      [projectId]
    );
    return rows[0].cnt > 0;
  },
  schedule_has_tasks: async (projectId) => {
    const [rows] = await db.query(
      `SELECT COUNT(*) as cnt FROM schedule_tasks WHERE project_id = ?`,
      [projectId]
    );
    return rows[0].cnt >= 1;
  }
};

// Legacy backward-compatibility SQL query structure to rule mapping
const SQL_QUERY_TO_RULE = {
  "SELECT COUNT(DISTINCT role) FROM project_assignments WHERE project_id = ? AND is_active = 1 AND role IN ('pmc_head','design_head','services_head','site_manager')": "project_team_assigned",
  "SELECT COUNT(*) FROM vendors WHERE clearance_status = 'approved'": "vendors_cleared",
  "SELECT COUNT(*) FROM vendor_engagements WHERE project_id = ? AND approval_status = 'approved'": "vendor_engagements_approved",
  "SELECT COUNT(*) FROM drawing_register WHERE project_id = ? AND stream = 'design'": "drawing_register_design_initialized",
  "SELECT COUNT(*) FROM drawing_register WHERE project_id = ? AND stream = 'services'": "drawing_register_services_initialized",
  "SELECT COUNT(*) FROM schedule_versions WHERE project_id = ? AND version_number = 1": "r0_schedule_baselined"
};

// Validation helpers
async function validateItem(item, projectId) {
  const config = item.validation_config ? JSON.parse(item.validation_config) : {};
  let ruleKey = config.rule || item.validation_rule_id; // Support explicit rule mapping

  if (!ruleKey) {
    // Attempt backward compatibility mapping of old config style to validation registry keys
    if (item.validation_type === 'sql_query' && config.query) {
      const normSql = config.query.replace(/\s+/g, ' ').trim();
      for (const [sqlPattern, targetRule] of Object.entries(SQL_QUERY_TO_RULE)) {
        if (sqlPattern.replace(/\s+/g, ' ').trim() === normSql) {
          ruleKey = targetRule;
          break;
        }
      }
    } else if (item.validation_type === 'field_populated' && config.table && config.fields) {
      if (config.table === 'clients' && config.fields.includes('gstin')) {
        ruleKey = 'client_details_complete';
      }
    } else if (item.validation_type === 'row_count' && config.table) {
      const tableToRule = {
        'boq_versions': 'internal_boq_uploaded',
        'boq_items': 'boq_has_items',
        'client_boq_items': 'client_boq_uploaded',
        'vendor_boq_mapping': 'boq_vendor_mapping_complete',
        'schedule_tasks': 'schedule_has_tasks'
      };
      ruleKey = tableToRule[config.table];
    }
  }

  if (ruleKey && VALIDATION_REGISTRY[ruleKey]) {
    try {
      return await VALIDATION_REGISTRY[ruleKey](projectId);
    } catch (err) {
      console.warn('[project-setup validateItem]', item.task_name, '→', err.message);
      return false;
    }
  }

  if (item.validation_type === 'manual') {
    return false;
  }

  // If a rule is configured but not found, or validation type is unrecognized/not matched,
  // do NOT execute raw SQL. Return false.
  console.warn('[project-setup validateItem] Unsupported or unmapped validation:', item.task_name, 'type:', item.validation_type, 'rule:', ruleKey);
  return false;
}

// GET /api/project-setup/:id/checklist
// Returns checklist with completion status
router.get('/:id/checklist', requireAuth, asyncHandler(async (req, res) => {
  const projectId = req.params.id;
  const { role } = req.session.user;
  
  // Get project and its template
  const [projects] = await db.query(
    `SELECT p.id, p.name, p.setup_template_id, t.template_name
     FROM projects p
     LEFT JOIN setup_checklist_templates t ON p.setup_template_id = t.id
     WHERE p.id = ?`,
    [projectId]
  );
  
  if (projects.length === 0) {
    return res.status(404).json({ error: 'Project not found' });
  }
  
  const project = projects[0];
  const templateId = project.setup_template_id;
  
  if (!templateId) {
    return res.json({ 
      project_id: projectId, 
      project_name: project.name,
      items: [], 
      total: 0,
      completed: 0,
      percent: 100,
      message: 'No setup checklist assigned to this project'
    });
  }
  
  // Get checklist items for this template
  const [allItems] = await db.query(
    `SELECT 
      ci.id,
      ci.task_name,
      ci.task_description,
      ci.task_category,
      ci.owner_role,
      ci.is_mandatory,
      ci.blocks_operations,
      ci.validation_type,
      ci.validation_config,
      ci.sort_order,
      COALESCE(pst.is_complete, 0) AS is_complete,
      pst.completed_at,
      pst.completed_by
     FROM setup_checklist_items ci
     LEFT JOIN project_setup_tracking pst ON ci.id = pst.checklist_item_id AND pst.project_id = ?
     WHERE ci.template_id = ?
     ORDER BY ci.sort_order`,
    [projectId, templateId]
  );
  const Auth = require('../../auth/contract');
  const compUsers = await Auth.functions.getUsers(allItems.map(i => i.completed_by).filter(Boolean));
  allItems.forEach(i => { i.completed_by_name = compUsers.get(i.completed_by)?.full_name || null; });
  
  // Auto-validate items that aren't manually completed
  const itemsWithStatus = await Promise.all(allItems.map(async (item) => {
    let isComplete = item.is_complete === 1;
    
    // If not manually marked complete, try auto-validation
    if (!isComplete && item.validation_type !== 'manual') {
      isComplete = await validateItem(item, projectId);
      
      // If auto-validated as complete, update tracking table
      if (isComplete) {
        await db.query(
          `INSERT INTO project_setup_tracking (project_id, checklist_item_id, is_complete, completed_at)
           VALUES (?, ?, 1, NOW())
           ON DUPLICATE KEY UPDATE is_complete = 1, completed_at = NOW()`,
          [projectId, item.id]
        );
      }
    }
    
    return {
      ...item,
      is_complete: isComplete,
      validation_config: undefined // Don't expose config to frontend
    };
  }));
  
  // Filter by role visibility
  const allowedCategories = ROLE_VISIBILITY[role] || [];
  const visibleItems = itemsWithStatus.filter(item => 
    allowedCategories.includes(item.task_category) ||
    item.owner_role === role // Always see items you own
  );
  
  // Calculate stats
  const total = itemsWithStatus.length;
  const completed = itemsWithStatus.filter(i => i.is_complete).length;
  const percent = total > 0 ? Math.round((completed / total) * 100) : 100;
  
  res.json({
    project_id: projectId,
    project_name: project.name,
    template_name: project.template_name,
    items: visibleItems,
    total,
    completed,
    percent,
    is_complete: percent === 100
  });
}));

// POST /api/project-setup/:id/checklist/:item_id/complete
// Manually mark an item as complete (for manual validation items)
//
// Bug B32: previously gated only by requireAuth + an inline role check.
// A site_manager from Project A could mark items complete on Project B
// if their role happened to match the item's owner_role. Now: scope
// enforced via middleware before any logic runs.
router.post('/:id/checklist/:item_id/complete',
  requireAuth,
  requireProjectScope(req => req.params.id),
  asyncHandler(async (req, res) => {
  const { id: projectId, item_id } = req.params;
  const { notes } = req.body;
  const userId = req.session.user.id;
  
  // Verify item exists and belongs to this project's template
  const [items] = await db.query(
    `SELECT ci.id, ci.owner_role, ci.validation_type
     FROM setup_checklist_items ci
     JOIN projects p ON p.setup_template_id = ci.template_id
     WHERE p.id = ? AND ci.id = ?`,
    [projectId, item_id]
  );
  
  if (items.length === 0) {
    return res.status(404).json({ error: 'Checklist item not found for this project' });
  }
  
  const item = items[0];
  
  // Verify user is authorized (must be item owner or principal/pmc_head)
  const userRole = req.session.user.role;
  if (item.owner_role !== userRole && !['principal', 'design_principal', 'pmc_head'].includes(userRole)) {
    return res.status(403).json({ error: 'Not authorized to complete this item' });
  }
  
  // Mark as complete
  await db.query(
    `INSERT INTO project_setup_tracking (project_id, checklist_item_id, is_complete, completed_at, completed_by, notes)
     VALUES (?, ?, 1, NOW(), ?, ?)
     ON DUPLICATE KEY UPDATE is_complete = 1, completed_at = NOW(), completed_by = ?, notes = ?`,
    [projectId, item_id, userId, notes, userId, notes]
  );

  const audit = require('../../../services/audit');
  audit.log({ userId, action: 'project_setup.checklist_complete',
    entityType: 'project_setup_tracking', entityId: parseInt(item_id, 10),
    details: { project_id: parseInt(projectId, 10), notes: notes || null }, req });

  res.json({ success: true, message: 'Item marked as complete' });
}));

// POST /api/project-setup/:id/checklist/:item_id/uncomplete
// Mark an item as incomplete (in case of error)
//
// Enforces project-scoped authorization to ensure users can only
// modify checklist items belonging to projects within their permitted scope.
router.post('/:id/checklist/:item_id/uncomplete',
  requireAuth,
  requireProjectScope(req => req.params.id),
  asyncHandler(async (req, res) => {
  const { id: projectId, item_id } = req.params;
  const userRole = req.session.user.role;
  
  // Only principals and PMC head can uncomplete items
  if (!['principal', 'design_principal', 'pmc_head'].includes(userRole)) {
    return res.status(403).json({ error: 'Not authorized' });
  }
  
  await db.query(
    `UPDATE project_setup_tracking 
     SET is_complete = 0, completed_at = NULL, completed_by = NULL, notes = NULL
     WHERE project_id = ? AND checklist_item_id = ?`,
    [projectId, item_id]
  );

  const audit = require('../../../services/audit');
  audit.log({ userId: req.session.user.id, action: 'project_setup.checklist_uncomplete',
    entityType: 'project_setup_tracking', entityId: parseInt(item_id, 10),
    details: { project_id: parseInt(projectId, 10) }, req });

  res.json({ success: true, message: 'Item marked as incomplete' });
}));

module.exports = router;
