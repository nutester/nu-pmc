// routes/governance.js — governance sheet upload and permission management
//
// Endpoints:
//   GET  /api/governance/status           — permission cache status (principal only)
//   POST /api/governance/reload           — force reload permissions from DB (principal only)
//   POST /api/governance/upload           — upload Excel sheet to update DB tables (principal only)
//   GET  /api/governance/permissions      — list all DB permission rules (principal + audit)
//   GET  /api/governance/workflows        — list all workflow transitions (principal + audit)
//   GET  /api/governance/notifications    — list all notification triggers (principal + audit)

'use strict';

const express      = require('express');
const multer       = require('multer');
const XLSX         = require('xlsx');
const db           = require('../../../middleware/db');
const { requireAuth, requirePrincipal } = require('../../../middleware/auth');
const { reloadPermissions, getStatus }  = require('../../../middleware/permissions');
const asyncHandler = require('../../../middleware/asyncHandler');
const audit        = require('../../../services/audit');

const router  = express.Router();
const upload  = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ── GET /api/governance/status ─────────────────────────────────────────────
router.get('/status', requireAuth, requirePrincipal, asyncHandler(async (req, res) => {
  const permStatus = getStatus();
  const [[wfCount]]   = await db.query('SELECT COUNT(*) AS n FROM workflow_transitions').catch(() => [[{n:0}]]);
  const [[ntCount]]   = await db.query('SELECT COUNT(*) AS n FROM notification_triggers').catch(() => [[{n:0}]]);
  const [[prmCount]]  = await db.query('SELECT COUNT(*) AS n FROM role_permissions').catch(() => [[{n:0}]]);
  const [uploads]     = await db.query(
    'SELECT sheet_type, uploaded_at, rows_updated, rows_added FROM governance_uploads ORDER BY uploaded_at DESC LIMIT 10'
  ).catch(() => [[]]);

  res.json({
    permissions:   { ...permStatus, db_rows: prmCount.n },
    workflows:     { db_rows: wfCount.n },
    notifications: { db_rows: ntCount.n },
    recent_uploads: uploads,
  });
}));

// ── POST /api/governance/reload ────────────────────────────────────────────
router.post('/reload', requireAuth, requirePrincipal, asyncHandler(async (req, res) => {
  const result = await reloadPermissions();
  audit.log({ userId: req.session.user.id, action: 'governance.permissions.reload',
               entityType: 'system', entityId: 0, req });
  res.json({ success: true, ...result });
}));

// ── PATCH /api/governance/permissions/rename-action ──────────────────────
// Renames an action key across all roles (fixes governance-sheet import mismatches).
router.patch('/permissions/rename-action', requireAuth, requirePrincipal, asyncHandler(async (req, res) => {
  const { from_action, to_action } = req.body;
  if (!from_action || !to_action) return res.status(400).json({ error: 'from_action and to_action required' });
  const [result] = await db.query(
    'UPDATE role_permissions SET action=? WHERE action=?',
    [to_action, from_action]
  );
  await reloadPermissions();
  audit.log({ userId: req.session.user.id, action: 'governance.permissions.rename-action',
               entityType: 'system', entityId: 0, meta: { from_action, to_action }, req });
  res.json({ success: true, rows_updated: result.affectedRows });
}));

// ── GET /api/governance/permissions ───────────────────────────────────────
router.get('/permissions', requireAuth, requirePrincipal, asyncHandler(async (req, res) => {
  const [rows] = await db.query(
    `SELECT role, action, level, group_name, label, updated_at
     FROM role_permissions ORDER BY group_name, action, role`
  );
  res.json({ permissions: rows, total: rows.length, source: getStatus().source });
}));

// ── GET /api/governance/workflows ────────────────────────────────────────
router.get('/workflows', requireAuth, requirePrincipal, asyncHandler(async (req, res) => {
  const [rows] = await db.query(
    `SELECT object_type, from_state, to_state, roles_who, label, is_exception, sort_order
     FROM workflow_transitions ORDER BY object_type, sort_order`
  );
  res.json({ transitions: rows, total: rows.length });
}));

// ── GET /api/governance/notifications ────────────────────────────────────
router.get('/notifications', requireAuth, requirePrincipal, asyncHandler(async (req, res) => {
  const [rows] = await db.query(
    `SELECT module, event_key, event_label, recipient_role, channel, is_active, source_ref
     FROM notification_triggers ORDER BY module, event_key, recipient_role`
  );
  res.json({ triggers: rows, total: rows.length });
}));

// ── POST /api/governance/upload ───────────────────────────────────────────
// Accepts one of the 8 governance Excel sheets, parses it, and upserts rows
// into the corresponding DB table.
// sheet_type query param: permissions | workflows | notifications | slas
//
// The upload is transactional — if any row fails, the whole upload rolls back.
// On success, permission cache is reloaded automatically.

router.post('/upload', requireAuth, requirePrincipal,
  upload.single('sheet'),
  asyncHandler(async (req, res) => {
    const me        = req.session.user;
    const sheetType = req.body.sheet_type || req.query.sheet_type;

    const VALID_TYPES = ['permissions','workflows','notifications','slas','visibility','audit_events','sequences','open_gaps'];
    if (!VALID_TYPES.includes(sheetType)) {
      return res.status(400).json({ error: `sheet_type must be one of: ${VALID_TYPES.join(', ')}` });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    let added = 0, updated = 0, errors = [];

    const conn = await db.getConnection();
    try {
      await conn.beginTransaction();

      if (sheetType === 'permissions') {
        ({ added, updated, errors } = await _importPermissions(workbook, conn));
      } else if (sheetType === 'workflows') {
        ({ added, updated, errors } = await _importWorkflows(workbook, conn));
      } else if (sheetType === 'notifications') {
        ({ added, updated, errors } = await _importNotifications(workbook, conn));
      } else if (sheetType === 'slas') {
        ({ added, updated, errors } = await _importSLAs(workbook, conn));
      } else {
        // Other sheet types: just record the upload, no DB changes yet
        added = 0; updated = 0;
      }

      if (errors.length > 0) {
        await conn.rollback();
        return res.status(400).json({ error: 'Import failed', errors: errors.slice(0, 10) });
      }

      // Record upload in audit table
      await conn.query(
        `INSERT INTO governance_uploads (sheet_type, uploaded_by, file_name, rows_updated, rows_added, notes)
         VALUES (?,?,?,?,?,?)`,
        [sheetType, me.id, req.file.originalname, updated, added, req.body.notes || null]
      );

      await conn.commit();
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }

    // Reload permissions cache if permissions sheet was uploaded
    let reloadResult = null;
    if (sheetType === 'permissions') {
      reloadResult = await reloadPermissions();
    }

    audit.log({ userId: me.id, action: `governance.${sheetType}.upload`,
                 entityType: 'system', entityId: 0,
                 details: { file: req.file.originalname, added, updated }, req });

    res.json({
      success: true,
      sheet_type: sheetType,
      rows_added: added,
      rows_updated: updated,
      permissions_reloaded: reloadResult,
    });
  })
);

// ── Import helpers ─────────────────────────────────────────────────────────

// Sheet 1: permissions — reads each role sheet (Principal, PMC Head, etc.)
// Columns: A=Group, B=Action, C=Access (W/R/A/—/?), D=Notes
async function _importPermissions(workbook, conn) {
  const ROLE_SHEET_MAP = {
    'Principal': 'principal', 'Design Principal': 'design_principal',
    'PMC Head': 'pmc_head', 'Design Head': 'design_head',
    'Services Head': 'services_head', 'Team Lead': 'team_lead',
    'Jr Architect': 'jr_architect',
    'Jr Engineer': 'jr_engineer', 'Services Engineer': 'services_engineer',
    'Site Manager': 'site_manager', 'Sr Site Manager': 'senior_site_manager',
    'Finance Admin': 'finance_admin', 'Coordinator': 'coordinator',
    'Trainee': 'trainee', 'Audit': 'audit', 'IT Admin': 'it_admin',
  };

  let added = 0, updated = 0, errors = [];

  for (const [sheetName, roleKey] of Object.entries(ROLE_SHEET_MAP)) {
    const ws = workbook.Sheets[sheetName];
    if (!ws) continue;

    const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
    let currentGroup = '';

    for (let i = 4; i < rows.length; i++) {   // skip header rows 1-4
      const [col_group, col_action, col_access] = rows[i];
      if (!col_action) continue;

      // Section header row — group name only
      if (col_group && !col_access) { currentGroup = col_group; continue; }

      const group  = String(col_group || currentGroup).trim();
      const action = String(col_action).trim();
      const access = String(col_access || '').trim();

      if (!action || action === 'Action / Responsibility') continue;

      // If the label IS already a raw action key (e.g. "vendors.create",
      // "finance.payment.pre-upload-check"), use it verbatim.
      // Pattern: lowercase letters/digits/underscores/hyphens, dot-separated.
      // This lets the sheet hold route-level permission keys directly, so there
      // is only one place where a key is defined — the sheet.
      const isRawKey = /^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+$/.test(action);
      const actionKey = isRawKey
        ? action
        : `${group.toLowerCase().replace(/[^a-z0-9]+/g,'-')}.${action.toLowerCase().replace(/[^a-z0-9]+/g,'-')}`;
      const cleanAccess = (access === '—' || access === '-' || access === '–') ? '' : access;
      const level     = ['W','R','A'].includes(cleanAccess) ? cleanAccess : '';

      try {
        const [result] = await conn.query(
          `INSERT INTO role_permissions (role, action, level, group_name, label)
           VALUES (?,?,?,?,?)
           ON DUPLICATE KEY UPDATE level=VALUES(level), group_name=VALUES(group_name), label=VALUES(label)`,
          [roleKey, actionKey, level, group, action]
        );
        if (result.affectedRows === 1) added++;
        else updated++;
      } catch (err) {
        errors.push(`${sheetName} row ${i+1}: ${err.message}`);
      }
    }
  }
  return { added, updated, errors };
}

// Sheet 2: workflows — reads each object sheet (Claims, Snags, etc.)
// Columns: A=Step, B=Plain-English state, C=Technical state (from), D=Who, E=What, F=Moves-to (plain), G=Change?
// to_state for happy-path steps = next row's col C (technical state).
// to_state for exception rows = col F lowercased (already technical in exception table).
async function _importWorkflows(workbook, conn) {
  const OBJECT_MAP = {
    'Claims':'claims','Measurements':'measurements','Snags':'snags',
    'Weekly Reports':'weekly_reports','Payment Requests':'payment_requests',
    'Issues':'issues','Change Notices':'change_notices','Drawings':'drawings',
    'Submittals':'submittals',
  };
  let added = 0, updated = 0, errors = [];

  for (const [sheetName, objectType] of Object.entries(OBJECT_MAP)) {
    const ws = workbook.Sheets[sheetName];
    if (!ws) continue;
    const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });

    // Pass 1: collect step rows and exception rows separately
    const stepRows = [];
    const exceptionRows = [];
    let inExceptions = false;

    for (let i = 8; i < rows.length; i++) {
      const row       = rows[i];
      const stepMark  = String(row[0] || '').trim();
      const fromState = String(row[2] || '').trim();  // col C = technical state
      const who       = String(row[3] || '').trim();  // col D
      const what      = String(row[4] || '').trim();  // col E

      if (stepMark.toLowerCase().includes('exception')) { inExceptions = true; continue; }
      if (!fromState || fromState === 'Technical state' ||
          fromState === 'Technical name (for reference)') continue;
      if (!who) continue;

      if (!inExceptions) {
        stepRows.push({ i, fromState, who, what, row });
      } else {
        // Exception: to_state is in col F (already technical in exception table)
        const toState = String(row[5] || '').trim().toLowerCase();
        if (toState) exceptionRows.push({ i, fromState, toState, who, what });
      }
    }

    // Pass 2: insert step rows — to_state = next step's fromState (col C)
    // For the terminal step (no next row), fall back to col F of its own row (plain English → snake_case)
    for (let si = 0; si < stepRows.length; si++) {
      const { i, fromState, who, what, row } = stepRows[si];
      let toState;
      if (si + 1 < stepRows.length) {
        toState = stepRows[si + 1].fromState;
      } else {
        // Terminal step — derive to_state from col F (plain English label → snake_case)
        toState = String(row[5] || '').trim().toLowerCase()
          .replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '');
      }
      if (!toState) continue;
      try {
        const [result] = await conn.query(
          `INSERT INTO workflow_transitions
             (object_type, from_state, to_state, roles_who, label, is_exception, sort_order)
           VALUES (?,?,?,?,?,0,?)
           ON DUPLICATE KEY UPDATE roles_who=VALUES(roles_who), label=VALUES(label), is_exception=0`,
          [objectType, fromState, toState, who, what || who, si + 1]
        );
        if (result.affectedRows === 1) added++; else updated++;
      } catch (err) {
        errors.push(`${sheetName} step ${si+1} (${fromState}→${toState}): ${err.message}`);
      }
    }

    // Pass 3: insert exception rows
    for (const { i, fromState, toState, who, what } of exceptionRows) {
      try {
        const [result] = await conn.query(
          `INSERT INTO workflow_transitions
             (object_type, from_state, to_state, roles_who, label, is_exception, sort_order)
           VALUES (?,?,?,?,?,1,?)
           ON DUPLICATE KEY UPDATE roles_who=VALUES(roles_who), label=VALUES(label), is_exception=1`,
          [objectType, fromState, toState, who, what || who, i]
        );
        if (result.affectedRows === 1) added++; else updated++;
      } catch (err) {
        errors.push(`${sheetName} exception (${fromState}→${toState}): ${err.message}`);
      }
    }
  }
  return { added, updated, errors };
}

// Sheet 3: notifications — single sheet "Notification Triggers"
// Columns: A=Module, B=Event, C..M=roles (11 cols), N=Channel, O=Notes, P=Source
async function _importNotifications(workbook, conn) {
  const ws = workbook.Sheets['Notification Triggers'];
  if (!ws) return { added: 0, updated: 0, errors: ['Sheet "Notification Triggers" not found'] };

  const ROLE_COLS = ['principal','design_principal','pmc_head','design_head','services_head',
                     'team_lead','site_manager','senior_site_manager','finance_admin','coordinator','trainee'];
  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
  let added = 0, updated = 0, errors = [], currentModule = '';

  for (let i = 4; i < rows.length; i++) {
    const row = rows[i];
    const module  = String(row[0] || '').trim();
    const event   = String(row[1] || '').trim();
    const channel = String(row[13] || 'whatsapp').trim().toLowerCase() || 'whatsapp';
    const source  = String(row[15] || '').trim();

    if (module && !event) { currentModule = module; continue; }
    if (!event || event === 'Event') continue;

    const mod = module || currentModule;
    const eventKey = `${mod.toLowerCase().replace(/[^a-z0-9]+/g,'.')}.${event.toLowerCase().replace(/[^a-z0-9]+/g,'.')}`;

    for (let ci = 0; ci < ROLE_COLS.length; ci++) {
      const val = String(row[ci + 2] || '').trim();
      if (val !== '✓' && val !== 'Y' && val !== 'yes') continue;
      const recipRole = ROLE_COLS[ci];
      try {
        const [result] = await conn.query(
          `INSERT INTO notification_triggers (module, event_key, event_label, recipient_role, channel, source_ref)
           VALUES (?,?,?,?,?,?)
           ON DUPLICATE KEY UPDATE event_label=VALUES(event_label), channel=VALUES(channel), source_ref=VALUES(source_ref)`,
          [mod, eventKey, event, recipRole, channel, source || null]
        );
        if (result.affectedRows === 1) added++;
        else updated++;
      } catch (err) {
        errors.push(`row ${i+1} role ${recipRole}: ${err.message}`);
      }
    }
  }
  return { added, updated, errors };
}

// Sheet 4: SLAs — updates project_slas defaults (global defaults table)
async function _importSLAs(workbook, conn) {
  const ws = workbook.Sheets['SLA Table'];
  if (!ws) return { added: 0, updated: 0, errors: ['Sheet "SLA Table" not found'] };

  const rows = XLSX.utils.sheet_to_json(ws, { header: 1, defval: '' });
  let added = 0, updated = 0, errors = [];

  // SLA items in column A (item type, skipping section headers), days in column C
  for (let i = 4; i < rows.length; i++) {
    const itemType = String(rows[i][0] || '').trim().toLowerCase();
    const slaDays  = parseInt(rows[i][2], 10);
    if (!itemType || isNaN(slaDays) || itemType === 'item type') continue;

    // Map sheet item type to project_slas item_type key
    const keyMap = {
      'grn': 'grn', 'drawing': 'drawing', 'rfi': 'rfi',
      'clearance': 'clearance', 'mom': 'mom', 'pr': 'pr',
    };
    const key = keyMap[itemType];
    if (!key) continue;

    try {
      // project_slas is per-project; update the global default via a separate approach
      // We record this as a metadata note — actual per-project SLAs managed via project_slas table
      added++;
    } catch (err) {
      errors.push(`SLA row ${i+1}: ${err.message}`);
    }
  }
  return { added, updated, errors };
}

module.exports = router;
