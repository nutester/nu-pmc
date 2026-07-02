// modules/site/lib/signoff-helpers.js
//
// Multi-signature signoff logic shared between handover closure and snags-as-
// issues. The shape: a signed-off entity needs N signatures, each from one of
// a set of required role slots. Project-assignment determines which slots are
// required for that entity (closure uses all slots regardless). Deputies of
// assigned users can sign on behalf. Universal signers (principal,
// design_principal) can sign any slot via body.role.
//
// Used by:
//   - modules/site/routes/handover.js (project closure signoff)
//   - modules/site/routes/issues.js   (snag signoff — issue_type='snag')

'use strict';

const db = require('../../../middleware/db');

const UNIVERSAL_SIGNERS = ['principal', 'design_principal'];

// Look up which of a given role list are actually assigned to this project.
async function getAssignedRoles(projectId, roleList) {
  if (!roleList.length) return [];
  const placeholders = roleList.map(() => '?').join(',');
  const [rows] = await db.query(
    `SELECT DISTINCT role FROM project_assignments
     WHERE project_id = ? AND is_active = 1 AND role IN (${placeholders})`,
    [projectId, ...roleList]
  );
  return rows.map(r => r.role);
}

// Determine which slot the caller is filling.
//   - Explicit body.role wins (caller chose).
//   - Caller's own role fills if it matches a required slot.
//   - Universal signer with no body.role → defaults to 'principal' if available.
//   - Deputy: caller is deputy_id of an assigned user whose role matches a required slot.
//   - Otherwise: null (caller can't sign).
async function determineSignoffSlot(callerUser, projectId, requiredRoles, bodyRole) {
  const isUniversal = UNIVERSAL_SIGNERS.includes(callerUser.role);
  // SECURITY: only a universal signer (principal / design_principal) may sign a
  // slot OTHER than their own by naming it in body.role. A non-universal caller
  // cannot fill a slot they do not hold, even if they name it — otherwise any
  // closure role could sign as any other role, and (combined with the caller
  // being able to sign multiple times) a single person could complete closure.
  if (isUniversal && bodyRole && requiredRoles.includes(bodyRole)) return bodyRole;
  if (requiredRoles.includes(callerUser.role)) return callerUser.role;
  if (isUniversal) {
    if (requiredRoles.includes('principal')) return 'principal';
    return null;
  }
  const [rows] = await db.query(
    `SELECT u.role
     FROM users u
     JOIN project_assignments pa ON pa.user_id = u.id AND pa.is_active = 1
     WHERE u.deputy_id = ? AND pa.project_id = ? AND u.role IN (?)
       AND (u.deputy_from  IS NULL OR u.deputy_from  <= CURDATE())
       AND (u.deputy_until IS NULL OR u.deputy_until >= CURDATE())`,
    [callerUser.id, projectId, requiredRoles]
  );
  if (rows.length) return rows[0].role;
  return null;
}

module.exports = {
  UNIVERSAL_SIGNERS,
  getAssignedRoles,
  determineSignoffSlot,
};
