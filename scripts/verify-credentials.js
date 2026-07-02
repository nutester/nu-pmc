#!/usr/bin/env node
/*
 * verify-credentials.js
 * Confirms the live DB matches handover/User credentials.txt:
 *   - which usernames actually exist (active)
 *   - whether each account's password IS the default Start@123 (bcrypt check)
 *   - whether force_password_change is set (forced reset on first login)
 *   - flags any username in the file but missing from the DB, or extra in the DB
 *
 * Passwords are bcrypt-hashed and cannot be read back; this VERIFIES the default
 * without ever printing a real password.
 *
 * Run:  node scripts/verify-credentials.js
 * (loads .env for DB connection, same as the app)
 */
require('dotenv').config();
const bcrypt = require('bcrypt');
const pool = require('../middleware/db');

const DEFAULT = 'Start@123';
const EXPECTED = [
  'principal','design_principal','pmc_head','design_head','services_head',
  'team_lead','jr_architect','jr_engineer','services_engineer','coordinator',
  'site_manager','senior_site_manager','finance_admin','trainee','audit','it_admin',
];

(async () => {
  try {
    const [rows] = await pool.query(
      `SELECT id, username, role, is_active, force_password_change, password_hash
         FROM users ORDER BY id`
    );

    const found = new Set();
    console.log('\nusername              active  pwd=Start@123  force_change  role');
    console.log('--------------------  ------  -------------  ------------  ----');
    for (const u of rows) {
      found.add(u.username);
      let isDefault = false;
      try { isDefault = await bcrypt.compare(DEFAULT, u.password_hash || ''); } catch (_) {}
      console.log(
        u.username.padEnd(20),
        String(!!u.is_active).padEnd(6),
        (isDefault ? 'YES' : 'no ').padEnd(13),
        String(u.force_password_change === 1 || u.force_password_change === true).padEnd(12),
        u.role
      );
    }

    const missing = EXPECTED.filter(u => !found.has(u));
    const extra   = rows.map(r => r.username).filter(u => !EXPECTED.includes(u));

    console.log('\nSUMMARY');
    console.log('  total user rows in DB :', rows.length);
    console.log('  active users          :', rows.filter(r => r.is_active).length);
    console.log('  expected (file) count :', EXPECTED.length);
    console.log('  in file but MISSING   :', missing.length ? missing.join(', ') : '(none)');
    console.log('  in DB but NOT in file :', extra.length ? extra.join(', ') : '(none)');
  } catch (e) {
    console.error('ERROR:', e.message);
  } finally {
    try { await pool.end(); } catch (_) {}
  }
})();
