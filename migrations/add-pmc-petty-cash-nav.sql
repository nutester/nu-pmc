-- Add petty_cash tab to PMC Head's Money nav.
-- NOTE: role_nav uses columns (bucket, is_visible), NOT (tab_group, is_active).
-- The old version referenced non-existent columns, so it errored and was skipped
-- under `mysql --force` — which is why it never applied on the server. Fixed below.
-- Idempotent: safe to re-run (guarded by NOT EXISTS).
INSERT INTO role_nav (role, bucket, tab_key, sort_order, is_visible)
SELECT 'pmc_head', 'money', 'petty_cash', 5, 1
 WHERE NOT EXISTS (
   SELECT 1 FROM role_nav rn
    WHERE rn.role = 'pmc_head' AND rn.bucket = 'money' AND rn.tab_key = 'petty_cash'
 );
