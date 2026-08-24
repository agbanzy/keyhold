/**
 * Give every test worker the real schema before any test runs.
 *
 * vitest.config.ts reads migrations/ and passes it through as TEST_MIGRATIONS;
 * this applies it. Without it the D1 binding exists but is empty, and every
 * test fails on "no such table" rather than on anything it meant to check.
 */

import { applyD1Migrations, env, type D1Migration } from 'cloudflare:test';

const migrations = (env as unknown as { TEST_MIGRATIONS: D1Migration[] })
  .TEST_MIGRATIONS;

await applyD1Migrations(env.DB, migrations);
