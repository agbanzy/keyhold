import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const here = path.dirname(fileURLToPath(import.meta.url));

// The schema the tests run against is the same file the deployed database runs
// against — read here and applied per test worker, so a test can never pass
// against a table shape that migrations/0001_genesis.sql does not describe.
const migrations = await readD1Migrations(path.join(here, 'migrations'));

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: './wrangler.toml' },
      miniflare: {
        d1Databases: ['DB'],
        bindings: {
          INSTANCE_NAME: 'Keyhold Test',
          TREASURY_ADDRESS: '0x0000000000000000000000000000000000000001',
          USDC_CONTRACT: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          BASE_RPC_URLS: 'https://mainnet.base.org',
          WITNESS_REPO: '',
          TEST_MIGRATIONS: migrations,
        },
      },
    }),
  ],
  test: {
    setupFiles: ['./test/apply-migrations.ts'],
  },
});
