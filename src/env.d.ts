/**
 * `Cloudflare.Env` is the runtime's idea of this Worker's bindings, and it
 * starts out empty. Merging our own Env into it means `env` from
 * `cloudflare:test` — and anything else typed against the ambient binding set —
 * is the same shape core/db.ts declares, rather than a second definition that
 * can quietly drift from wrangler.toml.
 */

import type { Env as KeyholdEnv } from './core/db';

declare global {
  namespace Cloudflare {
    interface Env extends KeyholdEnv {}
  }
}

export {};
