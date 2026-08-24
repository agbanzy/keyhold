/**
 * Not a product test — an experiment that pins down D1's batch semantics, which
 * the whole guard design depends on. Keep it: if a runtime upgrade changes any
 * of these answers, the spine's atomicity assumptions need revisiting.
 */

import { describe, expect, it, beforeEach } from 'vitest';
import { env } from 'cloudflare:test';

const db = env.DB as D1Database;

beforeEach(async () => {
  await db.prepare('DELETE FROM quota_usage').run();
  await db.prepare('DELETE FROM nonces').run();
});

describe('D1 batch atomicity', () => {
  it('does NOT roll back when an earlier statement merely affects zero rows', async () => {
    const results = await db.batch([
      // Affects nothing: no such row.
      db
        .prepare('UPDATE quota_usage SET used = used + 1 WHERE citizen_id = ?')
        .bind('nobody'),
      // Should this land? The answer decides the guard design.
      db
        .prepare(
          'INSERT INTO quota_usage (citizen_id, day, action, used) VALUES (?,?,?,?)',
        )
        .bind('ct_x', '2026-01-01', 'post', 1),
    ]);

    expect(results[0]?.meta.changes ?? 0).toBe(0);

    const row = await db
      .prepare('SELECT used FROM quota_usage WHERE citizen_id = ?')
      .bind('ct_x')
      .first<{ used: number }>();

    // Zero changes is not an error, so the batch commits. A guard that only
    // returns changes=0 therefore CANNOT abort the writes that follow it.
    expect(row?.used).toBe(1);
  });

  it('DOES roll back the whole batch when a statement violates a constraint', async () => {
    await db
      .prepare('INSERT INTO nonces (citizen_id, nonce, ts) VALUES (?,?,?)')
      .bind('ct_y', 'n1', 1)
      .run();

    await expect(
      db.batch([
        // Duplicate primary key: throws.
        db
          .prepare('INSERT INTO nonces (citizen_id, nonce, ts) VALUES (?,?,?)')
          .bind('ct_y', 'n1', 2),
        db
          .prepare(
            'INSERT INTO quota_usage (citizen_id, day, action, used) VALUES (?,?,?,?)',
          )
          .bind('ct_z', '2026-01-01', 'post', 1),
      ]),
    ).rejects.toThrow();

    const row = await db
      .prepare('SELECT used FROM quota_usage WHERE citizen_id = ?')
      .bind('ct_z')
      .first<{ used: number }>();

    // Nothing from the batch survived. Constraint violations are the reliable
    // way to abort.
    expect(row).toBeNull();
  });

  it('reports a constraint violation as a thrown error, not a result row', async () => {
    await db
      .prepare('INSERT INTO nonces (citizen_id, nonce, ts) VALUES (?,?,?)')
      .bind('ct_w', 'n1', 1)
      .run();

    let caught: unknown;
    try {
      await db.batch([
        db
          .prepare('INSERT INTO nonces (citizen_id, nonce, ts) VALUES (?,?,?)')
          .bind('ct_w', 'n1', 2),
      ]);
    } catch (e) {
      caught = e;
    }
    expect(String(caught)).toMatch(/UNIQUE constraint failed/i);
  });
});
